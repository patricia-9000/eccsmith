#include "Blacksmith.hpp"

#include <sys/resource.h>
#include <cstdio>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <array>

#include "Forges/FuzzyHammerer.hpp"
#include "Utilities/BlacksmithConfig.hpp"

#include <argagg/argagg.hpp>
#include <argagg/convert/csv.hpp>

ProgramArguments program_args;
RasWatcher *ras_watcher;

int main(int argc, char **argv) {
  Logger::initialize(program_args.logfile);

  handle_args(argc, argv);

  // load config
  Logger::log_debug("Loading DRAM config");
  BlacksmithConfig config = BlacksmithConfig::from_jsonfile(program_args.config);

  if (program_args.generate_patterns) {
    auto num_activations = program_args.generate_patterns;
    exit(handle_arg_generate_patterns(config, num_activations, program_args.num_address_mappings_per_pattern));
  }

  DRAMAddr::set_config(config);

  // prints the current git commit and some program metadata
  Logger::log_metadata(GIT_COMMIT_HASH, config, program_args.runtime_limit);

  // give this process the highest CPU priority so it can hammer with less interruptions
  int ret = setpriority(PRIO_PROCESS, 0, -20);
  if (ret!=0) Logger::log_error("Instruction setpriority failed.");

  // allocate a large bulk of contiguous memory
  Logger::log_debug("Allocating memory...");
  Memory memory(config, true);
  memory.allocate_memory();

  DramAnalyzer dram_analyzer(config, memory.get_starting_address());

  // initialize the DRAMAddr class to load the proper memory configuration
  DRAMAddr::initialize(memory.get_starting_address());

  // count the number of possible activations per refresh interval, if not given as program argument
  uint64_t acts_per_trefi = config.acts_per_trefi;
  if (acts_per_trefi == 0)
    acts_per_trefi = dram_analyzer.count_acts_per_trefi();
  
  // start the rasdaemon watcher
  Logger::log_debug("Connecting to Rasdaemon database...");
  ras_watcher = new RasWatcher();

  Logger::log_debug("Jumping to hammering logic");
  if (!program_args.load_json_filename.empty()) {
    ReplayingHammerer replayer(config, memory);
    if (program_args.sweeping) {
      replayer.replay_patterns_brief(program_args.load_json_filename, program_args.pattern_ids,
                                     MB(256), false);
    } else {
      replayer.replay_patterns(program_args.load_json_filename, program_args.pattern_ids);
    }
  } else {
    FuzzyHammerer::n_sided_frequency_based_hammering(config, dram_analyzer, memory,
                                                     acts_per_trefi, config.acts_per_trefi != 0,
                                                     program_args.runtime_limit,
                                                     program_args.num_address_mappings_per_pattern,
                                                     program_args.sweeping);
  }

  Logger::close();
  delete ras_watcher;
  return EXIT_SUCCESS;
}

int handle_arg_generate_patterns(BlacksmithConfig &config, size_t num_activations, const size_t probes_per_pattern) {
  // this parameter is defined in FuzzingParameterSet
  const size_t MAX_NUM_REFRESH_INTERVALS = 32;
  const size_t MAX_ACCESSES = num_activations*MAX_NUM_REFRESH_INTERVALS;
  void *rows_to_access = calloc(MAX_ACCESSES, sizeof(int));
  if (rows_to_access==nullptr) {
    Logger::log_error("Allocation of rows_to_access failed!");
    return EXIT_FAILURE;
  }
  FuzzyHammerer::generate_pattern_for_ARM(config, num_activations, static_cast<int *>(rows_to_access), static_cast<int>(MAX_ACCESSES), probes_per_pattern);
  return EXIT_SUCCESS;
}

void handle_args(int argc, char **argv) {
  // An option is specified by four things:
  //    (1) the name of the option,
  //    (2) the strings that activate the option (flags),
  //    (3) the option's help message,
  //    (4) and the number of arguments the option expects.
  argagg::parser argparser{{
      {"help", {"-h", "--help"}, "shows this help message", 0},

      {"config", {"-c", "--config"}, "loads the specified config file (JSON) as DRAM address config.", 1},

      {"generate-patterns", {"-g", "--generate-patterns"}, "generates N patterns, but does not perform hammering; used by ARM port", 1},
      {"replay-patterns", {"-y", "--replay-patterns"}, "replays patterns given as comma-separated list of pattern IDs", 1},
      {"load-json", {"-j", "--load-json"}, "loads the specified JSON file generated in a previous fuzzer run, loads patterns given by --replay-patterns or determines the best ones", 1},

      // note that this parameter doesn't require a value, its presence already equals a "true"
      {"sweeping", {"-w", "--sweeping"}, "sweep the best pattern over a contig. memory area after fuzzing (default: present)", 0},

      {"logfile", {"-l", "--logfile"}, "log to specified file (default: run.log)", 1},
      {"runtime-limit", {"-t", "--runtime-limit"}, "number of seconds to run the fuzzer before sweeping/terminating (default: 10800)", 1},
      {"acts-per-ref", {"-a", "--acts-per-ref"}, "number of activations in a tREF interval, i.e., 7.8us (default: None)", 1},
      {"probes", {"-p", "--probes"}, "number of different DRAM locations to try each pattern on (default: NUM_BANKS/4)", 1},
    }};

  argagg::parser_results parsed_args;
  try {
    parsed_args = argparser.parse(argc, argv);
  } catch (const std::exception &e) {
    std::cerr << e.what() << '\n';
    exit(EXIT_FAILURE);
  }

  if (parsed_args["help"]) {
    std::cerr << argparser;
    exit(EXIT_SUCCESS);
  }

  /**
   * mandatory parameters
   */
  if (parsed_args.has_option("config")) {
      program_args.config = parsed_args["config"].as<std::string>("");
      Logger::log_debug(format_string("Set --config=%s", program_args.config.c_str()));
  } else {
      Logger::log_error("Program argument '--config <string>' is mandatory! Cannot continue.");
      exit(EXIT_FAILURE);
  }

  /**
  * optional parameters
  */
  program_args.logfile = parsed_args["logfile"].as<std::string>(program_args.logfile);
  Logger::log_debug(format_string("Set --logfile=%s", program_args.logfile.c_str()));
  program_args.sweeping = parsed_args.has_option("sweeping") || program_args.sweeping;
  Logger::log_debug(format_string("Set --sweeping=%s", (program_args.sweeping ? "true" : "false")));

  program_args.runtime_limit = parsed_args["runtime-limit"].as<unsigned long>(program_args.runtime_limit);
  Logger::log_debug(format_string("Set --runtime_limit=%ld", program_args.runtime_limit));

  program_args.num_address_mappings_per_pattern = parsed_args["probes"].as<size_t>(program_args.num_address_mappings_per_pattern);
  Logger::log_debug(format_string("Set --probes=%d", program_args.num_address_mappings_per_pattern));

  /**
   * program modes
   */
  if (parsed_args.has_option("generate-patterns")) {
    program_args.generate_patterns = parsed_args["generate-patterns"].as<size_t>(0);
    Logger::log_debug(format_string("Set --generate-patterns=%u", program_args.generate_patterns));
    if (program_args.generate_patterns < 1) {
      Logger::log_error("Program argument '--generate-patterns' must be greater than zero! Cannot continue.");
      exit(EXIT_FAILURE);
    }
  } else if (parsed_args.has_option("load-json")) {
    program_args.load_json_filename = parsed_args["load-json"].as<std::string>("");
    if (parsed_args.has_option("replay-patterns")) {
      auto vec_pattern_ids = parsed_args["replay-patterns"].as<argagg::csv<std::string>>();
      program_args.pattern_ids = std::unordered_set<std::string>(
          vec_pattern_ids.values.begin(),
          vec_pattern_ids.values.end());
    } else {
      program_args.pattern_ids = std::unordered_set<std::string>();
    }
  }
}

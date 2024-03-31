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
  Logger::initialize("/dev/stdout");

  handle_args(argc, argv);

  Logger::close();
  Logger::initialize(program_args.logfile);
  Logger::stdout(true);

  // load config
  Logger::log_debug("Loading DRAM config");
  BlacksmithConfig config = BlacksmithConfig::from_jsonfile(program_args.config);
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

  // count the number of possible activations per refresh interval
  // and check the correctness of the memory mapping function in the config
  uint64_t acts_per_trefi = dram_analyzer.analyze_dram(true);
  
  // start the rasdaemon watcher
  Logger::log_debug("Connecting to Rasdaemon database");
  ras_watcher = new RasWatcher();

  Logger::log_debug("Jumping to hammering logic");
  
  FuzzyHammerer::n_sided_frequency_based_hammering(config, dram_analyzer, memory,
                                                   acts_per_trefi,
                                                   program_args.runtime_limit,
                                                   program_args.num_address_mappings_per_pattern);

  Logger::close();
  delete ras_watcher;
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

      {"runtime-limit", {"-t", "--runtime-limit"}, "number of hours to run the fuzzer before terminating (default: 3)", 1},
      {"logfile", {"-l", "--logfile"}, "log to specified file (default: run.log)", 1},
      
      {"probes", {"-p", "--probes"}, "number of different DRAM locations to try each pattern on (default: 3)", 1},
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
  program_args.runtime_limit = parsed_args["runtime-limit"].as<size_t>(program_args.runtime_limit);
  Logger::log_debug(format_string("Set --runtime_limit=%ld", program_args.runtime_limit));
  
  program_args.logfile = parsed_args["logfile"].as<std::string>(program_args.logfile);
  Logger::log_debug(format_string("Set --logfile=%s", program_args.logfile.c_str()));

  program_args.num_address_mappings_per_pattern = parsed_args["probes"].as<size_t>(program_args.num_address_mappings_per_pattern);
  Logger::log_debug(format_string("Set --probes=%d", program_args.num_address_mappings_per_pattern));
}

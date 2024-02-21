#ifndef BLACKSMITH_INCLUDE_BLACKSMITH_HPP_
#define BLACKSMITH_INCLUDE_BLACKSMITH_HPP_

#include <string>
#include <unordered_set>
#include <GlobalDefines.hpp>
#include "RasWatcher.hpp"

// defines the program's arguments and their default values
struct ProgramArguments {
  // the duration of the fuzzing run in seconds
  unsigned long runtime_limit = 10800;
  // path to logfile
  std::string logfile = "run.log";
  // path to JSON config
  std::string config;
  // path to JSON file to load
  std::string load_json_filename;
  // the IDs of the patterns to be loaded from a given JSON file
  std::unordered_set<std::string> pattern_ids{};
  // total number of mappings (i.e., Aggressor ID -> DRAM rows mapping) to try for a pattern
  size_t num_address_mappings_per_pattern = 3;
  // number of DRAM locations we use to check a (pattern, address mapping)'s effectiveness
  size_t num_dram_locations_per_mapping = 3;
  // whether to sweep the 'best pattern' that was found during fuzzing afterward over a contiguous chunk of memory
  bool sweeping = true;
  // these two parameters define the default program mode: do fuzzing and synchronize with REFRESH
  bool do_fuzzing = true;
  bool use_synchronization = true;
  size_t generate_patterns = 0;
};

extern ProgramArguments program_args;
extern RasWatcher *ras_watcher;

int main(int argc, char **argv);

void handle_args(int argc, char **argv);

int handle_arg_generate_patterns(BlacksmithConfig &config, size_t num_activations, size_t probes_per_pattern);

#endif //BLACKSMITH_INCLUDE_BLACKSMITH_HPP_

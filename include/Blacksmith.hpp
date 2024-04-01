#ifndef BLACKSMITH_INCLUDE_BLACKSMITH_HPP_
#define BLACKSMITH_INCLUDE_BLACKSMITH_HPP_

#include <string>
#include <unordered_set>
#include <GlobalDefines.hpp>
#include "Utilities/RasWatcher.hpp"

// defines the program's arguments and their default values
struct ProgramArguments {
  // path to JSON config
  std::string config;
  // the duration of the fuzzing run in hours
  size_t runtime_limit = 3;
  // path to logfile
  std::string logfile = "run.log";
  // number of DRAM locations we use to check a (pattern, address mapping)'s effectiveness
  size_t num_dram_locations_per_mapping = 3;
  // number of effective hammering patterns to be found for a run to end before its runtime limit
  size_t effective_patterns = 3;
  // total number of mappings (i.e., Aggressor ID -> DRAM rows mapping) to try for a pattern
  size_t num_address_mappings_per_pattern = 3;
};

extern ProgramArguments program_args;
extern RasWatcher *ras_watcher;

int main(int argc, char **argv);

void handle_args(int argc, char **argv);

#endif //BLACKSMITH_INCLUDE_BLACKSMITH_HPP_

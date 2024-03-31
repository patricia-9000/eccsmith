#include "Forges/FuzzyHammerer.hpp"

#include <Blacksmith.hpp>

#include "Utilities/TimeHelper.hpp"
#include "Fuzzer/PatternBuilder.hpp"

// initialize the static variables
size_t FuzzyHammerer::cnt_pattern_probes = 0UL;
size_t FuzzyHammerer::cnt_generated_patterns = 0UL;
std::unordered_map<std::string, std::unordered_map<std::string, int>> FuzzyHammerer::map_pattern_mappings_bitflips;
HammeringPattern FuzzyHammerer::hammering_pattern = HammeringPattern(); /* NOLINT */

void
FuzzyHammerer::n_sided_frequency_based_hammering(BlacksmithConfig &config, DramAnalyzer &dramAnalyzer, Memory &memory,
                                                 uint64_t acts, size_t runtime_limit, size_t probes_per_pattern) {
  std::mt19937 gen = std::mt19937(std::random_device()());

  Logger::log_info(format_string("Fuzzing has started. Details are being written to %s. Any detected bitflips will also be written to the console.", program_args.logfile.c_str()));
  Logger::stdout(false);

  // make sure that this is empty (e.g., from previous call to this function)
  map_pattern_mappings_bitflips.clear();

  FuzzingParameterSet fuzzing_params(acts);
  fuzzing_params.print_static_parameters();

#ifdef ENABLE_JSON
  nlohmann::json arr = nlohmann::json::array();
#endif

  // all patterns that triggered bit flips
  std::vector<HammeringPattern> effective_patterns;

  HammeringPattern best_hammering_pattern;
  PatternAddressMapper best_mapping(config.total_banks);

  size_t best_mapping_bitflips = 0;
  size_t best_hammering_pattern_bitflips = 0;

  const auto start_ts = get_timestamp_sec();
  const auto execution_time_limit = static_cast<int64_t>(start_ts + runtime_limit * 3600);

  for (; get_timestamp_sec() < execution_time_limit; ++cnt_generated_patterns) {
    Logger::log_timestamp();
    Logger::log_highlight(format_string("Generating hammering pattern #%lu.", cnt_generated_patterns));
    fuzzing_params.randomize_parameters(true);

    // generate a hammering pattern: this is like a general access pattern template without concrete addresses
    FuzzyHammerer::hammering_pattern = HammeringPattern(fuzzing_params.get_base_period());
    PatternBuilder pattern_builder(hammering_pattern);
    pattern_builder.generate_frequency_based_pattern(fuzzing_params);

    Logger::log_info("Abstract pattern based on aggressor IDs:");
    Logger::log_data(hammering_pattern.get_pattern_text_repr());
    Logger::log_info("Aggressor pairs, given as \"(id ...) : freq, amp, start_offset\":");
    Logger::log_data(hammering_pattern.get_agg_access_pairs_text_repr());

    // randomize the order of AggressorAccessPatterns to avoid biasing the PatternAddressMapper as it always assigns
    // rows in order of the AggressorAccessPatterns map (e.g., first element is assigned to the lowest DRAM row).]
    std::shuffle(hammering_pattern.agg_access_patterns.begin(), hammering_pattern.agg_access_patterns.end(), gen);

    // then test this pattern with N different mappings (i.e., address sets)
    size_t sum_flips_one_pattern_all_mappings = 0;
    for (cnt_pattern_probes = 0; cnt_pattern_probes < probes_per_pattern; ++cnt_pattern_probes) {
      PatternAddressMapper mapper(config.total_banks);

      // we test this combination of (pattern, mapping) at three different DRAM locations
      probe_mapping_and_scan(mapper, memory, fuzzing_params, program_args.num_dram_locations_per_mapping);
      sum_flips_one_pattern_all_mappings += mapper.count_bitflips();

      if (sum_flips_one_pattern_all_mappings > 0) {
        // it is important that we store this mapper only after we did memory.check_memory to include the found BitFlip
        hammering_pattern.address_mappings.push_back(mapper);
      }
    }

    if (sum_flips_one_pattern_all_mappings > 0) {
      effective_patterns.push_back(hammering_pattern);
      arr.push_back(hammering_pattern);
    }

    // TODO additionally consider the number of locations where this pattern triggers bit flips besides the total
    //  number of bit flips only because we want to find a pattern that generalizes well
    // if this pattern is better than every other pattern tried out before, mark this as 'new best pattern'
    if (sum_flips_one_pattern_all_mappings > best_hammering_pattern_bitflips) {
      best_hammering_pattern = hammering_pattern;
      best_hammering_pattern_bitflips = sum_flips_one_pattern_all_mappings;

      // find the best mapping of this pattern (generally it doesn't matter as we're sweeping anyway over a chunk of
      // memory but the mapper also contains a reference to the CodeJitter, which in turn uses some parameters that we
      // want to reuse during sweeping; other mappings could differ in these parameters)
      for (const auto &m : hammering_pattern.address_mappings) {
        size_t num_bitflips = m.count_bitflips();
        if (num_bitflips > best_mapping_bitflips) {
          best_mapping = m;
          best_mapping_bitflips = num_bitflips;
        }
      }
    }

    // dynamically change num acts per tREF after every 100 patterns; this is to avoid that we made a bad choice at the
    // beginning and then get stuck with that value
    if (cnt_generated_patterns % 100 == 0) {
      auto old_nacts = fuzzing_params.get_num_activations_per_t_refi();
      // repeat measuring the number of possible activations per tREF as it might be that the current value is not optimal
      fuzzing_params.set_num_activations_per_t_refi(static_cast<int>(dramAnalyzer.analyze_dram(false)));
      Logger::log_info(
          format_string("Recomputed number of row activations per refresh interval (old: %d, new: %d).",
                        old_nacts,
                        fuzzing_params.get_num_activations_per_t_refi()));
    }

  } // end of fuzzing

  log_overall_statistics(
      cnt_generated_patterns,
      best_mapping.get_instance_id(),
      best_mapping_bitflips,
      effective_patterns.size());

  // start the post-analysis stage ============================
  if (arr.empty()) {
    Logger::log_info("Skipping post-analysis stage as no effective patterns were found.");
  } else {
    Logger::log_info("Starting post-analysis stage.");
  }

#ifdef ENABLE_JSON
  // export everything to JSON, this includes the HammeringPattern, AggressorAccessPattern, and BitFlips
  std::ofstream json_export("fuzz-summary.json");

  nlohmann::json meta;
  meta["start"] = start_ts;
  meta["end"] = get_timestamp_sec();
  meta["num_patterns"] = arr.size();
  meta["memory_config"] = DRAMAddr::get_memcfg_json();
  meta["name"] = config.name;

  nlohmann::json root;
  root["metadata"] = meta;
  root["hammering_patterns"] = arr;

  json_export << root << std::endl;
  json_export.close();
#endif
}

void FuzzyHammerer::probe_mapping_and_scan(PatternAddressMapper &mapper, Memory &memory,
                                           FuzzingParameterSet &fuzzing_params, size_t num_dram_locations) {

  // ATTENTION: This method uses the global variable hammering_pattern to refer to the pattern that is to be hammered

  CodeJitter &code_jitter = mapper.get_code_jitter();

  // randomize the aggressor ID -> DRAM row mapping
  mapper.randomize_addresses(fuzzing_params, hammering_pattern.agg_access_patterns, true);

  // now fill the pattern with these random addresses
  std::vector<volatile char *> hammering_accesses_vec;
  mapper.export_pattern(hammering_pattern.aggressors, hammering_pattern.base_period, hammering_accesses_vec);
  Logger::log_info("Aggressor ID to DRAM address mapping (bank, row, column):");
  Logger::log_data(mapper.get_mapping_text_repr());

  // now create instructions that follow this pattern (i.e., do jitting of code)
  bool sync_at_each_ref = fuzzing_params.get_random_sync_each_ref();
  int num_aggs_for_sync = fuzzing_params.get_random_num_aggressors_for_sync();
  Logger::log_info("Creating ASM code for hammering.");
  code_jitter.jit_strict(fuzzing_params.get_num_activations_per_t_refi(),
      fuzzing_params.flushing_strategy, fuzzing_params.fencing_strategy,
      hammering_accesses_vec, sync_at_each_ref, num_aggs_for_sync,
      fuzzing_params.get_hammering_total_num_activations());

  size_t flipped_bits = 0;
  for (size_t dram_location = 0; dram_location < num_dram_locations; ++dram_location) {
    mapper.bit_flips.emplace_back();

    Logger::log_info(format_string("Running pattern #%lu (%s) for address set %d (%s) at DRAM location #%ld.",
        cnt_generated_patterns,
        hammering_pattern.instance_id.c_str(),
        cnt_pattern_probes,
        mapper.get_instance_id().c_str(),
        dram_location));

    // wait for a random time before starting to hammer, while waiting access random rows that are not part of the
    // currently hammering pattern; this wait interval serves for two purposes: to reset the sampler and start from a
    // clean state before hammering, and also to fuzz a possible dependence at which REF we start hammering
    auto wait_until_hammering_us = fuzzing_params.get_random_wait_until_start_hammering_us();
    FuzzingParameterSet::print_dynamic_parameters2(sync_at_each_ref, wait_until_hammering_us, num_aggs_for_sync);

    std::vector<volatile char *> random_rows;
    if (wait_until_hammering_us > 0) {
      random_rows = mapper.get_random_nonaccessed_rows(fuzzing_params.get_max_row_no());
      do_random_accesses(random_rows, wait_until_hammering_us);
    }

    // do hammering
    code_jitter.hammer_pattern(fuzzing_params, true);

    // check if any uncorrected bit flips happened
    flipped_bits += memory.check_memory(mapper, false, true);
    
    // check if any corrected bit flips happened
    flipped_bits += ras_watcher->report_corrected_bitflips(mapper);

    // now shift the mapping to another location
    std::mt19937 gen = std::mt19937(std::random_device()());
    mapper.shift_mapping(Range<int>(1,32).get_random_number(gen), {});

    if (dram_location + 1 < num_dram_locations) {
      // wait a bit and do some random accesses before checking reproducibility of the pattern
      if (random_rows.empty()) random_rows = mapper.get_random_nonaccessed_rows(fuzzing_params.get_max_row_no());
      do_random_accesses(random_rows, 64000); // 64ms (retention time)
    }
  }

  // store info about this bit flip (pattern ID, mapping ID, no. of bit flips)
  map_pattern_mappings_bitflips[hammering_pattern.instance_id].emplace(mapper.get_instance_id(), flipped_bits);

  // cleanup the jitter for its next use
  code_jitter.cleanup();
}

void FuzzyHammerer::log_overall_statistics(size_t cur_round, const std::string &best_mapping_id,
                                           size_t best_mapping_num_bitflips, size_t num_effective_patterns) {
  Logger::log_info("Fuzzing run finished successfully.");
  Logger::log_data(format_string("Number of generated patterns: %lu", cur_round));
  Logger::log_data(format_string("Number of generated mappings per pattern: %lu",
      program_args.num_address_mappings_per_pattern));
  Logger::log_data(format_string("Number of tested locations per pattern: %lu",
      program_args.num_dram_locations_per_mapping));
  Logger::log_data(format_string("Number of effective patterns: %lu", num_effective_patterns));
  Logger::log_data(format_string("Best pattern ID: %s", best_mapping_id.c_str()));
  Logger::log_data(format_string("Best pattern #bitflips: %ld", best_mapping_num_bitflips));
}

void FuzzyHammerer::generate_pattern_for_ARM(BlacksmithConfig &config,
                                             size_t acts,
                                             int *rows_to_access,
                                             int max_accesses,
                                             const size_t probes_per_pattern) {
  FuzzingParameterSet fuzzing_params(acts);
  fuzzing_params.print_static_parameters();
  fuzzing_params.randomize_parameters(true);

  hammering_pattern.aggressors.clear();
  if (cnt_pattern_probes > 1 && cnt_pattern_probes < probes_per_pattern) {
    cnt_pattern_probes++;
  } else {
    cnt_pattern_probes = 0;
    hammering_pattern = HammeringPattern(fuzzing_params.get_base_period());
  }

  PatternBuilder pattern_builder(hammering_pattern);
  pattern_builder.generate_frequency_based_pattern(fuzzing_params);

  Logger::log_info("Aggressor pairs, given as \"(id ...) : freq, amp, start_offset\":");
  Logger::log_data(hammering_pattern.get_agg_access_pairs_text_repr());

  // choose random addresses for pattern
  PatternAddressMapper mapper(config.total_banks);
  mapper.randomize_addresses(fuzzing_params, hammering_pattern.agg_access_patterns, true);
  mapper.export_pattern(hammering_pattern.aggressors, hammering_pattern.base_period, rows_to_access, max_accesses);
  Logger::log_info("Aggressor ID to DRAM address mapping (bank, rank, column):");
  Logger::log_data(mapper.get_mapping_text_repr());
}

void FuzzyHammerer::do_random_accesses(const std::vector<volatile char *> &random_rows, const int duration_us) {
  const auto random_access_limit = get_timestamp_us() + static_cast<int64_t>(duration_us);
  while (get_timestamp_us() < random_access_limit) {
    for (volatile char *e : random_rows) {
      (void)*e; // this should be fine as random_rows are volatile
    }
  }
}

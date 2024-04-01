#include "Memory/DramAnalyzer.hpp"

#include <cassert>
#include <unordered_set>

DramAnalyzer::DramAnalyzer(BlacksmithConfig &config, volatile char *target) :
  config(config), start_address(target) {
  std::random_device rd;
  gen = std::mt19937(rd());
  dist = std::uniform_int_distribution<>(0, std::numeric_limits<int>::max());
}

size_t DramAnalyzer::analyze_dram(bool check) {
  DRAMAddr base((void*)start_address);
  DRAMAddr diff = base.add(0, 1, 0);
  DRAMAddr same = base.add(0, 0, 1);

  if (!(base.bank == diff.bank && base.row != diff.row)) {
    Logger::log_error("Failed to find two differing-row addresses on the same bank. Is your config correct?");
    exit(1);
  } else if (!(base.bank == same.bank && base.row == same.row)) {
    Logger::log_error("Failed to find two same-row addresses on the same bank. Is your config correct?");
    exit(1);
  }

  volatile char* base_virt = (volatile char*)base.to_virt();
  volatile char* diff_virt = (volatile char*)diff.to_virt();
  volatile char* same_virt = (volatile char*)same.to_virt();

  size_t thresh = determine_conflict_thresh(base_virt, diff_virt, same_virt);
  if (check) check_addr_function(thresh);
  return count_acts_per_trefi(base_virt, diff_virt, thresh);
}

//
// This method uses some modified code from DetermineConflictThresh.cpp created by Luca Wilke
//
size_t DramAnalyzer::determine_conflict_thresh(volatile char *base, volatile char *diff, volatile char *same) {
  Logger::log_debug("Determining row conflict threshold");

  // Measure row conflict timing
  uint64_t conf_sum = 0;
  for (size_t sample_idx = 0; sample_idx < THRESH_SAMPLES; sample_idx++) {
    conf_sum += measure_time(base, diff, 1000);
  }
  uint64_t conf_avg = conf_sum / THRESH_SAMPLES;

  // Measure row hit timing
  uint64_t hit_sum = 0;
  for (size_t sample_idx = 0; sample_idx < THRESH_SAMPLES; sample_idx++) {
    hit_sum += measure_time(base, same, 1000);
  }
  uint64_t hit_avg = hit_sum / THRESH_SAMPLES;

  uint64_t thresh = hit_avg + ((conf_avg - hit_avg) / 2);
  Logger::log_info(format_string("Determined row conflict threshold to be %lu.", thresh));
  return thresh;
}

//
// This method uses some modified code from CheckAddrFunction.cpp created by Luca Wilke
//
void DramAnalyzer::check_addr_function(size_t thresh) {
  Logger::log_debug("Checking correctness of address function");

  size_t bank_count = DRAMAddr::get_bank_count();
  size_t row_count = DRAMAddr::get_row_count();
  size_t checked_banks = 4;
  if (bank_count < checked_banks)
    checked_banks = bank_count;

  for(size_t bank = 0; bank < checked_banks; bank++) {
    Logger::log_debug(format_string("Checking bank %zu", bank));
    for(size_t row = 1; row < row_count; row++) {
      auto addrA = DRAMAddr(bank,0,0);
      auto addrB = DRAMAddr(bank,row,0);
      auto timing = DramAnalyzer::measure_time((volatile char*)addrA.to_virt(),(volatile char*)addrB.to_virt(), 1000);
      if(timing < thresh) {
        Logger::log_error(format_string("Measured access time of %lu for two supposedly conflicting rows, "
                                        "which is below the row conflict threshold of %lu.",
                                        timing, thresh));
        Logger::log_error("The chosen config file may not be compatible with your system.");
        exit(1);
      }
    }
  }

  Logger::log_info("Selected config file has been checked, and seems to be correct.");
}

size_t DramAnalyzer::count_acts_per_trefi(volatile char *base, volatile char *diff, size_t start_threshold) {
  Logger::log_debug("Determining acts per ref");
  uint64_t acts_per_ref;

  size_t skip_first_N = 50;
  std::vector<uint64_t> acts;
  uint64_t running_sum = 0;
  uint64_t before;
  uint64_t after;
  uint64_t count = 0;
  uint64_t count_old = 0;
  size_t threshold = start_threshold;

  // computes the standard deviation
  auto compute_std = [](std::vector<uint64_t> &values, uint64_t running_sum, size_t num_numbers) {
    double mean = static_cast<double>(running_sum)/static_cast<double>(num_numbers);
    double var = 0;
    for (const auto &num : values) {
      if (static_cast<double>(num) < mean) continue;
      var += std::pow(static_cast<double>(num) - mean, 2);
    }
    auto val = std::sqrt(var/static_cast<double>(num_numbers));
    return val;
  };

  for (size_t i = 0;; i++) {
    // flush base and diff from caches
    clflushopt(base);
    clflushopt(diff);
    mfence();

    // get start timestamp and wait until we retrieved it
    before = rdtscp();
    lfence();

    // do DRAM accesses
    (void)*base;
    (void)*diff;

    // get end timestamp
    after = rdtscp();

    count++;
    if ((after - before) > threshold) {
      if (i > skip_first_N && count_old!=0) {
        // multiply by 2 to account for both accesses we do (base, diff)
        uint64_t value = (count - count_old)*2;
        acts.push_back(value);
        running_sum += value;
        // check the collected values after every 200 rounds
        if ((acts.size()%200)==0)
        {
          acts_per_ref = running_sum / acts.size();
          // restart with a higher threshold if acts_per_ref falls too low or std still hasn't converged after 10 checks
          if (acts_per_ref <= 5 || acts.size() > 2000) {
            acts.clear();
            running_sum = 0;
            i = 0;
            if (threshold < start_threshold + 200) {
              if (threshold == start_threshold)
                Logger::log_debug("Increasing threshold");
              threshold += 10;
            } else {
              threshold = start_threshold;
              Logger::log_debug(format_string("Threshold too high, resetting to %zu", start_threshold));
            }
          // a standard deviation of less than 3 means the average will probably be accurate, so we go ahead with these measurements
          } else if (compute_std(acts, running_sum, acts.size()) < 3.0) {
            Logger::log_info(format_string("Determined number of row activations per refresh interval to be %lu.", acts_per_ref));
            break;
          }
        }
      }
      count_old = count;
    }
  }

  return acts_per_ref;
}

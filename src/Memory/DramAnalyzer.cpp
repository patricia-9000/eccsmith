#include "Memory/DramAnalyzer.hpp"

#include <cassert>
#include <unordered_set>

DramAnalyzer::DramAnalyzer(BlacksmithConfig &config, volatile char *target) :
  config(config), start_address(target) {
  std::random_device rd;
  gen = std::mt19937(rd());
  dist = std::uniform_int_distribution<>(0, std::numeric_limits<int>::max());
}

size_t DramAnalyzer::count_acts_per_trefi() {
  DRAMAddr a((void*)start_address);
  DRAMAddr b = a.add(0, 1, 0);
  if(!(a.bank == b.bank && a.row != b.row)) {
    Logger::log_error("Failed to find two differing-row addresses on the same bank. Is your config correct?");
    exit(1);
  }
  Logger::log_debug(format_string("We will use %p and %p for count_acts_per_ref", a.to_virt(), b.to_virt()));

  return count_acts_per_trefi((volatile char*)a.to_virt(),(volatile char*)b.to_virt());
}

size_t DramAnalyzer::count_acts_per_trefi(volatile char *a, volatile char *b) {
  uint64_t acts_per_ref;
  size_t start_threshold = 500;

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
    // flush a and b from caches
    clflushopt(a);
    clflushopt(b);
    mfence();

    // get start timestamp and wait until we retrieved it
    before = rdtscp();
    lfence();

    // do DRAM accesses
    (void)*a;
    (void)*b;

    // get end timestamp
    after = rdtscp();

    count++;
    if ((after - before) > threshold) {
      if (i > skip_first_N && count_old!=0) {
        // multiply by 2 to account for both accesses we do (a, b)
        uint64_t value = (count - count_old)*2;
        acts.push_back(value);
        running_sum += value;
        // check the standard deviation after every 200 rounds
        if ((acts.size()%200)==0)
        {
          double std = compute_std(acts, running_sum, acts.size());
          // a standard deviation of less than 3 means the average will probably be accurate, so we go ahead with these measurements
          if (std < 3.0) {
            acts_per_ref = running_sum / acts.size();
            if (acts_per_ref <= 5) {
              acts.clear();
              running_sum = 0;
              i = 0;
              Logger::log_debug("Acts per ref too low");
            } else {
              Logger::log_info(format_string("Determined number of row activations per refresh interval to be %lu.", acts_per_ref));
              break;
            }
          // if 2000 rounds (10 checks) pass before either of these come true, restart with a higher threshold
          } else if (acts.size() >= 2000) {
            acts.clear();
            running_sum = 0;
            i = 0;
            if (threshold < start_threshold + 200) {
              if (threshold == start_threshold)
                Logger::log_debug("Too many rounds, increasing threshold");
              threshold += 10;
            } else {
              threshold = start_threshold;
              Logger::log_debug(format_string("Threshold too high, resetting to %zu", start_threshold));
            }
          }
        }
      }
      count_old = count;
    }
  }

  return acts_per_ref;
}

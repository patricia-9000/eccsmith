#ifndef DRAMANALYZER
#define DRAMANALYZER

#include <cinttypes>
#include <vector>
#include <random>

#include "Utilities/AsmPrimitives.hpp"
#include "Utilities/BlacksmithConfig.hpp"

class DramAnalyzer {
 private:
  BlacksmithConfig &config;

  volatile char *start_address;

 public:
  explicit DramAnalyzer(volatile char *target, BlacksmithConfig &config);

  /// Measures the time between accessing two addresses.
  static int inline measure_time(volatile char *a1, volatile char *a2, size_t rounds) {
    uint64_t before, after,sum,delta;
    sum = 0;

    for (size_t i = 0; i < rounds; i++) {
        mfence();
        before = rdtscp();
        *a1;
        *a2;
        after = rdtscp();
        mfence();
        delta = after-before;
        if( delta < 200 || delta > 430 ) { //reject outliers
			    i--; //if i =0; the i++ from the loop and will set it to 0 again, so no underflow
	      } else {
        	sum += delta;
		    }
        clflushopt(a1);
        clflushopt(a2);
    }
    return (int)((sum) / rounds);
  }

  /// Determine the number of possible total activations to an aggressor pair within a refresh interval.
  size_t count_acts_per_ref();
};

#endif /* DRAMANALYZER */

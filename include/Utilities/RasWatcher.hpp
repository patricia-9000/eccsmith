//
// Created by Patricia Norton
//

#include "Fuzzer/PatternAddressMapper.hpp"

#include <sqlite3.h>

class RasWatcher {
  public:
    RasWatcher();
    
    ~RasWatcher();
    
    int report_corrected_bitflips(PatternAddressMapper &mapping);
  
  private:
    sqlite3 *ras_db;
    int total_corrections = 0;
    
    //Fetches the current number of rows in the table which stores ECC event records,
    //then returns how much that number has increased by since the last call
    int fetch_new_corrections();
    
    //Automatically called after every call to sqlite3_exec, which is why the header has to be weird
    //Extracts the actual result from the data param, converts it from a string to an int, then puts it in the int pointed to by the value param
    //The 4th arg of sqlite3_exec becomes the value param, so that's how we extract the number into new_total_corrections
    static int callback(void *value, int, char **data, char **);
};

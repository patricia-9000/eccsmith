#include <Blacksmith.hpp>

#include <cstddef>
#include <stdlib.h>
#include <string>
#include <sqlite3.h>

using namespace std;

class RasWatcher {
  private:
    sqlite3 *ras_db;
    int total_corrections = 0;
    
    //Automatically called after every call to sqlite3_exec, which is why the header has to be weird
    //Extracts the actual result from the data param, converts it from a string to an int, then puts it in the int pointed to by the value param
    //The 4th arg of sqlite3_exec becomes the value param, so that's how we extract the number into new_total_corrections
    static int callback(void *value, int, char **data, char **) {
      *(int*)value = atoi(data[0]);
      return 0;
    }
    
  public:
    //Fetches the current number of rows in the table which stores ECC event records,
    //then returns how much that number has increased by since the last call
    int fetch_total_corrections() {
      string query = "SELECT COUNT(*) FROM mc_event;";
      int new_total_corrections;
      char **err_msg = 0;
      int ret = sqlite3_exec(ras_db, query.c_str(), callback, &new_total_corrections, err_msg);
      if (ret != SQLITE_OK) {
        Logger::log_error(format_string("SQL error: %s\n", *err_msg));
        sqlite3_free(err_msg);
      }
      
      int increase_in_corrections = new_total_corrections - total_corrections;
      total_corrections = new_total_corrections;
      return increase_in_corrections;
    }
    
    RasWatcher() {
      int ret = sqlite3_open_v2("/var/lib/rasdaemon/ras-mc_event.db", &ras_db, SQLITE_OPEN_READONLY, NULL);
      if (ret != SQLITE_OK) {
        Logger::log_error(format_string("Can't open Rasdaemon database: %s\n", sqlite3_errmsg(ras_db)));
      }
      
      fetch_total_corrections();
    }
    
    ~RasWatcher() {
      sqlite3_close(ras_db);
    }
};

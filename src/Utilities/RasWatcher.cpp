#include "Utilities/RasWatcher.hpp"

#include "Utilities/Logger.hpp"

#include <cstddef>
#include <stdlib.h>
#include <string>
#include <sqlite3.h>
#include <thread>
#include <chrono>

RasWatcher::RasWatcher() {
  int ret = sqlite3_open_v2("/var/lib/rasdaemon/ras-mc_event.db", &ras_db, SQLITE_OPEN_READONLY, NULL);
  if (ret != SQLITE_OK) Logger::log_sql_error(ret);
  fetch_new_corrections();
  Logger::log_info(format_string("Opening connection to Rasdaemon database, with a total of %d prior ECC corrections on record.", total_corrections));
}

RasWatcher::~RasWatcher() {
  sqlite3_close(ras_db);
}

int RasWatcher::report_corrected_bitflips(PatternAddressMapper &mapping) {
  Logger::log_info("Checking Rasdaemon database for ECC corrections.");
  int new_corrections = fetch_new_corrections();
  mapping.corrected_bit_flips += new_corrections;
  if (new_corrections > 0)
    Logger::log_corrected_bitflip(new_corrections, (size_t) time(nullptr));
  return new_corrections;
}

int RasWatcher::fetch_new_corrections() {
  std::string query = "SELECT COUNT(*) FROM mc_event;";
  int ret, new_total_corrections;
  while (true) {
    ret = sqlite3_exec(ras_db, query.c_str(), callback, &new_total_corrections, NULL);
    if (ret == SQLITE_BUSY)
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
    else {
      if (ret != SQLITE_OK) Logger::log_sql_error(ret);
      break;
    }
  }
  int increase_in_corrections = new_total_corrections - total_corrections;
  total_corrections = new_total_corrections;
  return increase_in_corrections;
}

int RasWatcher::callback(void *value, int, char **data, char **) {
  *(int*)value = atoi(data[0]);
  return 0;
}

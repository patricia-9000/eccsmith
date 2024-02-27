#include "Utilities/RasWatcher.hpp"

#include "Utilities/Logger.hpp"

#include <cstddef>
#include <stdlib.h>
#include <string>
#include <sqlite3.h>

RasWatcher::RasWatcher() {
  int ret = sqlite3_open_v2("/var/lib/rasdaemon/ras-mc_event.db", &ras_db, SQLITE_OPEN_READONLY, NULL);
  handle_sql_error(ret);
  fetch_new_corrections();
  Logger::log_info(format_string("Opened connection to Rasdaemon database, with %d total ECC corrections on record.", total_corrections));
}

RasWatcher::~RasWatcher() {
  sqlite3_close(ras_db);
}

int RasWatcher::report_corrected_bitflips() {
  Logger::log_info("Checking Rasdaemon database for ECC corrections.");
  int new_corrections = fetch_new_corrections();
  if (new_corrections > 0) {
    Logger::log_corrected_bitflip(new_corrections, (size_t) time(nullptr));
  }
  return new_corrections;
}

int RasWatcher::fetch_new_corrections() {
  std::string query = "SELECT COUNT(*) FROM mc_event;";
  int new_total_corrections;
  int ret = sqlite3_exec(ras_db, query.c_str(), callback, &new_total_corrections, NULL);
  handle_sql_error(ret);  
  int increase_in_corrections = new_total_corrections - total_corrections;
  total_corrections = new_total_corrections;
  return increase_in_corrections;
}

int RasWatcher::callback(void *value, int, char **data, char **) {
  *(int*)value = atoi(data[0]);
  return 0;
}

void RasWatcher::handle_sql_error(int result_code) {
  if (result_code == SQLITE_OK) return;
  char* err_msg = const_cast<char*>(sqlite3_errmsg(ras_db));
  if (err_msg == NULL) {
    std::string no_err_msg = "none provided";
    err_msg = const_cast<char*>(no_err_msg.c_str());
  }
  Logger::log_error(format_string("SQLite3 error - Result code: %s, Error message: %s", sqlite3_errstr(result_code), err_msg));
}

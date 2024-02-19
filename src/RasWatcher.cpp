#include "RasWatcher.hpp"

#include <Blacksmith.hpp>

#include <cstddef>
#include <stdlib.h>
#include <string>
#include <sqlite3.h>

RasWatcher::RasWatcher() {
  int ret = sqlite3_open_v2("/var/lib/rasdaemon/ras-mc_event.db", &ras_db, SQLITE_OPEN_READONLY, NULL);
  if (ret != SQLITE_OK) {
    Logger::log_error(format_string("Can't open Rasdaemon database: %s\n", sqlite3_errmsg(ras_db)));
  }
  fetch_new_corrections();
}

RasWatcher::~RasWatcher() {
  sqlite3_close(ras_db);
}

int RasWatcher::get_total_corrections() {
  return total_corrections;
}

int RasWatcher::fetch_new_corrections() {
  std::string query = "SELECT COUNT(*) FROM mc_event;";
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

int RasWatcher::callback(void *value, int, char **data, char **) {
  *(int*)value = atoi(data[0]);
  return 0;
}

#include "Utilities/Logger.hpp"

#include <iostream>
#include <GlobalDefines.hpp>
#include <sqlite3.h>

// initialize the singleton instance
Logger Logger::instance; /* NOLINT */

Logger::Logger() = default;

void Logger::initialize(const std::string &logfile_filename) {
  instance.logfile = std::ofstream();
  std::cout << "Eccsmith has started running" << std::endl
            << "Details are being written to " FF_BOLD << logfile_filename << F_RESET << std::endl
            << "Any detected bitflips will also be written to the console" << std::endl;
  instance.logfile.open(logfile_filename, std::ios::out | std::ios::trunc);
  instance.timestamp_start = (unsigned long) time(nullptr);
}

void Logger::close() {
  instance.logfile << std::endl;
  instance.logfile.close();
}

void Logger::log_info(const std::string &message, bool newline) {
  instance.logfile << FC_CYAN "[+] " << message;
  instance.logfile << F_RESET;
  if (newline) instance.logfile << std::endl;
}

void Logger::log_highlight(const std::string &message, bool newline) {
  instance.logfile << FC_MAGENTA << FF_BOLD << "[+] " << message;
  instance.logfile << F_RESET;
  if (newline) instance.logfile << std::endl;
}

void Logger::log_error(const std::string &message, bool newline) {
  instance.logfile << FC_RED "[-] " << message;
  instance.logfile << F_RESET;
  if (newline) instance.logfile << std::endl;
}

void Logger::log_data(const std::string &message, bool newline) {
  instance.logfile << message;
  if (newline) instance.logfile << std::endl;
}

void Logger::log_analysis_stage(const std::string &message, bool newline) {
  std::stringstream ss;
  ss << FC_CYAN_BRIGHT "████  " << message << "  ";
  // this makes sure that all log analysis stage messages have the same length
  auto remaining_chars = 80-message.length();
  while (remaining_chars--) ss << "█";
  instance.logfile << ss.str();
  instance.logfile << F_RESET;
  if (newline) instance.logfile << std::endl;
}

#define DEBUG
void Logger::log_debug(const std::string &message, bool newline) {
#ifdef DEBUG
  instance.logfile << FC_YELLOW "[DEBUG] " << message;
  instance.logfile << F_RESET;
  if (newline) instance.logfile << std::endl;
#else
  // this is just to ignore complaints of the compiler about unused params
  std::ignore = message;
  std::ignore = newline;
#endif
}

std::string Logger::format_timestamp(unsigned long ts) {
  auto minutes = ts/60;
  auto hours = minutes/60;
  std::stringstream ss;
  ss << int(hours) << " hours "
     << int(minutes%60) << " minutes "
     << int(ts%60) << " seconds";
  return ss.str();
}

void Logger::log_timestamp() {
  std::stringstream ss;
  auto current_time = (unsigned long) time(nullptr);
  ss << "Time elapsed: "
     << format_timestamp(current_time - instance.timestamp_start)
     << ".";
  log_info(ss.str());
}

void Logger::log_bitflip(volatile char *flipped_address, uint64_t row_no, unsigned char actual_value,
                         unsigned char expected_value, unsigned long timestamp, bool newline) {
  std::stringstream ss;
  ss << FC_RED_BRIGHT << FF_BOLD
     << "[!] ECC failed to correct bitflip " << std::hex << (void *) flipped_address << ", "
     << std::dec << "row " << row_no << ", "
     << "page offset: " << (uint64_t)flipped_address%(uint64_t)getpagesize() << ", "
     << "byte offset: " << (uint64_t)flipped_address%(uint64_t)8 << ", "
     << std::hex << "from " << (int) expected_value << " to " << (int) actual_value << ", "
     << std::dec << "at " << format_timestamp(timestamp - instance.timestamp_start) << "."
     << F_RESET;
  if (newline) ss << std::endl;
  
  instance.logfile << ss.str();
  std::cout << ss.str();
}

void Logger::log_corrected_bitflip(int count, unsigned long timestamp) {
  std::stringstream ss;
  ss << FC_GREEN << FF_BOLD
     << "[!] ECC successfully corrected " << count << " bitflip(s) at "
     << format_timestamp(timestamp - instance.timestamp_start) << "."
     << F_RESET << std::endl;
  
  instance.logfile << ss.str();
  std::cout << ss.str();
}

void Logger::log_sql_error(int result_code) {
  log_error(format_string("SQLite3 error: %s", sqlite3_errstr(result_code)));
}

void Logger::log_success(const std::string &message, bool newline) {
  instance.logfile << FC_GREEN << "[!] " << message;
  instance.logfile << F_RESET;
  if (newline) instance.logfile << std::endl;
}

void Logger::log_failure(const std::string &message, bool newline) {
  instance.logfile << FC_RED_BRIGHT << "[-] " << message;
  instance.logfile << F_RESET;
  if (newline) instance.logfile << std::endl;
}

void Logger::log_metadata(const char *commit_hash, BlacksmithConfig &config, unsigned long run_time_limit) {
  Logger::log_info("General information about this fuzzing run:");

  char name[1024] = "";
  gethostname(name, sizeof name);

  std::stringstream ss;
  ss << "Start timestamp:: " << instance.timestamp_start << std::endl
     << "Hostname: " << name << std::endl
     << "Commit SHA: " << commit_hash << std::endl
     << "Run time limit: " << run_time_limit << " hours";
  Logger::log_data(ss.str());

  log_config(config);
}

void Logger::log_config(BlacksmithConfig &config) {
  Logger::log_info("Printing run configuration:");
  std::stringstream ss;
  nlohmann::json json = config;
  ss << "Config:" << json.dump() << std::endl
     << "PAGE_SIZE: " << getpagesize() << std::endl;
  Logger::log_data(ss.str());
}

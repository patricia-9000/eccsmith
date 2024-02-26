//
// Created by rowhammer on 27.02.23.
//

#ifndef BLACKSMITH_BLACKSMITHCONFIG_HPP
#define BLACKSMITH_BLACKSMITHCONFIG_HPP

class BlacksmithConfig; // forward declaration needed to break include cycle

#include <string>
#include <vector>
#include <variant>
#include "Memory/DRAMAddr.hpp"
#include "nlohmann/json.hpp"

typedef std::variant<uint64_t, std::vector<uint64_t>> BitDef;

// (de-)serialize std::variant, required for BitDef
template<typename T, typename... Ts>
void variant_from_json(const nlohmann::json &j, std::variant<Ts...> &data) {
  try {
    data = j.get<T>();
  } catch (...) {
  }
}

template<typename... Ts>
struct nlohmann::adl_serializer<std::variant<Ts...>> {
  static void to_json(nlohmann::json &j, const std::variant<Ts...> &data) {
    std::visit([&j](const auto &v) {
      j = v;
    }, data);
  }

  static void from_json(const nlohmann::json &j, std::variant<Ts...> &data) {
    (variant_from_json<Ts>(j, data), ...);
  }
};

class BlacksmithConfig {
private:
public:
  /**
   * Parse a config file into a BlacksmithConfig
   *
   * @param filepath path to a JSON config file
   * @param out a pointer to a BlacksmithConfig. `out' will be populated according to the contents of `filepath',
   * @return true iff deserialization succeeded, false otherwise
   */
  static BlacksmithConfig from_jsonfile(const std::string &filepath);

  BlacksmithConfig();

  std::string name;
  uint64_t channels;
  uint64_t dimms;
  uint64_t ranks;
  uint64_t total_banks;
  std::vector<BitDef> row_bits;
  std::vector<BitDef> col_bits;
  std::vector<BitDef> bank_bits;

  /**
   * Convert a BlacksmithConfig to a MemConfiguration for use in DRAMAddr.
   *
   * @param config a reference to a BlacksmithConfig
   * @param out a pointer to a MemConfiguration. `out' will be updated with bit definitions from BlacksmithConfig
   */
  MemConfiguration to_memconfig();

  NLOHMANN_DEFINE_TYPE_INTRUSIVE(BlacksmithConfig, name,
                                 channels, dimms, ranks, total_banks,
                                 row_bits, col_bits, bank_bits)
};
#endif //BLACKSMITH_BLACKSMITHCONFIG_HPP

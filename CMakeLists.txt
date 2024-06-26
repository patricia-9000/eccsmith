cmake_minimum_required(VERSION 3.11 FATAL_ERROR)
project(eccsmith VERSION 0.0.1 LANGUAGES CXX)

# === OPTIONS ==================================================================

set(
        BLACKSMITH_ENABLE_JSON_EXPORT
        ON
        CACHE BOOL
        "Use the nlohmann/json library to export JSON-formatted fuzzing data."
        FORCE
)

set(
        BLACKSMITH_ENABLE_JITTING
        ON
        CACHE BOOL
        "Use the asmjit library to jit the hammering code."
        FORCE
)

string(ASCII 27 ESC)

# === DEFINITIONS ==============================================================

set(GIT_COMMIT_HASH "NO_REPOSITORY")

execute_process(
        COMMAND git status
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
        RESULT_VARIABLE ret
        OUTPUT_QUIET
        ERROR_QUIET
)

if (ret EQUAL "0")
    # We're in a git repository, attempt to retrieve the current commit tag.
    execute_process(
            COMMAND git rev-parse HEAD
            WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
            OUTPUT_VARIABLE GIT_COMMIT_HASH
            OUTPUT_STRIP_TRAILING_WHITESPACE
    )
endif ()

# === DEPENDENCIES =============================================================

add_subdirectory(external)

# === LIBBLACKSMITH ============================================================

add_library(
        bs
        include/GlobalDefines.hpp
        include/Utilities/TimeHelper.hpp
        src/Forges/FuzzyHammerer.cpp
        src/Fuzzer/Aggressor.cpp
        src/Fuzzer/AggressorAccessPattern.cpp
        src/Fuzzer/BitFlip.cpp
        src/Fuzzer/CodeJitter.cpp
        src/Fuzzer/FuzzingParameterSet.cpp
        src/Fuzzer/HammeringPattern.cpp
        src/Fuzzer/PatternAddressMapper.cpp
        src/Fuzzer/PatternBuilder.cpp
        src/Memory/DRAMAddr.cpp
        src/Memory/DramAnalyzer.cpp
        src/Memory/Memory.cpp
        src/Utilities/Enums.cpp
        src/Utilities/Logger.cpp
        src/Utilities/BlacksmithConfig.cpp
        src/Utilities/RasWatcher.cpp
)

target_include_directories(
        bs
        PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Note: PUBLIC to also force consumers (i.e., the blacksmith executable) to use
# these features and options.
target_compile_features(
        bs
        PUBLIC
        cxx_std_17
)

target_compile_options(
        bs
        PUBLIC
        -O0
        -Wall
        -Wextra
        -Wno-unused-function
        -Wno-format-security
)

target_link_libraries(
        bs
        PUBLIC
        nlohmann_json::nlohmann_json
)

if (BLACKSMITH_ENABLE_JSON_EXPORT)
    target_compile_definitions(
            bs
            PUBLIC
            ENABLE_JSON
    )
endif ()

if (BLACKSMITH_ENABLE_JITTING)
    # This fixes an issue that causes GCC 10.3 (but not 8.3 or 11.1) to miss a
    # header somehow.
    FetchContent_MakeAvailable(asmjit)

    target_include_directories(
            bs
            PUBLIC
            ${asmjit_SOURCE_DIR}/src
    )

    target_link_libraries(
            bs
            PRIVATE
            asmjit
    )

    target_compile_definitions(
            bs
            PUBLIC
            ENABLE_JITTING
    )
endif ()

target_link_libraries(
        bs
        PUBLIC
        Eigen3::Eigen
)

# === BLACKSMITH ===============================================================

add_executable(
        eccsmith
        include/Blacksmith.hpp
        src/Blacksmith.cpp
)

target_compile_definitions(
        eccsmith
        PRIVATE
        GIT_COMMIT_HASH="${GIT_COMMIT_HASH}"
)

find_package(SQLite3 REQUIRED)

target_link_libraries(
        eccsmith
        PRIVATE
        bs
        argagg
        SQLite::SQLite3
)

# === CLEANUP ==================================================================

unset(BLACKSMITH_ENABLE_JSON_EXPORT CACHE)
unset(BLACKSMITH_ENABLE_JITTING CACHE)

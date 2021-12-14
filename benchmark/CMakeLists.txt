cmake_minimum_required(VERSION 3.14 FATAL_ERROR)

project(wazuh-engine)

set(BENCHMARK_SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/source)

# Add google benchmark as CPM dependency
include(../cmake/CPM.cmake)
CPMAddPackage(
  NAME benchmark
  GITHUB_REPOSITORY google/benchmark
  VERSION 1.5.6
  OPTIONS
   "BENCHMARK_ENABLE_TESTING Off"
)

# Add unit benchmarks here
file(GLOB SOURCE_FILES ${BENCHMARK_SOURCE_DIR}/*.cpp)

# Build benchmarks
add_executable(unit_benchmarks ${SOURCE_FILES})
target_link_libraries(unit_benchmarks benchmark::benchmark_main)

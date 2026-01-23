cmake_minimum_required(VERSION 3.12.4)

project(utils_benchmark_test)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

include_directories(${SRC_FOLDER}/external/benchmark/include)
link_directories(${SRC_FOLDER}/external/benchmark/build/src)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  link_directories(${SRC_FOLDER}/external/rocksdb/build/)

  include_directories(${SRC_FOLDER}/shared_modules/common)
  include_directories(${SRC_FOLDER}/shared_modules/utils)
  include_directories(${SRC_FOLDER}/external/cJSON)
  include_directories(${SRC_FOLDER}/external/rocksdb/include)

  file(GLOB UTIL_CXX_BENCHMARKTEST_SRC "*_test.cpp" "main.cpp")
else()
  file(GLOB UTIL_CXX_BENCHMARKTEST_SRC "*_test.cpp" "main.cpp")
  list(FILTER UTIL_CXX_BENCHMARKTEST_SRC EXCLUDE REGEX "rocksdbqueue_test.cpp")
endif()

add_executable(utils_benchmark_test ${UTIL_CXX_BENCHMARKTEST_SRC})

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  target_link_libraries(utils_benchmark_test benchmark rocksdb)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  target_link_libraries(utils_benchmark_test benchmark shlwapi)
else()
  target_link_libraries(utils_benchmark_test benchmark)
endif()

add_test(NAME utils_benchmark_test COMMAND utils_benchmark_test)

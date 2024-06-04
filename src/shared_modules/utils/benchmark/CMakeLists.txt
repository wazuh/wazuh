cmake_minimum_required(VERSION 3.12.4)

project(utils_benchmark_test)

include_directories(${SRC_FOLDER}/external/benchmark/include)
link_directories(${SRC_FOLDER}/external/benchmark/build/src)

file(GLOB UTIL_CXX_BENCHMARKTEST_SRC
    "*_test.cpp"
    "main.cpp"
)

add_executable(utils_benchmark_test ${UTIL_CXX_BENCHMARKTEST_SRC})
target_link_libraries(utils_benchmark_test benchmark rocksdb)

add_test(NAME utils_benchmark_test
         COMMAND utils_benchmark_test)

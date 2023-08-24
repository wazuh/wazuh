cmake_minimum_required(VERSION 3.12.4)
project(urlrequest_benchmark_test)

include_directories(${SRC_FOLDER}/external/benchmark/include/benchmark/)
link_directories(${SRC_FOLDER}/external/benchmark/build/src/)

file(GLOB URL_REQUEST_BENCHMARK_TEST_SRC *.cpp)

add_executable(urlrequest_benchmark_test ${URL_REQUEST_BENCHMARK_TEST_SRC})
target_link_libraries(urlrequest_benchmark_test urlrequest
    benchmark_main
    benchmark)

add_test(NAME urlrequest_benchmark_test
         COMMAND urlrequest_benchmark_test)

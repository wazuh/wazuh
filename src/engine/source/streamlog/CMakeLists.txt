add_library(streamlogger STATIC
    src/logger.cpp
)
target_include_directories(streamlogger
    PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}/include
)
target_link_libraries(streamlogger
    PUBLIC
    base
    PRIVATE
    urlrequest
)

# Tests
if(ENGINE_BUILD_TEST)

set(TEST_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/test/src)
set(UNIT_SRC_DIR ${TEST_SRC_DIR}/unit)
set(COMPONENT_SRC_DIR ${TEST_SRC_DIR}/component)

add_executable(streamlogger_utest
    ${UNIT_SRC_DIR}/logger_test.cpp
)
target_link_libraries(streamlogger_utest GTest::gtest_main GTest::gmock streamlogger)
gtest_discover_tests(streamlogger_utest)

add_executable(streamlogger_ctest
    ${COMPONENT_SRC_DIR}/logger_test.cpp
)

target_link_libraries(streamlogger_ctest PRIVATE streamlogger GTest::gtest_main)
gtest_discover_tests(streamlogger_ctest)

endif(ENGINE_BUILD_TEST)

# Benchmarks
if(ENGINE_BUILD_BENCHMARK)

set(BENCH_DIR ${CMAKE_CURRENT_LIST_DIR}/benchmark)
set(BENCH_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/benchmark/src)

add_library(streamlogger_bench INTERFACE)

target_include_directories(streamlogger_bench INTERFACE ${BENCH_DIR}/include)
target_link_libraries(streamlogger_bench INTERFACE streamlogger benchmark::benchmark)
add_library(streamlogger::bench ALIAS streamlogger_bench)
add_executable(streamlogger_benchmark
    ${BENCH_SRC_DIR}/async_vs_sync_bench.cpp
)

target_include_directories(streamlogger_benchmark
    PRIVATE
    ${BENCH_SRC_DIR}
    ${SRC_DIR}
    ${INC_DIR}
)

target_link_libraries(streamlogger_benchmark
    PUBLIC
    streamlogger::bench
    benchmark::benchmark_main
)

endif(ENGINE_BUILD_BENCHMARK)

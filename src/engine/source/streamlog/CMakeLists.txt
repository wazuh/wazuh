# Defs
set(IFACE_DIR ${CMAKE_CURRENT_LIST_DIR}/interface)
set(SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/src)
set(INC_DIR ${CMAKE_CURRENT_LIST_DIR}/include)

# INTERFACE
add_library(streamlogger_istreamlogger INTERFACE)
target_include_directories(streamlogger_istreamlogger INTERFACE ${IFACE_DIR})
target_link_libraries(streamlogger_istreamlogger INTERFACE base queue scheduler::ischeduler store::istore)
add_library(streamlogger::istreamlogger ALIAS streamlogger_istreamlogger)

# Implementation
add_library(streamlogger_streamlogger STATIC
    ${SRC_DIR}/logger.cpp
    ${SRC_DIR}/channel.cpp
)
target_include_directories(streamlogger_streamlogger
    PUBLIC
    ${INC_DIR}
)
target_link_libraries(streamlogger_streamlogger
    PUBLIC
    base
    queue
    scheduler::ischeduler
    streamlogger::istreamlogger
    store::istore
    PRIVATE
    urlrequest
)
add_library(streamlogger::streamlogger ALIAS streamlogger_streamlogger)

# Tests
if(ENGINE_BUILD_TEST)

set(TEST_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/test/src)
set(UNIT_SRC_DIR ${TEST_SRC_DIR}/unit)
set(COMPONENT_SRC_DIR ${TEST_SRC_DIR}/component)
set(TEST_MOCK_DIR ${CMAKE_CURRENT_LIST_DIR}/test/mocks)

# Mocks
add_library(streamlogger_mocks INTERFACE)
target_include_directories(streamlogger_mocks INTERFACE ${TEST_MOCK_DIR})
target_link_libraries(streamlogger_mocks INTERFACE GTest::gmock streamlogger::istreamlogger)
add_library(streamlogger::mocks ALIAS streamlogger_mocks)


add_executable(streamlogger_utest
    ${UNIT_SRC_DIR}/logger_test.cpp
    ${UNIT_SRC_DIR}/channel_test.cpp
)
target_link_libraries(streamlogger_utest
    PRIVATE
    GTest::gtest_main
    GTest::gmock
    streamlogger::streamlogger
    scheduler::mocks
    store::mocks
)
target_include_directories(streamlogger_utest PRIVATE ${SRC_DIR})
gtest_discover_tests(streamlogger_utest)

add_executable(streamlogger_ctest
    ${COMPONENT_SRC_DIR}/logger_test.cpp
)

target_link_libraries(streamlogger_ctest PRIVATE streamlogger::streamlogger GTest::gtest_main)
gtest_discover_tests(streamlogger_ctest)

endif(ENGINE_BUILD_TEST)

# Benchmarks
if(ENGINE_BUILD_BENCHMARK)

set(BENCH_DIR ${CMAKE_CURRENT_LIST_DIR}/benchmark)
set(BENCH_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/benchmark/src)

add_library(streamlogger_bench INTERFACE)

target_include_directories(streamlogger_bench INTERFACE ${BENCH_DIR}/include)
target_link_libraries(streamlogger_bench INTERFACE streamlogger::streamlogger benchmark::benchmark)
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

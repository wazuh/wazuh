####################################################################################################
# BASE
####################################################################################################
# Defs
set(SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/src)
set(INC_DIR ${CMAKE_CURRENT_LIST_DIR}/include)

add_library(base STATIC
    ${SRC_DIR}/utils/ipUtils.cpp
    ${SRC_DIR}/utils/stringUtils.cpp
    ${SRC_DIR}/utils/timeUtils.cpp
    ${SRC_DIR}/expression.cpp
    ${SRC_DIR}/eventParser.cpp
    ${SRC_DIR}/json.cpp
    ${SRC_DIR}/logging.cpp
)
target_include_directories(base
    PUBLIC
    ${INC_DIR}

    PRIVATE
    ${INC_DIR}/base
    ${SRC_DIR}
)
target_link_libraries(base
    PUBLIC
    fmt::fmt
    spdlog::spdlog
    RapidJSON::RapidJSON
)

# Tests

if(ENGINE_BUILD_TEST)

set(TEST_DIR ${CMAKE_CURRENT_LIST_DIR}/test)
set(TEST_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/test/src)
set(UNIT_SRC_DIR ${TEST_SRC_DIR}/unit)

add_library(base_test INTERFACE)
target_include_directories(base_test INTERFACE ${TEST_DIR}/include)
target_link_libraries(base_test INTERFACE base GTest::gmock)
add_library(base::test ALIAS base_test)

add_executable(base_utest
    ${UNIT_SRC_DIR}/stringUtils_test.cpp
    ${UNIT_SRC_DIR}/ipUtils_test.cpp
    ${UNIT_SRC_DIR}/result_test.cpp
    ${UNIT_SRC_DIR}/graph_test.cpp
    ${UNIT_SRC_DIR}/name_test.cpp
    ${UNIT_SRC_DIR}/utils/timeUtils_test.cpp
    ${UNIT_SRC_DIR}/dotPath_test.cpp
    ${UNIT_SRC_DIR}/eventParser_test.cpp
    ${UNIT_SRC_DIR}/json_test.cpp
    ${UNIT_SRC_DIR}/error_test.cpp
    ${UNIT_SRC_DIR}/timer_test.cpp
    ${UNIT_SRC_DIR}/expression_test.cpp
    ${UNIT_SRC_DIR}/utils/singletonLocator_test.cpp
    ${UNIT_SRC_DIR}/utils/keyValue_test.cpp
    ${UNIT_SRC_DIR}/utils/evpHelper_test.cpp
)
target_include_directories(base_utest
    PRIVATE
    ${TEST_SRC_DIR}
    ${SRC_DIR}
    ${INC_DIR}/base
)
target_link_libraries(base_utest
    PUBLIC
    base::test

    PRIVATE
    base
    GTest::gtest_main
    OpenSSL::Crypto
    OpenSSL::SSL
)
gtest_discover_tests(base_utest)

# TODO this test needs to be instantiated alone because the logger is initialized on tests
add_executable(base_logger_utest
    ${UNIT_SRC_DIR}/logger_test.cpp
)
target_include_directories(base_logger_utest
    PRIVATE
    ${TEST_SRC_DIR}
    ${INC_DIR}/base
)
target_link_libraries(base_logger_utest
    PRIVATE
    base
    GTest::gtest_main
)
gtest_discover_tests(base_logger_utest)

endif(ENGINE_BUILD_TEST)

if(ENGINE_BUILD_BENCHMARK)

set(BENCH_DIR ${CMAKE_CURRENT_LIST_DIR}/benchmark)
set(BENCH_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/benchmark/src)

add_library(base_bench INTERFACE)
target_include_directories(base_bench INTERFACE ${BENCH_DIR}/include)
target_link_libraries(base_bench INTERFACE base benchmark::benchmark)
add_library(base::bench ALIAS base_bench)

add_executable(base_benchmark
    ${BENCH_SRC_DIR}/eventParser_bench.cpp
)
target_include_directories(base_benchmark
    PRIVATE
    ${BENCH_SRC_DIR}
    ${SRC_DIR}
    ${INC_DIR}/base
)
target_link_libraries(base_benchmark
    PUBLIC
    base::bench
    benchmark::benchmark_main
)

endif(ENGINE_BUILD_BENCHMARK)

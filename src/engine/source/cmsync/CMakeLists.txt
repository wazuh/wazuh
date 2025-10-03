# Defs
set(IFACE_DIR ${CMAKE_CURRENT_LIST_DIR}/interface)
set(SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/src)
set(INC_DIR ${CMAKE_CURRENT_LIST_DIR}/include)

# INTERFACE
add_library(cmsync_icmsync INTERFACE)
target_include_directories(cmsync_icmsync INTERFACE ${IFACE_DIR})
target_link_libraries(cmsync_icmsync INTERFACE base ctistore::ictistore)
add_library(cmsync::icmsync ALIAS cmsync_icmsync)

# Implementation
add_library(cmsync_cmsync STATIC
    ${SRC_DIR}/cm.cpp
    ${SRC_DIR}/coreoutput.cpp
)
target_include_directories(cmsync_cmsync
    PUBLIC
    ${INC_DIR}
)
target_link_libraries(cmsync_cmsync
    PUBLIC
    base
    cmsync::icmsync
    api::catalog::icatalog
    api::policy::ipolicy
    kvdb::ikvdb
    router::irouter
    PRIVATE
    urlrequest
)
add_library(cmsync::cmsync ALIAS cmsync_cmsync)

# Tests
if(ENGINE_BUILD_TEST)

set(TEST_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/test/src)
set(UNIT_SRC_DIR ${TEST_SRC_DIR}/unit)
set(COMPONENT_SRC_DIR ${TEST_SRC_DIR}/component)
set(TEST_MOCK_DIR ${CMAKE_CURRENT_LIST_DIR}/test/mocks)

# Mocks
add_library(cmsync_mocks INTERFACE)
target_include_directories(cmsync_mocks INTERFACE ${TEST_MOCK_DIR})
target_link_libraries(cmsync_mocks INTERFACE GTest::gmock cmsync::icmsync)
add_library(cmsync::mocks ALIAS cmsync_mocks)


add_executable(cmsync_utest
    ${UNIT_SRC_DIR}/cm_test.cpp
)
target_link_libraries(cmsync_utest
    PRIVATE
    GTest::gtest_main
    GTest::gmock
    cmsync::cmsync
)
target_include_directories(cmsync_utest PRIVATE ${SRC_DIR})
gtest_discover_tests(cmsync_utest)

add_executable(cmsync_ctest
    ${COMPONENT_SRC_DIR}/cm_test.cpp
)

target_link_libraries(cmsync_ctest PRIVATE cmsync::cmsync GTest::gtest_main)
gtest_discover_tests(cmsync_ctest)

endif(ENGINE_BUILD_TEST)

# Benchmarks 
# TODO: Enable or delete
if(ENGINE_BUILD_BENCHMARK)

set(BENCH_DIR ${CMAKE_CURRENT_LIST_DIR}/benchmark)
set(BENCH_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/benchmark/src)

add_library(cmsync_bench INTERFACE)

target_include_directories(cmsync_bench INTERFACE ${BENCH_DIR}/include)
target_link_libraries(cmsync_bench INTERFACE cmsync::cmsync benchmark::benchmark)
add_library(cmsync::bench ALIAS cmsync_bench)
add_executable(cmsync_benchmark
    ${BENCH_SRC_DIR}/cm_bench.cpp
)

target_include_directories(cmsync_benchmark
    PRIVATE
    ${BENCH_SRC_DIR}
    ${SRC_DIR}
    ${INC_DIR}
)

target_link_libraries(cmsync_benchmark
    PUBLIC
    cmsync::bench
)

endif(ENGINE_BUILD_BENCHMARK)

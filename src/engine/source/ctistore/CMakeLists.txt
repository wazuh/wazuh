# Defs
set(IFACE_DIR ${CMAKE_CURRENT_LIST_DIR}/interface)
set(SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/src)
set(INC_DIR ${CMAKE_CURRENT_LIST_DIR}/include)

# INTERFACE
add_library(ctistore_ictistore INTERFACE)
target_include_directories(ctistore_ictistore INTERFACE ${IFACE_DIR})
target_link_libraries(ctistore_ictistore INTERFACE base)
add_library(ctistore::ictistore ALIAS ctistore_ictistore)

# Implementation
add_library(ctistore_ctistore STATIC
    ${SRC_DIR}/cm.cpp
    ${SRC_DIR}/ctistoragedb.cpp
    ${SRC_DIR}/contentdownloader.cpp
    #${SRC_DIR}/ctiassetadapter.cpp
)
target_include_directories(ctistore_ctistore
    PUBLIC
    ${INC_DIR}
)
target_link_libraries(ctistore_ctistore
    PUBLIC
    base
    ctistore::ictistore
    PRIVATE
    urlrequest
    rocksdb
    content_manager
)
add_library(ctistore::ctistore ALIAS ctistore_ctistore)

# Tests
if(ENGINE_BUILD_TEST)

set(TEST_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/test/src)
set(UNIT_SRC_DIR ${TEST_SRC_DIR}/unit)
set(COMPONENT_SRC_DIR ${TEST_SRC_DIR}/component)
set(TEST_MOCK_DIR ${CMAKE_CURRENT_LIST_DIR}/test/mocks)

# Mocks
add_library(ctistore_mocks INTERFACE)
target_include_directories(ctistore_mocks INTERFACE ${TEST_MOCK_DIR})
target_link_libraries(ctistore_mocks INTERFACE GTest::gmock ctistore::ictistore)
add_library(ctistore::mocks ALIAS ctistore_mocks)


add_executable(ctistore_utest
    ${UNIT_SRC_DIR}/cm_test.cpp
    ${UNIT_SRC_DIR}/contentdownloader_test.cpp
)
target_link_libraries(ctistore_utest
    PRIVATE
    GTest::gtest_main
    GTest::gmock
    ctistore::ctistore
)
target_include_directories(ctistore_utest PRIVATE ${SRC_DIR})
target_include_directories(ctistore_utest PRIVATE ${SRC_FOLDER})
gtest_discover_tests(ctistore_utest)

add_executable(ctistore_ctest
    ${COMPONENT_SRC_DIR}/cm_test.cpp
    ${COMPONENT_SRC_DIR}/ctistoragedb_test.cpp
)

target_link_libraries(ctistore_ctest PRIVATE ctistore::ctistore GTest::gtest_main GTest::gmock rocksdb)
target_include_directories(ctistore_ctest PRIVATE ${SRC_DIR})
gtest_discover_tests(ctistore_ctest)

endif(ENGINE_BUILD_TEST)

# Benchmarks
# TODO: Enable or delete
if(ENGINE_BUILD_BENCHMARK)

set(BENCH_DIR ${CMAKE_CURRENT_LIST_DIR}/benchmark)
set(BENCH_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/benchmark/src)

add_library(ctistore_bench INTERFACE)

target_include_directories(ctistore_bench INTERFACE ${BENCH_DIR}/include)
target_link_libraries(ctistore_bench INTERFACE ctistore::ctistore benchmark::benchmark)
add_library(ctistore::bench ALIAS ctistore_bench)
add_executable(ctistore_benchmark
    ${BENCH_SRC_DIR}/cm_bench.cpp
    ${BENCH_SRC_DIR}/ctistoragedb_bench.cpp
)

target_include_directories(ctistore_benchmark
    PRIVATE
    ${BENCH_SRC_DIR}
    ${SRC_DIR}
    ${INC_DIR}
    ${SRC_FOLDER}
)

target_link_libraries(ctistore_benchmark
    PUBLIC
    ctistore::bench
)

endif(ENGINE_BUILD_BENCHMARK)

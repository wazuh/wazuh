## Defs
set(SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/src)
set(INC_DIR ${CMAKE_CURRENT_LIST_DIR}/include)
set(IFACE_DIR ${CMAKE_CURRENT_LIST_DIR}/interface)

## Interface
add_library(kvdb_ikvdb INTERFACE)
target_include_directories(kvdb_ikvdb INTERFACE ${IFACE_DIR})
target_link_libraries(kvdb_ikvdb INTERFACE base)
add_library(kvdb::ikvdb ALIAS kvdb_ikvdb)

## Kvdb
add_library(kvdb STATIC
    ${SRC_DIR}/kvdbManager.cpp
    ${SRC_DIR}/kvdbHandler.cpp
    ${SRC_DIR}/kvdbHandlerCollection.cpp
    ${SRC_DIR}/refCounter.cpp
)


target_include_directories(kvdb
    PUBLIC
    ${INC_DIR}
## TODO: private, after implement pimpl pattern
    ${rocksdb_SOURCE_DIR}/include
)

target_link_libraries(kvdb
    PRIVATE
    RocksDB::rocksdb
    base
    PUBLIC
    kvdb::ikvdb
)

# Tests
if(ENGINE_BUILD_TEST)

set(TEST_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/test/src)
set(TEST_MOCK_DIR ${CMAKE_CURRENT_LIST_DIR}/test/mocks)
set(UNIT_SRC_DIR ${TEST_SRC_DIR}/unit)
set(COMPONENT_SRC_DIR ${TEST_SRC_DIR}/component)

## Mocks
add_library(kvdb_mocks INTERFACE)
target_include_directories(kvdb_mocks INTERFACE ${TEST_MOCK_DIR})
target_link_libraries(kvdb_mocks INTERFACE GTest::gmock kvdb::ikvdb)
add_library(kvdb::mocks ALIAS kvdb_mocks)

# Unit test
add_executable(kvdb_utest
    ${UNIT_SRC_DIR}/kvdb_test.cpp
)
target_link_libraries(kvdb_utest GTest::gtest_main kvdb kvdb::mocks)
gtest_discover_tests(kvdb_utest)

# Component test
add_executable(kvdb_ctest
    ${COMPONENT_SRC_DIR}/kvdbHandler_test.cpp
    ${COMPONENT_SRC_DIR}/kvdbManager_test.cpp
)

target_link_libraries(kvdb_ctest GTest::gtest_main kvdb)
gtest_discover_tests(kvdb_ctest)

endif(ENGINE_BUILD_TEST)

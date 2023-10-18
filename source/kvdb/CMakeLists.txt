## Defs
set(SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/src)
set(INC_DIR ${CMAKE_CURRENT_LIST_DIR}/include)
set(IFACE_DIR ${CMAKE_CURRENT_LIST_DIR}/interface)

## Interface
add_library(kvdb_ikvdb INTERFACE)
target_include_directories(kvdb_ikvdb INTERFACE ${IFACE_DIR})
target_link_libraries(kvdb_ikvdb INTERFACE base)
add_library(kvdb::ikvdb ALIAS kvdb_ikvdb)

## Deps
CPMAddPackage(
  NAME rocksdb
  GITHUB_REPOSITORY facebook/rocksdb
  GIT_TAG v8.3.2
  VERSION 8.3.2
  OPTIONS
    "WITH_GFLAGS OFF"
    "WITH_TESTS OFF"
    "WITH_BENCHMARK_TOOLS OFF"
    "WITH_TOOLS OFF"
    "WITH_FOLLY_DISTRIBUTED_MUTEX OFF"
    "USE_RTTI 1"
    "FAIL_ON_WARNINGS ON"
    "ROCKSDB_BUILD_SHARED FALSE"
    "CMAKE_DISABLE_FIND_PACKAGE_gtest TRUE"
)

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
    ${rocksdb_SOURCE_DIR}/include
)

target_link_libraries(kvdb
    PRIVATE
    metrics
    rocksdb
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
target_link_libraries(kvdb_mocks INTERFACE gmock kvdb::ikvdb)
add_library(kvdb::mocks ALIAS kvdb_mocks)

endif(ENGINE_BUILD_TEST)
set(ENGINE_KVDB_SOURCE_DIR ${ENGINE_SOURCE_DIR}/kvdb/src)
set(ENGINE_KVDB_INCLUDE_DIR ${ENGINE_SOURCE_DIR}/kvdb/include)

####################################################################################################
# Dependencies
####################################################################################################

CPMAddPackage(
  NAME rocksdb
  GITHUB_REPOSITORY facebook/rocksdb
  GIT_TAG v6.29.3
  VERSION 6.29.3
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

####################################################################################################
# Sources - Includes
####################################################################################################
add_library(kvdb STATIC
    ${ENGINE_KVDB_SOURCE_DIR}/kvdbManager.cpp
    ${ENGINE_KVDB_SOURCE_DIR}/kvdbScope.cpp
    ${ENGINE_KVDB_SOURCE_DIR}/kvdbSpace.cpp
    ${ENGINE_KVDB_SOURCE_DIR}/kvdbHandlerCollection.cpp
    ${ENGINE_KVDB_SOURCE_DIR}/refCounter.cpp
)

target_link_libraries(kvdb PRIVATE rocksdb base metrics)

target_include_directories(kvdb PUBLIC
    ${ENGINE_KVDB_INCLUDE_DIR}
    ${rocksdb_SOURCE_DIR}/include
)

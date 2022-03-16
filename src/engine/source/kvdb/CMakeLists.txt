set(ENGINE_KVDB_SOURCE_DIR ${ENGINE_SOURCE_DIR}/kvdb/src)
set(ENGINE_KVDB_INCLUDE_DIR ${ENGINE_SOURCE_DIR}/kvdb/include)

####################################################################################################
# Dependencies
####################################################################################################

CPMAddPackage(
    NAME RapidJSON
    GITHUB_REPOSITORY Tencent/rapidjson
    GIT_TAG master
    VERSION 1.1.0
    OPTIONS
        "RAPIDJSON_BUILD_DOC OFF"
        "RAPIDJSON_BUILD_EXAMPLES OFF"
        "RAPIDJSON_BUILD_TESTS OFF"
)

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

CPMAddPackage(
  NAME glog
  GITHUB_REPOSITORY google/glog
  GIT_TAG v0.5.0
  VERSION 0.5.0
  OPTIONS
      "WITH_GTEST OFF"
      "BUILD_SHARED_LIBS OFF"
      "WITH_GFLAGS OFF"
      "WITH_UNWIND OFF"
)

# Add this dependencies to parent CMakeLists scope
set(EXTERNAL_DEPS ${EXTERNAL_DEPS} PARENT_SCOPE)

####################################################################################################
# Sources - Includes
####################################################################################################
add_library(kvdb ${ENGINE_KVDB_SOURCE_DIR}/kvdb.cpp)

target_link_libraries(kvdb PRIVATE rocksdb "glog::glog")

target_include_directories(kvdb PUBLIC
    ${ENGINE_KVDB_INCLUDE_DIR}
    ${CMAKE_BINARY_DIR}/_deps/rocksdb-src/include
)

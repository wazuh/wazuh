# Minimum 3.14 required by googletest discover tests
cmake_minimum_required(VERSION 3.14 FATAL_ERROR)

# Set c++17
set(CMAKE_CXX_STANDARD 17)

# Project Settings
project(wazuh-engine)

set(ENGINE_CDB_SOURCE_DIR ${ENGINE_SOURCE_DIR}/cdb/src)
set(ENGINE_CDB_INCLUDE_DIR ${ENGINE_SOURCE_DIR}/cdb/include)
set(ENGINE_ROCKSDB_DIR ${ENGINE_CDB_SOURCE_DIR}/rocksdb)
set(ENGINE_ROCKSDB_INCLUDE_DIR ${ENGINE_CDB_SOURCE_DIR}/rocksdb/include)

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
    NAME RocksDB
    GITHUB_REPOSITORY facebook/rocksdb
    GIT_TAG v6.29.3
    VERSION 6.29.3
    OPTIONS
        #"WITH_GTEST OFF"
        #"BUILD_SHARED_LIBS OFF"
        "WITH_GFLAGS OFF"
        #"WITH_UNWIND OFF"
)
#list(APPEND EXTERNAL_DEPS "RocksDB")

# Add this dependencies to parent CMakeLists scope
set(EXTERNAL_DEPS ${EXTERNAL_DEPS} PARENT_SCOPE)

####################################################################################################
# Sources - Includes
####################################################################################################
add_executable(cdb
    ${ENGINE_CDB_SOURCE_DIR}/cdb.cpp
)

target_include_directories(cdb PUBLIC
    ${ENGINE_CDB_INCLUDE_DIR}
    ${ENGINE_ROCKSDB_INCLUDE_DIR}
)

#target_link_libraries(cdb RocksDB)
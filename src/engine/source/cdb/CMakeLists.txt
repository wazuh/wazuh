# Minimum 3.14 required by googletest discover tests
cmake_minimum_required(VERSION 3.14 FATAL_ERROR)

# Set c++17
set(CMAKE_CXX_STANDARD 17)

# Project Settings
project(wazuh-engine)

set(ENGINE_CDB_SOURCE_DIR ${ENGINE_SOURCE_DIR}/cdb/src)
set(ENGINE_CDB_INCLUDE_DIR ${ENGINE_SOURCE_DIR}/cdb/include)
set(ENGINE_ROCKSDB_DIR ${ENGINE_CDB_SOURCE_DIR}/rocksdb)
set(ENGINE_ROCKSDB_INCLUDE_DIR ${ENGINE_CDB_SOURCE_DIR}/rocksdb)

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

include(ExternalProject)

ExternalProject_Add(rocksdb
    GIT_REPOSITORY https://github.com/facebook/rocksdb.git
    GIT_TAG v6.29.3
    CMAKE_ARGS -DUSE_RTTI=1
        -DCMAKE_CXX_STANDARD=17
        -DCMAKE_BUILD_TYPE=Release
        -DWITH_TESTS=OFF
        -DWITH_TOOLS=OFF
        -DWITH_BZ2=OFF
        -DWITH_LZ4=OFF
        -DWITH_SNAPPY=OFF
        -DWITH_ZLIB=OFF
        -DWITH_GFLAGS=OFF
        -DWITH_ZSTD=OFF
        -DCMAKE_POSITION_INDEPENDENT_CODE=True
    INSTALL_COMMAND $(MAKE) install DESTDIR=${ENGINE_ROCKSDB_DIR}
    )

list(APPEND EXTERNAL_DEPS "RocksDB")

# Add this dependencies to parent CMakeLists scope
set(EXTERNAL_DEPS ${EXTERNAL_DEPS} PARENT_SCOPE)

####################################################################################################
# Sources - Includes
####################################################################################################
add_executable(cdb
    ${ENGINE_CDB_SOURCE_DIR}/cdb.cpp
)

add_dependencies(cdb rocksdb)

target_include_directories(cdb PUBLIC
    ${ENGINE_CDB_INCLUDE_DIR}
    ${ENGINE_ROCKSDB_INCLUDE_DIR}
)

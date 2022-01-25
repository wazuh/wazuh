# Minimum 3.14 required by googletest discover tests
cmake_minimum_required(VERSION 3.14 FATAL_ERROR)
# Set c++17
set(CMAKE_CXX_STANDARD 17)
# Project settings
project(wazuh-engine)

# yaml-cpp::yaml-cpp vs yaml-cpp #FIXME 70 stars on github
CPMAddPackage(
  NAME yaml-cpp
  GITHUB_REPOSITORY jbeder/yaml-cpp
  GIT_TAG yaml-cpp-0.7.0
  VERSION 0.7.0
  OPTIONS
      "YAML_BUILD_SHARED_LIBS OFF"
      "YAML_CPP_BUILD_TESTS OFF"
)
list(APPEND EXTERNAL_DEPS "yaml-cpp")

CPMAddPackage(
    NAME RapidJSON
    GITHUB_REPOSITORY Tencent/rapidjson
    GIT_TAG v1.1.0
    VERSION 1.1.0
    OPTIONS
        "RAPIDJSON_BUILD_DOC OFF"
        "RAPIDJSON_BUILD_EXAMPLES OFF"
        "RAPIDJSON_BUILD_TESTS OFF"
        # "RAPIDJSON_BUILD_CXX17 ON"
)

# Parent scope scope
set(EXTERNAL_DEPS ${EXTERNAL_DEPS} PARENT_SCOPE)

set(CATALOG_SOURCES
    catalogSharedDef.hpp
    Catalog.hpp
    Catalog.cpp
    yml_to_json.hpp
    storageDriver/StorageDriverInterface.hpp
    storageDriver/disk/DiskStorage.hpp
    storageDriver/disk/DiskStorage.cpp
)

target_include_directories(main PUBLIC "${RapidJSON_SOURCE_DIR}/include/")
target_sources(main PRIVATE ${CATALOG_SOURCES})
# target_sources(main PUBLIC ${CATALOG_SOURCES})

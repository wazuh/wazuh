
# Minimum 3.14 required by googletest discover tests
cmake_minimum_required(VERSION 3.14 FATAL_ERROR)

# Set c++17
set(CMAKE_CXX_STANDARD 17)

# Project settings
project(wazuh-engine)

# nlohmann json_schema_validator  #FIXME 70 stars on github
CPMAddPackage(
  NAME json-schema-validator
  GITHUB_REPOSITORY pboettch/json-schema-validator
  GIT_TAG 2.1.0
  VERSION 2.1.0
  OPTIONS
      "BUILD_SHARED_LIBS OFF"
      "BUILD_TESTS OFF"
      "BUILD_EXAMPLES OFF"
)
list(APPEND EXTERNAL_DEPS "nlohmann_json_schema_validator")

CPMAddPackage(
  NAME yaml-cpp
  GITHUB_REPOSITORY jbeder/yaml-cpp
  GIT_TAG yaml-cpp-0.7.0
  VERSION 0.7.0
  OPTIONS
      "YAML_BUILD_SHARED_LIBS OFF"
      "YAML_CPP_BUILD_TESTS OFF"
)

# yaml-cpp::yaml-cpp vs yaml-cpp #FIXME 70 stars on github
list(APPEND EXTERNAL_DEPS "yaml-cpp")

# Parent scope scope
set(EXTERNAL_DEPS ${EXTERNAL_DEPS} PARENT_SCOPE)

set(CATALOG_SOURCES
    catalogSharedDef.hpp
    yml2json.hpp
    storageDriver/storageDriverInterface.hpp
    storageDriver/disk/diskStorage.hpp
    storageDriver/disk/diskStorage.cpp
)


#target_sources(main PRIVATE ${CATALOG_SOURCES})
target_sources(main PUBLIC ${CATALOG_SOURCES})

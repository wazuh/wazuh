# Minimum 3.14 required by googletest discover tests
cmake_minimum_required(VERSION 3.14 FATAL_ERROR)

# Set c++17
set(CMAKE_CXX_STANDARD 17)

# Project Settings
project(wazuh-engine)

set(JSON_ENGINE_SOURCE_DIR ${ENGINE_SOURCE_DIR}/json)

####################################################################################################
# Dependencies
####################################################################################################
CPMAddPackage(
  NAME rapidjson
  GITHUB_REPOSITORY Tencent/rapidjson
  GIT_TAG master
  VERSION 1.1.0
  OPTIONS
      "RAPIDJSON_BUILD_DOC OFF"
      "RAPIDJSON_BUILD_EXAMPLES OFF"
      "RAPIDJSON_BUILD_TESTS OFF"
)
FetchContent_GetProperties(
  rapidjson
  SOURCE_DIR rapidjson_headers
)

####################################################################################################
# Sources - Includes
####################################################################################################
target_include_directories(main PUBLIC
    ${JSON_ENGINE_SOURCE_DIR}
    ${rapidjson_headers}
)

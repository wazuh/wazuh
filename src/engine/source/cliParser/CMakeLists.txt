# Minimum 3.14 required by googletest discover tests
cmake_minimum_required(VERSION 3.14 FATAL_ERROR)

# Set c++17
set(CMAKE_CXX_STANDARD 17)

# Project settings
project(wazuh-engine)

set(CLI_PARSER_ENGINE_SOURCE_DIR ${ENGINE_SOURCE_DIR}/cliParser)

####################################################################################################
# Dependencies
####################################################################################################
CPMAddPackage(
  NAME argparse
  GITHUB_REPOSITORY p-ranav/argparse
  GIT_TAG v2.2
  VERSION 2.2
)
FetchContent_GetProperties(
  argparse
  SOURCE_DIR argparse_headers
)

# Add this dependencies to parent CMakeLists scope
set(EXTERNAL_DEPS ${EXTERNAL_DEPS} PARENT_SCOPE)

####################################################################################################
# Sources - Includes
####################################################################################################
target_sources(main PRIVATE
    ${CLI_PARSER_ENGINE_SOURCE_DIR}/cliParser.cpp
)

target_include_directories(main PUBLIC
    ${CLI_PARSER_ENGINE_SOURCE_DIR}
    ${argparse_headers}/include
)

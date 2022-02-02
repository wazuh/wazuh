cmake_minimum_required(VERSION 3.14 FATAL_ERROR)

####################################################################################################
# Settings
####################################################################################################
project(wazuh-engine)

set(CLI_PARSER_TEST_SOURCE_DIR ${TEST_SOURCE_DIR}/cliParser)
set(CLI_PARSER_ENGINE_SOURCE_DIR ${ENGINE_SOURCE_DIR}/cliParser)

####################################################################################################
# Dependencies -- assuming cpm is available
####################################################################################################
# google/googletest
CPMAddPackage(
  NAME googletest
  GITHUB_REPOSITORY google/googletest
  GIT_TAG release-1.11.0
  VERSION 1.11.0
  OPTIONS
      "INSTALL_GTEST OFF"
)

# ReactiveX/RxCpp
CPMAddPackage(
  NAME RxCpp
  GITHUB_REPOSITORY ReactiveX/RxCpp
  GIT_TAG v4.1.1
  VERSION 4.1.1
)

# Tencent/rapidjson
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

####################################################################################################
# Headers -- Libraries
####################################################################################################
include_directories(
  ${ENGINE_SOURCE_DIR}
  ${CLI_PARSER_ENGINE_SOURCE_DIR}
  ${CLI_PARSER_TEST_SOURCE_DIR}
  ${ENGINE_SOURCE_DIR}/cliParser
  ${argparse_headers}/include
)

link_libraries(
  gtest_main
  rxcpp
)

# CLI Parser test
add_executable(cli_parser_test ${CLI_PARSER_TEST_SOURCE_DIR}/cli_parser_test.cpp ${CLI_PARSER_ENGINE_SOURCE_DIR}/cliParser.cpp)
gtest_discover_tests(cli_parser_test)

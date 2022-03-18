# TODO we need to clean this
CPMAddPackage(
  NAME argparse
  GITHUB_REPOSITORY p-ranav/argparse
  GIT_TAG v2.2
  VERSION 2.2
  DOWNLOAD_ONLY YES
)

add_executable(cli_parser_test 
    cli_parser_test.cpp 
#---
    ${ENGINE_SOURCE_DIR}/cliParser/cliParser.cpp
)

target_link_libraries(cli_parser_test gtest_main)

target_include_directories(cli_parser_test
    PRIVATE
    ${ENGINE_SOURCE_DIR}
    ${ENGINE_SOURCE_DIR}/cliParser
    ${argparse_SOURCE_DIR}/include
)

gtest_discover_tests(cli_parser_test)

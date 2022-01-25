cmake_minimum_required(VERSION 3.14 FATAL_ERROR)

####################################################################################################
# Settings
####################################################################################################
project(wazuh-engine)

set(JSON_TEST_SOURCE_DIR ${TEST_SOURCE_DIR}/json)
set(JSON_ENGINE_SOURCE_DIR ${ENGINE_SOURCE_DIR}/json)

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
  NAME rapidjson
  GITHUB_REPOSITORY Tencent/rapidjson
  GIT_TAG v1.1.0
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
# Sources -- Headers -- Libraries
####################################################################################################

include_directories(
  ${JSON_ENGINE_SOURCE_DIR}
  ${rapidjson_headers}/include
)

link_libraries(
  gtest_main
  rxcpp
)
# Json tests
add_executable(json_test ${JSON_TEST_SOURCE_DIR}/json_test.cpp )
gtest_discover_tests(json_test)
list(APPEND ALL_BUILDER_TESTS ${JSON_TEST_SOURCE_DIR}/json_test.cpp)

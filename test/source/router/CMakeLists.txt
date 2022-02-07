cmake_minimum_required(VERSION 3.14 FATAL_ERROR)

####################################################################################################
# Settings
####################################################################################################
project(wazuh-engine)

####################################################################################################
# Dependencies -- assuming cpm is available
####################################################################################################
CPMAddPackage(
  NAME RxCpp
  GITHUB_REPOSITORY ReactiveX/RxCpp
  GIT_TAG v4.1.1
  VERSION 4.1.1
  OPTIONS
    "MAKE_BUILD_TYPE RelWithDebInfo"
)

# Tencent/rapidjson
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
# Sources -- Headers -- Libraries
####################################################################################################
add_executable(routerTest
  ${TEST_SOURCE_DIR}/router/routerTest.cpp
)

target_include_directories(routerTest PUBLIC
  ${ENGINE_SOURCE_DIR}/json
  ${rapidjson_headers}/include
  ${ENGINE_SOURCE_DIR}/router
)
target_link_libraries(routerTest gtest_main rxcpp)
gtest_discover_tests(routerTest)

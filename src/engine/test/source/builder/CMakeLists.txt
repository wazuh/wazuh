cmake_minimum_required(VERSION 3.14 FATAL_ERROR)

####################################################################################################
# Settings
####################################################################################################
project(wazuh-engine)

set(BUILDER_TEST_SOURCE_DIR ${TEST_SOURCE_DIR}/builder)
set(BUILDER_ENGINE_SOURCE_DIR ${ENGINE_SOURCE_DIR}/builder)

set(BUILDER_BUILDERS_TEST_SOURCE_DIR ${BUILDER_TEST_SOURCE_DIR}/builders)
set(BUILDER_BUILDERS_ENGINE_SOURCE_DIR ${BUILDER_ENGINE_SOURCE_DIR}/builders)

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
# Headers -- Libraries
####################################################################################################
include_directories(
  ${ENGINE_SOURCE_DIR}
  ${BUILDER_ENGINE_SOURCE_DIR}
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}
  ${BUILDER_ENSEMBLES_ENGINE_SOURCE_DIR}
  ${BUILDER_OPERATIONS_ENGINE_SOURCE_DIR}
  ${BUILDER_TEST_SOURCE_DIR}
  ${ENGINE_SOURCE_DIR}/json
  ${rapidjson_headers}/include
  ${BUILDER_ENGINE_SOURCE_DIR}/json
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}
)

link_libraries(
  gtest_main
  rxcpp
)

####################################################################################################
# Builder targets
####################################################################################################
# Builder test
add_executable(builder_test ${BUILDER_TEST_SOURCE_DIR}/builder_test.cpp)
gtest_discover_tests(builder_test)

####################################################################################################
# Builders targets
####################################################################################################
# condition_value test
add_executable(condition_value_test ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/condition_value_test.cpp)
gtest_discover_tests(condition_value_test)

# helper_exists test
add_executable(helper_exists_test ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/helper_exists_test.cpp)
gtest_discover_tests(helper_exists_test)

# condition test
add_executable(condition_test ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/condition_test.cpp)
gtest_discover_tests(condition_test)

# map_value test
add_executable(map_value_test ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/map_value_test.cpp)
gtest_discover_tests(map_value_test)

# map_reference test
add_executable(map_reference_test ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/map_reference_test.cpp)
gtest_discover_tests(map_reference_test)

# map test
add_executable(map_test ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/map_test.cpp)
gtest_discover_tests(map_test)

# decoder test
add_executable(decoder_test ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/decoder_test.cpp)
gtest_discover_tests(decoder_test)

# rule test
add_executable(rule_test ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/rule_test.cpp)
gtest_discover_tests(rule_test)

# filter test
add_executable(filter_test ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/filter_test.cpp)
gtest_discover_tests(filter_test)

####################################################################################################
# Special targets WIP
####################################################################################################
add_subdirectory(${BUILDER_TEST_SOURCE_DIR}/outputs/file)

cmake_minimum_required(VERSION 3.14 FATAL_ERROR)

####################################################################################################
# Settings
####################################################################################################
project(wazuh-engine)

set(BUILDER_TEST_SOURCE_DIR ${TEST_SOURCE_DIR}/builder)
set(BUILDER_ENGINE_SOURCE_DIR ${ENGINE_SOURCE_DIR}/builder)

set(BUILDER_OPERATIONS_TEST_SOURCE_DIR ${BUILDER_TEST_SOURCE_DIR}/operations)
set(BUILDER_OPERATIONS_ENGINE_SOURCE_DIR ${BUILDER_ENGINE_SOURCE_DIR}/operations)

set(BUILDER_ENSEMBLES_TEST_SOURCE_DIR ${BUILDER_TEST_SOURCE_DIR}/ensembles)
set(BUILDER_ENSEMBLES_ENGINE_SOURCE_DIR ${BUILDER_ENGINE_SOURCE_DIR}/ensembles)

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
# Sources -- Headers -- Libraries
####################################################################################################
# set(SOURCES
#   ${BUILDER_ENGINE_SOURCE_DIR}/utils.cpp
#   ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/decoders.cpp
#   ${BUILDER_ENSEMBLES_ENGINE_SOURCE_DIR}/decoder.cpp
#   ${BUILDER_OPERATIONS_ENGINE_SOURCE_DIR}/condition_value.cpp
#   ${BUILDER_OPERATIONS_ENGINE_SOURCE_DIR}/condition_builder.cpp
#   ${BUILDER_OPERATIONS_ENGINE_SOURCE_DIR}/map_value.cpp
#   ${BUILDER_OPERATIONS_ENGINE_SOURCE_DIR}/helper_exists.cpp
#   ${BUILDER_OPERATIONS_ENGINE_SOURCE_DIR}/map_reference.cpp
#   ${BUILDER_OPERATIONS_ENGINE_SOURCE_DIR}/map_builder.cpp
# )

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
)

link_libraries(
  gtest_main
  rxcpp
)

####################################################################################################
# Builder targets
####################################################################################################
# Asset Builder test
add_executable(asset_builder_test ${BUILDER_TEST_SOURCE_DIR}/asset_builder_test.cpp)
gtest_discover_tests(asset_builder_test)

# Registry test
add_executable(registry_test ${BUILDER_TEST_SOURCE_DIR}/registry_test.cpp)
gtest_discover_tests(registry_test)

# Registry-Builder test
add_executable(registry_builder_test ${BUILDER_TEST_SOURCE_DIR}/registry_builder_test.cpp)
gtest_discover_tests(registry_builder_test)

# Utils test
add_executable(utils_test ${BUILDER_TEST_SOURCE_DIR}/utils_test.cpp ${BUILDER_ENGINE_SOURCE_DIR}/utils.cpp)
gtest_discover_tests(utils_test)

# Builder test
add_executable(builder_test ${BUILDER_TEST_SOURCE_DIR}/builder_test.cpp)
gtest_discover_tests(builder_test)

####################################################################################################
# Engines targets
####################################################################################################
# add_executable(decoders_test ${BUILDER_ENGINES_TEST_SOURCE_DIR}/decoders_test.cpp ${SOURCES})
# gtest_discover_tests(decoders_test)
# list(APPEND ALL_BUILDER_TESTS ${BUILDER_ENGINES_TEST_SOURCE_DIR}/decoders_test.cpp)

####################################################################################################
# Ensemble targets
####################################################################################################
add_executable(decoder_test ${BUILDER_ENSEMBLES_TEST_SOURCE_DIR}/decoder_test.cpp)
gtest_discover_tests(decoder_test)
list(APPEND ALL_BUILDER_TESTS ${BUILDER_ENSEMBLES_TEST_SOURCE_DIR}/decoder_test.cpp)

####################################################################################################
# Operations targets
####################################################################################################
# condition_builder test
add_executable(condition_builder_test ${BUILDER_OPERATIONS_TEST_SOURCE_DIR}/condition_builder_test.cpp ${BUILDER_OPERATIONS_ENGINE_SOURCE_DIR}/condition_builder.cpp ${BUILDER_OPERATIONS_ENGINE_SOURCE_DIR}/condition_value.cpp ${BUILDER_OPERATIONS_ENGINE_SOURCE_DIR}/helper_exists.cpp)
gtest_discover_tests(condition_builder_test)

# condition_value test
add_executable(condition_value_test ${BUILDER_OPERATIONS_TEST_SOURCE_DIR}/condition_value_test.cpp ${BUILDER_OPERATIONS_ENGINE_SOURCE_DIR}/condition_value.cpp)
gtest_discover_tests(condition_value_test)

# helper_exists test
add_executable(helper_exists_test ${BUILDER_OPERATIONS_TEST_SOURCE_DIR}/helper_exists_test.cpp ${BUILDER_OPERATIONS_ENGINE_SOURCE_DIR}/helper_exists.cpp)
gtest_discover_tests(helper_exists_test)

# map_builder test
add_executable(map_builder_test ${BUILDER_OPERATIONS_TEST_SOURCE_DIR}/map_builder_test.cpp)
gtest_discover_tests(map_builder_test)
list(APPEND ALL_BUILDER_TESTS ${BUILDER_OPERATIONS_TEST_SOURCE_DIR}/map_builder_test.cpp)

# map_value test
add_executable(map_value_test ${BUILDER_OPERATIONS_TEST_SOURCE_DIR}/map_value_test.cpp ${BUILDER_OPERATIONS_ENGINE_SOURCE_DIR}/map_value.cpp)
gtest_discover_tests(map_value_test)

# map_reference test
add_executable(map_reference_test ${BUILDER_OPERATIONS_TEST_SOURCE_DIR}/map_reference_test.cpp ${BUILDER_OPERATIONS_ENGINE_SOURCE_DIR}/map_reference.cpp)
gtest_discover_tests(map_reference_test)

####################################################################################################
# Special targets WIP
####################################################################################################
# add_executable(all_builder_tests ${ALL_BUILDER_TESTS} ${SOURCES})
# gtest_discover_tests(all_builder_tests)

add_subdirectory(${BUILDER_TEST_SOURCE_DIR}/outputs/file)

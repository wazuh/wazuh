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

set(BUILDER_ENGINES_TEST_SOURCE_DIR ${BUILDER_TEST_SOURCE_DIR}/engines)
set(BUILDER_ENGINES_ENGINE_SOURCE_DIR ${BUILDER_ENGINE_SOURCE_DIR}/engines)

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

# nlohmann/json
CPMAddPackage(
  NAME json
  GITHUB_REPOSITORY nlohmann/json
  GIT_TAG v3.10.4
  VERSION 3.10.4
  OPTIONS
      "JSON_BuildTests OFF"
      "JSON_Install OFF"
)

####################################################################################################
# Sources -- Headers -- Libraries
####################################################################################################
set(SOURCES
  ${BUILDER_ENGINE_SOURCE_DIR}/builder.cpp
  ${BUILDER_ENGINE_SOURCE_DIR}/registry.cpp
  ${BUILDER_ENGINE_SOURCE_DIR}/utils.cpp
  ${BUILDER_ENGINES_ENGINE_SOURCE_DIR}/decoders.cpp
  ${BUILDER_ENSEMBLES_ENGINE_SOURCE_DIR}/decoder.cpp
  ${BUILDER_OPERATIONS_ENGINE_SOURCE_DIR}/condition_value.cpp
  ${BUILDER_OPERATIONS_ENGINE_SOURCE_DIR}/condition_builder.cpp
  ${BUILDER_OPERATIONS_ENGINE_SOURCE_DIR}/map_value.cpp
  ${BUILDER_OPERATIONS_ENGINE_SOURCE_DIR}/helper_exists.cpp
  ${BUILDER_OPERATIONS_ENGINE_SOURCE_DIR}/map_reference.cpp
)

include_directories(
  ${BUILDER_ENGINE_SOURCE_DIR}
  ${BUILDER_ENGINES_ENGINE_SOURCE_DIR}
  ${BUILDER_ENSEMBLES_ENGINE_SOURCE_DIR}
  ${BUILDER_OPERATIONS_ENGINE_SOURCE_DIR}
)

link_libraries(
  gtest_main
  rxcpp
  nlohmann_json::nlohmann_json
)

####################################################################################################
# Builder targets
####################################################################################################
# Builder test
add_executable(builder_test ${BUILDER_TEST_SOURCE_DIR}/builder_test.cpp ${SOURCES})
gtest_discover_tests(builder_test)
list(APPEND ALL_BUILDER_TESTS ${BUILDER_TEST_SOURCE_DIR}/builder_test.cpp)

# Registry test
add_executable(registry_test ${BUILDER_TEST_SOURCE_DIR}/registry_test.cpp ${SOURCES})
gtest_discover_tests(registry_test)
#list(APPEND ALL_BUILDER_TESTS ${BUILDER_TEST_SOURCE_DIR}/registry_test.cpp)

# Utils test
add_executable(utils_test ${BUILDER_TEST_SOURCE_DIR}/utils_test.cpp ${SOURCES})
gtest_discover_tests(utils_test)
list(APPEND ALL_BUILDER_TESTS ${BUILDER_TEST_SOURCE_DIR}/utils_test.cpp)

####################################################################################################
# Engines targets
####################################################################################################
add_executable(decoders_test ${BUILDER_ENGINES_TEST_SOURCE_DIR}/decoders_test.cpp ${SOURCES})
gtest_discover_tests(decoders_test)
list(APPEND ALL_BUILDER_TESTS ${BUILDER_ENGINES_TEST_SOURCE_DIR}/decoders_test.cpp)

####################################################################################################
# Ensemble targets
####################################################################################################
add_executable(decoder_test ${BUILDER_ENSEMBLES_TEST_SOURCE_DIR}/decoder_test.cpp ${SOURCES})
gtest_discover_tests(decoder_test)
list(APPEND ALL_BUILDER_TESTS ${BUILDER_ENSEMBLES_TEST_SOURCE_DIR}/decoder_test.cpp)

####################################################################################################
# Operations targets
####################################################################################################
# condition_builder test
add_executable(condition_builder_test ${BUILDER_OPERATIONS_TEST_SOURCE_DIR}/condition_builder_test.cpp ${SOURCES})
gtest_discover_tests(condition_builder_test)
list(APPEND ALL_BUILDER_TESTS ${BUILDER_OPERATIONS_TEST_SOURCE_DIR}/condition_builder_test.cpp)

# condition_value test
add_executable(condition_value_test ${BUILDER_OPERATIONS_TEST_SOURCE_DIR}/condition_value_test.cpp ${SOURCES})
gtest_discover_tests(condition_value_test)
list(APPEND ALL_BUILDER_TESTS ${BUILDER_OPERATIONS_TEST_SOURCE_DIR}/condition_value_test.cpp)

# helper_exists test
add_executable(helper_exists_test ${BUILDER_OPERATIONS_TEST_SOURCE_DIR}/helper_exists_test.cpp ${SOURCES})
gtest_discover_tests(helper_exists_test)
list(APPEND ALL_BUILDER_TESTS ${BUILDER_OPERATIONS_TEST_SOURCE_DIR}/helper_exists_test.cpp)

# map_value test
add_executable(map_value_test ${BUILDER_OPERATIONS_TEST_SOURCE_DIR}/map_value_test.cpp ${SOURCES})
gtest_discover_tests(map_value_test)
list(APPEND ALL_BUILDER_TESTS ${BUILDER_OPERATIONS_TEST_SOURCE_DIR}/map_value_test.cpp)

# map_reference test
add_executable(map_reference_test ${BUILDER_OPERATIONS_TEST_SOURCE_DIR}/map_reference_test.cpp ${SOURCES})
gtest_discover_tests(map_reference_test)
list(APPEND ALL_BUILDER_TESTS ${BUILDER_OPERATIONS_TEST_SOURCE_DIR}/map_reference_test.cpp)

####################################################################################################
# Special targets WIP
####################################################################################################
# add_executable(all_builder_tests ${ALL_BUILDER_TESTS} ${SOURCES})
# gtest_discover_tests(all_builder_tests)

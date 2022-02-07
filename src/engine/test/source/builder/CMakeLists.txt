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
# Headers -- Libraries
####################################################################################################
include_directories(
  ${ENGINE_SOURCE_DIR}
  ${BUILDER_ENGINE_SOURCE_DIR}
  ${BUILDER_ENGINE_SOURCE_DIR}/builders
  ${BUILDER_TEST_SOURCE_DIR}
  ${ENGINE_SOURCE_DIR}/json
  ${ENGINE_SOURCE_DIR}/graph
  ${rapidjson_headers}/include
)

link_libraries(
  gtest_main
  rxcpp
)

####################################################################################################
# Builder targets
####################################################################################################
# Builder test
add_executable(builderTest ${BUILDER_TEST_SOURCE_DIR}/builderTest.cpp)
gtest_discover_tests(builderTest)

####################################################################################################
# Builders targets
####################################################################################################

add_executable(buildCheckTest ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/buildCheckTest.cpp)
gtest_discover_tests(buildCheckTest)

add_executable(buildMapTest ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/buildMapTest.cpp)
gtest_discover_tests(buildMapTest)

add_executable(checkStageTest ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/checkStageTest.cpp)
gtest_discover_tests(checkStageTest)

add_executable(checkValTest ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/checkValTest.cpp)
gtest_discover_tests(checkValTest)

add_executable(decoderTest ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/decoderTest.cpp)
gtest_discover_tests(decoderTest)

add_executable(fileOutputTest ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/fileOutputTest.cpp)
gtest_discover_tests(fileOutputTest)

add_executable(filterTest ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/filterTest.cpp)
gtest_discover_tests(filterTest)

add_executable(mapRefTest ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/mapRefTest.cpp)
gtest_discover_tests(mapRefTest)

add_executable(mapValTest ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/mapValTest.cpp)
gtest_discover_tests(mapValTest)

add_executable(outputTest ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/outputTest.cpp)
gtest_discover_tests(outputTest)

add_executable(ruleTest ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/ruleTest.cpp)
gtest_discover_tests(ruleTest)


####################################################################################################
# Output targets
####################################################################################################
add_subdirectory(outputs)

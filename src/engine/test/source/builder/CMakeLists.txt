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
  glog::glog
  gtest_main
  rxcpp
)

####################################################################################################
# Builder targets
####################################################################################################
# Builder test
add_executable(
  builderTest
  ${BUILDER_ENGINE_SOURCE_DIR}/builder.cpp
  ${BUILDER_TEST_SOURCE_DIR}/builderTest.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/buildCheck.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/buildMap.cpp
)
target_link_libraries(builderTest glog::glog)
gtest_discover_tests(builderTest)

# Registry test
add_executable(registryTest ${BUILDER_TEST_SOURCE_DIR}/registryTest.cpp ${BUILDER_ENGINE_SOURCE_DIR}/registry.cpp)
target_link_libraries(registryTest glog::glog)
gtest_discover_tests(registryTest)

# Register test
add_executable(registerTest
  ${BUILDER_TEST_SOURCE_DIR}/registerTest.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/buildCheck.cpp
  ${BUILDER_ENGINE_SOURCE_DIR}/registry.cpp
  )
target_link_libraries(registerTest glog::glog)
gtest_discover_tests(registerTest)

####################################################################################################
# Builders targets
####################################################################################################

add_executable(opBuilderConditionValueTest ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderConditionValueTest.cpp ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderConditionValue.cpp)
gtest_discover_tests(opBuilderConditionValueTest)

add_executable(opBuilderConditionReferenceTest ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderConditionReferenceTest.cpp ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderConditionReference.cpp)
gtest_discover_tests(opBuilderConditionReferenceTest)

add_executable(opBuilderHelperExistsTest ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperExistsTest.cpp ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderHelperExists.cpp)
gtest_discover_tests(opBuilderHelperExistsTest)

add_executable(opBuilderConditionTest ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderConditionTest.cpp ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderCondition.cpp ${BUILDER_ENGINE_SOURCE_DIR}/registry.cpp ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderConditionValue.cpp ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderConditionReference.cpp ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderHelperExists.cpp)
gtest_discover_tests(opBuilderConditionTest)

add_executable(opBuilderMapValueTest ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderMapValueTest.cpp ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderMapValue.cpp)
gtest_discover_tests(opBuilderMapValueTest)

add_executable(opBuilderMapReferenceTest ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderMapReferenceTest.cpp ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderMapReference.cpp)
gtest_discover_tests(opBuilderMapReferenceTest)

add_executable(opBuilderMapTest ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderMapTest.cpp ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderMap.cpp ${BUILDER_ENGINE_SOURCE_DIR}/registry.cpp ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderMapValue.cpp ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderMapReference.cpp)
gtest_discover_tests(opBuilderMapTest)



add_executable(buildMapTest ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/buildMapTest.cpp ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/buildMap.cpp)
gtest_discover_tests(buildMapTest)

add_executable(checkStageTest ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/checkStageTest.cpp)
gtest_discover_tests(checkStageTest)

add_executable(checkValTest ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/checkValTest.cpp)
gtest_discover_tests(checkValTest)

add_executable(decoderTest ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/decoderTest.cpp ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/decoder.cpp)
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

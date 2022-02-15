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
  ${BUILDER_ENGINE_SOURCE_DIR}/outputs
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
add_executable(builderTest
  ${BUILDER_TEST_SOURCE_DIR}/builderTest.cpp
  ${BUILDER_ENGINE_SOURCE_DIR}/registry.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/combinatorBuilderBroadcast.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/stageBuilderOutputs.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/combinatorBuilderChain.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/stageBuilderCheck.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderCondition.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderConditionValue.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderConditionReference.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/OpBuilderHelperFilter.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/assetBuilderOutput.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderFileOutput.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/stageBuilderNormalize.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderMap.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderMapValue.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderMapReference.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/assetBuilderFilter.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/assetBuilderRule.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/assetBuilderDecoder.cpp
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
  ${BUILDER_ENGINE_SOURCE_DIR}/registry.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/combinatorBuilderBroadcast.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/stageBuilderOutputs.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/combinatorBuilderChain.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/stageBuilderCheck.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderCondition.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderConditionValue.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderConditionReference.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/OpBuilderHelperFilter.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/assetBuilderOutput.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderFileOutput.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/stageBuilderNormalize.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderMap.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderMapValue.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderMapReference.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/assetBuilderFilter.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/assetBuilderRule.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/assetBuilderDecoder.cpp
  )
target_link_libraries(registerTest glog::glog)
gtest_discover_tests(registerTest)

####################################################################################################
# Builders targets
####################################################################################################

add_executable(opBuilderConditionValueTest
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderConditionValueTest.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderConditionValue.cpp)
gtest_discover_tests(opBuilderConditionValueTest)

add_executable(opBuilderConditionReferenceTest
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderConditionReferenceTest.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderConditionReference.cpp)
gtest_discover_tests(opBuilderConditionReferenceTest)

add_executable(opBuilderHelperExistsTest
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperExistsTest.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/OpBuilderHelperFilter.cpp)
gtest_discover_tests(opBuilderHelperExistsTest)

add_executable(opBuilderConditionTest
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderConditionTest.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderCondition.cpp
  ${BUILDER_ENGINE_SOURCE_DIR}/registry.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderConditionValue.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderConditionReference.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/OpBuilderHelperFilter.cpp)
gtest_discover_tests(opBuilderConditionTest)

add_executable(opBuilderMapValueTest
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderMapValueTest.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderMapValue.cpp)
gtest_discover_tests(opBuilderMapValueTest)

add_executable(opBuilderMapReferenceTest
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderMapReferenceTest.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderMapReference.cpp)
gtest_discover_tests(opBuilderMapReferenceTest)

add_executable(opBuilderMapTest
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderMapTest.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderMap.cpp
  ${BUILDER_ENGINE_SOURCE_DIR}/registry.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderMapValue.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderMapReference.cpp)
gtest_discover_tests(opBuilderMapTest)

# add_executable(combinatorBuilderChainTest)
# gtest_discover_tests(combinatorBuilderChainTest)
# add_executable(combinatorBuilderBroadcastTest)
# gtest_discover_tests(combinatorBuilderBroadcastTest)

add_executable(stageBuilderCheckTest
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/stageBuilderCheckTest.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/stageBuilderCheck.cpp
  ${BUILDER_ENGINE_SOURCE_DIR}/registry.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderCondition.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderConditionValue.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderConditionReference.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/OpBuilderHelperFilter.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/combinatorBuilderChain.cpp)
gtest_discover_tests(stageBuilderCheckTest)

add_executable(stageBuilderNormalizeTest
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/stageBuilderNormalizeTest.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/stageBuilderNormalize.cpp
  ${BUILDER_ENGINE_SOURCE_DIR}/registry.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderMap.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderMapValue.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderMapReference.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/combinatorBuilderChain.cpp)
gtest_discover_tests(stageBuilderNormalizeTest)

add_executable(assetBuilderDecoderTest
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/assetBuilderDecoderTest.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/assetBuilderDecoder.cpp
  ${BUILDER_ENGINE_SOURCE_DIR}/registry.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/stageBuilderNormalize.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderMap.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderMapValue.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderMapReference.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/combinatorBuilderChain.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/stageBuilderCheck.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderCondition.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderConditionValue.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderConditionReference.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/OpBuilderHelperFilter.cpp)
gtest_discover_tests(assetBuilderDecoderTest)

add_executable(assetBuilderRuleTest
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/assetBuilderRuleTest.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/assetBuilderRule.cpp
  ${BUILDER_ENGINE_SOURCE_DIR}/registry.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/stageBuilderNormalize.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderMap.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderMapValue.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderMapReference.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/combinatorBuilderChain.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/stageBuilderCheck.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderCondition.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderConditionValue.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderConditionReference.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/OpBuilderHelperFilter.cpp)
gtest_discover_tests(assetBuilderRuleTest)

add_executable(assetBuilderFilterTest
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/assetBuilderFilterTest.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/assetBuilderFilter.cpp
  ${BUILDER_ENGINE_SOURCE_DIR}/registry.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/combinatorBuilderChain.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/stageBuilderCheck.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderCondition.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderConditionValue.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderConditionReference.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/OpBuilderHelperFilter.cpp)
gtest_discover_tests(assetBuilderFilterTest)

add_executable(opBuilderFileOutputTest
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderFileOutputTest.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderFileOutput.cpp)
gtest_discover_tests(opBuilderFileOutputTest)

add_executable(stageBuilderOutputsTest
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/stageBuilderOutputsTest.cpp
  ${BUILDER_ENGINE_SOURCE_DIR}/registry.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/combinatorBuilderBroadcast.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/stageBuilderOutputs.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderFileOutput.cpp)
gtest_discover_tests(stageBuilderOutputsTest)

add_executable(assetBuilderOutputTest
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/assetBuilderOutputTest.cpp
  ${BUILDER_ENGINE_SOURCE_DIR}/registry.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/combinatorBuilderBroadcast.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/stageBuilderOutputs.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/combinatorBuilderChain.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/stageBuilderCheck.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderCondition.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderConditionValue.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderConditionReference.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/OpBuilderHelperFilter.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/assetBuilderOutput.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderFileOutput.cpp)
gtest_discover_tests(assetBuilderOutputTest)

####################################################################################################
# Output targets
####################################################################################################
add_subdirectory(outputs)

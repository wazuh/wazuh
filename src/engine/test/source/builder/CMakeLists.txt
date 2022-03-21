# Copyright (C) 2015-2021, Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

####################################################################################################
# Settings
####################################################################################################

set(BUILDER_TEST_SOURCE_DIR ${TEST_SOURCE_DIR}/builder)
set(BUILDER_ENGINE_SOURCE_DIR ${ENGINE_SOURCE_DIR}/builder)

set(BUILDER_BUILDERS_TEST_SOURCE_DIR ${BUILDER_TEST_SOURCE_DIR}/builders)
set(BUILDER_BUILDERS_ENGINE_SOURCE_DIR ${BUILDER_ENGINE_SOURCE_DIR}/builders)

####################################################################################################
<<<<<<< HEAD
=======
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
  OPTIONS
    "RXCPP_DISABLE_TESTS_AND_EXAMPLES"
)

CPMAddPackage(
  NAME RE2
  GITHUB_REPOSITORY google/re2
  GIT_TAG 2022-02-01
  VERSION release 2022-02-01
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
>>>>>>> 20bf8d8658 (Refactored graph, tests not updated)
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
<<<<<<< HEAD
)

#TODO do this better
link_libraries(gtest_main hlp rxcpp builders)
=======
  ${rapidjson_headers}/include
  ${RxCpp_SOURCE_DIR}/Rx/v2/src
)

link_libraries(
  glog::glog
  gtest_main
  re2
)
>>>>>>> 20bf8d8658 (Refactored graph, tests not updated)

####################################################################################################
# Builder targets
####################################################################################################
# Builder test
add_executable(builderTest
  ${BUILDER_TEST_SOURCE_DIR}/builder_test.cpp
)
gtest_discover_tests(builderTest)

# Registry test
add_executable(registryTest
    ${BUILDER_TEST_SOURCE_DIR}/registry_test.cpp
    )
gtest_discover_tests(registryTest)

# Register test
add_executable(registerTest
  ${BUILDER_TEST_SOURCE_DIR}/register_test.cpp
  )
gtest_discover_tests(registerTest)

<<<<<<< HEAD
add_executable(opBuilderTest
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderConditionReference_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderConditionValue_test.cpp
=======
# Configuration graph test
add_executable(graphTest
  ${BUILDER_TEST_SOURCE_DIR}/graphTest.cpp
)

target_link_libraries(graphTest gtest_main)
gtest_discover_tests(graphTest)

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

add_executable(opBuilderHelperExists_test
  ${ENGINE_SOURCE_DIR}/shared/stringUtils.cpp
  ${ENGINE_SOURCE_DIR}/shared/ipUtils.cpp
>>>>>>> 20bf8d8658 (Refactored graph, tests not updated)
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperExists_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperNotExists_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperStringEq_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperStringGe_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperStringGt_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperStringLO_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperStringLe_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperStringLt_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperStringNe_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperStringUP_test.cpp
)
gtest_discover_tests(opBuilderTest)

add_executable(opBuilderHelperTest
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperIPCIDRCheck_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperIntCalc_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperIntEqual_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperIntGreaterThanEqual_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperIntGreaterThan_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperIntLessThanEqual_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperIntLessThan_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperIntNotEqual_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperRegexExtract_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperRegexMatch_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperRegexNotMatch_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperStringTrim_test.cpp
)
gtest_discover_tests(opBuilderHelperTest)

add_executable(opBuilderMapTest
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderMapValue_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderMapReference_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderMap_test.cpp
)
gtest_discover_tests(opBuilderMapTest)

add_executable(stageBuilderTest
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/stageBuilderCheck_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/stageBuilderNormalize_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/stageBuilderOutputs_test.cpp
)
gtest_discover_tests(stageBuilderTest)

add_executable(assetBuilderTest
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/assetBuilderDecoder_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/assetBuilderOutput_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/assetBuilderFilter_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/assetBuilderRule_test.cpp
)
gtest_discover_tests(assetBuilderTest)

add_executable(opBuilderConditionTest
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderCondition_test.cpp
)
gtest_discover_tests(opBuilderConditionTest)

add_executable(outputTest
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderFileOutput_test.cpp
  ${TEST_SOURCE_DIR}/builder/outputs/fileOutput_test.cpp
)

gtest_discover_tests(outputTest)

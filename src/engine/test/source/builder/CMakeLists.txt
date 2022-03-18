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
)

#TODO do this better
link_libraries(base gtest_main hlp rxcpp re2)

####################################################################################################
# Builder targets
####################################################################################################
# Builder test
add_executable(builderTest
  ${BUILDER_TEST_SOURCE_DIR}/builderTest.cpp
  ${BUILDER_ENGINE_SOURCE_DIR}/registry.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/combinatorBuilderBroadcast.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/stageBuilderOutputs.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/stageParse.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/combinatorBuilderChain.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/stageBuilderCheck.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderCondition.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderConditionValue.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderConditionReference.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderHelperFilter.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderHelperMap.cpp
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
target_link_libraries(builderTest base)
gtest_discover_tests(builderTest)

# Registry test
add_executable(registryTest
    ${BUILDER_TEST_SOURCE_DIR}/registryTest.cpp 
    ${BUILDER_ENGINE_SOURCE_DIR}/registry.cpp
    )
gtest_discover_tests(registryTest)

# Register test
add_executable(registerTest
  ${BUILDER_TEST_SOURCE_DIR}/registerTest.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/assetBuilderDecoder.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/assetBuilderFilter.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/assetBuilderOutput.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/assetBuilderRule.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/combinatorBuilderBroadcast.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/combinatorBuilderChain.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderCondition.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderConditionReference.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderConditionValue.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderFileOutput.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderHelperFilter.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderHelperMap.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderMap.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderMapReference.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderMapValue.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/stageBuilderCheck.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/stageBuilderNormalize.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/stageBuilderOutputs.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/stageParse.cpp
  ${BUILDER_ENGINE_SOURCE_DIR}/registry.cpp
  )
target_link_libraries(registerTest base)
gtest_discover_tests(registerTest)

add_executable(opBuilderTest
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderConditionReferenceTest.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderConditionValueTest.cpp
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
#------
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderHelperMap.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderHelperFilter.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderConditionReference.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderConditionValue.cpp
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
#------
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderHelperFilter.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderHelperMap.cpp
)
gtest_discover_tests(opBuilderHelperTest)

add_executable(opBuilderMapTest
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderMapValueTest.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderMapReferenceTest.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderMapTest.cpp
#------
  ${BUILDER_ENGINE_SOURCE_DIR}/registry.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderMap.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderMapValue.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderMapReference.cpp
)
gtest_discover_tests(opBuilderMapTest)

add_executable(stageBuilderTest
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/stageBuilderCheckTest.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/stageBuilderNormalizeTest.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/stageBuilderOutputsTest.cpp
#-----
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/combinatorBuilderChain.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/combinatorBuilderBroadcast.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderCondition.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderConditionReference.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderConditionValue.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderFileOutput.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderFileOutput.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderHelperFilter.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderMap.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderMapReference.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderMapValue.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/stageBuilderCheck.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/stageBuilderNormalize.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/stageBuilderOutputs.cpp
  ${BUILDER_ENGINE_SOURCE_DIR}/registry.cpp
)
gtest_discover_tests(stageBuilderTest)

add_executable(assetBuilderTest
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/assetBuilderDecoderTest.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/assetBuilderOutputTest.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/assetBuilderFilterTest.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/assetBuilderRuleTest.cpp
#-------
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/assetBuilderDecoder.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/assetBuilderFilter.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/assetBuilderOutput.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/assetBuilderRule.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/combinatorBuilderBroadcast.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/combinatorBuilderChain.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderCondition.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderConditionReference.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderConditionValue.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderFileOutput.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderHelperFilter.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderMap.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderMapReference.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderMapValue.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/stageBuilderCheck.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/stageBuilderNormalize.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/stageBuilderOutputs.cpp
  ${BUILDER_ENGINE_SOURCE_DIR}/registry.cpp
)
gtest_discover_tests(assetBuilderTest)

add_executable(opBuilderConditionTest
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderConditionTest.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderCondition.cpp
  ${BUILDER_ENGINE_SOURCE_DIR}/registry.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderConditionValue.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderConditionReference.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderHelperFilter.cpp
)
gtest_discover_tests(opBuilderConditionTest)

add_executable(opBuilderFileOutputTest
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderFileOutputTest.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderFileOutput.cpp
)
gtest_discover_tests(opBuilderFileOutputTest)

add_executable(fileOutputTest
  ${TEST_SOURCE_DIR}/builder/outputs/fileOutputTest.cpp
  ${ENGINE_SOURCE_DIR}/builder/outputs/file.hpp
)

gtest_discover_tests(fileOutputTest)

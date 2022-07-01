# Copyright (C) 2015-2021, Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

# ###################################################################################################
# Settings
# ###################################################################################################

set(BUILDER_TEST_SOURCE_DIR ${TEST_SOURCE_DIR}/builder)
set(BUILDER_ENGINE_SOURCE_DIR ${ENGINE_SOURCE_DIR}/builder)

set(BUILDER_BUILDERS_TEST_SOURCE_DIR ${BUILDER_TEST_SOURCE_DIR}/builders)
set(BUILDER_BUILDERS_ENGINE_SOURCE_DIR ${BUILDER_ENGINE_SOURCE_DIR}/builders)

# ###################################################################################################
# Headers -- Libraries
# ###################################################################################################
include_directories(
  ${ENGINE_SOURCE_DIR}
  ${BUILDER_ENGINE_SOURCE_DIR}
  ${BUILDER_ENGINE_SOURCE_DIR}/builders
  ${BUILDER_ENGINE_SOURCE_DIR}/outputs
  ${BUILDER_TEST_SOURCE_DIR}
  ${ENGINE_SOURCE_DIR}/json
  ${ENGINE_SOURCE_DIR}/graph
  ${RxCpp_SOURCE_DIR}/Rx/v2/src
)

# TODO do this better
# link_libraries(gtest engine_test_main hlp kvdb builders logicExpression)

# ###################################################################################################
# Builder targets
# ###################################################################################################
# Expression test
add_executable(expression_test
  ${BUILDER_TEST_SOURCE_DIR}/expression_test.cpp
)
target_link_libraries(expression_test
  gtest_main base
)
gtest_discover_tests(expression_test)

# Registry test
add_executable(registry_test
  ${BUILDER_TEST_SOURCE_DIR}/registry_test.cpp
)
target_link_libraries(registry_test
  gtest_main base
)
gtest_discover_tests(registry_test)

# Operation Builder test
add_executable(operationBuilder_test
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/operationBuilder_test.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/operationBuilder.cpp
)
target_link_libraries(operationBuilder_test
  gtest_main base
)
gtest_discover_tests(operationBuilder_test)

# Stage Check Builder test
add_executable(stageBuilderCheck_test
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/stageBuilderCheck_test.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/stageBuilderCheck.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/operationBuilder.cpp
)
target_link_libraries(stageBuilderCheck_test
  gtest_main base logicExpression
)
gtest_discover_tests(stageBuilderCheck_test)

# Stage Map Builder test
add_executable(stageBuilderMap_test
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/stageBuilderMap_test.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/stageBuilderMap.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/operationBuilder.cpp
)
target_link_libraries(stageBuilderMap_test
  gtest_main base
)
gtest_discover_tests(stageBuilderMap_test)

# Stage Normalize Builder test
add_executable(stageBuilderNormalize_test
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/stageBuilderNormalize_test.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/stageBuilderNormalize.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/stageBuilderCheck.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/stageBuilderMap.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/operationBuilder.cpp
)
target_link_libraries(stageBuilderNormalize_test
  gtest_main base logicExpression
)
gtest_discover_tests(stageBuilderNormalize_test)

# Stage Outputs Builder test
add_executable(stageBuilderOutputs_test
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/stageBuilderOutputs_test.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/stageBuilderOutputs.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderFileOutput.cpp
)
target_link_libraries(stageBuilderOutputs_test
  gtest_main base
)
gtest_discover_tests(stageBuilderOutputs_test)

# File Output test
add_executable(fileOutput_test
  ${BUILDER_TEST_SOURCE_DIR}/outputs/fileOutput_test.cpp
)
target_link_libraries(fileOutput_test
  gtest_main base
)
gtest_discover_tests(fileOutput_test)

# Operation Builder File Output test
add_executable(opBuilderFileOutput_test
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderFileOutput_test.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderFileOutput.cpp
)
target_link_libraries(opBuilderFileOutput_test
  gtest_main base
)
gtest_discover_tests(opBuilderFileOutput_test)

# Asset test
add_executable(asset_test
  ${BUILDER_TEST_SOURCE_DIR}/asset_test.cpp
)
target_link_libraries(asset_test
  gtest_main base
)
gtest_discover_tests(asset_test)

# Environment test
add_executable(environment_test
  ${BUILDER_TEST_SOURCE_DIR}/environment_test.cpp
)
target_link_libraries(environment_test
  gtest_main base
)
gtest_discover_tests(environment_test)

add_executable(opBuilderHelperCheck_test
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/baseHelper.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderHelperFilter.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperIntEqual_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperIntNotEqual_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperIntGreaterThanEqual_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperIntGreaterThan_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperIntLessThanEqual_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperIntLessThan_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperExists_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperNotExists_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperStringEqual_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperStringNotEqual_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperStringGreaterThanEqual_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperStringGreaterThan_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperStringLessThanEqual_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperStringLessThan_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperRegexMatch_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperRegexNotMatch_test.cpp
  # ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperIPCIDRCheck_test.cpp
)
target_link_libraries(opBuilderHelperCheck_test
  gtest_main base re2
)
gtest_discover_tests(opBuilderHelperCheck_test)

add_executable(opBuilderHelperMapTest
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/baseHelper.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderHelperMap.cpp

  # ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperIntCalc_test.cpp
  # ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperStringLO_test.cpp
  # ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperStringUP_test.cpp
  # ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperStringTrim_test.cpp
  # ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperRegexExtract_test.cpp
)
target_link_libraries(opBuilderHelperMapTest
  gtest_main base re2
)
gtest_discover_tests(opBuilderHelperMapTest)

add_executable(opBuilderKVDBTest
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderKVDBExtract_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderKVDBMatch_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderKVDBNotMatch_test.cpp
)
gtest_discover_tests(opBuilderKVDBTest)

add_executable(definitions_test
  ${BUILDER_TEST_SOURCE_DIR}/definitions_test.cpp
)
gtest_discover_tests(definitions_test)

# Register test
add_executable(register_test
  ${BUILDER_TEST_SOURCE_DIR}/register_test.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/stageBuilderNormalize.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/stageBuilderCheck.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/stageBuilderMap.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/stageBuilderOutputs.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/stageBuilderParse.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/operationBuilder.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/baseHelper.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderHelperFilter.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderHelperMap.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderKVDB.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderLogqlParser.cpp
  ${BUILDER_BUILDERS_ENGINE_SOURCE_DIR}/opBuilderFileOutput.cpp
)
target_link_libraries(register_test
  gtest_main base kvdb hlp logicExpression re2
)
gtest_discover_tests(register_test)

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
  ${ENGINE_SOURCE_DIR}/wdb/src
  ${TEST_SOURCE_DIR}/base/socketInterface/testAuxiliar/
  ${TEST_SOURCE_DIR}/common/
)

# TODO do this better
link_libraries(gtest_main gtest base builders metrics defs::mocks schemf::mocks date::date store::mocks)

# ###################################################################################################
# Builder targets
# ###################################################################################################
# Expression test
add_executable(expression_test
  ${BUILDER_TEST_SOURCE_DIR}/expression_test.cpp
)
gtest_discover_tests(expression_test)

# Registry test
add_executable(registry_test
  ${BUILDER_TEST_SOURCE_DIR}/registry_test.cpp
)
gtest_discover_tests(registry_test)

# Operation Builder test
add_executable(operationBuilder_test
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/operationBuilder_test.cpp
)
gtest_discover_tests(operationBuilder_test)

# Stage Check Builder test
add_executable(stageBuilderCheck_test
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/stageBuilderCheck_test.cpp
)
gtest_discover_tests(stageBuilderCheck_test)

# Stage Map Builder test
add_executable(stageBuilderMap_test
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/stageBuilderMap_test.cpp
)
gtest_discover_tests(stageBuilderMap_test)

# Stage Normalize Builder test
add_executable(stageBuilderNormalize_test
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/stageBuilderNormalize_test.cpp
)
gtest_discover_tests(stageBuilderNormalize_test)

# Stage Outputs Builder test
add_executable(stageBuilderOutputs_test
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/stageBuilderOutputs_test.cpp
)
gtest_discover_tests(stageBuilderOutputs_test)

# Stage Parse Builder test
# add_executable(stageBuilderParse_test
#   ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/stageBuilderParse_test.cpp
# )
# gtest_discover_tests(stageBuilderParse_test)

# Operation Logpar Parser Builder test
# add_executable(opBuilderLogParser_test
#   ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderLogParser_test.cpp
# )
# gtest_discover_tests(opBuilderLogParser_test)

# File Output test
add_executable(fileOutput_test
  ${BUILDER_TEST_SOURCE_DIR}/outputs/fileOutput_test.cpp
)
gtest_discover_tests(fileOutput_test)

# Operation Builder File Output test
add_executable(opBuilderFileOutput_test
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderFileOutput_test.cpp
)
gtest_discover_tests(opBuilderFileOutput_test)

# Asset test
add_executable(asset_test
  ${BUILDER_TEST_SOURCE_DIR}/asset_test.cpp
)
gtest_discover_tests(asset_test)

# Environment test
add_executable(policy_test
  ${BUILDER_TEST_SOURCE_DIR}/policy_test.cpp
)
gtest_discover_tests(policy_test)

add_executable(baseHelper_test
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/baseHelper_test.cpp
)
gtest_discover_tests(baseHelper_test)

add_executable(opBuilderHelperCheck_test
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperExists_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperIntEqual_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperIntGreaterThan_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperIntGreaterThanEqual_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperIntLessThan_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperIntLessThanEqual_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperIntNotEqual_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperIPCIDRCheck_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperNotExists_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperNotContainsString_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperRegexMatch_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperRegexNotMatch_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperStringEqual_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperStringGreaterThan_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperStringGreaterThanEqual_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperStringLessThan_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperStringLessThanEqual_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperStringNotEqual_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperStringStarts_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperTypeCheck_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperContainsString_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperStringContains_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperMatchValue_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperMatchKey_test.cpp
)
gtest_discover_tests(opBuilderHelperCheck_test)

add_executable(opBuilderHelperMap_test
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperEraseCustomField_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperAppend_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperAppendSplitString_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperDateFromEpochTime_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperHashSHA1_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperHexToNumber_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperIntCalc_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperJsonDeleteField_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperMerge_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperMergeRecursively_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperRegexExtract_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperRenameField_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperStringConcat_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperStringFromArray_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperStringFromHexa_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperStringIPVersion_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperStringLO_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperStringReplace_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperStringTrim_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperStringUP_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperTimeEpoch_test.cpp
)
gtest_discover_tests(opBuilderHelperMap_test)

add_executable(opBuilderHelperKVDB_test
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderKVDBDelete_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderKVDBGet_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderKVDBSet_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperGetValue_test.cpp
)
gtest_discover_tests(opBuilderHelperKVDB_test)

add_executable(opBuilderWdb_test
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderWdbQuery_test.cpp
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderWdbUpdate_test.cpp
)
target_link_libraries(opBuilderWdb_test wdb::mocks)
gtest_discover_tests(opBuilderWdb_test)

add_executable(opBuilderSpeficHLP_test
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderSpeficHLP_test.cpp
)
gtest_discover_tests(opBuilderSpeficHLP_test)

add_executable(opBuilderHelperActiveResponse_test
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperActiveResponse_test.cpp
)
target_link_libraries(opBuilderHelperActiveResponse_test sockiface::mocks)
gtest_discover_tests(opBuilderHelperActiveResponse_test)

# Register test
add_executable(register_test
  ${BUILDER_TEST_SOURCE_DIR}/register_test.cpp
)
gtest_discover_tests(register_test)

add_executable(opBuilderSCAdecoder_test
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderSCAdecoder_test.cpp
)
target_link_libraries(opBuilderSCAdecoder_test sockiface::mocks wdb::mocks)
gtest_discover_tests(opBuilderSCAdecoder_test)

add_executable(opBuilderHelperNetInfoAddress_test
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperNetInfoAddress_test.cpp
)
target_link_libraries(opBuilderHelperNetInfoAddress_test wdb::mocks)
gtest_discover_tests(opBuilderHelperNetInfoAddress_test)

add_executable(opBuilderHelperUpgradeConfirmation_test
  ${BUILDER_BUILDERS_TEST_SOURCE_DIR}/opBuilderHelperUpgradeConfirmation_test.cpp
)
target_link_libraries(opBuilderHelperUpgradeConfirmation_test sockiface::mocks)
gtest_discover_tests(opBuilderHelperUpgradeConfirmation_test)

add_executable(helperParser_test
  ${BUILDER_TEST_SOURCE_DIR}/helperParser_test.cpp
)
gtest_discover_tests(helperParser_test)

get_filename_component(SRC_FOLDER ${CMAKE_SOURCE_DIR}/../../ ABSOLUTE)

if(FSANITIZE AND NOT CMAKE_SYSTEM_NAME STREQUAL "Windows")
  set(CMAKE_CXX_FLAGS_DEBUG " -g --coverage -fsanitize=address,leak,undefined")
endif()

include_directories(
    ${SRC_FOLDER}/external/googletest/googletest/include/
    ${SRC_FOLDER}/external/googletest/googlemock/include/
    ${SRC_FOLDER}/wazuh_modules/sca/sca_impl/src
    ${SRC_FOLDER}/wazuh_modules/sca/sca_impl/include
    ${SRC_FOLDER}/wazuh_modules/sca/sca_impl/tests
    ${SRC_FOLDER}/wazuh_modules/sca/sca_impl/tests/mocks
    ${SRC_FOLDER}/shared_modules/dbsync/tests/mocks
    ${SRC_FOLDER}/shared_modules/file_helper/filesystem/tests/mocks
    ${SRC_FOLDER}/shared_modules/file_helper/file_io/tests/mocks
    ${SRC_FOLDER}/shared_modules/utils/tests/mocks
    ${SRC_FOLDER}/data_provider/tests/mocks
)

link_directories(${SRC_FOLDER}/external/googletest/lib/)
link_libraries(
    debug gtestd
    debug gmockd
    debug gtest_maind
    debug gmock_maind
    optimized gtest
    optimized gmock
    optimized gtest_main
    optimized gmock_main
)

add_executable(sca_unit_test sca_test.cpp)
target_link_libraries(sca_unit_test PRIVATE SCAImpl)
add_test(NAME SCATest COMMAND sca_unit_test)

add_executable(sca_policy_loader_unit_test sca_policy_loader_test.cpp)
target_link_libraries(sca_policy_loader_unit_test PRIVATE SCAImpl)
add_test(NAME SCAPolicyLoaderTest COMMAND sca_policy_loader_unit_test)

add_executable(sca_event_handler_unit_test sca_event_handler_test.cpp)
target_link_libraries(sca_event_handler_unit_test PRIVATE SCAImpl)
add_test(NAME SCAEventHandlerTest COMMAND sca_event_handler_unit_test)

add_executable(sca_utils_unit_test sca_utils_test.cpp)
target_link_libraries(sca_utils_unit_test PRIVATE SCAImpl)
add_test(NAME SCAUtilsTest COMMAND sca_utils_unit_test)

add_executable(check_condition_evaluator_unit_test check_condition_evaluator_test.cpp)
target_link_libraries(check_condition_evaluator_unit_test PRIVATE SCAImpl)
add_test(NAME CheckConditionEvaluatorTest COMMAND check_condition_evaluator_unit_test)

add_executable(rule_creation_unit_test rule_creation_test.cpp)
target_link_libraries(rule_creation_unit_test PRIVATE SCAImpl)
add_test(NAME RuleCreationTest COMMAND rule_creation_unit_test)

add_executable(file_rule_evaluator_unit_test file_rule_evaluator_test.cpp)
target_link_libraries(file_rule_evaluator_unit_test PRIVATE SCAImpl)
add_test(NAME FileRuleEvaluatorTest COMMAND file_rule_evaluator_unit_test)

add_executable(command_rule_evaluator_unit_test command_rule_evaluator_test.cpp)
target_link_libraries(command_rule_evaluator_unit_test PRIVATE SCAImpl)
add_test(NAME CommandRuleEvaluatorTest COMMAND command_rule_evaluator_unit_test)

add_executable(directory_rule_evaluator_unit_test directory_rule_evaluator_test.cpp)
target_link_libraries(directory_rule_evaluator_unit_test PRIVATE SCAImpl)
add_test(NAME DirectoryRuleEvaluatorTest COMMAND directory_rule_evaluator_unit_test)

add_executable(process_rule_evaluator_unit_test process_rule_evaluator_test.cpp)
target_link_libraries(process_rule_evaluator_unit_test PRIVATE SCAImpl)
add_test(NAME ProcessRuleEvaluatorTest COMMAND process_rule_evaluator_unit_test)

add_executable(sca_policy_parser_unit_test sca_policy_parser_test.cpp)
target_link_libraries(sca_policy_parser_unit_test PRIVATE SCAImpl)
add_test(NAME SCAPolicyParserTest COMMAND sca_policy_parser_unit_test)

add_executable(sca_checksum_unit_test sca_checksum_test.cpp)
target_link_libraries(sca_checksum_unit_test PRIVATE SCAImpl)
add_test(NAME SCAChecksumTest COMMAND sca_checksum_unit_test)

if(WIN32)
    add_executable(registry_rule_evaluator_unit_test registry_rule_evaluator_test.cpp)
    target_link_libraries(registry_rule_evaluator_unit_test PRIVATE SCAImpl)
    add_test(NAME RegistryRuleEvaluatorTest COMMAND registry_rule_evaluator_unit_test)
endif()

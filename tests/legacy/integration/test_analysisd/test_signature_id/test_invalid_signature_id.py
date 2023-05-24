
# # ----------------------------------------TEST_INVALID_SIGNATURE_ID------------------------------------------
# # Configuration and cases data
# t2_configurations_path = os.path.join(CONFIGS_PATH, 'configuration_signature_id_values.yaml')
# t2_cases_path = os.path.join(TEST_CASES_PATH, 'cases_invalid_signature_id.yaml')

# # test_empty_signature_id configurations
# t2_configuration_parameters, t2_configuration_metadata, t2_case_ids = get_test_cases_data(t2_cases_path)
# t2_configurations = load_configuration_template(t2_configurations_path, t2_configuration_parameters,
#                                                 t2_configuration_metadata)


# @pytest.mark.tier(level=1)
# @pytest.mark.parametrize('configuration, metadata', zip(t2_configurations, t2_configuration_metadata), ids=t2_case_ids)
# def test_invalid_signature_id(configuration, metadata, set_wazuh_configuration, truncate_monitored_files,
#                               prepare_custom_rules_file, restart_wazuh_function):
#     '''
#     description: Check that when a rule has an empty or invalid signature ID value (invalid format) assigned to the
#                  if_sid option, the rule is ignored.

#     test_phases:
#         - Setup:
#             - Set wazuh configuration.
#             - Copy custom rules file into manager
#             - Clean logs files and restart wazuh to apply the configuration.
#         - Test:
#             - Check "invalid if_sid" log is detected
#         - Tierdown:
#             - Delete custom rule file
#             - Restore configuration
#             - Stop wazuh


#     wazuh_min_version: 4.4.0

#     tier: 1

#     parameters:
#         - configuration:
#             type: dict
#             brief: Configuration loaded from `configuration_template`.
#         - metadata:
#             type: dict
#             brief: Test case metadata.
#         - set_wazuh_configuration:
#             type: fixture
#             brief: Set wazuh configuration.
#         - truncate_monitored_files:
#             type: fixture
#             brief: Truncate all the log files and json alerts files before and after the test execution.
#         - prepare_custom_rules_file:
#             type: fixture
#             brief: Copies custom rules_file before test, deletes after test.
#         - restart_wazuh_function:
#             type: fixture
#             brief: Restart wazuh at the start of the module to apply configuration.

#     assertions:
#         - Check that wazuh starts
#         - Check ".*wazuh-testrule.*Empty 'if_sid' value. Rule '(\\d*)' will be ignored.*"

#     input_description:
#         - The `configuration_signature_id_values.yaml` file provides the module configuration for
#           this test.
#         - The `cases_empty_signature_id.yaml` file provides the test cases.
#     '''

#     wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

#     # Check that expected log appears for rules if_sid field being invalid
#     ev.check_invalid_if_sid(wazuh_log_monitor, metadata['is_empty'])

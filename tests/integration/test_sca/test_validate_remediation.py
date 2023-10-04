'''
copyright: Copyright (C) 2015-2023, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests will that a scan is ran using the configured sci_sca ruleset and regex engine.

components:
    - sca

suite: sca

targets:
    - manager
    - agent

daemons:
    - wazuh-modulesd

os_platform:
    - linux

os_version:
    - CentOS 8

references:
    - https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/index.html

tags:
    - sca
'''
import os
import pytest

from wazuh_testing import LOG_FILE_PATH
from wazuh_testing.tools.configuration import load_configuration_template, get_test_cases_data
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.modules.sca import event_monitor as evm
from wazuh_testing.modules.sca import SCA_DEFAULT_LOCAL_INTERNAL_OPTIONS as local_internal_options


pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0)]

# Reference paths
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
CONFIGURATIONS_PATH = os.path.join(TEST_DATA_PATH, 'configuration_template')
TEST_CASES_PATH = os.path.join(TEST_DATA_PATH, 'test_cases')

# Configuration and cases data
configurations_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_sca.yaml')
cases_path = os.path.join(TEST_CASES_PATH, 'cases_validate_remediation.yaml')

# Test configurations
configuration_parameters, configuration_metadata, case_ids = get_test_cases_data(cases_path)
configurations = load_configuration_template(configurations_path, configuration_parameters, configuration_metadata)
test_folder = '/testfile'


# Tests
@pytest.mark.parametrize('configuration, metadata', zip(configurations, configuration_metadata), ids=case_ids)
def test_validate_remediation_results(configuration, metadata, prepare_cis_policies_file, truncate_monitored_files,
                                      prepare_test_folder, set_wazuh_configuration,
                                      configure_local_internal_options_function, restart_wazuh_function,
                                      wait_for_sca_enabled):
    '''
    description: This test will check that a SCA scan results, with the  expected initial results (passed/failed) for a
                 given check, results change on subsequent checks if change is done to the system. For this a folder's
                 permissions will be checked, passing or failing if the permissions match. Then, the permissions for
                 the folder will be changed and wait for a new scan, and validate the results changed as expected.

    test_phases:
        - Copy cis_sca ruleset file into agent
        - Create a folder that will be checked by the SCA rules
        - Restart wazuh
        - Validate the result for a given SCA check are as expected
        - Change the folder's permissions
        - Validate the result for a given SCA check change as expected

    wazuh_min_version: 4.6.0

    tier: 0

    parameters:
        - configuration:
            type: dict
            brief: Wazuh configuration data. Needed for set_wazuh_configuration fixture.
        - metadata:
            type: dict
            brief: Wazuh configuration metadata.
        - prepare_cis_policies_file:
            type: fixture
            brief: copy test sca policy file. Delete it after test.
        - prepare_test_folder:
            type: fixture
            brief: Create a folder with a given set of permissions. Delete it after test.
        - set_wazuh_configuration:
            type: fixture
            brief: Set the wazuh configuration according to the configuration data.
        - configure_local_internal_options_function:
            type: fixture
            brief: Configure the local_internal_options_file.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate all the log files and json alerts files before and after the test execution.
        - restart_modulesd_function:
            type: fixture
            brief: Restart the wazuh-modulesd daemon.
        - wait_for_sca_enabled:
            type: fixture
            brief: Wait for the sca Module to start before starting the test.

    assertions:
        - Assert the result for a given check passed/failed as expected
        - Assert the result for a given check changes as expected after remediation/breaking commands

    input_description:
        - The `cases_validate_remediation.yaml` file provides the module configuration for this test.
        - The cis*.yaml files located in the policies folder provide the sca rules to check.

    expected_output:
        - r".*sca.*wm_sca_hash_integrity.*DEBUG: ID: (\\d+); Result: '(.*)'"
    '''

    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)

    # Get the results for the checks obtained in the initial SCA scan
    results = evm.get_sca_scan_rule_id_results(file_monitor=wazuh_log_monitor, results_num=2)

    # Assert the tested check has initial expected results (failed/passed)
    check_result = results[metadata['check_id']-1][1]
    assert check_result == metadata['initial_result'], f"Got unexcepted SCA result: {metadata['initial_result']},\
                                                         got {check_result}"
    # Modify the folder's permissions
    os.chmod(test_folder, metadata['perms'])

    # Get the results for the checks obtained in the SCA scan
    results = evm.get_sca_scan_rule_id_results(file_monitor=wazuh_log_monitor, results_num=2)

    # Assert the tested check result changed as expected (passed to failed, and vice-versa)
    check_result = results[metadata['check_id']-1][1]
    assert check_result == metadata['final_result'], f"Got unexcepted SCA result: {metadata['initial_result']},\
                                                       got {check_result}"

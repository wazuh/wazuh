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

from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.utils import callbacks, configuration
from wazuh_testing.tools.monitors import file_monitor
from wazuh_testing.modules.sca import patterns
from wazuh_testing.modules.modulesd.configuration import MODULESD_DEBUG


pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0)]

# Reference paths
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
CONFIGURATIONS_PATH = os.path.join(TEST_DATA_PATH, 'configuration_template')
TEST_CASES_PATH = os.path.join(TEST_DATA_PATH, 'test_cases')

local_internal_options = {MODULESD_DEBUG: '2'}

# Configuration and cases data
configurations_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_sca.yaml')
cases_path = os.path.join(TEST_CASES_PATH, 'cases_scan_results.yaml')

# Test configurations
configuration_parameters, configuration_metadata, case_ids = configuration.get_test_cases_data(cases_path)
configurations = configuration.load_configuration_template(configurations_path, configuration_parameters, configuration_metadata)

# Test daemons to restart.
daemons_handler_configuration = {'all_daemons': True}


# Tests
@pytest.mark.parametrize('test_configuration, test_metadata', zip(configurations, configuration_metadata), ids=case_ids)
def test_sca_scan_results(test_configuration, test_metadata, prepare_cis_policies_file, truncate_monitored_files,
                          set_wazuh_configuration, configure_local_internal_options, daemons_handler,
                          wait_for_sca_enabled):
    '''
    description: This test will check that a SCA scan is correctly executed on an agent, with a given policy file and
                 a regex engine. For this it will copy a policy file located in the data folder and verify the engine
                 used, the amount of results found, and that the results come from the policy file.

    test_phases:
        - Copy cis_sca ruleset file into agent.
        - Restart wazuh.
        - Check in the log that the sca module started appears.
        - Check the regex engine used by the policy.
        - Get the result for each ID check
        - Check that the policy_id from the scan matches with the file used.

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
        - Verify that when the `enabled` option is set to `yes`, the SCA module is enabled.
        - Assert the engine used matches the regex_type configured in the metadata
        - Assert the scan gets results from each rule check

    input_description:
        - The `cases_scan_results.yaml` file provides the module configuration for this test.
        - The cis*.yaml files located in the policies folder provide the sca rules to check.

    expected_output:
        - r'.*sca.*INFO: (Module started.)'
        - r'.*sca.*INFO: (Starting Security Configuration Assessment scan).'
        - r".*sca.*DEBUG: SCA will use '(.*)' engine to check the rules."
        - r".*sca.*wm_sca_hash_integrity.*DEBUG: ID: (\\d+); Result: '(.*)'"
        - r'.*sca_send_alert.*Sending event: (.*)'
    '''

    log_monitor = file_monitor.FileMonitor(WAZUH_LOG_PATH)

    # Wait for the end of SCA scan
    log_monitor.start(callback=callbacks.generate_callback(patterns.CB_SCA_SCAN_STARTED), timeout=10)
    assert log_monitor.callback_result

    # Check the regex engine used by SCA
    log_monitor.start(callback=callbacks.generate_callback(patterns.CB_SCA_OSREGEX_ENGINE), timeout=10)
    engine = log_monitor.callback_result[0] if log_monitor.callback_result != None else None

    assert engine == test_metadata['regex_type'], \
        f"Wrong regex-engine found: {engine}, expected: {test_metadata['regex_type']}"

    # Check all checks have been done
    log_monitor.start(callback=patterns.callback_scan_id_result, timeout=20, accumulations=int(test_metadata['results']))

    # # Get scan summary event and check it matches with the policy file used
    log_monitor.start(callback=patterns.callback_detect_sca_scan_summary, timeout=20)
    summary = log_monitor.callback_result

    assert summary['policy_id'] == test_metadata['policy_file'][0:-5], f"Unexpected policy_id found. Got \
                                                                    {summary['policy_id']}, expected \
                                                                    {test_metadata['policy_file'][0:-5]}"

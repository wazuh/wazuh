'''
copyright: Copyright (C) 2015-2023, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests will check if the `enabled` option of the SCA module
       is working correctly. This option is located in its corresponding section of
       the `ossec.conf` file and allows enabling or disabling this module.

components:
    - sca

targets:
    - manager
    - agent
daemons:
    - wazuh-modulesd

os_platform:
    - linux

os_version:
    - Arch Linux
    - Amazon Linux 2
    - Amazon Linux 1
    - CentOS 8
    - CentOS 7
    - Debian Buster
    - Red Hat 8
    - Ubuntu Focal
    - Ubuntu Bionic

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

# ---------------------------------------------------- TEST_ENABLED ---------------------------------------------------
# Test configurations
t1_cases_path = os.path.join(TEST_CASES_PATH, 'cases_sca_enabled.yaml')
t1_configuration_parameters, t1_configuration_metadata, t1_case_ids = get_test_cases_data(t1_cases_path)
t1_configurations = load_configuration_template(configurations_path, t1_configuration_parameters,
                                                t1_configuration_metadata)

# ---------------------------------------------------- TEST_DISABLED --------------------------------------------------
# Test configurations
t2_cases_path = os.path.join(TEST_CASES_PATH, 'cases_sca_disabled.yaml')
t2_configuration_parameters, t2_configuration_metadata, t2_case_ids = get_test_cases_data(t2_cases_path)
t2_configurations = load_configuration_template(configurations_path, t2_configuration_parameters,
                                                t2_configuration_metadata)


@pytest.mark.parametrize('configuration, metadata', zip(t1_configurations, t1_configuration_metadata), ids=t1_case_ids)
def test_sca_enabled(configuration, metadata, prepare_cis_policies_file, truncate_monitored_files,
                     set_wazuh_configuration, configure_local_internal_options_function, restart_wazuh_function):
    '''
    description: Check SCA behavior when enabled tag is set to yes.

    test_phases:
        - Set a custom Wazuh configuration.
        - Copy cis_sca ruleset file into agent.
        - Restart wazuh.
        - Check that sca module starts if enabled is set to 'yes'
        - Check in the log that the sca module started appears.
        - Check that sca scan starts and finishes

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
        - Verify the sca scan starts.
        - Verify the sca scan ends.

    input_description:
        - The `cases_sca_enabled.yaml` file provides the module configuration for this test.
        - the cis*.yaml files located in the policies folder provide the sca rules to check.

    expected_output:
        - r'.*sca.*INFO: (Module started.)'
        - r'.*sca.*INFO: (Starting Security Configuration Assessment scan).'
        - r".*sca.*INFO: Security Configuration Assessment scan finished. Duration: (\\d+) seconds."
    '''
    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
    evm.check_sca_enabled(wazuh_log_monitor)
    evm.check_sca_scan_started(wazuh_log_monitor)
    evm.check_sca_scan_ended(wazuh_log_monitor)


@pytest.mark.parametrize('configuration, metadata', zip(t2_configurations, t2_configuration_metadata), ids=t2_case_ids)
def test_sca_disabled(configuration, metadata, prepare_cis_policies_file, truncate_monitored_files,
                      set_wazuh_configuration, configure_local_internal_options_function, restart_wazuh_function):
    '''
    description: Check SCA behavior when enabled tag is set no.

    test_phases:
        - Set a custom Wazuh configuration.
        - Copy cis_sca ruleset file into agent.
        - Restart wazuh.
        - Check that sca module is disabled if enabled tag is set to 'no'

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
        - Verify that when the `enabled` option is set to `no`, the SCA module does not start.

    input_description:
        - The `cases_sca_disabled.yaml` file provides the module configuration for this test.
        - the cis*.yaml files located in the policies folder provide the sca rules to check.

    expected_output:
        - r".*sca.*INFO: (Module disabled). Exiting."
    '''

    wazuh_log_monitor = FileMonitor(LOG_FILE_PATH)
    evm.check_sca_disabled(wazuh_log_monitor)

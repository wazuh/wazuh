'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests will check if the `enabled` option of the SCA module
       is working correctly. This option is located in its corresponding section of
       the `ossec.conf` file and allows enabling or disabling this module.

components:
    - sca

targets:
    - agent

daemons:
    - wazuh-modulesd

os_platform:
    - linux
    - windows

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
    - Windows 10
    - Windows Server 2019
    - Windows Server 2016

references:
    - https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/index.html

tags:
    - sca
'''
import sys
import pytest
from pathlib import Path

from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.utils import callbacks, configuration
from wazuh_testing.tools.monitors import file_monitor
from wazuh_testing.modules.modulesd.sca import patterns
from wazuh_testing.modules.modulesd.configuration import MODULESD_DEBUG
from wazuh_testing.modules.agentd.configuration import AGENTD_WINDOWS_DEBUG
from wazuh_testing.constants.platforms import WINDOWS

from . import CONFIGURATIONS_FOLDER_PATH, TEST_CASES_FOLDER_PATH


pytestmark = [pytest.mark.agent, pytest.mark.linux, pytest.mark.win32, pytest.mark.tier(level=0)]

local_internal_options = {AGENTD_WINDOWS_DEBUG if sys.platform == WINDOWS else MODULESD_DEBUG: '2'}

# Configuration and cases data
configurations_path = Path(CONFIGURATIONS_FOLDER_PATH, 'configuration_sca.yaml')

# ---------------------------------------------------- TEST_ENABLED ---------------------------------------------------
# Test configurations
t1_cases_path = Path(TEST_CASES_FOLDER_PATH, 'cases_sca_enabled.yaml')
t1_configuration_parameters, t1_configuration_metadata, t1_case_ids = configuration.get_test_cases_data(t1_cases_path)
t1_configurations = configuration.load_configuration_template(configurations_path, t1_configuration_parameters,
                                                t1_configuration_metadata)

# ---------------------------------------------------- TEST_DISABLED --------------------------------------------------
# Test configurations
t2_cases_path = Path(TEST_CASES_FOLDER_PATH, 'cases_sca_disabled.yaml')
t2_configuration_parameters, t2_configuration_metadata, t2_case_ids = configuration.get_test_cases_data(t2_cases_path)
t2_configurations = configuration.load_configuration_template(configurations_path, t2_configuration_parameters,
                                                t2_configuration_metadata)

# Test daemons to restart.
daemons_handler_configuration = {'all_daemons': True}


@pytest.mark.parametrize('test_configuration, test_metadata', zip(t1_configurations, t1_configuration_metadata), ids=t1_case_ids)
def test_sca_enabled(test_configuration, test_metadata, prepare_cis_policies_file, truncate_monitored_files,
                     set_wazuh_configuration, configure_local_internal_options, daemons_handler):
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
        - test_configuration:
            type: dict
            brief: Wazuh configuration data. Needed for set_wazuh_configuration fixture.
        - test_metadata:
            type: dict
            brief: Wazuh configuration metadata.
        - prepare_cis_policies_file:
            type: fixture
            brief: copy test sca policy file. Delete it after test.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate all the log files and json alerts files before and after the test execution.
        - set_wazuh_configuration:
            type: fixture
            brief: Set the wazuh configuration according to the configuration data.
        - configure_local_internal_options:
            type: fixture
            brief: Configure the local_internal_options_file.
        - daemons_handler:
            type: fixture
            brief: Handler of Wazuh daemons.

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
    log_monitor = file_monitor.FileMonitor(WAZUH_LOG_PATH)

    log_monitor.start(callback=callbacks.generate_callback(patterns.CB_SCA_ENABLED), timeout=60 if sys.platform == WINDOWS else 10)
    assert log_monitor.callback_result
    log_monitor.start(callback=callbacks.generate_callback(patterns.CB_SCA_SCAN_STARTED), timeout=10)
    assert log_monitor.callback_result
    log_monitor.start(callback=callbacks.generate_callback(patterns.CB_SCA_SCAN_ENDED), timeout=30)
    assert log_monitor.callback_result


@pytest.mark.parametrize('test_configuration, test_metadata', zip(t2_configurations, t2_configuration_metadata), ids=t2_case_ids)
def test_sca_disabled(test_configuration, test_metadata, prepare_cis_policies_file, truncate_monitored_files,
                      set_wazuh_configuration, configure_local_internal_options, daemons_handler):
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
        - test_configuration:
            type: dict
            brief: Wazuh configuration data. Needed for set_wazuh_configuration fixture.
        - test_metadata:
            type: dict
            brief: Wazuh configuration metadata.
        - prepare_cis_policies_file:
            type: fixture
            brief: copy test sca policy file. Delete it after test.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate all the log files and json alerts files before and after the test execution.
        - set_wazuh_configuration:
            type: fixture
            brief: Set the wazuh configuration according to the configuration data.
        - configure_local_internal_options:
            type: fixture
            brief: Configure the local_internal_options_file.
        - daemons_handler:
            type: fixture
            brief: Handler of Wazuh daemons.

    assertions:
        - Verify that when the `enabled` option is set to `no`, the SCA module does not start.

    input_description:
        - The `cases_sca_disabled.yaml` file provides the module configuration for this test.
        - the cis*.yaml files located in the policies folder provide the sca rules to check.

    expected_output:
        - r".*sca.*INFO: (Module disabled). Exiting."
    '''

    log_monitor = file_monitor.FileMonitor(WAZUH_LOG_PATH)

    log_monitor.start(callback=callbacks.generate_callback(patterns.CB_SCA_DISABLED), timeout=10)
    assert log_monitor.callback_result

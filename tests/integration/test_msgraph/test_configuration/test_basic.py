'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: The Wazuh 'ms-graph' module is capable of communicating with Microsoft Graph & parsing its various
       logging sources, with an emphasis on the security resource. This includes a full set of rules for
       categorizing these logs, alongside a standardized suite of configuration options that mirror other
       modules, such as Azure, GCP, and Office365.

components:
    - ms-graph

suite: configuration

targets:
    - agent

daemons:
    - wazuh-analysisd
    - wazuh-monitord
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

tags:
    - ms-graph_configuration
'''
import pytest
from pathlib import Path

from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.modules.modulesd.configuration import MODULESD_DEBUG
from wazuh_testing.modules.modulesd import patterns
from wazuh_testing.tools.monitors.file_monitor import FileMonitor
from wazuh_testing.utils.configuration import get_test_cases_data
from wazuh_testing.utils.configuration import load_configuration_template
from wazuh_testing.utils import callbacks
from . import CONFIGS_PATH, TEST_CASES_PATH

# Marks
pytestmark = [pytest.mark.agent, pytest.mark.linux, pytest.mark.tier(level=0)]

# Configuration and cases data.
configs_path = Path(CONFIGS_PATH, 'config_basic.yaml')

# ---------------------------------------------------- TEST_ENABLED ---------------------------------------------------
# Test configurations
t1_cases_path = Path(TEST_CASES_PATH, 'cases_enabled.yaml')
t1_configuration_parameters, t1_configuration_metadata, t1_case_ids = get_test_cases_data(t1_cases_path)
t1_configurations = load_configuration_template(configs_path, t1_configuration_parameters,
                                                t1_configuration_metadata)

# ---------------------------------------------------- TEST_DISABLED --------------------------------------------------
# Test configurations
t2_cases_path = Path(TEST_CASES_PATH, 'cases_disabled.yaml')
t2_configuration_parameters, t2_configuration_metadata, t2_case_ids = get_test_cases_data(t2_cases_path)
t2_configurations = load_configuration_template(configs_path, t2_configuration_parameters,
                                                t2_configuration_metadata)

# Test configurations.
daemons_handler_configuration = {'all_daemons': True, 'ignore_errors': True}
local_internal_options = {MODULESD_DEBUG: '2'}

# Tests
@pytest.mark.parametrize('test_configuration, test_metadata', zip(t1_configurations, t1_configuration_metadata), ids=t1_case_ids)
def test_enabled(test_configuration, test_metadata, set_wazuh_configuration, configure_local_internal_options,
                 truncate_monitored_files, daemons_handler, wait_for_msgraph_start):
    '''
    description: Check 'ms-graph' behavior when enabled tag is set to yes and if run_on_start is enabled or not.
    wazuh_min_version: 4.6.0

    tier: 0

    parameters:
        - test_configuration:
            type: data
            brief: Configuration used in the test.
        - test_metadata:
            type: data
            brief: Configuration cases.
        - set_wazuh_configuration:
            type: fixture
            brief: Configure a custom environment for testing.
        - configure_local_internal_options:
            type: fixture
            brief: Set internal configuration for testing.
        - truncate_monitored_files:
            type: fixture
            brief: Reset the 'ossec.log' file and start a new monitor.
        - daemons_handler:
            type: fixture
            brief: Manages daemons to reset Wazuh.
        - wait_for_msgraph_start:
            type: fixture
            brief: Checks integration start message does not appear.

    assertions:
        - Verify that when the `enabled` option is set to `yes`, the ms-graph module is enabled.
        - Verify that when the `run_on_start` option is set to `yes`, the ms-graph module is started.
        - Verify that when the `run_on_start` option is set to `no`, the ms-graph module start is delayed.

    input_description: A configuration template is contained in an external YAML file
                       (config_basic.yaml). That template is combined with different test cases defined in
                       the module. Those include configuration settings for the 'ms-graph' module.

    expected_output:
        - r'.*wazuh-modulesd:ms-graph.*INFO: Started module'
    '''

    wazuh_log_monitor = FileMonitor(WAZUH_LOG_PATH)

    wazuh_log_monitor.start(callback=callbacks.generate_callback(r".*wazuh-modulesd:ms-graph.*INFO: Started module"))
    assert (wazuh_log_monitor.callback_result != None), f'Error module enabled event not detected'

    wazuh_log_monitor.start(callback=callbacks.generate_callback(r".*wazuh-modulesd:ms-graph.*{msg}", {
                              'msg': str(test_metadata['msg'])}))
    assert (wazuh_log_monitor.callback_result != None), f'Error module started or delayed event not detected'


@pytest.mark.parametrize('test_configuration, test_metadata', zip(t2_configurations, t2_configuration_metadata), ids=t2_case_ids)
def test_disabled(test_configuration, test_metadata, set_wazuh_configuration, configure_local_internal_options,
                 truncate_monitored_files, daemons_handler, wait_for_msgraph_start):
    '''
    description: Check 'ms-graph' behavior when enabled tag is set to no.
    wazuh_min_version: 4.6.0

    tier: 0

    parameters:
        - test_configuration:
            type: data
            brief: Configuration used in the test.
        - test_metadata:
            type: data
            brief: Configuration cases.
        - set_wazuh_configuration:
            type: fixture
            brief: Configure a custom environment for testing.
        - configure_local_internal_options:
            type: fixture
            brief: Set internal configuration for testing.
        - truncate_monitored_files:
            type: fixture
            brief: Reset the 'ossec.log' file and start a new monitor.
        - daemons_handler:
            type: fixture
            brief: Manages daemons to reset Wazuh.
        - wait_for_msgraph_start:
            type: fixture
            brief: Checks integration start message does not appear.

    assertions:
        - Verify that when the `enabled` option is set to `no`, the ms-graph module does not start.

    input_description: A configuration template is contained in an external YAML file
                       (config_basic.yaml). That template is combined with a test case defined in
                       the module. This include configuration settings for the 'ms-graph' module.

    expected_output:
        - r'.*wazuh-modulesd:ms-graph.*INFO: (Module disabled). Exiting.'
    '''

    wazuh_log_monitor = FileMonitor(WAZUH_LOG_PATH)
    wazuh_log_monitor.start(callback=callbacks.generate_callback(r".*wazuh-modulesd:ms-graph.*INFO: (Module disabled). Exiting."))

    assert (wazuh_log_monitor.callback_result != None), f'Error module disabled event not detected'

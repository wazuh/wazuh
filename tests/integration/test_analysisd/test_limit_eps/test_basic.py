'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: The 'wazuh-analysisd' daemon uses a series of decoders and rules to analyze and interpret logs and events and
       generate alerts when the decoded information matches the established rules. There is a feature to limit the
       number of events that the manager can process, in order to allow the correct functioning of the daemon. These
       tests check if this feature is enabled/disabled when desired.

components:
    - analysisd

suite: analysisd

targets:
    - manager

daemons:
    - wazuh-analysisd

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
    - https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html#if-sid
'''
import pytest

from pathlib import Path

from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.modules.analysisd import patterns
from wazuh_testing.tools.monitors import file_monitor
from wazuh_testing.utils import configuration, callbacks

from . import CONFIGS_PATH, TEST_CASES_PATH


pytestmark = [pytest.mark.server, pytest.mark.tier(level=0)]

# Configuration and cases data.
test_configs_path = Path(CONFIGS_PATH, 'basic_test_module', 'configuration_enabled.yaml')
test_cases_path = Path(TEST_CASES_PATH, 'basic_test_module', 'cases_enabled.yaml')

test2_configs_path = Path(CONFIGS_PATH, 'basic_test_module', 'configuration_disabled.yaml')
test2_cases_path = Path(TEST_CASES_PATH, 'basic_test_module', 'cases_disabled.yaml')

# Test configurations.
test_configuration, test_metadata, test_cases_ids = configuration.get_test_cases_data(test_cases_path)
test_configuration = configuration.load_configuration_template(test_configs_path, test_configuration, test_metadata)

test2_configuration, test2_metadata, test2_cases_ids = configuration.get_test_cases_data(test2_cases_path)
test2_configuration = configuration.load_configuration_template(test2_configs_path, test2_configuration, test2_metadata)

# Test daemons to restart.
daemons_handler_configuration = {'all_daemons': True}


# Test function.
@pytest.mark.parametrize('test_configuration, test_metadata', zip(test_configuration, test_metadata), ids=test_cases_ids)
def test_enabled(test_configuration, test_metadata, load_wazuh_basic_configuration, set_wazuh_configuration,
                 truncate_monitored_files, daemons_handler):
    """
    description: Check whether the event analysis limitation is activated after its activation in the configuration.

    test_phases:
        - setup:
            - Load Wazuh light configuration.
            - Apply ossec.conf configuration changes according to the configuration template and use case.
            - Truncate wazuh logs.
            - Restart wazuh-manager service to apply configuration changes.
        - test:
            - Check in the ossec.log that a line has appeared indicating that EPS limiting has been enabled.
            - Check that wazuh-analysisd is running (it has not been crashed).
        - teardown:
            - Truncate wazuh logs.
            - Restore initial configuration.

    wazuh_min_version: 4.4.0

    parameters:
        - test_configuration:
            type: dict
            brief: Configuration loaded from `configuration_templates`.
        - test_metadata:
            type: dict
            brief: Test case metadata.
        - load_wazuh_basic_configuration:
            type: fixture
            brief: Load basic wazuh configuration.
        - set_wazuh_configuration:
            type: fixture
            brief: Apply changes to the ossec.conf configuration.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate wazuh logs.
        - daemons_handler:
            type: fixture
            brief: Handler of Wazuh daemons.

    assertions:
        - Check in the log that the EPS limitation has been activated.

    input_description:
        - The `configuration_enabled` file provides the module configuration for this test.
        - The `cases_enabled` file provides the test cases.
    """
    # Start monitor
    monitor_enabled = file_monitor.FileMonitor(WAZUH_LOG_PATH)
    monitor_enabled.start(callback=callbacks.generate_callback(patterns.ANALYSISD_EPS_ENABLED, {
                              'maximum': str(test_metadata['maximum']),
                              'timeframe': str(test_metadata['timeframe'])
                          }))

    # Check that expected log appears for rules if_sid field being invalid
    assert monitor_enabled.callback_result


@pytest.mark.parametrize('test_configuration, test_metadata', zip(test2_configuration, test2_metadata), ids=test2_cases_ids)
def test_disabled(test_configuration, test_metadata, load_wazuh_basic_configuration, set_wazuh_configuration,
                 truncate_monitored_files, daemons_handler):
    """
    description: Check if when the EPS limitation setting is not applied, the feature is not activated.

    test_phases:
        - setup:
            - Load Wazuh light configuration.
            - Apply ossec.conf configuration changes according to the configuration template and use case.
            - Truncate wazuh logs.
            - Restart wazuh-manager service to apply configuration changes.
        - test:
            - Look in the ossec.log to see if the EPS limitation activation does not appear.
            - Check that wazuh-analysisd is running (it has not been crashed).
        - teardown:
            - Truncate wazuh logs.
            - Restore initial configuration.

    wazuh_min_version: 4.4.0

    parameters:
        - test_configuration:
            type: dict
            brief: Configuration loaded from `configuration_templates`.
        - test_metadata:
            type: dict
            brief: Test case metadata.
        - load_wazuh_basic_configuration:
            type: fixture
            brief: Load basic wazuh configuration.
        - set_wazuh_configuration:
            type: fixture
            brief: Apply changes to the ossec.conf configuration.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate wazuh logs.
        - daemons_handler:
            type: fixture
            brief: Handler of Wazuh daemons.

    assertions:
        - Check in the ossec.log to see if the EPS limitation activation does not appear.

    input_description:
        - The `configuration_disabled` file provides the module configuration for this test.
        - The `cases_disabled` file provides the test cases.
    """
    # Start monitor
    monitor_disabled = file_monitor.FileMonitor(WAZUH_LOG_PATH)
    monitor_disabled.start(callback=callbacks.generate_callback(patterns.ANALYSISD_EPS_DISABLED))

    # Check that expected log appears for rules if_sid field being invalid
    assert monitor_disabled.callback_result

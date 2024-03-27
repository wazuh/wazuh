'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: The 'wazuh-analysisd' daemon uses a series of decoders and rules to analyze and interpret logs and events and
       generate alerts when the decoded information matches the established rules. There is a feature to limit the
       number of events that the manager can process, in order to allow the correct functioning of the daemon. These
       tests check different configuration values for this feature.

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
test_configs_path = Path(CONFIGS_PATH, 'configuration_test_module', 'configuration_accepted_values.yaml')
test_cases_path = Path(TEST_CASES_PATH, 'configuration_test_module', 'cases_accepted_values.yaml')

test2_configs_path = Path(CONFIGS_PATH, 'configuration_test_module', 'configuration_invalid_values.yaml')
test2_cases_path = Path(TEST_CASES_PATH, 'configuration_test_module', 'cases_invalid_values.yaml')

test3_configs_path = Path(CONFIGS_PATH, 'configuration_test_module', 'configuration_missing_configuration.yaml')
test3_cases_path = Path(TEST_CASES_PATH, 'configuration_test_module', 'cases_missing_configuration.yaml')

# Test configurations.
test_configuration, test_metadata, test_cases_ids = configuration.get_test_cases_data(test_cases_path)
test_configuration = configuration.load_configuration_template(test_configs_path, test_configuration, test_metadata)

test2_configuration, test2_metadata, test2_cases_ids = configuration.get_test_cases_data(test2_cases_path)
test2_configuration = configuration.load_configuration_template(test2_configs_path, test2_configuration, test2_metadata)

test3_configuration, test3_metadata, test3_cases_ids = configuration.get_test_cases_data(test3_cases_path)
test3_configuration = configuration.load_configuration_template(test3_configs_path, test3_configuration, test3_metadata)

# Test daemons to restart.
daemons_handler_configuration = {'all_daemons': True, 'ignore_errors': True}


# Test function.
@pytest.mark.parametrize('test_configuration, test_metadata', zip(test_configuration, test_metadata), ids=test_cases_ids)
def test_accepted_values(test_configuration, test_metadata, load_wazuh_basic_configuration, set_wazuh_configuration,
                         truncate_monitored_files, daemons_handler):
    """
    description: Check that the EPS limitation is activated under accepted parameters.

    test_phases:
        - setup:
            - Load Wazuh light configuration.
            - Apply ossec.conf configuration changes according to the configuration template and use case.
            - Truncate wazuh logs.
            - Restart wazuh-manager service to apply configuration changes.
        - test:
            - Check in the log that the EPS limitation has been activated with the specified parameters.
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
        - Check in the log that the EPS limitation has been activated with the specified parameters.

    input_description:
        - The `configuration_accepted_values` file provides the module configuration for this test.
        - The `cases_accepted_values` file provides the test cases.
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
def test_invalid_values(test_configuration, test_metadata, load_wazuh_basic_configuration, set_wazuh_configuration,
                        truncate_monitored_files, daemons_handler):
    """
    description: Check for configuration error and wazuh-analysisd if the EPS limiting configuration has unaccepted
        values. Done for the following cases:
            - Maximum value above the allowed value.
            - Timeframe value above the allowed value.
            - Timeframe = 0
            - Maximum, timeframe = 0

    test_phases:
        - setup:
            - Load Wazuh light configuration.
            - Apply ossec.conf configuration changes according to the configuration template and use case.
            - Truncate wazuh logs.
        - test:
            - Restart wazuh-manager service to apply configuration changes.
            - Check that a configuration error is raised when trying to start wazuh-manager.
            - Check that wazuh-analysisd is not running (due to configuration error).
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
        - Check that a configuration error is raised when trying to start wazuh-manager.

    input_description:
        - The `configuration_invalid_values` file provides the module configuration for this test.
        - The `cases_invalid_values` file provides the test cases.
    """
    # Start monitor
    monitor_error = file_monitor.FileMonitor(WAZUH_LOG_PATH)
    monitor_error.start(callback=callbacks.generate_callback(patterns.ANALYSISD_CONFIGURATION_ERROR))

    # Check that expected log appears for rules if_sid field being invalid
    assert monitor_error.callback_result


@pytest.mark.parametrize('test_configuration, test_metadata', zip(test3_configuration, test3_metadata), ids=test3_cases_ids)
def test_missing_configuration(test_configuration, test_metadata, load_wazuh_basic_configuration, set_wazuh_configuration,
                               truncate_monitored_files, configure_remove_tags, daemons_handler):
    """
    description: Checks what happens if tags are missing in the event analysis limitation settings. Done for the
        following cases:
            - Missing <timeframe>.
            - Missing <maximum>.
            - Missing <timeframe> and <maximum>.

    test_phases:
        - setup:
            - Load Wazuh light configuration.
            - Apply ossec.conf configuration changes according to the configuration template and use case.
            - Truncate wazuh logs.
        - test:
            - Remove the specified tag in ossec.conf
            - Restart wazuh-manager service to apply configuration changes.
            - Check whether the EPS limitation is activated, deactivated or generates a configuration error due to a
              missing label.
            - Check if wazuh-analysisd is running or not (according to the expected behavior).
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
        - configure_remove_tags:
            type: fixture
            brief: Remove section from ossec.conf.
        - daemons_handler:
            type: fixture
            brief: Handler of Wazuh daemons.

    assertions:
        - Check whether the EPS limitation is activated, deactivated or generates a configuration error due to a
            missing label.

    input_description:
        - The `configuration_missing_values` file provides the module configuration for this test.
        - The `cases_missing_values` file provides the test cases.
    """
    log_monitor = file_monitor.FileMonitor(WAZUH_LOG_PATH)
    if test_metadata['behavior'] == 'works':
        # Start monitor
        log_monitor.start(callback=callbacks.generate_callback(patterns.ANALYSISD_EPS_ENABLED, {
                                'maximum': str(test_metadata['maximum']),
                                'timeframe': str(10)
                            }))

        # Check that expected log appears for rules if_sid field being invalid
        assert log_monitor.callback_result
    elif test_metadata['behavior'] == 'missing_maximum':
        # Start monitor
        log_monitor.start(callback=callbacks.generate_callback(patterns.ANALYSISD_EPS_MISSING_MAX))

        # Check that expected log appears for rules if_sid field being invalid
        assert log_monitor.callback_result
    else:
        # Start monitor
        log_monitor.start(callback=callbacks.generate_callback(patterns.ANALYSISD_CONFIGURATION_ERROR))

        # Check that expected log appears for rules if_sid field being invalid
        assert log_monitor.callback_result

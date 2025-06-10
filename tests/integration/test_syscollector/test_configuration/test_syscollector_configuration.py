'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: Wazuh gathers information about the agent system (OS, hardware, packages, etc.) periodically in a DB and sends
       it to the manager, which finally stores this information in a DB. These tests check the different syscollector
       configurations and the complete scan process.

components:
    - modulesd

suite: syscollector

targets:
    - agent

daemons:
    - wazuh-modulesd
    - wazuh-analysisd
    - wazuh-db

os_platform:
    - linux
    - windows

os_version:
    - CentOS 8
    - Ubuntu Bionic
    - Windows Server 2016
    - Windows Server 2019

references:
    - https://documentation.wazuh.com/current/user-manual/capabilities/syscollector.html
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/wodle-syscollector.html
'''
import sys
from pathlib import Path

import pytest
from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.constants.platforms import WINDOWS
from wazuh_testing.utils import services
from wazuh_testing.tools.monitors import file_monitor
from wazuh_testing.utils import callbacks, configuration
from wazuh_testing.modules.agentd.configuration import AGENTD_WINDOWS_DEBUG
from wazuh_testing.modules.modulesd.configuration import MODULESD_DEBUG
from wazuh_testing.modules.modulesd.syscollector import patterns
from . import CONFIGURATIONS_FOLDER_PATH, TEST_CASES_FOLDER_PATH


# Marks
pytestmark = [pytest.mark.agent, pytest.mark.linux, pytest.mark.win32, pytest.mark.tier(level=0)]

# Variables
daemons_handler_configuration = {'all_daemons': True, 'ignore_errors': True}
if sys.platform == WINDOWS:
    local_internal_options = {AGENTD_WINDOWS_DEBUG: '2'}
else:
    local_internal_options = {MODULESD_DEBUG: '2'}

# T1 Parameters: Check that Syscollector is disabled.
t1_3_5_config_path = Path(CONFIGURATIONS_FOLDER_PATH, 'configuration_syscollector.yaml')
t1_cases_path = Path(TEST_CASES_FOLDER_PATH, 'case_test_syscollector_deactivation.yaml')
t1_config_parameters, t1_config_metadata, t1_case_ids = configuration.get_test_cases_data(t1_cases_path)
t1_configurations = configuration.load_configuration_template(t1_3_5_config_path, t1_config_parameters, t1_config_metadata)

# T2 Parameters: Check that each scan is disabled.
t2_config_path = Path(CONFIGURATIONS_FOLDER_PATH, 'configuration_syscollector_scans_disabled.yaml')
t2_cases_path = Path(TEST_CASES_FOLDER_PATH, 'case_test_all_scans_disabled.yaml')
t2_config_parameters, t2_config_metadata, t2_case_ids = configuration.get_test_cases_data(t2_cases_path)
t2_configurations = configuration.load_configuration_template(t2_config_path, t2_config_parameters, t2_config_metadata)

# T3 Parameters: Check the behavior of Syscollector while setting invalid configurations.
t3_cases_path = Path(TEST_CASES_FOLDER_PATH, 'case_test_invalid_configurations.yaml')
t3_config_parameters, t3_config_metadata, t3_case_ids = configuration.get_test_cases_data(t3_cases_path)
t3_configurations = configuration.load_configuration_template(t1_3_5_config_path, t3_config_parameters, t3_config_metadata)

# T4 Parameters: Check that Syscollector sets the default values when the configuration block is empty.
t4_config_path = Path(CONFIGURATIONS_FOLDER_PATH, 'configuration_syscollector_no_tags.yaml')
t4_cases_path = Path(TEST_CASES_FOLDER_PATH, 'case_test_default_values.yaml')
t4_config_parameters, t4_config_metadata, t4_case_ids = configuration.get_test_cases_data(t4_cases_path)
t4_configurations = configuration.load_configuration_template(t4_config_path, t4_config_parameters, t4_config_metadata)

# T5 Parameters: Check that the scan is completed when all scans are enabled.
t5_cases_path = Path(TEST_CASES_FOLDER_PATH, 'case_test_scanning.yaml')
t5_config_parameters, t5_config_metadata, t5_case_ids = configuration.get_test_cases_data(t5_cases_path)
t5_configurations = configuration.load_configuration_template(t1_3_5_config_path, t5_config_parameters, t5_config_metadata)


# Tests
@pytest.mark.parametrize('test_configuration, test_metadata', zip(t1_configurations, t1_config_metadata), ids=t1_case_ids)
def test_syscollector_deactivation(test_configuration, test_metadata, set_wazuh_configuration,
                                   configure_local_internal_options, truncate_monitored_files,
                                   daemons_handler):
    '''
    description: Check that syscollector is disabled.

    test_phases:
        - setup:
            - Set Syscollector configuration.
            - Configure modulesd in debug mode.
            - Truncate all the log files and json alerts files.
            - Restart the necessary daemons for each test case.
        - test:
            - Check if Syscollector was disabled.
        - teardown:
            - Restore Wazuh configuration.
            - Restore local internal options.
            - Truncate all the log files and json alerts files.
            - Stop the necessary daemons.

    wazuh_min_version: 4.4.0

    tier: 0

    parameters:
        - test_configuration:
            type: dict
            brief: Configuration loaded from the template located in `configuration` folder.
        - test_metadata:
            type: dict
            brief: Test case metadata.
        - set_wazuh_configuration:
            type: fixture
            brief: Set wazuh configuration using the configuration template.
        - configure_local_internal_options:
            type: fixture
            brief: Configure the local internal options file.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate all the log files and json alerts files before and after the test execution.
        - daemons_handler:
            type: fixture
            brief: Handler of Wazuh daemons for each test case.

    assertions:
        - Check if the syscollector module is disabled.

    input_description:
        - The `configuration_syscollector.yaml` file provides the module configuration for this test.
        - The `case_test_syscollector_deactivation.yaml` file provides the test cases.
    '''
    log_monitor = file_monitor.FileMonitor(WAZUH_LOG_PATH)

    log_monitor.start(callback=callbacks.generate_callback(patterns.CB_SYSCOLLECTOR_DISABLED), timeout=30)
    assert log_monitor.callback_result


@pytest.mark.parametrize('test_configuration, test_metadata', zip(t2_configurations, t2_config_metadata), ids=t2_case_ids)
def test_syscollector_all_scans_disabled(test_configuration, test_metadata, set_wazuh_configuration,
                                         configure_local_internal_options, truncate_monitored_files,
                                         daemons_handler):
    '''
    description: Check that each scan is disabled.

    test_phases:
        - setup:
            - Set Syscollector configuration.
            - Configure modulesd in debug mode.
            - Truncate all the log files and json alerts files.
            - Restart the necessary daemons for each test case.
        - test:
            - Check that no scan is triggered.
        - teardown:
            - Restore Wazuh configuration.
            - Restore local internal options.
            - Truncate all the log files and json alerts files.
            - Stop the necessary daemons.

    wazuh_min_version: 4.4.0

    tier: 0

    parameters:
        - test_configuration:
            type: dict
            brief: Configuration loaded from the template located in `configuration` folder.
        - test_metadata:
            type: dict
            brief: Test case metadata.
        - set_wazuh_configuration:
            type: fixture
            brief: Set wazuh configuration using the configuration template.
        - configure_local_internal_options:
            type: fixture
            brief: Configure the local internal options file.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate the log file before and after the test execution.
        - daemons_handler:
            type: fixture
            brief: Handler of Wazuh daemons for each test case.

    assertions:
        - Check if a specific scan is disabled and not triggered.

    input_description:
        - The `configuration_syscollector_scans_disabled.yaml` file provides the module configuration for this test.
        - The `case_test_all_scans_disabled.yaml` file provides the test cases.
    '''
    check_callbacks = [patterns.CB_HARDWARE_SCAN_STARTED, patterns.CB_OS_SCAN_STARTED,
                       patterns.CB_NETWORK_SCAN_STARTED, patterns.CB_PACKAGES_SCAN_STARTED,
                       patterns.CB_PORTS_SCAN_STARTED, patterns.CB_PROCESSES_SCAN_STARTED,
                       patterns.CB_GROUPS_SCAN_STARTED]
    # Add the hotfixes check if the platform is Windows.
    if sys.platform == WINDOWS:
        check_callbacks.append(patterns.CB_HOTFIXES_SCAN_STARTED)

    # Check that no scan is triggered.
    log_monitor = file_monitor.FileMonitor(WAZUH_LOG_PATH)
    for callback in check_callbacks:
        log_monitor.start(callback=callbacks.generate_callback(callback), timeout=5)
        assert not log_monitor.callback_result


@pytest.mark.parametrize('test_configuration, test_metadata', zip(t3_configurations, t3_config_metadata), ids=t3_case_ids)
def test_syscollector_invalid_configurations(test_configuration, test_metadata, set_wazuh_configuration,
                                             configure_local_internal_options, truncate_monitored_files,
                                             daemons_handler):
    '''
    description: Check the behavior of Syscollector while setting invalid configurations.

    test_phases:
        - setup:
            - Set Syscollector configuration.
            - Configure modulesd in debug mode.
            - Truncate all the log files and json alerts files.
            - Restart the necessary daemons for each test case.
        - test:
            - Skip test if the field is hotfixes and the platform is not Windows.
            - Check if the tag/attribute error is present in the logs.
            - Check if Syscollector starts depending on the criticality of the field.
        - teardown:
            - Restore Wazuh configuration.
            - Restore local internal options.
            - Truncate all the log files and json alerts files.
            - Stop the necessary daemons.

    wazuh_min_version: 4.4.0

    tier: 0

    parameters:
        - test_configuration:
            type: dict
            brief: Configuration loaded from the template located in `configuration` folder.
        - test_metadata:
            type: dict
            brief: Test case metadata.
        - set_wazuh_configuration:
            type: fixture
            brief: Set wazuh configuration using the configuration template.
        - configure_local_internal_options:
            type: fixture
            brief: Configure the local internal options file.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate the log file before and after the test execution.
        - daemons_handler:
            type: fixture
            brief: Handler of Wazuh daemons for each test case.

    assertions:
        - Check if the scan is triggered after N seconds.
        - Check if a specific scan is disabled and not triggered.

    input_description:
        - The `configuration_syscollector.yaml` file provides the module configuration for this test.
        - The `case_test_invalid_configurations.yaml` file provides the test cases.
    '''
    field = test_metadata['field']
    attribute = test_metadata['attribute']
    non_critical_fields = ('max_eps')
    log_monitor = file_monitor.FileMonitor(WAZUH_LOG_PATH)

    # Skip test if the field is hotfixes and the platform is not Windows.
    if field == 'hotfixes' and sys.platform != WINDOWS:
        pytest.skip('The hotfixes scan is exclusive of Windows agents.')

    # If the field has no value, it means that the test should search for the attribute error in the logs, not for the
    # tag error.

    if field is not None:

        callbacks_options = {
            'max_eps': patterns.CB_FIELDS_MAX_EPS,
            'interval': patterns.CB_FIELDS_INTERVAL,
            'all': patterns.CB_FIELDS_ALL.format(field)
        }

        selected_callback =  callbacks_options['all'] if field not in callbacks_options.keys() else callbacks_options[field]

        log_monitor.start(callback=callbacks.generate_callback(selected_callback), timeout=5)
        assert log_monitor.callback_result

        log_monitor.start(callback=callbacks.generate_callback(patterns.CB_MODULE_STARTING), timeout=5)
        # Check that the module has started if the field is not critical
        if field in non_critical_fields:
            assert log_monitor.callback_result
        else:
            assert not log_monitor.callback_result
    else:
        callback = f"ERROR: Invalid content for attribute '{attribute}' at module 'syscollector'."
        callback =  fr'{patterns.WMODULES_PREFIX}{callback}'
        log_monitor.start(callback=callbacks.generate_callback(callback), timeout=5)
        assert log_monitor.callback_result
        # Check that the module does not start
        log_monitor.start(callback=callbacks.generate_callback(patterns.CB_MODULE_STARTING), timeout=5)
        assert not log_monitor.callback_result


@pytest.mark.parametrize('test_configuration, test_metadata', zip(t4_configurations, t4_config_metadata), ids=t4_case_ids)
def test_syscollector_default_values(test_configuration, test_metadata, set_wazuh_configuration,
                                     configure_local_internal_options, truncate_monitored_files,
                                     daemons_handler):
    '''
    description: Check that Syscollector sets the default values when the configuration block is empty.

    test_phases:
        - setup:
            - Set Syscollector configuration.
            - Configure modulesd in debug mode.
            - Truncate all the log files and json alerts files.
            - Restart the necessary daemons for each test case.
        - test:
            - Check if the default configuration was applied.
            - Check if Syscollector starts correctly.
        - teardown:
            - Restore Wazuh configuration.
            - Restore local internal options.
            - Truncate all the log files and json alerts files.
            - Stop the necessary daemons.

    wazuh_min_version: 4.4.0

    tier: 0

    parameters:
        - test_configuration:
            type: dict
            brief: Configuration loaded from the template located in `configuration` folder.
        - test_metadata:
            type: dict
            brief: Test case metadata.
        - set_wazuh_configuration:
            type: fixture
            brief: Set wazuh configuration using the configuration template.
        - configure_local_internal_options:
            type: fixture
            brief: Configure the local internal options file.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate the log file before and after the test execution.
        - daemons_handler:
            type: fixture
            brief: Handler of Wazuh daemons for each test case.

    assertions:
        - Check if the module sets the default configuration.

    input_description:
        - The `configuration_syscollector_no_tags.yaml` file provides the module configuration for this test.
        - The `case_test_default_values.yaml` file provides the test cases.
    '''
    log_monitor = file_monitor.FileMonitor(WAZUH_LOG_PATH)
    log_monitor.start(callback=callbacks.generate_callback(patterns.CB_MODULE_STARTING), timeout=5)
    assert log_monitor.callback_result

    callback = patterns.CB_CHECK_CONFIG
    if sys.platform == WINDOWS:
        callback = patterns.CB_CHECK_CONFIG_WIN

    log_monitor.start(callback=callbacks.generate_callback(callback), timeout=5)
    assert log_monitor.callback_result

    log_monitor.start(callback=callbacks.generate_callback(patterns.CB_MODULE_STARTED), timeout=5)
    assert log_monitor.callback_result


@pytest.mark.parametrize('test_configuration, test_metadata', zip(t5_configurations, t5_config_metadata), ids=t5_case_ids)
def test_syscollector_scanning(test_configuration, test_metadata, set_wazuh_configuration,
                               configure_local_internal_options, truncate_monitored_files,
                               daemons_handler):
    '''
    description: Check that the scan is completed when all scans are enabled.

    test_phases:
        - setup:
            - Set Syscollector configuration.
            - Configure modulesd in debug mode.
            - Truncate all the log files and json alerts files.
            - Restart the necessary daemons for each test case.
        - test:
            - Check if the default configuration was applied.
            - Check if Syscollector starts correctly.
        - teardown:
            - Restore Wazuh configuration.
            - Restore local internal options.
            - Truncate all the log files and json alerts files.
            - Stop the necessary daemons.

    wazuh_min_version: 4.4.0

    tier: 0

    parameters:
        - test_configuration:
            type: dict
            brief: Configuration loaded from the template located in `configuration` folder.
        - test_metadata:
            type: dict
            brief: Test case metadata.
        - set_wazuh_configuration:
            type: fixture
            brief: Set wazuh configuration using the configuration template.
        - configure_local_internal_options:
            type: fixture
            brief: Configure the local internal options file.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate the log file before and after the test execution.
        - daemons_handler:
            type: fixture
            brief: Handler of Wazuh daemons for each test case.

    assertions:
        - Check if each scan is completed.
        - Check if the synchronization is completed.

    input_description:
        - The `configuration_syscollector.yaml` file provides the module configuration for this test.
        - The `case_test_scanning.yaml` file provides the test cases.
    '''
    log_monitor = file_monitor.FileMonitor(WAZUH_LOG_PATH)
    # 60s + 2 seconds of margin because it includes the case when the agent starts for the first time
    log_monitor.start(callback=callbacks.generate_callback(patterns.CB_MODULE_STARTING), timeout=60 + 2)
    assert log_monitor.callback_result
    # Check general scan has started
    log_monitor.start(callback=callbacks.generate_callback(patterns.CB_SCAN_STARTED), timeout=10)
    assert log_monitor.callback_result

    # Check that each scan was accomplished
    check_callbacks = [patterns.CB_HARDWARE_SCAN_FINISHED, patterns.CB_OS_SCAN_FINISHED,
                    patterns.CB_NETWORK_SCAN_FINISHED, patterns.CB_PACKAGES_SCAN_FINISHED,
                    patterns.CB_PORTS_SCAN_FINISHED, patterns.CB_PROCESSES_SCAN_STARTED,
                    patterns.CB_GROUPS_SCAN_FINISHED]
    if sys.platform == WINDOWS:
        check_callbacks.append(patterns.CB_HOTFIXES_SCAN_FINISHED)

    for callback in check_callbacks:
        # Run check
        log_monitor.start(callback=callbacks.generate_callback(callback), timeout=10)
        assert log_monitor.callback_result

    # Check general scan has finished
    log_monitor.start(callback=callbacks.generate_callback(patterns.CB_SCAN_FINISHED), timeout=10)
    assert log_monitor.callback_result
    # Check that the sync has finished
    log_monitor.start(callback=callbacks.generate_callback(patterns.CB_SYNC_FINISHED), timeout=10)
    assert log_monitor.callback_result

'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: The container_images module inventories the packages found inside container images and keeps
       that inventory in a local database, synchronizing the changes with the manager. These tests
       check the parsing of the `<container_images>` configuration block: enabling and disabling the
       module, the default values, and the rejection of invalid values.

components:
    - modulesd

suite: container_images

targets:
    - agent

daemons:
    - wazuh-modulesd

os_platform:
    - linux

os_version:
    - Ubuntu Jammy
    - CentOS 8
'''
from pathlib import Path

import pytest
from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.tools.monitors import file_monitor
from wazuh_testing.utils import callbacks, configuration
from wazuh_testing.modules.modulesd.configuration import MODULESD_DEBUG
from wazuh_testing.modules.modulesd.container_images import patterns

from . import CONFIGURATIONS_FOLDER_PATH, TEST_CASES_FOLDER_PATH


# Marks
pytestmark = [pytest.mark.agent, pytest.mark.linux, pytest.mark.tier(level=0)]

# Variables
daemons_handler_configuration = {'all_daemons': True, 'ignore_errors': True}
local_internal_options = {MODULESD_DEBUG: '2'}

config_path = Path(CONFIGURATIONS_FOLDER_PATH, 'configuration_container_images.yaml')
no_tags_config_path = Path(CONFIGURATIONS_FOLDER_PATH, 'configuration_container_images_no_tags.yaml')

# T1: module disabled -> it does not start.
t1_cases_path = Path(TEST_CASES_FOLDER_PATH, 'case_test_deactivation.yaml')
t1_params, t1_metadata, t1_ids = configuration.get_test_cases_data(t1_cases_path)
t1_configurations = configuration.load_configuration_template(config_path, t1_params, t1_metadata)

# T2: empty block -> module starts with default values.
t2_cases_path = Path(TEST_CASES_FOLDER_PATH, 'case_test_default_values.yaml')
t2_params, t2_metadata, t2_ids = configuration.get_test_cases_data(t2_cases_path)
t2_configurations = configuration.load_configuration_template(no_tags_config_path, t2_params, t2_metadata)

# T3: invalid values -> the module reports a configuration error.
t3_cases_path = Path(TEST_CASES_FOLDER_PATH, 'case_test_invalid_configurations.yaml')
t3_params, t3_metadata, t3_ids = configuration.get_test_cases_data(t3_cases_path)
t3_configurations = configuration.load_configuration_template(config_path, t3_params, t3_metadata)


# Tests
@pytest.mark.parametrize('test_configuration, test_metadata', zip(t1_configurations, t1_metadata), ids=t1_ids)
def test_container_images_deactivation(test_configuration, test_metadata, set_wazuh_configuration,
                                       configure_local_internal_options, truncate_monitored_files,
                                       daemons_handler):
    '''
    description: Check that the container_images module does not start when it is disabled.

    test_phases:
        - setup: set the configuration with enabled=no, enable modulesd debug, truncate logs, restart daemons.
        - test: confirm the "Module is disabled." line appears and no scan is started.
        - teardown: restore configuration and logs, stop daemons.

    assertions:
        - The disabled-module message is logged.

    expected_result: PASS when the module logs that it is disabled.
    '''
    log_monitor = file_monitor.FileMonitor(WAZUH_LOG_PATH)

    log_monitor.start(callback=callbacks.generate_callback(patterns.CB_MODULE_DISABLED), timeout=30)
    assert log_monitor.callback_result, 'The container_images module did not report being disabled.'


@pytest.mark.parametrize('test_configuration, test_metadata', zip(t2_configurations, t2_metadata), ids=t2_ids)
def test_container_images_default_values(test_configuration, test_metadata, set_wazuh_configuration,
                                         configure_local_internal_options, truncate_monitored_files,
                                         daemons_handler):
    '''
    description: Check that the module starts with default values when the block is present but empty.

    assertions:
        - The module-initialized message is logged (module came up with defaults).

    expected_result: PASS when the module initializes from an empty block.
    '''
    log_monitor = file_monitor.FileMonitor(WAZUH_LOG_PATH)

    log_monitor.start(callback=callbacks.generate_callback(patterns.CB_MODULE_INITIALIZED), timeout=30)
    assert log_monitor.callback_result, 'The container_images module did not initialize with default values.'


@pytest.mark.parametrize('test_configuration, test_metadata', zip(t3_configurations, t3_metadata), ids=t3_ids)
def test_container_images_invalid_configuration(test_configuration, test_metadata, set_wazuh_configuration,
                                                configure_local_internal_options, truncate_monitored_files,
                                                daemons_handler):
    '''
    description: Check that invalid configuration values are rejected with the expected error message.

    assertions:
        - For enabled / scan_on_start: an "Invalid content for tag" error is logged.
        - For interval: an "Invalid interval" error is logged.
        - For an empty local reference: an "Empty 'local' reference" error is logged.

    expected_result: PASS when the matching configuration error is logged for each invalid field.
    '''
    field = test_metadata['field']

    if field == 'interval':
        pattern = patterns.CB_INVALID_INTERVAL
    elif field == 'local':
        pattern = patterns.CB_EMPTY_LOCAL_REFERENCE
    else:  # enabled / scan_on_start
        pattern = patterns.CB_INVALID_BOOL.replace('{0}', field)

    log_monitor = file_monitor.FileMonitor(WAZUH_LOG_PATH)
    log_monitor.start(callback=callbacks.generate_callback(pattern), timeout=30)
    assert log_monitor.callback_result, f'Expected configuration error for invalid {field} was not logged.'

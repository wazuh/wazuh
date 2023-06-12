"""
Copyright (C) 2015-2022, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""
import pytest

from wazuh_testing.constants.paths.configurations import WAZUH_API_LOG_FILE_PATH, WAZUH_API_JSON_LOG_FILE_PATH
from wazuh_testing.modules.api.configuration import get_configuration, append_configuration, delete_configuration_file
from wazuh_testing.modules.api.constants import API_HOST, API_PORT
from wazuh_testing.modules.api.patterns import API_STARTED_MSG
from wazuh_testing.tools import file_monitor
from wazuh_testing.utils.callbacks import generate_callback


@pytest.fixture
def add_configuration(test_configuration: list[dict]) -> None:
    """Add configuration to the Wazuh API configuration files.

    Args:
        test_configuration (list[dict]): Configuration data to be added to the configuration files.
    """
    configuration_types = ('base', 'security')
    # Configuration files the test will modify = test_target_types
    test_target_types = []
    backups = {}

    # Define target files
    for type in configuration_types:
        if test_configuration.get(type, None):
            # Add the target file to the configuration files that the test will modify
            test_target_types.append(type)
            # Create an empty dict where the configuration backup will be saved
            backups[type] = {}

    # Add configuration to the test target files
    for type in test_target_types:
        # Save current configuration
        backups[type] = get_configuration(configuration_type=type)
        # Set new configuration at the end of the configuration file
        append_configuration(test_configuration[type], type)

    yield

    # Restore target configuration files
    for type in test_target_types:
        append_configuration(backups[type], type)
        if type == 'security':
            delete_configuration_file(type)


@pytest.fixture
def wait_for_api_start(test_configuration: list[dict]) -> None:
    """Monitor the API log file to detect whether it has been started or not.

    Args:
        test_configuration (list[dict]): Configuration data.
    """
    # Set the default `log_format` value
    log_format = 'plain'
    try:
        log_format = test_configuration['base']['logs']['format']
    except (KeyError, TypeError):
        pass

    file_to_monitor = WAZUH_API_JSON_LOG_FILE_PATH if log_format == 'json' else WAZUH_API_LOG_FILE_PATH
    monitor_invalid = file_monitor.FileMonitor(file_to_monitor)
    monitor_invalid.start(
        callback=generate_callback(API_STARTED_MSG, {
            'host': API_HOST,
            'port': API_PORT
        })
    )

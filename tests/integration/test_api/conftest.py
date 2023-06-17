"""
Copyright (C) 2015-2022, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""
import pytest

from wazuh_testing.constants.paths.api import WAZUH_API_LOG_FILE_PATH, WAZUH_API_JSON_LOG_FILE_PATH
from wazuh_testing.modules.api.configuration import get_configuration, append_configuration, delete_configuration_file
from wazuh_testing.constants.api import WAZUH_API_HOST, WAZUH_API_PORT, CONFIGURATION_TYPES
from wazuh_testing.modules.api.patterns import API_STARTED_MSG
from wazuh_testing.tools import file_monitor
from wazuh_testing.utils.callbacks import generate_callback


@pytest.fixture
def add_configuration(test_configuration: list[dict], request: pytest.FixtureRequest) -> None:
    """Add configuration to the Wazuh API configuration files.

    Args:
        test_configuration (dict): Configuration data to be added to the configuration files.
        request (pytest.FixtureRequest): Gives access to the requesting test context and has an optional `param`
                                         attribute in case the fixture is parametrized indirectly.
    """
    # Configuration file that will be used to apply the test configuration
    test_target_type = request.module.configuration_type
    # Save current configuration
    backup = get_configuration(configuration_type=test_target_type)
    # Set new configuration at the end of the configuration file
    append_configuration(test_configuration['blocks'], test_target_type)

    yield

    # Restore base configuration file or delete security configuration file
    if test_target_type != CONFIGURATION_TYPES[1]:
        append_configuration(backup, test_target_type)
    else:
        delete_configuration_file(test_target_type)


@pytest.fixture
def wait_for_api_start(test_configuration: list[dict]) -> None:
    """Monitor the API log file to detect whether it has been started or not.

    Args:
        test_configuration (dict): Configuration data.
    """
    # Set the default `log_format` value
    log_format = 'plain'
    try:
        log_format = test_configuration['base']['logs']['format']
    except (KeyError, TypeError):
        pass

    file_to_monitor = WAZUH_API_JSON_LOG_FILE_PATH if log_format == 'json' else WAZUH_API_LOG_FILE_PATH
    monitor_start_message = file_monitor.FileMonitor(file_to_monitor)
    monitor_start_message.start(
        callback=generate_callback(API_STARTED_MSG, {
            'host': WAZUH_API_HOST,
            'port': WAZUH_API_PORT
        })
    )

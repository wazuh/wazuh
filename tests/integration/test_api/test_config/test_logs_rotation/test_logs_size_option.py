"""
copyright: Copyright (C) 2015, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: This test checks that API properly initializes depending of the logs configuration.

components:
    - api

suite: config

targets:
    - manager

daemons:
    - wazuh-apid
    - wazuh-modulesd
    - wazuh-analysisd
    - wazuh-execd
    - wazuh-db
    - wazuh-remoted

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
    - https://documentation.wazuh.com/current/user-manual/api/getting-started.html
    - https://documentation.wazuh.com/current/user-manual/api/configuration.html

tags:
    - api
"""


import pytest
from pathlib import Path
from subprocess import CalledProcessError

from . import CONFIGURATIONS_FOLDER_PATH, TEST_CASES_FOLDER_PATH
from wazuh_testing.constants.api import CONFIGURATION_TYPES, WAZUH_API_PORT
from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template
from wazuh_testing.constants.paths.logs import WAZUH_API_LOG_FILE_PATH
from wazuh_testing.tools.monitors import file_monitor
from wazuh_testing.utils import services
from wazuh_testing.utils.callbacks import generate_callback
from wazuh_testing.modules.api.patterns import API_STARTED_MSG

# Marks
pytestmark = pytest.mark.server

# Variables
# Used by add_configuration to select the target configuration file
configuration_type = CONFIGURATION_TYPES[0]

# Paths
test_configuration_path = Path(CONFIGURATIONS_FOLDER_PATH, 'configuration_logs_rotation_config.yaml')
test_cases_path = Path(TEST_CASES_FOLDER_PATH, 'cases_sizes_options.yaml')

# Configurations
test_configuration, test_metadata, test_cases_id = get_test_cases_data(test_cases_path)
test_configuration = load_configuration_template(test_configuration_path, test_configuration, test_metadata)


@pytest.mark.tier(level=0)
@pytest.mark.parametrize('test_configuration,test_metadata', zip(test_configuration, test_metadata), ids=test_cases_id)
def test_logs_rotation_size_option_values(test_configuration, test_metadata, add_configuration,
                                          truncate_monitored_files, capfd):
    """
    description: Check if the API works as expected with different values of log rotation size.

    wazuh_min_version: 4.6.0

    test_phases:
        - setup:
            - Append configuration to the target configuration files (defined by configuration_type)
            - Truncate the log files
        - test:
            - Get expected message from the subprocess
        - teardown:
            - Remove configuration and restore backup configuration
            - Truncate the log files

    tier: 0

    parameters:
        - test_configuration:
            type: dict
            brief: Configuration data from the test case.
        - test_metadata:
            type: dict
            brief: Metadata from the test case.
        - add_configuration:
            type: fixture
            brief: Add configuration to the Wazuh API configuration files.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate all the log files and json alerts files before and after the test execution.
        - capfd:
            type: fixture
            brief: Enable text capturing of writes to file descriptors 1 (stdout) and 2 (stderr).

    input_description: The test gets the configuration from the YAML file, which contains the API configuration.

    assertions:
        - Verify that the API returns a proper message and initialize or not depending on the configuration.
    """

    # Get metadata for the tests
    expected_error_code = test_metadata['expected_error_code']
    expected_message = test_metadata['expected_message']

    try:
        # Restart the API
        services.control_service('restart', 'wazuh-apid')
    except CalledProcessError:
        # Captures the output printed by the subprocess
        stdout_error_message = capfd.readouterr().out

        # Asserts the error was expected
        assert expected_error_code != 0, f"Didn't expect error, but {stdout_error_message} was returned"
        # Assert the error code is the expected one
        assert str(expected_error_code) in stdout_error_message, f"Expected error code {expected_error_code} but " \
                                                                 f"{stdout_error_message} was returned"
        # Assert the error message is the expected one
        assert expected_message in stdout_error_message, f"Expected error message {expected_message} but " \
                                                         f"{stdout_error_message} was returned"
    # If it wasn't expected to fail
    if expected_error_code == 0:
        host = '0.0.0.0'
        port = WAZUH_API_PORT

        # Monitor de API logs
        monitor_start_message = file_monitor.FileMonitor(WAZUH_API_LOG_FILE_PATH)
        monitor_start_message.start(
            callback=generate_callback(API_STARTED_MSG, {
                'host': str(host),
                'port': str(port)
            })
        )

        # Assert the API initialized without errors
        assert expected_message in monitor_start_message.callback_result

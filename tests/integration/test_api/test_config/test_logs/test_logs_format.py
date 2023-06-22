"""
copyright: Copyright (C) 2015-2023, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: There is an API configuration option, called logs, which allows to log in 4 different ways ("json", "plain",
       "json,plain", and "plain,json") through the format field. When the API is configured with one of those values the
       logs are stored in the api.log and api.json files.

components:
    - api

targets:
    - manager

daemons:
    - wazuh-apid

os_platform:
    - linux

os_version:
    - Arch Linux
    - Amazon Linux 2
    - Amazon Linux 1
    - CentOS 8
    - CentOS 7
    - CentOS 6
    - Ubuntu Focal
    - Ubuntu Bionic
    - Ubuntu Xenial
    - Ubuntu Trusty
    - Debian Buster
    - Debian Stretch
    - Debian Jessie
    - Debian Wheezy
    - Red Hat 8
    - Red Hat 7
    - Red Hat 6

references:
    - https://documentation.wazuh.com/current/user-manual/api/configuration.html#logs

tags:
    - api
    - logs
    - logging
"""
import os
import pytest

from wazuh_testing.constants.api import CONFIGURATION_TYPES
from wazuh_testing.constants.daemons import API_DAEMON
from wazuh_testing.constants.paths.api import WAZUH_API_JSON_LOG_FILE_PATH
from wazuh_testing.modules.api.helpers import login
from wazuh_testing.modules.api.callbacks import search_timeout_error, search_login_request
from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template


# Marks
pytestmark = pytest.mark.server

# Variables
# Used by add_configuration to select the target configuration file
configuration_type = CONFIGURATION_TYPES[0]

# Paths
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configuration_folder_path = os.path.join(test_data_path, 'configuration_template')
cases_folder_path = os.path.join(test_data_path, 'test_cases')
test_configuration_path = os.path.join(configuration_folder_path, 'configuration_logs_format.yaml')
test_cases_path = os.path.join(cases_folder_path, 'cases_logs_format.yaml')

# Configurations
test_configuration, test_metadata, test_cases_ids = get_test_cases_data(test_cases_path)
test_configuration = load_configuration_template(test_configuration_path, test_configuration, test_metadata)
daemons_handler_configuration = {'daemons': [API_DAEMON]}

# Tests

@pytest.mark.tier(level=1)
@pytest.mark.parametrize('test_configuration,test_metadata', zip(test_configuration, test_metadata), ids=test_cases_ids)
def test_logs_formats(test_configuration, test_metadata, add_configuration, truncate_monitored_files, daemons_handler,
                      wait_for_api_start):
    """
    description: Check if the logs of the API are stored in the specified formats and the content of the log
                 files are the expected.

    wazuh_min_version: 4.4.0

    test_phases:
        - setup:
            - Append configuration to the target configuration files (defined by configuration_type)
            - Truncate the log files
            - Restart daemons defined in `daemons_handler_configuration` in this module
            - Wait until the API is ready to receive requests
        - test:
            - Send a login request to the API to generate the desired event
            - Check in the log file that the expected event has been recorded
        - teardown:
            - Remove configuration and restore backup configuration
            - Truncate the log files
            - Stop daemons defined in `daemons_handler_configuration` in this module

    tier: 1

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
        - daemons_handler:
            type: fixture
            brief: Wrapper of a helper function to handle Wazuh daemons.
        - wait_for_api_start:
            type: fixture
            brief: Monitor the API log file to detect whether it has been started or not.

    assertions:
        - Verify that the response status code is the expected one.
        - Verify that the expected log exists in the log file.

    input_description: The test gets the configuration from the YAML file, which contains the API configuration.

    expected_output:
        - r".*ERROR.*{api.TIMEOUT_ERROR_LOG}.*" (Timeout error log)
        - r".*INFO.*{user}.*{host}.*{API_LOGIN_ENDPOINT}.*" (Authentication log)

    tags:
        - api
        - logs
        - logging
    """
    current_formats = test_configuration['blocks']['logs']['format'].split(',')
    current_level = test_configuration['blocks']['logs']['level']
    expected_code = test_metadata['expected_code']

    if current_level == 'error':
        with pytest.raises(RuntimeError) as exception:
            login()
        response = exception.value.args[1]
    else:
        _, response = login()

    assert response.status_code == expected_code, f"The status code was {response.status_code}." \
                                                  f"\nExpected: {expected_code}."

    # Check whether the expected event exists in the log files according to the configured levels
    if 'json' in current_formats:
        if current_level == 'error':
            search_timeout_error(WAZUH_API_JSON_LOG_FILE_PATH)
        else:
            search_login_request(WAZUH_API_JSON_LOG_FILE_PATH)

    if 'plain' in current_formats:
        if current_level == 'error':
            search_timeout_error()
        else:
            search_login_request()

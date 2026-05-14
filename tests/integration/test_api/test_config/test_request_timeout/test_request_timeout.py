"""
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests will check if the 'request_timeout' setting of the API is working properly.
       This setting allows specifying the time limit for the API to process a request.
       The Wazuh API is an open source 'RESTful' API that allows for interaction with
       the Wazuh manager from a web browser, command line tool like 'cURL' or any script
       or program that can make web requests.

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

from . import CONFIGURATIONS_FOLDER_PATH, TEST_CASES_FOLDER_PATH
from wazuh_testing.constants.api import CONFIGURATION_TYPES
from wazuh_testing.constants.daemons import API_DAEMONS_REQUIREMENTS
from wazuh_testing.modules.api.utils import login
from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template


# Marks
pytestmark = pytest.mark.server

# Variables
# Used by add_configuration to select the target configuration file
configuration_type = CONFIGURATION_TYPES[0]

# Paths
test_configuration_path = Path(CONFIGURATIONS_FOLDER_PATH, 'configuration_request_timeout.yaml')
test_cases_path = Path(TEST_CASES_FOLDER_PATH, 'cases_request_timeout.yaml')

# Configurations
test_configuration, test_metadata, test_cases_ids = get_test_cases_data(test_cases_path)
test_configuration = load_configuration_template(test_configuration_path, test_configuration, test_metadata)
daemons_handler_configuration = {'daemons': API_DAEMONS_REQUIREMENTS}


# Tests
@pytest.mark.tier(level=0)
@pytest.mark.parametrize('test_configuration,test_metadata', zip(test_configuration, test_metadata), ids=test_cases_ids)
def test_request_timeout(test_configuration, test_metadata, add_configuration, truncate_monitored_files,
                         daemons_handler, wait_for_api_start):
    """
    description: Check if the maximum request time for an API request works.
                 For this purpose, a value of '0' seconds is set for the 'request_timeout'
                 setting, and a request is made to the API, expecting an error in the response.

    wazuh_min_version: 4.3.0

    test_phases:
        - setup:
            - Append configuration to the target configuration files (defined by configuration_type)
            - Truncate the log files
            - Restart daemons defined in `daemons_handler_configuration` in this module
            - Wait until the API is ready to receive requests
        - test:
            - Make a login request to the API and verify that a RuntimeError is thrown
            - Check if the status code is the expected
            - Check if the error code in the response is the expected
        - teardown:
            - Remove configuration and restore backup configuration
            - Truncate the log files
            - Stop daemons defined in `daemons_handler_configuration` in this module

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
        - daemons_handler:
            type: fixture
            brief: Wrapper of a helper function to handle Wazuh daemons.
        - wait_for_api_start:
            type: fixture
            brief: Monitor the API log file to detect whether it has been started or not.

    assertions:
        - Verify that the request cannot finish successfully, resulting in a timeout error.

    input_description: A test case is contained in an external YAML file (conf.yaml) which includes
                       API configuration parameters ('request_timeout' set to '0' seconds).

    expected_output:
        - 500 ('Internal server error' HTTP status code)
        - 3021 ('timeout error' in the response body)
    """
    expected_status_code = test_metadata['expected_status_code']
    expected_error_code = test_metadata['expected_error_code']

    # Make a login request to the API and verify that a RuntimeError is thrown
    with pytest.raises(RuntimeError) as exception:
        login()

    response = exception.value.args[1]
    response_error_code = response.json()['error']

    # Check if the status code is the expected
    assert response.status_code == expected_status_code, f"Expected status code was {expected_status_code}, " \
                                                         f"but {response.status_code} was returned.\n" \
                                                         f"Full response: {response.text}"
    # Check if the error code in the response is the expected
    assert response_error_code == expected_error_code, f"Expected error code was {expected_error_code}, " \
                                                       f"but {response_error_code} was returned.\n" \
                                                       f"Full response: {response.text}"

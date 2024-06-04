"""
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests will check if the 'auth_token_exp_timeout' setting of the API is working properly.
       This setting allows specifying the expiration time of the 'JWT' token used for authentication.
       The Wazuh API is an open source 'RESTful' API that allows for interaction with the Wazuh manager
       from a web browser, command line tool like 'cURL' or any script or program that can make web requests.

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
    - https://documentation.wazuh.com/current/user-manual/api/configuration.html#auth-token-exp-timeout
    - https://en.wikipedia.org/wiki/JSON_Web_Token

tags:
    - api
"""
import time
import pytest
import requests
from pathlib import Path

from . import CONFIGURATIONS_FOLDER_PATH, TEST_CASES_FOLDER_PATH
from wazuh_testing import session_parameters
from wazuh_testing.constants.api import CONFIGURATION_TYPES, MANAGER_INFORMATION_ROUTE
from wazuh_testing.constants.daemons import API_DAEMONS_REQUIREMENTS
from wazuh_testing.modules.api.utils import get_base_url, login
from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template


# Marks
pytestmark = pytest.mark.server

# Variables
# Used by add_configuration to select the target configuration file
configuration_type = CONFIGURATION_TYPES[1]

# Paths
test_configuration_path = Path(CONFIGURATIONS_FOLDER_PATH, 'configuration_jwt_token_exp_timeout.yaml')
test_cases_path = Path(TEST_CASES_FOLDER_PATH, 'cases_jwt_token_exp_timeout.yaml')

# Configurations
test_configuration, test_metadata, test_cases_ids = get_test_cases_data(test_cases_path)
test_configuration = load_configuration_template(test_configuration_path, test_configuration, test_metadata)
daemons_handler_configuration = {'daemons': API_DAEMONS_REQUIREMENTS}


# Tests
@pytest.mark.tier(level=0)
@pytest.mark.parametrize('test_configuration,test_metadata', zip(test_configuration, test_metadata), ids=test_cases_ids)
def test_jwt_token_exp_timeout(test_configuration, test_metadata, add_configuration, truncate_monitored_files,
                               daemons_handler, wait_for_api_start):
    """
    description: Check if the API 'JWT' token expires after defined time. For this purpose, an expiration time is set
                 for the token, and API requests are made before and after the expiration time, waiting for a
                 valid 'HTTP status code'.

    wazuh_min_version: 4.2.0

    test_phases:
        - setup:
            - Append configuration to the target configuration files (defined by configuration_type)
            - Truncate the log files
            - Restart daemons defined in `daemons_handler_configuration` in this module
            - Wait until the API is ready to receive requests
        - test:
            - Fix to minimum time to avoid waiting longer than necessary
            - Get login token
            - Request the API before the token expires
            - Wait until it expires
            - Request the API after the token expires
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
        - Verify that the API requests are successful if the 'JWT' token has not expired and vice versa.

    input_description: Different test cases are contained in an external YAML file (cases_jwt_token_exp_timeout.yaml)
                       which includes API configuration parameters (timeouts for token expiration).

    expected_output:
        - 200 ('OK' HTTP status code if the token has not expired)
        - 401 ('Unauthorized' HTTP status code if the token has expired)

    tags:
        - token
    """
    token_timeout = test_configuration['blocks']['auth_token_exp_timeout']
    # Fix to minimum time to avoid waiting longer than necessary
    token_timeout = min(token_timeout + 1, 8)
    expected_code_after_expiration = test_metadata['expected_code']
    url = get_base_url() + MANAGER_INFORMATION_ROUTE

    # Get token
    authenticator_headers, _ = login(backoff_factor=session_parameters.default_timeout/2, login_attempts=2)

    # Request before the token expires
    response = requests.get(url, headers=authenticator_headers, verify=False)
    assert response.status_code == 200, 'Expected status code was 200, ' \
                                        f"but {response.status_code} was returned." \
                                        f"\nFull response: {response.text}"

    # Wait until the token expires
    time.sleep(token_timeout)

    # Request after the token expires
    response = requests.get(url, headers=authenticator_headers, verify=False)
    assert response.status_code == expected_code_after_expiration, 'Expected status code was ' \
                                                                   f"{expected_code_after_expiration} " \
                                                                   f"but {response.status_code} was returned." \
                                                                   f"\nFull response: {response.text}"

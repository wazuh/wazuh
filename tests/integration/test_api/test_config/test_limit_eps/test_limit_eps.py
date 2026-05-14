"""
copyright: Copyright (C) 2015, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: This test checks that the API works as expected when uploading configurations with forbidden sections

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
import requests

from . import CONFIGURATIONS_FOLDER_PATH, TEST_CASES_FOLDER_PATH
from wazuh_testing.constants.api import CONFIGURATION_TYPES, MANAGER_CONFIGURATION_ROUTE
from wazuh_testing.constants.daemons import API_DAEMONS_REQUIREMENTS
from wazuh_testing.modules.api.utils import login, get_base_url
from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template, get_wazuh_conf

# Marks
pytestmark = pytest.mark.server

# Variables
# Used by add_configuration to select the target configuration file
configuration_type = CONFIGURATION_TYPES[0]

# Paths
test_configuration_path = Path(CONFIGURATIONS_FOLDER_PATH, 'configuration_limit_eps_api_config.yaml')
test_cases_path = Path(TEST_CASES_FOLDER_PATH, 'cases_limit_eps_config.yaml')

# Configurations
test_configuration, test_metadata, test_cases_id = get_test_cases_data(test_cases_path)
test_configuration = load_configuration_template(test_configuration_path, test_configuration, test_metadata)
daemons_handler_configuration = {'daemons': API_DAEMONS_REQUIREMENTS}


@pytest.mark.tier(level=0)
@pytest.mark.parametrize('test_configuration,test_metadata', zip(test_configuration, test_metadata), ids=test_cases_id)
def test_limit_eps(test_configuration, test_metadata, set_wazuh_configuration, add_configuration,
                   truncate_monitored_files, daemons_handler, wait_for_api_start):
    """
    description: Check if the API works as expected when uploading configurations with forbidden sections

    wazuh_min_version: 4.4.0

    test_phases:
        - setup:
            - Apply ossec.conf configuration changes according to the configuration template and use case.
            - Append configuration to the target configuration files (defined by configuration_type)
            - Truncate the log files
            - Restart daemons defined in `daemons_handler_configuration` in this module
            - Wait until the API is ready to receive requests
        - test:
            - Get expected code and request body
            - Get expected configuration
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
        - set_wazuh_configuration:
            type: fixture
            brief: Apply changes to the ossec.conf configuration.
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

    input_description: The test gets the configuration from the YAML file, which contains the API configuration.

    assertions:
        - Verify that the API requests are made correctly and the ossec.conf file is updated as expected.

    expected_output:
        - r'200' ('OK' HTTP status code)
    """
    # Get metadata for the tests
    expected_code = test_metadata['expected_code']
    expected_error_code = test_metadata['expected_error_code']
    request_body = test_metadata['request_body']

    # Get url and token for the request
    url = get_base_url()
    authentication_headers, _ = login()
    authentication_headers['Content-Type'] = 'application/octet-stream'

    # Makes an API request for uploading the new configuration
    response = requests.put(url + MANAGER_CONFIGURATION_ROUTE, headers=authentication_headers, verify=False, timeout=10,
                            data=request_body)

    # Parses the response
    json_response = response.json()
    error_code = json_response['error']

    # Assert the status code
    assert response.status_code == expected_code, f"Expected status code {expected_code}, but " \
                                                  f"{response.status_code} was returned: {json_response}"
    # Assert the error code is the expected one
    assert error_code == expected_error_code, f"Expected error code {expected_error_code}, but " \
                                              f"{error_code} was returned: {json_response}"
    if error_code == 1:
        internal_error_code = json_response['data']["failed_items"][0]['error']['code']
        assert internal_error_code == 1127, f"Expected error code {1127}, but " \
                                            f"{internal_error_code} was returned: {json_response}"

    # Asserts that the configuration has the expected values
    wazuh_config = " ".join(get_wazuh_conf())
    assert f"<maximum>{test_metadata['expected_max_value']}</maximum>" in wazuh_config
    assert f"<timeframe>{test_metadata['expected_timeframe_value']}</timeframe>" in wazuh_config

"""
copyright: Copyright (C) 2015, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: This test checks that the configuration is set correctly in the manager via the API.

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
import requests
from pathlib import Path

from . import CONFIGURATIONS_FOLDER_PATH, TEST_CASES_FOLDER_PATH
from wazuh_testing.constants.api import CONFIGURATION_TYPES, MANAGER_CONFIGURATION_ROUTE
from wazuh_testing.constants.daemons import API_DAEMONS_REQUIREMENTS
from wazuh_testing.modules.api.utils import login, get_base_url
from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template


# Marks
pytestmark = pytest.mark.server

# Variables
# Used by add_configuration to select the target configuration file
configuration_type = CONFIGURATION_TYPES[0]

# Paths
test_configuration_path = Path(CONFIGURATIONS_FOLDER_PATH, 'configuration_upload_configuration.yaml')
test_cases_path = Path(TEST_CASES_FOLDER_PATH, 'cases_upload_configuration.yaml')

# Configurations
test_configuration, test_metadata, test_cases_ids = get_test_cases_data(test_cases_path)
test_configuration = load_configuration_template(test_configuration_path, test_configuration, test_metadata)
daemons_handler_configuration = {'daemons': API_DAEMONS_REQUIREMENTS}

# Tests
@pytest.mark.tier(level=0)
@pytest.mark.parametrize('test_configuration,test_metadata', zip(test_configuration, test_metadata), ids=test_cases_ids)
def test_upload_configuration(test_configuration, test_metadata, backup_wazuh_configuration, add_configuration,
                              truncate_monitored_files, daemons_handler, wait_for_api_start):
    """
    description: Check if the API works when uploading configurations.

    wazuh_min_version: 4.4.0

    test_phases:
        - setup:
            - Append configuration to the target configuration files (defined by configuration_type)
            - Truncate the log files
            - Restart daemons defined in `daemons_handler_configuration` in this module
            - Wait until the API is ready to receive requests
        - test:
            - Get expected code and request body
            - Login and get the authorization headers
            - Make a request to verify that the configuration was successfully updated
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
        - backup_wazuh_configuration:
            type: fixture
            brief: Save the initial wazuh configuration and restore it after the test.
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
        - Verify that the API requests are made correctly when uploading one and two configuration blocks.

    expected_output:
        - r'200' ('OK' HTTP status code)
    """
    expected_code = test_metadata['expected_code']
    body = test_metadata['body']

    url = get_base_url()
    authentication_headers, _ = login()
    authentication_headers['Content-Type'] = 'application/octet-stream'

    response = requests.put(url + MANAGER_CONFIGURATION_ROUTE, headers=authentication_headers, verify=False, timeout=10,
                             data=body)
    assert response.status_code == expected_code, f"Expected status code {expected_code}, but " \
                                                  f"{response.status_code} was returned: {response.json()}"

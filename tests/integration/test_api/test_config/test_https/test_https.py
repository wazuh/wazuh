"""
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests will check that the API works correctly using the 'HTTPS' protocol.
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
    - https://documentation.wazuh.com/current/user-manual/api/configuration.html#https

tags:
    - api
"""
import pytest
import requests
from pathlib import Path

from . import CONFIGURATIONS_FOLDER_PATH, TEST_CASES_FOLDER_PATH
from wazuh_testing.constants.api import CONFIGURATION_TYPES
from wazuh_testing.constants.daemons import API_DAEMONS_REQUIREMENTS
from wazuh_testing.modules.api.utils import get_base_url, login
from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template


# Marks
pytestmark = pytest.mark.server

# Variables
# Used by add_configuration to select the target configuration file
configuration_type = CONFIGURATION_TYPES[0]

# Paths
test_configuration_path = Path(CONFIGURATIONS_FOLDER_PATH, 'configuration_https.yaml')
test_cases_path = Path(TEST_CASES_FOLDER_PATH, 'cases_https.yaml')

# Configurations
test_configuration, test_metadata, test_cases_ids = get_test_cases_data(test_cases_path)
test_configuration = load_configuration_template(test_configuration_path, test_configuration, test_metadata)
daemons_handler_configuration = {'daemons': API_DAEMONS_REQUIREMENTS}


# Tests
@pytest.mark.tier(level=0)
@pytest.mark.parametrize('test_configuration,test_metadata', zip(test_configuration, test_metadata), ids=test_cases_ids)
def test_https(test_configuration, test_metadata, add_configuration, truncate_monitored_files, daemons_handler,
               wait_for_api_start):
    """
    description: Check if the API works with 'HTTP' and 'HTTPS' protocols. For this purpose, it configures the API
                 to use both protocols and makes requests to it, waiting for a correct response.

    wazuh_min_version: 4.2.0

    test_phases:
        - setup:
            - Append configuration to the target configuration files (defined by configuration_type)
            - Truncate the log files
            - Restart daemons defined in `daemons_handler_configuration` in this module
            - Wait until the API is ready to receive requests
        - test:
            - Get url with the configured protocol
            - Login and get the authorization headers
            - Make a request to verify if the protocol was successfully configured
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
        - Verify that the API requests are made correctly using both 'HTTP' and 'HTTPS' protocols.

    input_description: Different test cases are contained in an external YAML file (cases_https.yaml) which includes
                       API configuration parameters (HTTPS settings).

    expected_output:
        - r'200' ('OK' HTTP status code)

    tags:
        - ssl
    """
    https = test_configuration['blocks']['https']['enabled']
    protocol = 'https' if https is True else 'http'
    url = get_base_url(protocol=protocol)
    authentication_headers, _ = login(protocol=protocol)

    response = requests.get(url, headers=authentication_headers, verify=False)

    assert response.status_code == 200, f"Expected status code was 200, but {response.status_code} was " \
                                        f"returned.\nFull response: {response.text}"

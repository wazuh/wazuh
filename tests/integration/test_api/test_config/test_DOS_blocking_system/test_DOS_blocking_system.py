"""
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests will check if the 'DOS' (Denial-of-service attack) blocking feature of the API handled
       by the 'wazuh-apid' daemon is working properly. The Wazuh API is an open source 'RESTful' API
       that allows for interaction with the Wazuh manager from a web browser, command line tool
       like 'cURL' or any script or program that can make web requests.

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
    - https://documentation.wazuh.com/current/user-manual/api/configuration.html#access
    - https://en.wikipedia.org/wiki/Denial-of-service_attack

tags:
    - api
"""
import time
import pytest
import requests
from pathlib import Path

from . import CONFIGURATIONS_FOLDER_PATH, TEST_CASES_FOLDER_PATH
from wazuh_testing.constants.api import CONFIGURATION_TYPES, AGENTS_ROUTE
from wazuh_testing.constants.daemons import API_DAEMONS_REQUIREMENTS
from wazuh_testing.modules.api.utils import get_base_url, login
from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template


# Marks
pytestmark = pytest.mark.server

# Variables
# Used by add_configuration to select the target configuration file
configuration_type = CONFIGURATION_TYPES[0]

# Paths
test_configuration_path = Path(CONFIGURATIONS_FOLDER_PATH, 'configuration_DOS_blocking_system.yaml')
test_cases_path = Path(TEST_CASES_FOLDER_PATH, 'cases_DOS_blocking_system.yaml')

# Configurations
test_configuration, test_metadata, test_cases_ids = get_test_cases_data(test_cases_path)
test_configuration = load_configuration_template(test_configuration_path, test_configuration, test_metadata)
daemons_handler_configuration = {'daemons': API_DAEMONS_REQUIREMENTS}


# Tests
@pytest.mark.tier(level=0)
@pytest.mark.parametrize('test_configuration,test_metadata', zip(test_configuration, test_metadata), ids=test_cases_ids)
def test_DOS_blocking_system(test_configuration, test_metadata, add_configuration, truncate_monitored_files,
                             daemons_handler, wait_for_api_start):
    """
    description: Check if the API blocking system for IP addresses detected as 'DOS' attack works.
                 For this purpose, the test causes an IP blocking, makes a request within
                 the same minute, makes a request after the minute.

    wazuh_min_version: 4.2.0

    test_phases:
        - setup:
            - Append configuration to the target configuration files (defined by configuration_type)
            - Truncate the log files
            - Restart daemons defined in `daemons_handler_configuration` in this module
            - Wait until the API is ready to receive requests
        - test:
            - Provoke an API block
            - Request within a minute
            - Request after a minute to check if the IP is not blocked anymore
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
        - Verify that the IP address is blocked using multiple requests.
        - Verify that the IP address is still blocked within the one-minute block time.
        - Verify that the IP address is not blocked when expires the blocking time.

    input_description: Different test cases are in the `cases_DOS_blocking_system.yaml` file which includes API
                       configuration parameters that will be replaced in the configuration template file.

    expected_output:
        - r'429' ('Too Many Requests' HTTP status code)
        - r'200' ('OK' HTTP status code)

    tags:
        - dos_attack
    """
    max_request_per_minute = test_configuration['blocks']['access']['max_request_per_minute']
    expected_code = test_metadata['expected_http_code']
    url = get_base_url() + AGENTS_ROUTE
    authentication_headers, _ = login()

    # Provoke an API block
    for _ in range(max_request_per_minute):
        requests.get(url, headers=authentication_headers, verify=False)

    # Request within a minute
    response = requests.get(url, headers=authentication_headers, verify=False)
    assert response.status_code == expected_code, f"Expected status code: {expected_code}, " \
                                                  f"but {response.status_code} was returned.\n" \
                                                  f"Full response: {response.text}"

    # Request after the minute
    time.sleep(60)  # 60 = 1 minute
    response = requests.get(url, headers=authentication_headers, verify=False)

    # After blocking time, status code must be 200 again
    assert response.status_code == 200, 'Expected status code was 200, ' \
                                        f"but {response.status_code} was returned.\n" \
                                        f"Full response: {response.text}"

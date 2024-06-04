"""
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests will check if the set_secure_headers middleware of the API handled by the 'wazuh-apid' daemon is
       working properly. The Wazuh API is an open source 'RESTful' API that allows for interaction with the Wazuh
       manager from a web browser, command line tool like 'cURL' or any script or program that can make web requests.

components:
    - api

suite: middlewares

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
    - https://documentation.wazuh.com/current/user-manual/api/getting-started.html

tags:
    - api
    - response
    - headers
"""
import pytest
import requests
from pathlib import Path

from . import TEST_CASES_FOLDER_PATH, CONFIGURATIONS_FOLDER_PATH
from wazuh_testing.constants.api import AGENTS_ROUTE, CONFIGURATION_TYPES
from wazuh_testing.constants.daemons import API_DAEMONS_REQUIREMENTS
from wazuh_testing.modules.api.utils import get_base_url, login
from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template


# Marks
pytestmark = pytest.mark.server

# Variables
# Used by add_configuration to select the target configuration file
configuration_type = CONFIGURATION_TYPES[0]

# Paths
test_configuration_path = Path(CONFIGURATIONS_FOLDER_PATH, 'configuration_set_secure_headers.yaml')
test_cases_path = Path(TEST_CASES_FOLDER_PATH, 'cases_set_secure_headers.yaml')

# Configurations
test_configuration, test_metadata, test_cases_ids = get_test_cases_data(test_cases_path)
test_configuration = load_configuration_template(test_configuration_path, test_configuration, test_metadata)
daemons_handler_configuration = {'daemons': API_DAEMONS_REQUIREMENTS}


# Tests
@pytest.mark.tier(level=0)
@pytest.mark.parametrize('test_configuration,test_metadata', zip(test_configuration, test_metadata), ids=test_cases_ids)
def test_set_secure_headers(test_configuration, test_metadata, add_configuration, truncate_monitored_files,
                            daemons_handler, wait_for_api_start):
    """
    description: Check if the set_secure_headers API middleware works.
                 For this purpose, the test makes an API request and checks that the response headers fulfill the REST
                 recommended standard.

    wazuh_min_version: 4.1.0

    test_phases:
        - setup:
            - Append configuration to the target configuration files (defined by configuration_type)
            - Add user in the RBAC database
            - Truncate the log files
            - Restart daemons defined in `daemons_handler_configuration` in this module
            - Wait until the API is ready to receive requests
        - test:
            - Make an API request
            - Check response headers fulfill the REST standard
        - teardown:
            - Remove configuration and restore backup configuration
            - Remove user in the RBAC database
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
        - Verify that the response headers fulfill the REST recommended standard in terms of security.

    tags:
        - headers
        - security
    """
    security_headers = test_metadata['security_headers']
    url = get_base_url() + AGENTS_ROUTE

    # Make an API request
    response = requests.get(url, headers=login()[0], verify=False)

    # Check response headers fulfill the REST standard
    security_headers_keys = set(list(security_headers.keys()))
    # Check that all the security headers are in the response
    assert security_headers_keys.issubset(response.headers.keys()), 'Not all of the security headers are in the' \
                                                                    ' response.\n' \
                                                                    f"Expected: {security_headers_keys}\n" \
                                                                    f"Current: {response.headers.keys()}"
    # Check the value of each security header
    assert all(security_headers[key] in response.headers[key] for key in security_headers), 'The values of the ' \
                                                                                            'security headers are ' \
                                                                                            'not the expected.\n' \
                                                                                            'Expected: ' \
                                                                                            f"{security_headers}\n" \
                                                                                            'Current: ' \
                                                                                            f"{response.headers}"

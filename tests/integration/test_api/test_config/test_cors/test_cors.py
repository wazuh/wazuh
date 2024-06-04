"""
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests will check if the 'CORS' (Cross-origin resource sharing) feature of the API handled
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
    - https://documentation.wazuh.com/current/user-manual/api/configuration.html#cors
    - https://en.wikipedia.org/wiki/Cross-origin_resource_sharing

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
test_configuration_path = Path(CONFIGURATIONS_FOLDER_PATH, 'configuration_cors.yaml')
test_cases_path = Path(TEST_CASES_FOLDER_PATH, 'cases_cors.yaml')

# Configurations
test_configuration, test_metadata, test_cases_ids = get_test_cases_data(test_cases_path)
test_configuration = load_configuration_template(test_configuration_path, test_configuration, test_metadata)
daemons_handler_configuration = {'daemons': API_DAEMONS_REQUIREMENTS}


# Tests
@pytest.mark.tier(level=0)
@pytest.mark.parametrize('test_configuration,test_metadata', zip(test_configuration, test_metadata), ids=test_cases_ids)
def test_cors(test_configuration, test_metadata, add_configuration, truncate_monitored_files, daemons_handler,
              wait_for_api_start):
    """
    description: Check if expected headers are returned when 'CORS' is enabled.
                 When 'CORS' is enabled, special headers must be returned in case the
                 request origin matches the one established in the 'CORS' configuration
                 of the API.

    wazuh_min_version: 4.2.0

    test_phases:
        - setup:
            - Append configuration to the target configuration files (defined by configuration_type)
            - Truncate the log files
            - Restart daemons defined in `daemons_handler_configuration` in this module
            - Wait until the API is ready to receive requests
        - test:
            - Request to default API url to get CORS headers
            - If origin is allowed, check for expected CORS headers
            - If origin is not allowed, check that Access-Control-Allow-Origin is not in the response headers
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
        - Verify that when CORS is enabled, the 'Access-Control-Allow-Origin' header is received.
        - Verify that when CORS is enabled, the 'Access-Control-Expose-Headers' header is received.
        - Verify that when CORS is enabled, the 'Access-Control-Allow-Credentials' header is received.
        - Verify that when CORS is disabled, the 'Access-Control-Allow-Origin' header is not received.

    input_description: Different test cases are in the `cases_cors.yaml` file which includes API configuration
                       parameters that will be replaced in the configuration template file.

    expected_output:
        - Access-Control-Allow-Origin
        - https://allowed.com
        - Test-expose
        - another-expose
        - true
        - Content-type

    tags:
        - cors
    """
    # Headers
    allow_origin_header_name = 'Access-Control-Allow-Origin'
    expose_header_name = 'Access-Control-Expose-Headers'
    allow_credentials_header_name = 'Access-Control-Allow-Credentials'
    allow_headers_header_name = 'Access-Control-Allow-Headers'
    # Expected content from the response headers.
    source_route = test_configuration['blocks']['cors']['source_route']
    expose_headers = test_configuration['blocks']['cors']['expose_headers']
    allow_headers = test_configuration['blocks']['cors']['allow_headers']
    allow_credentials = str(test_configuration['blocks']['cors']['allow_credentials']).lower()

    url = get_base_url()
    authentication_headers, _ = login()
    origin = test_metadata['origin']
    authentication_headers['origin'] = origin

    # Request to default API url.
    response = requests.get(url, headers=authentication_headers, verify=False)
    response_headers_names = response.headers.keys()

    # If origin is allowed, check for expected CORS headers.
    if origin == source_route:
        assert allow_origin_header_name in response_headers_names, 'Allow origin was not found in headers.\n' \
                                                                   f"Expected header: {allow_origin_header_name}\n" \
                                                                   f"Response headers: {response_headers_names}"

        assert response.headers[allow_origin_header_name] == origin, 'Allow origin value is not the expected.\n' \
                                                                     f"Expected origin: {origin}\n" \
                                                                     'Response allowed origin: \n' \
                                                                     f"{response.headers[allow_origin_header_name]}"

        for header in expose_headers:
            assert header in response.headers[expose_header_name], f"The header '{header}' is not present in " \
                                                                   f"'{expose_header_name}'\n" \
                                                                   'Current headers: ' \
                                                                   f"{response.headers[expose_header_name]}"

        header_value = response.headers[allow_credentials_header_name]
        assert header_value == allow_credentials, 'Allow credentials value is not the expected.\n' \
                                                  f"Expected credentials: {allow_credentials}\n" \
                                                  f"Response allowed credentials: {header_value}"
        try:
            header_value = response.headers[allow_headers_header_name]
            for header in allow_headers:
                assert header in header_value, f"The header '{header}' is not present in " \
                                               f"'{allow_headers_header_name}'\n" \
                                               f"Current headers: {header_value}"
        except KeyError:
            pytest.xfail(reason='Xfailed due to Access-Control-Allow-Headers not being returned.')
    else:
        assert allow_origin_header_name not in response_headers_names, f"{allow_origin_header_name} was found in " \
                                                                        'headers but it was not expected to be.'

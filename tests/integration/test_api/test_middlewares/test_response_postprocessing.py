"""
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests will check if the response_postprocessing middleware of the API handled by the 'wazuh-apid' daemon is
       working properly. The Wazuh API is an open source 'RESTful' API that allows the interaction with the Wazuh
       manager from a web browser, command line tools like 'cURL' or any script or program that can make web requests.

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
    - response fields
"""
import json
import pytest
import requests
from requests.adapters import HTTPAdapter, Retry
from pathlib import Path

from . import TEST_CASES_FOLDER_PATH
from wazuh_testing.constants.daemons import API_DAEMONS_REQUIREMENTS
from wazuh_testing.constants.api import WAZUH_API_PROTOCOL
from wazuh_testing.modules.api.utils import login, get_base_url, set_authorization_header
from wazuh_testing.utils.configuration import get_test_cases_data


# Marks
pytestmark = pytest.mark.server

# Paths
test_cases_path = Path(TEST_CASES_FOLDER_PATH, 'cases_response_postprocessing.yaml')

# Configurations
_, test_metadata, test_cases_ids = get_test_cases_data(test_cases_path)
daemons_handler_configuration = {'daemons': API_DAEMONS_REQUIREMENTS}


# Tests
@pytest.mark.tier(level=0)
@pytest.mark.parametrize('test_configuration, test_metadata', zip(_, test_metadata), ids=test_cases_ids)
def test_response_postprocessing(test_configuration, test_metadata, truncate_monitored_files, daemons_handler,
                                 wait_for_api_start):
    """
    description: Check if the response_postprocessing API middleware works.

    wazuh_min_version: 4.0.0

    test_phases:
        - setup:
            - Truncate the log files
            - Restart daemons defined in `daemons_handler_configuration` in this module
            - Wait until the API is ready to receive requests
        - test:
            - Make the API request
            - Verify the response content
        - teardown:
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
        - Verify that the response content is the expected when getting an specific status code.

    input_description: Different test cases are contained in an external YAML file which includes API configuration
                       parameters.

    tags:
        - headers
        - security
    """
    use_login_token = test_metadata['use_login_token']
    method = test_metadata['method']
    endpoint_url = test_metadata['endpoint_url']
    json_body = test_metadata['json_body']
    expected_status_code = test_metadata['expected_status_code']
    expected_response_text = test_metadata['expected_response_text']
    expected_content_type = test_metadata['expected_content_type']

    url = get_base_url() + endpoint_url
    session = requests.Session()

    if use_login_token:
        authentication_headers, _ = login()
    else:
        authentication_headers = set_authorization_header('user', 'pass')
        retry = Retry(total=None, connect=3, backoff_factor=0.5)
        adapter = HTTPAdapter(max_retries=retry)
        session.mount(f"{WAZUH_API_PROTOCOL}://", adapter)

    # Make the API request
    response = session.request(method=method, url=url, headers=authentication_headers, verify=False, json=json_body)

    response_text = json.loads(response.text)
    # Verify the response content
    assert response.headers['Content-Type'] == expected_content_type, "Response's Content-Type header is not the " \
                                                                      f"expected.\nExpected: {expected_content_type}" \
                                                                      f"\nCurrent: {response.headers['Content-Type']}"
    assert response.status_code == expected_status_code, "Response's status code is not the expected.\n" \
                                                         f"Expected: {expected_status_code}\n" \
                                                         f"Current: {response.status_code}"
    assert response_text == expected_response_text, "Response's is not the expected.\n" \
                                                    f"Expected: {expected_response_text}\n" \
                                                    f"Current: {response_text}"

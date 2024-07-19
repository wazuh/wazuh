"""
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests will check if the 'max_upload_size' setting of the API is working properly.
       This setting allows specifying the size limit of the request body for the API to process.
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
import string
import pytest
import requests
from pathlib import Path
from random import choices

from . import CONFIGURATIONS_FOLDER_PATH, TEST_CASES_FOLDER_PATH
from wazuh_testing.constants.api import CONFIGURATION_TYPES, GROUPS_ROUTE, CDB_LIST_ROUTE
from wazuh_testing.constants.daemons import API_DAEMONS_REQUIREMENTS
from wazuh_testing.modules.api.utils import login, get_base_url
from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template


# Marks
pytestmark = pytest.mark.server

# Variables
# Used by add_configuration to select the target configuration file
configuration_type = CONFIGURATION_TYPES[0]

# Paths
test_configuration_path = Path(CONFIGURATIONS_FOLDER_PATH, 'configuration_max_upload_size.yaml')
test_cases_path = Path(TEST_CASES_FOLDER_PATH, 'cases_max_upload_size.yaml')

# Configurations
test_configuration, test_metadata, test_cases_ids = get_test_cases_data(test_cases_path)
test_configuration = load_configuration_template(test_configuration_path, test_configuration, test_metadata)
daemons_handler_configuration = {'daemons': API_DAEMONS_REQUIREMENTS}


# Functions
def create_group_name(length: int) -> str:
    """Return a random string, with characters and digits, of a given length.

    Args:
        length (int): Number of characters that the string should contain.

    Returns:
        string: String with 'length' random characters and digits.
    """
    return ''.join(choices(string.ascii_uppercase + string.digits, k=length))


def create_cdb_list(min_length: int) -> str:
    """Create a string formatted as a CDB list which is at least 'min_length' long.

    Args:
        min_length (int): Minimum length of the string. More characters could be returned if necessary.

    Returns:
        cdb_content (str): String of `min_length` length formatted as a CDB list.
    """
    cdb_content = ''
    key_counter = 0

    while len(cdb_content) < min_length:
        cdb_content = cdb_content + f'{key_counter}:\n'
        key_counter += 1

    return cdb_content


# Tests
@pytest.mark.tier(level=2)
@pytest.mark.parametrize('test_configuration,test_metadata', zip(test_configuration, test_metadata), ids=test_cases_ids)
def test_max_upload_size(test_configuration, test_metadata, add_configuration, truncate_monitored_files,
                         daemons_handler, wait_for_api_start):
    """
    description: Check if a '413' HTTP status code ('Payload Too Large') is returned if the response body is
                 bigger than the value of the 'max_upload_size' tag. For this purpose, the test will call to
                 a PUT and a POST endpoint specifying a body. If the 'max_upload_size' is 0 (limitless),
                 a '200' HTTP status code ('OK') should be returned. If 'max_upload_size' is not limitless,
                 both PUT and POST endpoints should fail when trying to send a bigger body.

    wazuh_min_version: 4.3.0

    test_phases:
        - setup:
            - Append configuration to the target configuration files (defined by configuration_type)
            - Truncate the log files
            - Restart daemons defined in `daemons_handler_configuration` in this module
            - Wait until the API is ready to receive requests
        - test:
            - Create a new group
            - Check if it was created or not depending on the expected code
            - Upload a new CDB list (another type of content)
            - Check if the CDB list was uploaded or not depending on the expected code
            - Delete the created content to clean the environment
        - teardown:
            - Remove configuration and restore backup configuration
            - Truncate the log files
            - Stop daemons defined in `daemons_handler_configuration` in this module

    tier: 2

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
        - Verify that the 'wazuh-apid' daemon returns a proper HTTP status code depending on the value
          of the 'max_upload_size' tag and the size of the response body received.

    input_description: The test gets the configuration from the YAML file, which contains the API configuration.

    expected_output:
        - 413 ('Payload Too Large' HTTP status code)
        - 200 ('OK' HTTP status code)
    """
    content_size = test_metadata['request_content_size']
    expected_code = test_metadata['expected_code']

    base_url = get_base_url()
    authentication_headers, _ = login()
    group_name = create_group_name(content_size)
    cdb_list_name = 'new_cdb_list'
    cdb_list_content = create_cdb_list(content_size).encode()

    # Create a new group
    response = requests.post(base_url + GROUPS_ROUTE, headers=authentication_headers, verify=False,
                             json={'group_id': group_name})
    # Check if it was created or not depending on the expected code
    assert response.status_code == expected_code, f"Expected status code was {expected_code}, but " \
                                                  f"{response.status_code} was returned: {response.json()}"

    # Upload a new CDB list (another type of content)
    authentication_headers['Content-Type'] = 'application/octet-stream'
    response = requests.put(base_url + f"{CDB_LIST_ROUTE}/{cdb_list_name}", headers=authentication_headers,
                            verify=False, data=cdb_list_content)
    # Check if the CDB list was uploaded or not depending on the expected code
    assert response.status_code == expected_code, f"Expected status code was {expected_code}, but " \
                                                  f"{response.status_code} was returned: {response.json()}"

    # Delete the created content to clean the environment
    if expected_code == 200:
        requests.delete(base_url + f"{GROUPS_ROUTE}?groups_list={group_name}", headers=authentication_headers,
                        verify=False)
        requests.delete(base_url + f"{CDB_LIST_ROUTE}/{cdb_list_name}", headers=authentication_headers,
                        verify=False, data=cdb_list_content)

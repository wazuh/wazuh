"""
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests will check if the 'RBAC' (Role-Based Access Control) feature of the API is working properly.
       Specifically, they will verify that the different actions that can be performed with admin resources
       are working correctly. The 'RBAC' capability allows users accessing the API to be assigned a role
       that will define the privileges they have.

components:
    - api

suite: rbac

targets:
    - manager

daemons:
    - wazuh-apid
    - wazuh-db
    - wazuh-execd
    - wazuh-analysisd
    - wazuh-remoted
    - wazuh-modulesd

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
    - https://documentation.wazuh.com/current/user-manual/api/reference.html#tag/Security
    - https://en.wikipedia.org/wiki/Role-based_access_control

tags:
    - api
"""
import pytest
from pathlib import Path

from . import TEST_CASES_FOLDER_PATH
from wazuh_testing.constants.daemons import API_DAEMONS_REQUIREMENTS
from wazuh_testing.modules.api.utils import manage_security_resources, get_resource_admin_ids
from wazuh_testing.utils.configuration import get_test_cases_data


# Marks
pytestmark = pytest.mark.server

# Paths
test_cases_path = Path(TEST_CASES_FOLDER_PATH, 'cases_manage_admin_resource.yaml')

# Configurations
_, test_metadata, test_cases_ids = get_test_cases_data(test_cases_path)
daemons_handler_configuration = {'daemons': API_DAEMONS_REQUIREMENTS}


# Tests
@pytest.mark.tier(level=0)
@pytest.mark.parametrize('test_configuration, test_metadata', zip(_, test_metadata), ids=test_cases_ids)
def test_manage_admin_resource(test_configuration, test_metadata, truncate_monitored_files, daemons_handler,
                               wait_for_api_start):
    """
    description: Check if the administrator's security resources cannot be removed/updated.

    wazuh_min_version: 4.2.0

    test_phases:
        - setup:
            - Truncate monitored files
            - Restart daemons defined in `daemons_handler_configuration` in this module
            - Wait until the API is ready to receive requests
            - Configure the security resources using the API
        - test:
            - Get resource and get all the ids
            - Attempt to delete the resource
            - Check if the failed items are present in the response
            - Get failed item information
            - Check the error code and the IDs
        - teardown:
            - Truncate monitored files
            - Stop daemons defined in `daemons_handler_configuration` in this module
            - Clean added resources

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
        - Check if the deletion attempt can be done
        - Check if the response has failed items in it
        - Check if the response's error code is the expected
        - Check if the ID of the failed item matches with the expected

    input_description: Different test cases are contained in an external YAML file which includes API configuration
                       parameters.

    expected_output:
        - 200
        - 200
        - {..., 'failed_items': [{...}]} (Response with a non-empty failed_items element)
        - Expected error code in the response
        - The ID of the resource that was intended to be removed

    tags:
        - rbac
    """
    target_resource = test_metadata['target_resource']['name']
    expected_error_code = test_metadata['expected_error_code']
    action = test_metadata['action']
    updated_resource_payload = None
    if action == 'update':
        updated_resource_payload = test_metadata['resources'][target_resource][0]
        updated_resource_payload = {target_resource: updated_resource_payload}

    # Get resource and get all the ids
    response = manage_security_resources('get', resource=target_resource)
    assert response.status_code == 200, f"Could not get the resource {target_resource}" \
                                        f"Expected status code was 200. Full response: {response.text}"
    administrator_users_ids = get_resource_admin_ids(response)

    # For each obtained ID check if it can be removed/updated
    for resource_id in administrator_users_ids:
        # Attempt to remove/update the resource
        response = manage_security_resources(action, resource=updated_resource_payload,
                                             params_values={target_resource: resource_id})

        assert response.status_code == 200, f"Resource could not be {action}d.\nExpected status code was 200.\n" \
                                            f"Full response: {response.text}"
        # Check if the failed items are present in the response
        failed_items = response.json()['data']['failed_items']
        assert failed_items, f"The response must have failed items. The administrator resource was {action}d." \
                             f"\nFull response: {response.text}"
        # Get failed item information
        item_error_code = failed_items[0]['error']['code']
        item_id = response.json()['data']['failed_items'][0]['id']

        # Check the error code and the IDs
        item_error_code == expected_error_code, f"The error code was not the expected.\nExpected error code " \
                                                f"was {expected_error_code}.\nFull response: {response.text}"
        item_id == resource_id, f"The ID do not match with the expected.\nExpected: {resource_id}\n" \
                                f"Current: {item_id}.\nFull response: {response.text}"

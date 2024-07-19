"""
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests will check if the 'RBAC' (Role-Based Access Control) feature of the API is working properly.
       Specifically, they will verify that when resources are added with the same identifier of previously
       existing ones, the previous relationships are not maintained. The 'RBAC' capability allows users
       accessing the API to be assigned a role that will define the privileges they have.

components:
    - api

suite: rbac

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
    - https://documentation.wazuh.com/current/user-manual/api/reference.html#tag/Security
    - https://en.wikipedia.org/wiki/Role-based_access_control

tags:
    - api
"""
import pytest
from pathlib import Path

from . import TEST_CASES_FOLDER_PATH
from wazuh_testing.constants.daemons import API_DAEMONS_REQUIREMENTS
from wazuh_testing.modules.api.utils import manage_security_resources
from wazuh_testing.utils.configuration import get_test_cases_data


# Marks
pytestmark = pytest.mark.server

# Paths
test_cases_path = Path(TEST_CASES_FOLDER_PATH, 'cases_add_old_resource.yaml')

# Configurations
_, test_metadata, test_cases_ids = get_test_cases_data(test_cases_path)
daemons_handler_configuration = {'daemons': API_DAEMONS_REQUIREMENTS}


# Tests
@pytest.mark.tier(level=0)
@pytest.mark.parametrize('test_configuration, test_metadata', zip(_, test_metadata), ids=test_cases_ids)
def test_add_old_resource(test_configuration, test_metadata, truncate_monitored_files, daemons_handler,
                          wait_for_api_start, set_security_resources):
    """
    description: Check if the security relationships of a previous user are removed from the system after adding a
                 new user with the same ID.

    wazuh_min_version: 4.2.0

    test_phases:
        - setup:
            - Truncate monitored files
            - Restart daemons defined in `daemons_handler_configuration` in this module
            - Wait until the API is ready to receive requests
            - Configure the security resources using the API
        - test:
            - Check if the user can be deleted
            - Check if the deleted user can be created with the same ID as before
            - Get relationships
            - Check if relationships between resources were removed
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
        - set_security_resources:
            type: fixture
            brief: Configure the security resources using the API and clean the added resources.

    assertions:
        - Verify that the testing user information exists.
        - Verify that the request to remove the testing agent is successfully processed.
        - Verify that the request to add the testing agent is successfully processed.
        - Verify that security relationships do not exist between the old and the new user.

    input_description: Different test cases are contained in an external YAML file which includes API configuration
                       parameters.

    expected_output:
        - 200 (Resource deleted)
        - 200 (Resource inserted)
        - Not empty

    tags:
        - rbac
    """
    target_resource = test_metadata['target_resource']['name']
    resource_id = test_metadata['target_resource']['id']
    relationships_keys = test_metadata['target_resource']['relationships_keys']
    resource_data = test_metadata['resources'][target_resource][0]

    # Check if the user can be deleted
    response = manage_security_resources('delete', params_values={target_resource: resource_id})
    assert response.status_code == 200, f"Could not delete {target_resource}.\nResponse: {response.text}"

    # Check if the deleted user can be created with the same ID as before
    response = manage_security_resources('post', resource={target_resource: resource_data})
    assert response.status_code == 200, f"Could not create the same {target_resource} as before." \
                                        f"\nResponse: {response.text}"

    # Get relationships
    relationships = response.json()['data']['affected_items'][0]
    # Check if relationships between resources were removed
    for key, value in relationships.items():
        if key in relationships_keys:
            assert not value, f"Relationship is not empty: {key}->{value}"

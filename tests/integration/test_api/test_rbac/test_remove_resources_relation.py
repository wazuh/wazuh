"""
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests will check if the 'RBAC' (Role-Based Access Control) feature of the API is working properly.
       Specifically, they will verify that the different relationships between users-roles-policies can be
       correctly removed. The 'RBAC' capability allows users accessing the API to be assigned a role
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
from wazuh_testing.constants.api import TARGET_ROUTE_MAP
from wazuh_testing.constants.daemons import API_DAEMONS_REQUIREMENTS
from wazuh_testing.modules.api.utils import manage_security_resources, remove_resources_relationship
from wazuh_testing.utils.configuration import get_test_cases_data

# Marks
pytestmark = pytest.mark.server

# Paths
test_cases_path = Path(TEST_CASES_FOLDER_PATH, 'cases_remove_resources_relation.yaml')

# Configurations
_, test_metadata, test_cases_ids = get_test_cases_data(test_cases_path)
daemons_handler_configuration = {'daemons': API_DAEMONS_REQUIREMENTS}


# Tests
@pytest.mark.tier(level=0)
@pytest.mark.parametrize('test_configuration, test_metadata', zip(_, test_metadata), ids=test_cases_ids)
def test_remove_resources_relation(test_configuration, test_metadata, truncate_monitored_files, daemons_handler,
                                   wait_for_api_start, set_security_resources):
    """
    description: Check if the resources exist after removing their relation.

    wazuh_min_version: 4.2.0

    test_phases:
        - setup:
            - Truncate monitored files
            - Restart daemons defined in `daemons_handler_configuration` in this module
            - Wait until the API is ready to receive requests
            - Configure the security resources using the API
        - test:
            - Remove relation between origin and target
            - Verify that the target resource still exists independently from the relation
            - Check if the relation was removed
            - Verify that the origin resource still exists independently from the relation
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
        - Verify that the resource still exists independently from the relation
        - Verify that the user-role relationship is removed

    inputs:
        - The testing 'user_id' as a module attribute.
        - The testing 'role_id' as a module attribute.

    input_description: From the 'set_security_resources' fixture information is obtained
                       to perform the test, concretely the 'user_id' and 'role_id'.

    expected_output:
        - 0 (No errors when getting the target resource)
        - Non-empty relation
        - 0 (No errors when getting the origin resource)

    tags:
        - rbac
    """
    origin_resource_name = list(test_metadata['relationships'].keys())[0]
    target_resource_name = test_metadata['relationships'][origin_resource_name]
    origin_resource_id = test_metadata['resources_ids'][origin_resource_name][0]
    target_resource_id = test_metadata['resources_ids'][target_resource_name][0]
    origin_resource = {origin_resource_name: origin_resource_id}
    target_resource = {target_resource_name: target_resource_id}
    relation = TARGET_ROUTE_MAP[origin_resource_name]

    # Remove relation between origin and target
    remove_resources_relationship(origin_resource=origin_resource, target_resource=target_resource)

    response = manage_security_resources(params_values=target_resource).json()
    # Verify that the target resource still exists independently from the relation
    assert response['error'] == 0, 'The target resource was deleted together with the relation.\n' \
                                   f"Full response: {response}"
    # Check if the relation was removed
    relation = response['data']['affected_items'][0][relation]
    assert not relation, f"The relation still existing after being deleted.\nExpected: []\nCurrent: {relation}"

    response = manage_security_resources(params_values=origin_resource).json()
    # Verify that the origin resource still exists independently from the relation
    assert response['error'] == 0, 'The target resource was deleted together with the relation.\n' \
                                   f"Full response: {response}"

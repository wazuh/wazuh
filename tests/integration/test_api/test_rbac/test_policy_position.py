"""
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests will check if the 'RBAC' (Role-Based Access Control) feature of the API is working properly.
       Specifically, they will verify that that the policies are applied to the roles in the right order.
       The 'RBAC' capability allows users accessing the API to be assigned a role
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
from copy import deepcopy
from pathlib import Path
from typing import List, Tuple

from . import TEST_CASES_FOLDER_PATH
from wazuh_testing.constants.daemons import API_DAEMONS_REQUIREMENTS
from wazuh_testing.modules.api.utils import manage_security_resources, remove_resources_relationship, relate_resources
from wazuh_testing.utils.configuration import get_test_cases_data

# Marks
pytestmark = pytest.mark.server

# Paths
test_cases_path = Path(TEST_CASES_FOLDER_PATH, 'cases_policy_position.yaml')

# Configurations
_, test_metadata, test_cases_ids = get_test_cases_data(test_cases_path)
daemons_handler_configuration = {'daemons': API_DAEMONS_REQUIREMENTS}


def get_policies_from_resource(origin_resource: dict) -> List:
    """Get the policies in the origin resource.

    Args:
        origin_resource (dict): Origin resource from which policies will be obtained.
    """
    # Get the origin resource by its ID
    response = manage_security_resources('get', params_values=origin_resource)
    # Get the policies list from the response
    policies_list = response.json()['data']['affected_items'][0]['policies']

    return policies_list


def remove_policy_relation(policy_id: int, policies_ids: List, origin_resource: dict,
                           policy_resource: dict) -> Tuple[List, List]:
    """Helper to remove a policy from different positions.

    Args:
        policy_id (int): ID of the policy whose relation will be removed.
        policies_ids (List): List of current policies.
        origin_resource (dict): Origin resource from which policies will be removed.
        policy_resource (dict): Policy to be removed.
    """
    # Remove the relationship between the origin resource and the policy in the position_from
    remove_resources_relationship(origin_resource=origin_resource, target_resource=policy_resource)
    # Remove policy from its `position_from`
    policies_ids.remove(policy_id)

    return policies_ids, get_policies_from_resource(origin_resource)


def relate_policy(position_to: int, policy_id: int, policies_ids: List, origin_resource: dict,
                  test_metadata: dict) -> Tuple[List, List]:
    """Relate the origin resource with the policy.

    Args:
        position_to (int): Position in which the policy will be inserted.
        policy_id (int): ID of the policy whose relation will be removed.
        policies_ids (List): List of current policies.
        origin_resource (dict): Origin resource from which policies will be removed.
        test_metadata (dict): Metadata that will be used to relate only the `origin_resource` with the `policy_id`
    """
    # Copy the metadata to a new object with the aim to modify it to relate only 1 policy at the specified `position_to`
    mutable_metadata = deepcopy(test_metadata)
    # Replace the necessary data
    policies = mutable_metadata['resources']['policy_ids']
    extra_params = mutable_metadata['extra_params']
    mutable_metadata['resources']['policy_ids'] = [policies[position_to]]
    # Set literal position coming from the test
    extra_params[position_to] = '='.join([extra_params[position_to].split('=')[0], str(position_to)])
    mutable_metadata['extra_params'] = [extra_params[position_to]]
    mutable_metadata['resources_ids']['policy_ids'] = [policy_id]
    # Relate the origin resource with the policy
    relate_resources(test_metadata=mutable_metadata)
    # Add policy to `position_to`
    policies_ids.insert(position_to, policy_id)

    return policies_ids, get_policies_from_resource(origin_resource)


# Tests
@pytest.mark.tier(level=0)
@pytest.mark.parametrize('test_configuration, test_metadata', zip(_, test_metadata), ids=test_cases_ids)
def test_policy_position(test_configuration, test_metadata, truncate_monitored_files, daemons_handler,
                         wait_for_api_start, set_security_resources):
    """
    description: Check if the correct order between role-policy relationships remain after removing some of them
                 and adding others using the 'position' parameter.

    wazuh_min_version: 4.2.0

    test_phases:
        - setup:
            - Truncate monitored files
            - Restart daemons defined in `daemons_handler_configuration` in this module
            - Wait until the API is ready to receive requests
            - Configure the security resources using the API
        - test:
            - Remove and add in the same position
            - Check if the policies from the response match with the list of policies IDs
            - Remove and add in different positions
            - Check if the policies from the response match with the list of policies IDs
            - Remove and add in the same position after changing the initial state
            - Check if the policies from the response match with the list of policies IDs
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
        - Verify that the policies from the response match with the list of policies IDs

    input_description: Different test cases are contained in an external YAML file which includes API configuration
                       parameters.

    expected_output:
        - List of policies from the response == list of policies with current positions

    tags:
        - rbac
    """
    resources_ids = test_metadata['resources_ids']
    policy_resource_name = test_metadata['target_resource']['name']
    policies_ids = resources_ids[policy_resource_name]
    # Get the origin from the first position in the resources IDs
    origin_resource_name = list(resources_ids.keys())[0]
    origin_resource_id = resources_ids[origin_resource_name][0]
    origin_resource = {origin_resource_name: origin_resource_id}

    # Remove and add in the same position
    position_from = 1
    position_to = 1
    policy_id = policies_ids[position_from]
    policy_resource = {policy_resource_name: policy_id}
    policies_ids, policies_list = remove_policy_relation(policy_id, policies_ids, origin_resource, policy_resource)
    # Check if the policies from the response match with the list of policies IDs
    assert policies_list == policies_ids, 'The positions of policies do not match with the expected.\n' \
                                          f"Expected: {policies_ids}.\nCurrent: {policies_list}"
    policies_ids, policies_list = relate_policy(position_to, policy_id, policies_list, origin_resource, test_metadata)
    # Check if the policies from the response match with the list of policies IDs
    assert policies_list == policies_ids, 'The positions of policies do not match with the expected.\n' \
                                          f"Expected: {policies_ids}.\nCurrent: {policies_list}"

    # Remove and add in different positions
    position_from = 2
    position_to = 0
    policy_id = policies_ids[position_from]
    policy_resource = {policy_resource_name: policy_id}
    policies_ids, policies_list = remove_policy_relation(policy_id, policies_ids, origin_resource, policy_resource)
    # Check if the policies from the response match with the list of policies IDs
    assert policies_list == policies_ids, 'The positions of policies do not match with the expected.\n' \
                                          f"Expected: {policies_ids}.\nCurrent: {policies_list}"
    policies_ids, policies_list = relate_policy(position_to, policy_id, policies_list, origin_resource, test_metadata)
    # Check if the policies from the response match with the list of policies IDs
    assert policies_list == policies_ids, 'The positions of policies do not match with the expected.\n' \
                                          f"Expected: {policies_ids}.\nCurrent: {policies_list}"

    # Remove and add in the same position after changing the initial state
    position_from = 0
    position_to = 0
    policy_id = policies_ids[position_from]
    policy_resource = {policy_resource_name: policy_id}
    policies_ids, policies_list = remove_policy_relation(policy_id, policies_ids, origin_resource, policy_resource)
    # Check if the policies from the response match with the list of policies IDs
    assert policies_list == policies_ids, 'The positions of policies do not match with the expected.\n' \
                                          f"Expected: {policies_ids}.\nCurrent: {policies_list}"
    policies_ids, policies_list = relate_policy(position_to, policy_id, policies_list, origin_resource, test_metadata)
    # Check if the policies from the response match with the list of policies IDs
    assert policies_list == policies_ids, 'The positions of policies do not match with the expected.\n' \
                                          f"Expected: {policies_ids}.\nCurrent: {policies_list}"

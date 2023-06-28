"""
Copyright (C) 2015-2023, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""
import pytest
import requests

from wazuh_testing.constants.api import RESOURCE_ROUTE_MAP
from wazuh_testing.modules.api.helpers import get_base_url, login, manage_security_resources, allow_user_to_authenticate


def add_resources(test_metadata: dict) -> dict:
    """Add the security resources using the API.

    Args:
        test_metadata (dict): Test metadata.
    """
    resources = test_metadata['resources']

    for resource in resources:
        for payload in resources[resource]:
            response = manage_security_resources('post', resource={resource: payload})
            if response.status_code != 200 or response.json()['error'] != 0:
                raise RuntimeError(f"Could not add {resource}.\nFull response: {response.text}")
            resource_id = response.json()['data']['affected_items'][0]['id']
            # Enable authentication for the new user
            if resource == 'user_ids':
                allow_user_to_authenticate(resource_id)
            # Set the resource ID for the test to use it
            test_metadata['resources_ids'][resource] = resource_id
            # Catch exception if the test does not have target resource
            try:
                test_metadata['target_resource']['id'] = resource_id
            except KeyError:
                pass

    return test_metadata


def remove_resources(test_metadata: dict) -> None:
    """Remove the security resources using the API.

    Args:
        test_metadata (dict): Test metadata.
    """
    resources = test_metadata['resources']

    for resource in resources:
        response = manage_security_resources('delete', params_values={resource: 'all'})
        if response.status_code != 200 or response.json()['error'] != 0:
            raise RuntimeError(f"Could not remove {resource}.\nFull response: {response.text}")


def relate_resources(test_metadata: dict) -> None:
    """Relate security resources.

    Args:
        get_base_request_data (fixture): Get authentication headers and base url.
    """
    resources_ids = test_metadata['resources_ids']
    relationships = test_metadata['relationships']
    target_route_map = {
        'role_ids': 'roles',
        'policy_ids': 'policies',
        'rule_ids': 'rules'
    }

    for origin in relationships:
        origin_id = resources_ids[origin]
        target_param = relationships[origin]
        target_value = resources_ids[target_param]
        target_route = target_route_map[target_param]
        url = get_base_url() + RESOURCE_ROUTE_MAP[origin] + f"/{origin_id}/{target_route}?{target_param}={target_value}"
        # Relate the origin resource with the target resource
        response = requests.post(url, headers=login()[0], verify=False)
        if response.status_code != 200 or response.json()['error'] != 0:
            raise RuntimeError(f"Could not relate {origin}: {origin_id} with {target_route}: {target_value}."
                               f"\nResponse: {response.text}")


@pytest.fixture
def set_security_resources(test_metadata: dict) -> None:
    """Configure the security resources using the API and clean the added resources.

    Args:
        test_metadata (dict): Test metadata.
    """
    remove_resources(test_metadata)
    test_metadata = add_resources(test_metadata)
    relate_resources(test_metadata)

    yield

    remove_resources(test_metadata)

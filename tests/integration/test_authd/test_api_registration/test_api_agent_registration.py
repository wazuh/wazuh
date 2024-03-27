'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests will check if the 'wazuh-authd' daemon correctly handles the enrollment requests
       from the API.

tier: 0

modules:
    - authd
    - API

components:
    - manager

daemons:
    - wazuh-authd
    - wazuh-api

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
    - https://documentation.wazuh.com/current/user-manual/registering/restful-api-registration.html

tags:
    - authd
    - api
'''
import ipaddress
import re
import requests
import pytest
import time
from pathlib import Path

from wazuh_testing.utils.client_keys import get_client_keys
from wazuh_testing.modules.api.utils import get_base_url, login
from wazuh_testing.utils.configuration import get_test_cases_data

from . import TEST_CASES_FOLDER_PATH


# Marks
pytestmark = [pytest.mark.server, pytest.mark.tier(level=0)]

# Configuration
test_cases_path = Path(TEST_CASES_FOLDER_PATH, 'cases_api_agent_registration.yaml')
test_configuration, test_metadata, test_cases_ids = get_test_cases_data(test_cases_path)

client_keys_update_timeout = 1

daemons_handler_configuration = {'all_daemons': True}

def retrieve_client_key_entry(agent_parameters):
    client_keys_dictionary = get_client_keys()
    desired_entries = []
    for client_keys_entry_dict in client_keys_dictionary:
        if agent_parameters.items() <= client_keys_entry_dict.items():
            desired_entries.append(agent_parameters)
    return desired_entries


def check_valid_agent_id(id):
    return re.match('(^[0-9][0-9][0-9]$)', id)


def check_valid_agent_key(key):
    return len(key) > 0


def check_api_data_response(api_response, expected_response):
    api_response_error = api_response['error']
    assert api_response_error == expected_response['error'], f"Expected API response \
                                                               {expected_response} but {api_response_error} \
                                                               was received instead"

    if api_response_error == 0:
        if 'key' in expected_response['data']:
            assert check_valid_agent_key(api_response['data']['key']), f"Invalid agent key received:\
                                                                        {api_response['data']['key']}"
            del api_response['data']['key']
            del expected_response['data']['key']

        if 'id' in expected_response['data']:
            assert check_valid_agent_id(api_response['data']['id']), f"Invalid id received:\
                                                                        {api_response['data']['id']}"
            del api_response['data']['id']
            del expected_response['data']['id']

    return api_response == expected_response


@pytest.mark.filterwarnings('ignore::urllib3.exceptions.InsecureRequestWarning')
@pytest.mark.parametrize('test_metadata', test_metadata, ids=test_cases_ids)
def test_agentd_server_configuration(test_metadata, truncate_monitored_files_module,
                                     daemons_handler_module, wait_for_api_startup_module):
    '''
    description:
        Checks `wazuh-api` responds correctly to agent registration requests. Also, ensure client.keys is update
        accordingly to the new agents parameters.

    wazuh_min_version:
        4.4.0

    parameters:
        - test_metadata:
            type: dict
            brief: Test case metadata.
        - truncate_monitored_files_module:
            type: fixture
            brief: Truncate all the log files and json alerts files before and after the test execution.
        - wait_for_api_startup_module:
            type: fixture
            brief: Wait for api starts.
        - daemons_handler_module:
            type: fixture
            brief: Handler of Wazuh daemons.

    assertions:
        - Verify that agents IPV4 agents can be registered
        - Verify that agents IPV6 agents can be registered
        - Verify that multiple agents with the same IP can not be registered.
        - Verify that the format of client.keys is consistent.

    input_description: Different test cases are contained in an external YAML file (api_agent_registration_cases.yaml).
                       Manager configuration is contained in agent_api_registration_configuration.yaml

    expected_output:
        - r"{'error':0," (When the agent has enrolled)
        - r"{'error':1706," (When the agent name or IP is already used)

    tags:
        - api
        - registration
    '''
    for stage in range(len(test_metadata['parameters'])):

        request_parameters = test_metadata['parameters'][stage]
        expected = test_metadata['expected'][stage]

        url = get_base_url()
        authentication_headers, _ = login()
        api_query = f"{url}/agents?"

        expected_client_keys_ip = request_parameters['agent_ip']
        if test_metadata['parameters'][stage]['ipv6']:
            expected_client_keys_ip = (ipaddress.IPv6Address(request_parameters['agent_ip']).exploded).upper()

        if 'ipv4_as_ipv6' in request_parameters:
            # IPv4 as IPv6 format: '::ffff:127.1.3.4'
            expected_client_keys_ip = expected_client_keys_ip.split(':')[3]

        expected_client_keys_entry = {'name': request_parameters['agent_name'],
                                      'ip':  expected_client_keys_ip}
        request_json = {'name': request_parameters['agent_name'],
                        'ip':  request_parameters['agent_ip']}

        response = requests.post(api_query, headers=authentication_headers, json=request_json,
                                 verify=False)

        # Assert response is the same specified in the api_registration_parameters
        assert check_api_data_response(response.json(), expected['json']), \
            f"The API response expected {expected['json']} but {response.json()} was received"

        # Ensure client keys is updated
        if response.json()['error'] == 0:
            time.sleep(client_keys_update_timeout)
            assert retrieve_client_key_entry(expected_client_keys_entry),\
                f"Client keys expected {expected_client_keys_entry} but no agent was found for that configuration"

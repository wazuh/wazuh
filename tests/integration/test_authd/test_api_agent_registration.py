'''
copyright: Copyright (C) 2015-2021, Wazuh Inc.

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
import os
import pytest
import time

from wazuh_testing.tools import API_LOG_FILE_PATH, CLIENT_KEYS_PATH
from wazuh_testing.api import get_api_details_dict
from wazuh_testing.tools.file import truncate_file, read_yaml
from wazuh_testing.tools.services import control_service


# Marks
pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]

# Configuration
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
api_registration_requets_file = os.path.join(test_data_path, 'api_agent_registration_cases.yaml')
daemons_handler_configuration = {'all_daemons': True}
api_registration_requests = read_yaml(api_registration_requets_file)
api_registration_requests_ids = [tcase['name'].replace(' ', '-').lower() for tcase in api_registration_requests]
client_keys_update_timeout = 1

def retrieve_client_key_entry(agent_parameters):
    with open(CLIENT_KEYS_PATH) as client_keys_file:
        client_keys_content = client_keys_file.readlines()
        client_keys_dictionary = []
        for entry in client_keys_content:
            client_key_agent_list = entry.split()

            client_key_agent_dict = {}
            client_key_agent_dict.update({'id': client_key_agent_list[0], 'name': client_key_agent_list[1],
                                          'ip': client_key_agent_list[2], 'key': client_key_agent_list[3]})

            client_keys_dictionary.append(client_key_agent_dict)

    desired_entries = []
    for client_keys_entry_dict in client_keys_dictionary:
        if agent_parameters.items() <= client_keys_entry_dict.items():
            desired_entries.append(agent_parameters)
    return desired_entries


@pytest.fixture(scope='module')
def clean_registered_agents():
    control_service('stop')
    truncate_file(CLIENT_KEYS_PATH)
    control_service('start')

    yield

    control_service('stop')
    truncate_file(CLIENT_KEYS_PATH)
    control_service('start')


@pytest.fixture(scope='module')
def truncate_api_log():
    truncate_file(API_LOG_FILE_PATH)


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
@pytest.mark.parametrize('api_registration_parameters', api_registration_requests, ids=api_registration_requests_ids)
def test_agentd_server_configuration(truncate_api_log, clean_registered_agents, wait_for_start_module,
                                     api_registration_parameters):
    '''
    description:
        Checks `wazuh-api` responds correctly to agent registration requests. Also, ensure client.keys is update
        accordingly to the new agents parameters.

    wazuh_min_version:
        4.4.0

    parameters:
        - api_registration_parameters:
            type: list
            brief: List of agent registration tcases.
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - truncate_api_log:
            type: fixture
            brief: Truncate API logs.
        - clean_registered_agents:
            type: fixture
            brief: Remove current registered agents in the environment.
        - wait_for_start_module:
            type: fixture
            brief: Wait for api starts.

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
    for stage in range(len(api_registration_parameters['parameters'])):

        request_parameters = api_registration_parameters['parameters'][stage]
        expected = api_registration_parameters['expected'][stage]

        api_details = get_api_details_dict()
        api_query = f"{api_details['base_url']}/agents?"

        expected_client_keys_ip = request_parameters['agent_ip']
        if api_registration_parameters['parameters'][stage]['ipv6']:
            expected_client_keys_ip = (ipaddress.IPv6Address(request_parameters['agent_ip']).exploded).upper()

        if 'ipv4_as_ipv6' in request_parameters:
            # IPv4 as IPv6 format: '::ffff:127.1.3.4'
            expected_client_keys_ip = expected_client_keys_ip.split(':')[3]

        expected_client_keys_entry = {'name': request_parameters['agent_name'],
                                      'ip':  expected_client_keys_ip}
        request_json = {'name': request_parameters['agent_name'],
                        'ip':  request_parameters['agent_ip']}

        response = requests.post(api_query, headers=api_details['auth_headers'], json=request_json,
                                 verify=False)

        # Assert response is the same specified in the api_registration_parameters
        assert check_api_data_response(response.json(), expected['json']), \
            f"The API response expected {expected['json']} but {response.json()} was received"

        # Ensure client keys is updated
        if response.json()['error'] == 0:
            time.sleep(client_keys_update_timeout)
            assert retrieve_client_key_entry(expected_client_keys_entry),\
                f"Client keys expected {expected_client_keys_entry} but no agent was found for that configuration"

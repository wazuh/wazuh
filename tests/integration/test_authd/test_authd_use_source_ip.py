'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: This module verifies the correct behavior of the setting 'use_source_ip'.

components:
    - authd

targets:
    - manager

daemons:
    - wazuh-authd
    - wazuh-db
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

tags:
    - enrollment
'''
import os
import ssl
import time
import pytest
from wazuh_testing.tools import WAZUH_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.file import read_yaml
from wazuh_testing.authd import validate_authd_response

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]

# Configurations

parameters = [
    {'USE_SOURCE_IP': 'yes'},
    {'USE_SOURCE_IP': 'no'}
]

metadata = [
    {'use_source_ip': 'yes'},
    {'use_source_ip': 'no'}
]

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_authd_configuration.yaml')
client_keys_path = os.path.join(WAZUH_PATH, 'etc', 'client.keys')
test_authd_use_source_ip_tests = read_yaml(os.path.join(test_data_path, 'test_authd_use_source_ip.yaml'))
configuration_ids = [f"Use_source_ip_{x['USE_SOURCE_IP']}" for x in parameters]
test_cases_ids = [case['name'].replace(' ', '_') for case in test_authd_use_source_ip_tests]
configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)

# Variables

log_monitor_paths = []
monitored_sockets_params = [('wazuh-modulesd', None, True), ('wazuh-db', None, True), ('wazuh-authd', None, True)]
receiver_sockets, monitored_sockets, log_monitors = None, None, None  # Set in the fixtures

# Fixtures


@pytest.fixture(scope='module', params=configurations, ids=configuration_ids)
def get_configuration(request):
    """
    Get configurations from the module
    """
    return request.param


@pytest.fixture(scope='function', params=test_authd_use_source_ip_tests, ids=test_cases_ids)
def get_current_test_case(request):
    """Get current test case from the module"""
    return request.param


@pytest.fixture(scope='function')
def configure_receiver_sockets(request, get_current_test_case):
    """
    Get configurations from the module
    """
    global receiver_sockets_params
    if 'ipv6' in get_current_test_case:
        receiver_sockets_params = [(("localhost", 1515), 'AF_INET6', 'SSL_TLSv1_2')]
    else:
        receiver_sockets_params = [(("localhost", 1515), 'AF_INET', 'SSL_TLSv1_2')]
    return receiver_sockets_params


def test_authd_use_source_ip(get_configuration, configure_environment, get_current_test_case, configure_receiver_sockets,
                             configure_sockets_environment, clean_client_keys_file_function, restart_wazuh_daemon_function,
                             wait_for_authd_startup_function, connect_to_sockets_function, tear_down):
    '''
    description:
        Checks that every input message in authd port generates the adequate output

    wazuh_min_version:
        4.2.0

    tier: 0

    parameters:
        - get_configuration:
            type: fixture
            brief: Get the configuration of the test.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - configure_sockets_environment:
            type: fixture
            brief: Configure the socket listener to receive and send messages on the sockets.
        - clean_client_keys_file_function:
            type: fixture
            brief: Cleans any previous key in client.keys file at function scope.
        - restart_authd_function:
            type: fixture
            brief: stops the wazuh-authd daemon
        - wait_for_authd_startup_function:
            type: fixture
            brief: Waits until Authd is accepting connections.
        - connect_to_sockets_function:
            type: fixture
            brief: Bind to the configured sockets at function scope.
        - test_case:
            type: list
            brief: List all the test cases for the test.
        - tear_down:
            type: fixture
            brief: Roll back the daemon and client.keys state after the test ends.

    assertions:
        - The manager uses the agent's IP as requested
        - Setting an IP overrides the configuration
        - If the IP is not defined and the setting is disabled, use 'any'

    input_description:
        Different test cases are contained in an external YAML file (test_authd_use_source_ip.yaml) which includes
        the different possible registration requests and the expected responses.

    expected_output:
        - Registration request responses on Authd socket
    '''

    metadata = get_configuration['metadata']
    test_case =  get_current_test_case['test_case']

    # Reopen socket (socket is closed by manager after sending message with client key)
    receiver_sockets[0].open()

    for stage in test_case:
        message = stage['input']
        receiver_sockets[0].send(message, size=False)
        timeout = time.time() + 10
        response = ''
        while response == '':
            response = receiver_sockets[0].receive().decode()
            if time.time() > timeout:
                assert response != '', 'The manager did not respond to the message sent.'
        if metadata['use_source_ip'] == 'yes' and get_current_test_case['ip_specified'] == 'no':
            if 'ipv6' in get_current_test_case:
                expected = {"status": "success", "name": "user1", "ip": "0000:0000:0000:0000:0000:0000:0000:0001"}
            else:
                expected = {"status": "success", "name": "user1", "ip": "127.0.0.1"}
        else:
            expected = stage['output']
        result, err_msg = validate_authd_response(response, expected)
        assert result == 'success', f"Failed stage '{get_current_test_case['name']}': {err_msg} Complete response: '{response}'"

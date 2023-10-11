'''
copyright: Copyright (C) 2015-2023, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: This module verifies the correct behavior of 'authd' under different name/IP combinations.

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
import socket
import time
import pytest
from wazuh_testing.tools import WAZUH_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.file import read_yaml
from wazuh_testing.authd import validate_authd_response

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]

# Configurations

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_authd_configuration.yaml')
client_keys_path = os.path.join(WAZUH_PATH, 'etc', 'client.keys')
test_cases = read_yaml(os.path.join(test_data_path, 'test_authd_valid_name_ip.yaml'))
configurations = load_wazuh_configurations(configurations_path, __name__)

# Variables

log_monitor_paths = []
receiver_sockets_params = [(("localhost", 1515), 'AF_INET', 'SSL_TLSv1_2')]
monitored_sockets_params = [('wazuh-modulesd', None, True), ('wazuh-db', None, True), ('wazuh-authd', None, True)]
receiver_sockets, monitored_sockets, log_monitors = None, None, None  # Set in the fixtures
hostname = socket.gethostname()


# Fixtures


@pytest.fixture(scope='module', params=configurations, ids=[__name__])
def get_configuration(request):
    """
    Get configurations from the module
    """
    return request.param


# Test

@pytest.mark.parametrize('test_case', [case['test_case'] for case in test_cases],
                         ids=[case['name'] for case in test_cases])
def test_authd_valid_name_ip(get_configuration, configure_environment, configure_sockets_environment,
                             clean_client_keys_file_function, connect_to_sockets_module, test_case,
                             restart_authd_function, wait_for_authd_startup_function, tear_down):
    '''
    description:
        Checks that every input message in authd port generates the adequate output.

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
            brief: Stops Wazuh and cleans any previous key in client.keys file at function scope.
        - restart_authd_function:
            type: fixture
            brief: Restart the 'wazuh-authd' daemon, clear the 'ossec.log' file and start a new file monitor.
        - wait_for_authd_startup_function:
            type: fixture
            brief: Waits until Authd is accepting connections.
        - connect_to_sockets_module:
            type: fixture
            brief: Bind to the configured sockets at module scope.
        - test_case:
            type: list
            brief: List all the test cases for the test.
        - tear_down:
            type: fixture
            brief: Roll back the daemon and client.keys state after the test ends.

    assertions:
        - The manager registers agents with valid IP and name
        - The manager rejects invalid input

    input_description:
        Different test cases are contained in an external YAML file (test_authd_valid_name_ip.yaml) which includes
        the different possible registration requests and the expected responses.

    expected_output:
        - Registration request responses on Authd socket
    '''

    # Reopen socket (socket is closed by manager after sending message with client key).
    receiver_sockets[0].open()

    # Set 'hostname' in test case's expected output message.
    if test_case.get('insert_hostname_in_query'):
        test_case['input'] = test_case.get('input').format(hostname)
        if 'message' in test_case.get('output'):
            test_case['output']['message'] = test_case['output'].get('message').format(hostname)

    # Send the message to the socket.
    receiver_sockets[0].send(test_case['input'], size=False)
    # Set the timeout and the empty response str.
    timeout = time.time() + 10
    response = ''

    # Wait the socket response or raise an error if timeout.
    while response == '':
        if time.time() > timeout:
            raise ConnectionResetError('Manager did not respond to sent message!')
        response = receiver_sockets[0].receive().decode()

    # Get the validated authd response.
    result, err_msg = validate_authd_response(response, test_case['output'])

    # ASSERTIONS.
    if test_case.get('expected_fail'):
        with pytest.raises(Exception):
            assert "ERROR" in result, f"No error raised. Complete response: '{response}'"
    else:
        assert result == 'success', f"Failed with {err_msg} Complete response: '{response}'"

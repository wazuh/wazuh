'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: This module verifies the correct behavior of the setting 'use_password'.

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

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]

# Configurations

parameters = [
    {'USE_PASSWORD': 'yes'},
    {'USE_PASSWORD': 'no'}
]

metadata = [
    {'use_password': 'yes'},
    {'use_password': 'no'}
]

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_authd_configuration.yaml')
client_keys_path = os.path.join(WAZUH_PATH, 'etc', 'client.keys')
test_authd_use_password_tests = read_yaml(os.path.join(test_data_path, 'test_authd_use_password.yaml'))
configuration_ids = [f"Use_password_{x['USE_PASSWORD']}" for x in parameters]
configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)
authd_default_password_path = os.path.join(WAZUH_PATH, 'etc', 'authd.pass')

# Variables
DEFAULT_TEST_PASSWORD = 'TopSecret'
AGENT_INPUT = "OSSEC A:'{}'"
AGENT_INPUT_WITH_PASS = "OSSEC PASS: {} OSSEC A:'{}'"
INVALID_REQUEST_MESSAGE = 'ERROR: Invalid request for new agent'
INVALID_PASSWORD_MESSAGE = 'ERROR: Invalid password'
SUCCESS_MESSAGE = "OSSEC K:'001 {} any "

log_monitor_paths = []
receiver_sockets_params = [(("localhost", 1515), 'AF_INET', 'SSL_TLSv1_2')]
monitored_sockets_params = [('wazuh-modulesd', None, True), ('wazuh-db', None, True), ('wazuh-authd', None, True)]
receiver_sockets, monitored_sockets, log_monitors = None, None, None  # Set in the fixtures


# Functions

def read_random_pass():
    """
    Search for the random password creation in Wazuh logs
    """
    osseclog_path = os.path.join(WAZUH_PATH, 'logs', 'ossec.log')
    passw = None
    try:
        with open(osseclog_path, 'r') as log_file:
            lines = log_file.readlines()
            for line in lines:
                if "Random password" in line:
                    passw = line.split()[-1]
            log_file.close()
    except IOError as exception:
        raise
    return passw

# Fixtures


@pytest.fixture(scope='function')
def reset_password(test_case, get_configuration):
    """
    Write the password file.
    """
    metadata = get_configuration['metadata']
    set_password = None
    try:
        if metadata['use_password'] == 'yes':
            set_password = 'defined'
            if test_case['random_pass'] == 'yes':
                set_password = 'random'
        else:
            set_password = 'undefined'
    except KeyError:
        pass

    # in case of random pass, remove /etc/authd.pass
    if set_password == 'random' or set_password == 'undefined':
        try:
            os.remove(authd_default_password_path)
        except FileNotFoundError:
            pass
        except IOError:
            raise
    # in case of defined pass, set predefined pass in  /etc/authd.pass
    elif set_password == 'defined':
        # Write authd.pass
        try:
            with open(authd_default_password_path, 'w') as pass_file:
                pass_file.write(DEFAULT_TEST_PASSWORD)
                pass_file.close()
        except IOError as exception:
            raise


@pytest.fixture(scope='module', params=configurations, ids=configuration_ids)
def get_configuration(request):
    """
    Get configurations from the module
    """
    return request.param


# Test

@pytest.mark.parametrize('test_case', [case for case in test_authd_use_password_tests],
                         ids=[test_case['name'] for test_case in test_authd_use_password_tests])
def test_authd_force_options(get_configuration, configure_environment, configure_sockets_environment,
                             clean_client_keys_file_function, reset_password, restart_wazuh_daemon_function,
                             wait_for_authd_startup_function, connect_to_sockets_function,
                             test_case, tear_down):
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
            brief: Cleans any previous key in client.keys file at function scope.
        - reset_password:
            type: fixture
            brief: Write the password file.
        - restart_authd_function:
            type: fixture
            brief: stops the wazuh-authd daemon.
        - wait_for_authd_startup_function:
            type: fixture
            brief: Waits until Authd is accepting connections.
        - connect_to_sockets_function:
            type: fixture
            brief: Bind to the configured sockets at function scope.
        - test_case:
            type: list
            brief: List with all the test cases for the test.
        - tear_down:
            type: fixture
            brief: Roll back the daemon and client.keys state after the test ends.

    assertions:
        - The random password works as expected.
        - A wrong password is rejected.
        - A request with password and use_password = 'no' is rejected.

    input_description:
        Different test cases are contained in an external YAML file (test_authd_use_password.yaml) which
        includes the different possible registration requests and the expected responses.

    expected_output:
        - Registration request responses on 'authd' socket.
    '''
    metadata = get_configuration['metadata']

    for stage in test_case['test_case']:
        # Reopen socket (socket is closed by manager after sending message with client key)
        receiver_sockets[0].open()

        # Creating input message
        if 'insert_random_pass_in_query' in stage and stage['insert_random_pass_in_query'] == 'yes':
            message = AGENT_INPUT_WITH_PASS.format(read_random_pass(), stage['user'])
        elif 'pass' in stage:
            message = AGENT_INPUT_WITH_PASS.format(stage['pass'], stage['user'])
        else:
            message = AGENT_INPUT.format(stage['user'])

        receiver_sockets[0].send(message, size=False)
        timeout = time.time() + 10
        response = ''
        while response == '':
            response = receiver_sockets[0].receive().decode()
            if time.time() > timeout:
                raise ConnectionResetError('Manager did not respond to sent message!')

        # Creating output message
        if metadata['use_password'] == 'yes':
            if 'random_pass' in test_case and 'insert_random_pass_in_query' in stage:
                expected = SUCCESS_MESSAGE.format(stage['user'])
            elif 'pass' in stage and stage['pass'] == DEFAULT_TEST_PASSWORD:
                expected = SUCCESS_MESSAGE.format(stage['user'])
            else:
                expected = INVALID_PASSWORD_MESSAGE
        # use_password = 'no'
        else:
            if 'pass' in stage or 'insert_random_pass_in_query' in stage:
                expected = INVALID_REQUEST_MESSAGE
            else:
                expected = SUCCESS_MESSAGE.format(stage['user'])

        assert response[:len(expected)] == expected, 'Failed: Response is different from expected'

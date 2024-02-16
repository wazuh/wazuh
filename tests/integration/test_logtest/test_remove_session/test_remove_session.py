'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: The 'wazuh-logtest' tool allows the testing and verification of rules and decoders against provided log examples
       remotely inside a sandbox in 'wazuh-analysisd'. This functionality is provided by the manager, whose work
       parameters are configured in the ossec.conf file in the XML rule_test section. Test logs can be evaluated through
       the 'wazuh-logtest' tool or by making requests via RESTful API. These tests will check if the logtest
       configuration is valid. Also checks rules, decoders, decoders, alerts matching logs correctly.

components:
    - logtest

suite: remove_session

targets:
    - manager

daemons:
    - wazuh-analysisd

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
    - https://documentation.wazuh.com/current/user-manual/reference/tools/wazuh-logtest.html
    - https://documentation.wazuh.com/current/user-manual/capabilities/wazuh-logtest/index.html
    - https://documentation.wazuh.com/current/user-manual/ruleset/testing.html?highlight=logtest
    - https://documentation.wazuh.com/current/user-manual/capabilities/wazuh-logtest/logtest-configuration.html
    - https://documentation.wazuh.com/current/user-manual/reference/daemons/wazuh-analysisd.html

tags:
    - logtest_configuration
'''
import json
from pathlib import Path

import pytest
from wazuh_testing.constants.paths.sockets import LOGTEST_SOCKET_PATH
from wazuh_testing.constants.daemons import ANALYSISD_DAEMON, WAZUH_DB_DAEMON
from wazuh_testing.tools.socket_controller import SocketController
from wazuh_testing.utils import configuration

from . import TEST_CASES_FOLDER_PATH


# Marks
pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]

# Configuration
t_cases_path = Path(TEST_CASES_FOLDER_PATH, 'cases_remove_session.yaml')
t_config_parameters, t_config_metadata, t_case_ids = configuration.get_test_cases_data(t_cases_path)

# Variables
receiver_sockets_params = [(LOGTEST_SOCKET_PATH, 'AF_UNIX', 'TCP')]
receiver_sockets = None  # Set in the fixtures

# Test daemons to restart.
daemons_handler_configuration = {'daemons': [ANALYSISD_DAEMON, WAZUH_DB_DAEMON]}


def create_session():
    msg = """{"version":1,"origin":{"name":"Integration Test","module":"api"},
        "command":"log_processing","parameters":{"event":"Jun 24 11:54:19 Master systemd[2099]:
        Started VTE child process 20118 launched by terminator process 17756.","log_format":"syslog",
        "location":"master->/var/log/syslog"}}"""

    receiver_sockets[0].send(msg, size=True)
    token = json.loads(receiver_sockets[0].receive(size=True).rstrip(b'\x00').decode())['data']['token']

    # Close socket
    for socket in receiver_sockets:
        try:
            # We flush the buffer before closing the connection if the protocol is TCP:
            if socket.protocol == 1:
                socket.sock.settimeout(5)
                socket.receive()  # Flush buffer before closing connection
            socket.close()
        except OSError as e:
            if e.errno == 9:
                # Do not try to close the socket again if it was reused or closed already
                pass

    # Renew socket for future connections
    receiver_sockets[0] = SocketController(address=LOGTEST_SOCKET_PATH, family='AF_UNIX', connection_protocol='TCP')
    return token


# Tests
@pytest.mark.parametrize('test_metadata', t_config_metadata, ids=t_case_ids)
def test_remove_session(test_metadata, daemons_handler_module, 
                        wait_for_logtest_startup, connect_to_sockets):
    '''
    description: Check if 'wazuh-logtest' correctly detects and removes the sessions under pre-defined scenarios.
                 To do this, the session input is sent and the output is received, then it checks if the received data
                 within the logtest socket is the same that the test case expected output.

    wazuh_min_version: 4.2.0

    tier: 0

    parameters:
        - daemons_handler_module:
            type: fixture
            brief: Wazuh logtests daemons handler.
        - wait_for_logtest_startup:
            type: fixture
            brief: Wait until logtest has begun.
        - connect_to_sockets:
            type: fixture
            brief: Function scope version of 'connect_to_sockets' which connects to the specified sockets for the test.
        - test_metadata:
            type: list
            brief: List of metadata values. (dicts with input, output and stage keys)

    assertions:
        - Verify that every test case output matches with the actual received.

    input_description: Some test cases are defined in the module. These include some input configurations stored in
                       the 'remove_session.yaml' and the session creation data from the module.

    expected_output:
        - r'Failed test case stage <test_case_index>: .*'

    tags:
        - analysisd
    '''
    if test_metadata["stage"] != 'Remove session OK':
        receiver_sockets[0].send(test_metadata['input'], size=True)
        reply = receiver_sockets[0].receive(size=True).rstrip(b'\x00').decode()
        expected = json.loads(test_metadata['output'])
    else:
        session_token = create_session()
        receiver_sockets[0].send(test_metadata['input'].format(session_token), size=True)
        reply = receiver_sockets[0].receive(size=True).rstrip(b'\x00').decode()
        expected = json.loads(test_metadata['output'].format(session_token))

    result = json.loads(reply)
    if 'messages' in expected['data'] and 'messages' in result['data']:
        message_expected = expected['data']['messages'][0]
        message_recieved = result['data']['messages'][0]
        if message_recieved.split(': ')[-1] == message_expected.split(': ')[-1]:
            expected['data']['messages'][0] = result['data']['messages'][0]

    assert expected == result, 'Failed test case stage {}'.format(test_metadata['stage'])

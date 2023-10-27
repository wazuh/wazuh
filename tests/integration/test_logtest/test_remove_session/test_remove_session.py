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
import os

import pytest
import yaml
from wazuh_testing.constants.paths import WAZUH_PATH
from wazuh_testing.tools.socket_controller import SocketController
from conftest import close_sockets


# Marks
pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]

# Configurations
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data/config_templates')
messages_path = os.path.join(test_data_path, 'config_remove_session.yaml')

with open(messages_path) as f:
    test_cases = yaml.safe_load(f)

# Variables
logtest_path = os.path.join(os.path.join(WAZUH_PATH, 'queue', 'sockets', 'logtest'))
receiver_sockets_params = [(logtest_path, 'AF_UNIX', 'TCP')]
receiver_sockets = None  # Set in the fixtures


def create_session():
    msg = """{"version":1,"origin":{"name":"Integration Test","module":"api"},
        "command":"log_processing","parameters":{"event":"Jun 24 11:54:19 Master systemd[2099]:
        Started VTE child process 20118 launched by terminator process 17756.","log_format":"syslog",
        "location":"master->/var/log/syslog"}}"""

    receiver_sockets[0].send(msg, size=True)
    token = json.loads(receiver_sockets[0].receive(size=True).rstrip(b'\x00').decode())['data']['token']

    # Close socket
    close_sockets(receiver_sockets)

    # Renew socket for future connections
    receiver_sockets[0] = SocketController(address=logtest_path, family='AF_UNIX', connection_protocol='TCP')
    return token


# Tests

@pytest.mark.parametrize('test_case',
                         [test_case['test_case'] for test_case in test_cases],
                         ids=[test_case['name'] for test_case in test_cases])
def test_remove_session(restart_required_logtest_daemons, wait_for_logtest_startup, connect_to_sockets_function,
                        test_case: list):
    '''
    description: Check if 'wazuh-logtest' correctly detects and removes the sessions under pre-defined scenarios.
                 To do this, the session input is sent and the output is received, then it checks if the received data
                 within the logtest socket is the same that the test case expected output.

    wazuh_min_version: 4.2.0

    tier: 0

    parameters:
        - restart_required_logtest_daemons:
            type: fixture
            brief: Wazuh logtests daemons handler.
        - wait_for_logtest_startup:
            type: fixture
            brief: Wait until logtest has begun.
        - connect_to_sockets_function:
            type: fixture
            brief: Function scope version of 'connect_to_sockets' which connects to the specified sockets for the test.
        - test_case:
            type: list
            brief: List of test_case stages. (dicts with input, output and stage keys)

    assertions:
        - Verify that every test case output matches with the actual received.

    input_description: Some test cases are defined in the module. These include some input configurations stored in
                       the 'remove_session.yaml' and the session creation data from the module.

    expected_output:
        - r'Failed test case stage <test_case_index>: .*'

    tags:
        - analysisd
    '''
    stage = test_case[0]

    if stage["stage"] != 'Remove session OK':
        receiver_sockets[0].send(stage['input'], size=True)
        reply = receiver_sockets[0].receive(size=True).rstrip(b'\x00').decode()
        expected = json.loads(stage['output'])
    else:
        session_token = create_session()
        receiver_sockets[0].send(stage['input'].format(session_token), size=True)
        reply = receiver_sockets[0].receive(size=True).rstrip(b'\x00').decode()
        expected = json.loads(stage['output'].format(session_token))

    result = json.loads(reply)
    if 'messages' in expected['data'] and 'messages' in result['data']:
        message_expected = expected['data']['messages'][0]
        message_recieved = result['data']['messages'][0]
        if message_recieved.split(': ')[-1] == message_expected.split(': ')[-1]:
            expected['data']['messages'][0] = result['data']['messages'][0]

    assert expected == result, 'Failed test case stage {}: {}'.format(
        test_case.index(stage) + 1,
        stage['stage'])

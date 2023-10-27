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

suite: invalid_token

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
    - https://documentation.wazuh.com/current/user-manual/reference/daemons/wazuh-analysisd.html

tags:
    - logtest_configuration
'''
import json
import os
import pytest
import yaml

from logtest import callback_session_initialized, callback_invalid_token
from wazuh_testing.constants.paths import WAZUH_PATH
from wazuh_testing.tools.socket_controller import SocketController

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]

# Configurations

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data/config_templates')
messages_path = os.path.join(test_data_path, 'config_invalid_session_token.yaml')
with open(messages_path) as f:
    test_cases = yaml.safe_load(f)
    tc = list(test_cases)

# Variables

logtest_path = os.path.join(os.path.join(WAZUH_PATH, 'queue', 'sockets', 'logtest'))


# Functions used on the test

def create_connection():
    return SocketController(address=logtest_path, family='AF_UNIX', connection_protocol='TCP')


def close_connection(connection):
    connection.close()


# Tests

@pytest.mark.parametrize('test_case',
                         [test_case['test_case'] for test_case in test_cases],
                         ids=[test_case['name'] for test_case in test_cases])
def test_invalid_session_token(restart_required_logtest_daemons, wait_for_logtest_startup, test_case):
    '''
    description: Check if `wazuh-logtest` correctly detects and handles errors when using a session token.
                 To do this, it sends the inputs through a socket, receives and decodes the message. Then, it checks
                 if any invalid token or session token is not caught.

    wazuh_min_version: 4.2.0

    tier: 0

    parameters:
        - restart_required_logtest_daemons:
            type: fixture
            brief: Wazuh logtests daemons handler.
        - wait_for_logtest_startup:
            type: fixture
            brief: Wait until logtest has begun.
        - test_case:
            type: list
            brief: List of test_case stages (dicts with input, output and stage keys)

    assertions:
        - Verify that new session is correctly initialized.
        - Verify that invalid session token is received.
        - Verify that errors are retrieved due to invalid session tokens.

    input_description: Some test cases are defined in the module. These include some input configurations stored in
                       the 'invalid_session_token.yaml'.

    expected_output:
        - r'Failed test case stage(s): .*' (When an error occurs, it is appended)
        - r'.*: .* is not a valid token' (An error that could be appended)
        - r'.*: Session initialized with token .*' (An error that could be appended)
        - 'Error when executing .* in daemon .*. Exit status: .*'

    tags:
        - session_error
        - analysisd
    '''
    errors = []
    stage = test_case[0]
    connection = create_connection()

    # Generate logtest request
    request_pattern = """{{ "version":1,
        "origin":{{"name":"Integration Test","module":"api"}},
        "command":"log_processing",
        "parameters":{{ "token":{} , {} , {} , {} }}
        }}"""

    input = request_pattern.format(stage['input_token'],
                                   stage['input_event'],
                                   stage['input_log_format'],
                                   stage['input_location'])

    # Send request
    connection.send(input, size=True)

    # Parse logtest reply as JSON
    result = json.loads(connection.receive(size=True).rstrip(b'\x00').decode())

    close_connection(connection)

    # Get the generated token
    new_token = result["data"]['token']

    # Check invalid token warning message
    match = callback_invalid_token(result["data"]['messages'][0])
    if match is None:
        errors.append(stage['stage'])

    # Check new token message is generated
    match = callback_session_initialized(result["data"]['messages'][1])
    if match is None:
        errors.append(stage['stage'])

    assert not errors, "Failed stage(s) :{}".format("\n".join(errors))

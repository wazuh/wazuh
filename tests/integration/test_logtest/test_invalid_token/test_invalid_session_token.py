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
from pathlib import Path
import pytest

from wazuh_testing.constants.paths.sockets import LOGTEST_SOCKET_PATH
from wazuh_testing.constants.daemons import ANALYSISD_DAEMON, WAZUH_DB_DAEMON
from wazuh_testing.tools.socket_controller import SocketController
from wazuh_testing.utils import configuration
from wazuh_testing.utils.callbacks import generate_callback
from wazuh_testing.modules.analysisd import patterns

from . import TEST_CASES_FOLDER_PATH

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]

# Configuration
t_cases_path = Path(TEST_CASES_FOLDER_PATH, 'cases_invalid_session_token.yaml')
t_config_parameters, t_config_metadata, t_case_ids = configuration.get_test_cases_data(t_cases_path)

# Test daemons to restart.
daemons_handler_configuration = {'daemons': [ANALYSISD_DAEMON, WAZUH_DB_DAEMON]}


# Tests
@pytest.mark.parametrize('test_metadata', t_config_metadata, ids=t_case_ids)
def test_invalid_session_token(test_metadata, daemons_handler_module, wait_for_logtest_startup):
    '''
    description: Check if `wazuh-logtest` correctly detects and handles errors when using a session token.
                 To do this, it sends the inputs through a socket, receives and decodes the message. Then, it checks
                 if any invalid token or session token is not caught.

    wazuh_min_version: 4.2.0

    tier: 0

    parameters:
        - daemons_handler_module:
            type: fixture
            brief: Wazuh logtests daemons handler.
        - wait_for_logtest_startup:
            type: fixture
            brief: Wait until logtest has begun.
        - test_metadata:
            type: list
            brief: List of metadata values (dicts with input, output and stage keys)

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
    connection = SocketController(address=LOGTEST_SOCKET_PATH, family='AF_UNIX', connection_protocol='TCP')

    # Generate logtest request
    request_pattern = """{{ "version":1,
        "origin":{{"name":"Integration Test","module":"api"}},
        "command":"log_processing",
        "parameters":{{ "token":{} , {} , {} , {} }}
        }}"""

    input = request_pattern.format(test_metadata['input_token'],
                                   test_metadata['input_event'],
                                   test_metadata['input_log_format'],
                                   test_metadata['input_location'])

    # Send request
    connection.send(input, size=True)

    # Parse logtest reply as JSON
    result = json.loads(connection.receive(size=True).rstrip(b'\x00').decode())

    connection.close()

    # Check invalid token warning 
    callback = generate_callback(patterns.LOGTEST_INVALID_TOKEN)
    match = callback(result["data"]['messages'][0])
    if match is None:
        errors.append(test_metadata['stage'])

    # Check new token message is generated
    callback = generate_callback(patterns.LOGTEST_SESSION_INIT)
    match = callback(result["data"]['messages'][1])
    if match is None:
        errors.append(test_metadata['stage'])

    assert not errors, "Failed stage(s) :{}".format("\n".join(errors))

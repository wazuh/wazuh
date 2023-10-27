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

suite: invalid_socket_input

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
import os
import pytest
import yaml
from struct import pack

from wazuh_testing.constants.paths import WAZUH_PATH

# Marks
pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]

# Configurations
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data/config_templates')
messages_path = os.path.join(test_data_path, 'config_invalid_socket_input.yaml')
with open(messages_path) as f:
    test_cases = yaml.safe_load(f)

# Variables
logtest_path = os.path.join(os.path.join(WAZUH_PATH, 'queue', 'sockets', 'logtest'))
receiver_sockets_params = [(logtest_path, 'AF_UNIX', 'TCP')]
receiver_sockets = None  # Set in the fixtures


# Tests

@pytest.mark.parametrize('test_case',
                         [test_case['test_case'] for test_case in test_cases],
                         ids=[test_case['name'] for test_case in test_cases])
def test_invalid_socket_input(restart_required_logtest_daemons, wait_for_logtest_startup, connect_to_sockets_function,
                              test_case: list):
    '''
    description: Check if `wazuh-logtest` correctly detects and handles errors when sending a message through
                 the socket to `wazuh-analysisd`. To do this, it sends the inputs through a socket(differentiating by
                 oversized messages), receives and decodes the message. Then, that message is compared with the test
                 case output.

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
        - Verify that the communication through the sockets works well by verifying that all the test cases produce
          the right output.
        - Verify that oversized messages log an error.

    input_description: Some test cases are defined in the module. These include some input configurations stored in
                       the 'invalid_socket_input.yaml'.

    expected_output:
        - r'Failed test case stage <test_case_index>: .*'

    tags:
        - errors
        - analysisd
    '''
    stage = test_case[0]

    if stage["stage"] != 'Oversize message':
        receiver_sockets[0].send(stage['input'], size=True)
    else:
        logtest_max_req_size = 2 ** 16
        oversize_header = pack("<I", logtest_max_req_size)
        receiver_sockets[0].send(stage['input'].format(oversize_header))

    result = receiver_sockets[0].receive(size=True).rstrip(b'\x00').decode()
    assert stage['output'] == result, 'Failed test case stage {}: {}'.format(test_case.index(stage) + 1,
                                                                             stage['stage'])

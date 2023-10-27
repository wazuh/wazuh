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

suite: invalid_rule_decoders_syntax

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
import pytest
import os
from yaml import safe_load
from shutil import copy
from json import loads

from wazuh_testing.constants.paths import WAZUH_PATH

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]

# Configurationsa

config_test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data/config_templates')
messages_path = os.path.join(config_test_data_path, 'config_invalid_decoder_syntax.yaml')
with open(messages_path) as f:
    test_cases = safe_load(f)

# Cases
cases_test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data/test_cases')

# Variables

logtest_path = os.path.join(os.path.join(WAZUH_PATH, 'queue', 'sockets', 'logtest'))
receiver_sockets_params = [(logtest_path, 'AF_UNIX', 'TCP')]


# Fixtures

@pytest.fixture(scope='function')
def configure_local_decoders(get_configuration):
    """Configure a custom decoder for testing."""

    # configuration for testing
    file_test = os.path.join(cases_test_data_path, get_configuration['decoder'])
    target_file_test = os.path.join(WAZUH_PATH, 'etc', 'decoders', get_configuration['decoder'])

    copy(file_test, target_file_test)

    yield

    # restore previous configuration
    os.remove(target_file_test)


@pytest.fixture(scope='module', params=test_cases, ids=[test_case['name'] for test_case in test_cases])
def get_configuration(request):
    """Get configurations from the module."""
    return request.param


# Tests
def test_invalid_decoder_syntax(get_configuration, configure_local_decoders,
                                restart_required_logtest_daemons,
                                wait_for_logtest_startup,
                                connect_to_sockets_function):
    '''
    description: Check if `wazuh-logtest` correctly detects and handles errors when processing a decoders file.
                 To do this, it sends a logtest request using the input configurations and parses the logtest reply
                 received looking for errors.

    wazuh_min_version: 4.2.0

    tier: 0

    parameters:
        - get_configuration:
            type: fixture
            brief: Get configuration from the module.
        - configure_local_decoders:
            type: fixture
            brief: Configure a custom decoder for testing.
        - restart_required_logtest_daemons:
            type: fixture
            brief: Wazuh logtests daemons handler.
        - wait_for_logtest_startup:
            type: fixture
            brief: Wait until logtest has begun.
        - connect_to_sockets_function:
            type: fixture
            brief: Function scope version of 'connect_to_sockets' which connects to the specified sockets for the test.

    assertions:
        - Verify that `wazuh-logtest` retrieves errors when the loaded decoders are invalid.

    input_description: Some test cases are defined in the module. These include some input configurations stored in
                       the 'invalid_decoder_syntax.yaml'.

    expected_output:
        - r'Failed stage(s) : .*' (When an error occurs, it is appended)
        - 'Error when executing {action} in daemon {daemon}. Exit status: {result}'

    tags:
        - errors
        - invalid_settings
        - decoder
        - analysisd
    '''
    # send the logtest request
    receiver_sockets[0].send(get_configuration['input'], size=True)

    # receive logtest reply and parse it
    response = receiver_sockets[0].receive(size=True).rstrip(b'\x00').decode()
    result = loads(response)

    # error list to enable multi-assert per test-case
    errors = []

    if 'output_error' in get_configuration and get_configuration['output_error'] != result["error"]:
        errors.append("output_error")

    if ('output_data_msg' in get_configuration and
            get_configuration['output_data_msg'] not in result["data"]["messages"][0]):
        errors.append("output_data_msg")

    if ('output_data_codemsg' in get_configuration and
            get_configuration['output_data_codemsg'] != result["data"]["codemsg"]):
        errors.append("output_data_codemsg")

    # error if any check fails
    assert not errors, "Failed stage(s) :{}".format("\n".join(errors))

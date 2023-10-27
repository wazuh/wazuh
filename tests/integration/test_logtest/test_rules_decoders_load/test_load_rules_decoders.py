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

suite: rules_decoders_load

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
import shutil

import pytest
import yaml
from wazuh_testing.constants.paths import WAZUH_PATH
from wazuh_testing.tools.socket_controller import SocketController

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]

# Configurations

config_test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data/config_templates')
messages_path = os.path.join(config_test_data_path, 'config_load_rules_decoders.yaml')
with open(messages_path) as f:
    test_cases = yaml.safe_load(f)
    tc = list(test_cases)

test_cases_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data/test_cases')

# Variables

logtest_path = os.path.join(os.path.join(WAZUH_PATH, 'queue', 'sockets', 'logtest'))


# Functions used on the test

def create_connection():
    return SocketController(address=logtest_path, family='AF_UNIX', connection_protocol='TCP')


def close_connection(connection):
    connection.close()


def create_dummy_session():
    connection = create_connection()
    dummy_request = """{ "version": 1,
            "origin":{"name":"Integration Test","module":"api"},
            "command":"log_processing",
            "parameters":{ "event": "Dummy event to generate new session token","log_format": "syslog",
            "location": "master->/var/log/syslog"}, "origin": {"name":"integration tests", "module": "qa"} }"""

    connection.send(dummy_request, size=True)
    token = json.loads(connection.receive(size=True).rstrip(b'\x00').decode())["data"]["token"]
    close_connection(connection)
    return token


# Tests
@pytest.mark.parametrize('test_case',
                         list(test_cases),
                         ids=[test_case['name'] for test_case in test_cases])
def test_load_rules_decoders(restart_required_logtest_daemons, wait_for_logtest_startup, test_case):
    '''
    description: Check if 'wazuh-logtest' does produce the right decoder/rule matching when processing a log under
                 different sets of configurations. To do this, it creates backup rules and decoders and copies the test
                 case rules and decoders to restore after the checks. It sends the requests to the logtest socket and
                 checks if the outputs match with the expected test cases.

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
        - Verify that the predecoder output matches with test case expected.
        - Verify that the decoder output matches with test case expected.
        - Verify that the rule output matches with test case expected.
        - Verify that the alert output matches with test case expected.

    input_description: Some test cases are defined in the module. These include some input configurations stored in
                       the 'remove_session.yaml' and the dummy session from the module.

    expected_output:
        - r'Failed stage(s) :.*'

    tags:
        - decoder
        - rules
        - analysisd
    '''
    # List to store assert messages
    errors = []

    if 'local_rules' in test_case:
        # save current rules
        shutil.copy('/var/ossec/etc/rules/local_rules.xml',
                    '/var/ossec/etc/rules/local_rules.xml.cpy')

        file_test = test_case['local_rules']
        # copy test rules
        shutil.copy(test_cases_data_path + file_test, '/var/ossec/etc/rules/local_rules.xml')
        shutil.chown('/var/ossec/etc/rules/local_rules.xml', "wazuh", "wazuh")

    if 'local_decoders' in test_case:
        # save current decoders
        shutil.copy('/var/ossec/etc/decoders/local_decoder.xml',
                    '/var/ossec/etc/decoders/local_decoder.xml.cpy')

        file_test = test_case['local_decoders']
        # copy test decoder
        shutil.copy(test_cases_data_path + file_test, '/var/ossec/etc/decoders/local_decoder.xml')
        shutil.chown('/var/ossec/etc/decoders/local_decoder.xml', "wazuh", "wazuh")

    # Create session token
    if 'same_session' in test_case and test_case['same_session']:
        session_token = create_dummy_session()

    for stage in test_case['test_case']:

        for i in range(stage['repeat'] if 'repeat' in stage else 1):

            connection = create_connection()
            # Generate logtest request
            if 'same_session' in test_case and test_case['same_session']:
                request_pattern = """{{ "version":1,
                    "origin":{{"name":"Integration Test","module":"api"}},
                    "command":"log_processing",
                    "parameters":{{ "token":"{}" , {} , {} , {} }}
                    }}"""
                input = request_pattern.format(session_token, stage['input_event'],
                                               test_case['input_log_format'],
                                               test_case['input_location'])
            else:
                request_pattern = """{{ "version":1,
                    "origin":{{"name":"Integration Test","module":"api"}},
                    "command":"log_processing",
                    "parameters":{{ {} , {} , {} }}
                    }}"""
                input = request_pattern.format(stage['input_event'],
                                               test_case['input_log_format'],
                                               test_case['input_location'])

            # Send request
            connection.send(input, size=True)

            # Get response
            response = connection.receive(size=True).rstrip(b'\x00').decode()

            # Parse logtest response as JSON
            result = json.loads(response)

            close_connection(connection)

            # Check predecoder
            if ('output_predecoder' in stage and
                    json.loads(stage['output_predecoder']) != result["data"]['output']['predecoder']):
                errors.append(stage['stage'])

            # Check decoder
            if ('output_decoder' in stage and
                    json.loads(stage['output_decoder']) != result["data"]['output']['decoder']):
                errors.append(stage['stage'])

            # Check rule
            if 'output_rule_id' in stage and stage['output_rule_id'] != result["data"]['output']['rule']['id']:
                errors.append(stage['stage'])

            # Check alert
            if 'output_alert' in stage and stage['output_alert'] != result["data"]['alert']:
                errors.append(stage['stage'])

    if 'local_rules' in test_case:
        # restore previous rules
        shutil.move('/var/ossec/etc/rules/local_rules.xml.cpy',
                    '/var/ossec/etc/rules/local_rules.xml')
    shutil.chown('/var/ossec/etc/rules/local_rules.xml', "wazuh", "wazuh")

    if 'local_decoders' in test_case:
        # restore previous decoders
        shutil.move('/var/ossec/etc/decoders/local_decoder.xml.cpy',
                    '/var/ossec/etc/decoders/local_decoder.xml')
        shutil.chown('/var/ossec/etc/decoders/local_decoder.xml', "wazuh", "wazuh")

    assert not errors, "Failed stage(s) :{}".format("\n".join(errors))

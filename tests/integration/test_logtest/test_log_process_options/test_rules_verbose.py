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

suite: log_process_option

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
import shutil
import re

import pytest
from wazuh_testing.constants.paths.sockets import LOGTEST_SOCKET_PATH
from wazuh_testing.constants import users
from wazuh_testing.constants.paths import ruleset
from wazuh_testing.utils import configuration

from . import TEST_CASES_FOLDER_PATH, TEST_RULES_PATH


# Marks
pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]

# Configuration
t_cases_path = Path(TEST_CASES_FOLDER_PATH, 'cases_rules_verbose.yaml')
t_config_parameters, t_config_metadata, t_case_ids = configuration.get_test_cases_data(t_cases_path)

# Variables
receiver_sockets_params = [(LOGTEST_SOCKET_PATH, 'AF_UNIX', 'TCP')]
receiver_sockets = None

# Test daemons to restart.
daemons_handler_configuration = {'daemons': ['wazuh-analysisd', 'wazuh-db']}

local_rules_debug_messages = ['Trying rule: 880000 - Parent rules verbose', '*Rule 880000 matched',
                              '*Trying child rules', 'Trying rule: 880001 - test last_match', '*Rule 880001 matched',
                              '*Trying child rules', 'Trying rule: 880002 - test_child test_child']


# Fixtures
@pytest.fixture(scope='function')
def configure_rules_list(test_metadata):
    """Configure a custom rules for testing.

    Restart Wazuh is not needed for applying the configuration, is optional.
    """

    # save current rules
    shutil.copy(ruleset.LOCAL_RULES_PATH, ruleset.LOCAL_RULES_PATH + '.cpy')

    file_test = Path(TEST_RULES_PATH, test_metadata['rule_file'])
    # copy test rules
    shutil.copy(file_test, ruleset.LOCAL_RULES_PATH)
    shutil.chown(ruleset.LOCAL_RULES_PATH, users.WAZUH_UNIX_USER, users.WAZUH_UNIX_GROUP)

    yield

    # restore previous configuration
    shutil.move(ruleset.LOCAL_RULES_PATH + '.cpy', ruleset.LOCAL_RULES_PATH)
    shutil.chown(ruleset.LOCAL_RULES_PATH, users.WAZUH_UNIX_USER, users.WAZUH_UNIX_GROUP)



# Tests
@pytest.mark.parametrize('test_metadata', t_config_metadata, ids=t_case_ids)
def test_rules_verbose(test_metadata, daemons_handler_module,
                       configure_rules_list, wait_for_logtest_startup,
                       connect_to_sockets_function):
    '''
    description: Check if 'wazuh-logtest' works correctly in 'verbose' mode for rules debugging. To do this, it sends
                 the inputs through a socket, receives and decodes the message. Then, it checks
                 if any invalid token or session token is not caught.

    wazuh_min_version: 4.2.0

    tier: 0

    parameters:
        - test_metadata:
            type: list
            brief: List of metadata values. (dicts with input, output and stage keys)
        - daemons_handler_module:
            type: fixture
            brief: Wazuh logtests daemons handler.
        - configure_rules_list:
            type: fixture
            brief: Configure a custom rules for testing. Restart Wazuh is not needed for applying the configuration
                   is optional.
        - wait_for_logtest_startup:
            type: fixture
            brief: Wait until logtest has begun.
        - connect_to_sockets_function:
            type: fixture
            brief: Function scope version of 'connect_to_sockets' which connects to the specified sockets for the test.

    assertions:
        - Verify that the logtest reply message has no run error.
        - Verify that the 'rule_id' within the reply message is correct.
        - Verify that logtest is running in verbose mode.
        - Verify that when running in verbose mode the local rule debug messages has been written
        - Verify that when running in verbose mode the local rule debug messages written are the expected count.
        - Verify that if a warning message is caught it matches with any test case message.

    input_description: Some test cases are defined in the module. These include some input configurations stored in
                       the 'rules_verbose.yaml'.

    expected_output:
        - 'The rules_debug field was not found in the response data'
        - 'The warning message was not found in the response data'
        - 'Error when executing .* in daemon .*. Exit status: .*'

    tags:
        - settings
        - analysisd
    '''
    # send the logtest request
    receiver_sockets[0].send(test_metadata['input'], size=True)

    # receive logtest reply and parse it
    response = receiver_sockets[0].receive(size=True).rstrip(b'\x00').decode()
    result = json.loads(response)

    assert result['error'] == 0
    assert result['data']['output']['rule']['id'] == test_metadata['rule_id']

    if 'verbose_mode' in test_metadata and test_metadata['verbose_mode']:
        if 'rules_debug' in result['data']:
            assert result['data']['rules_debug'][-len(local_rules_debug_messages):] == local_rules_debug_messages
        else:
            assert False, 'The rules_debug field was not found in the response data'

    else:
        assert 'rules_debug' not in result['data']

    if 'warning_message' in test_metadata:
        r = re.compile(test_metadata['warning_message'])
        match_list = list(filter(r.match, result['data']['messages']))
        assert match_list, 'The warning message was not found in the response data'

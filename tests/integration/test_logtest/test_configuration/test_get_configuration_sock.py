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

suite: configuration

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
from pathlib import Path
import re

import pytest
from wazuh_testing.constants.paths.sockets import ANALYSISD_ANALISIS_SOCKET_PATH
from wazuh_testing.utils import configuration

from . import CONFIGURATIONS_FOLDER_PATH, TEST_CASES_FOLDER_PATH

# Marks
pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]

# Configuration
t_config_path = Path(CONFIGURATIONS_FOLDER_PATH, 'configuration_wazuh_conf.yaml')
t_cases_path = Path(TEST_CASES_FOLDER_PATH, 'cases_get_configuration_sock.yaml')
t_config_parameters, t_config_metadata, t_case_ids = configuration.get_test_cases_data(t_cases_path)
t_configurations = configuration.load_configuration_template(t_config_path, t_config_parameters, t_config_metadata)

# Variables
receiver_sockets_params = [(ANALYSISD_ANALISIS_SOCKET_PATH, 'AF_UNIX', 'TCP')]
receiver_sockets = None
msg_get_config = '{"version": 1, "origin": {"module": "api"}, "command": "getconfig", "module": "api",\
                 "parameters": {"section": "rule_test"}}'

# Test daemons to restart.
daemons_handler_configuration = {'all_daemons': True}

# Test
@pytest.mark.parametrize('test_configuration, test_metadata', zip(t_configurations, t_config_metadata), ids=t_case_ids)
def test_get_configuration_sock(test_configuration, test_metadata, set_wazuh_configuration,
                                daemons_handler, connect_to_sockets):
    '''
    description: Check analysis Unix socket returns the correct Logtest configuration under different sets of
                 configurations, `wazuh-analisysd` returns the right information from the `rule_test` configuration
                 block. To do this, it overwrites wrong field values and checks that the values within the received
                 message after establishing a connection using the logtest AF_UNIX socket that uses TCP are the same
                 that the loaded fields from the 'wazuh_conf.yaml' file.

    wazuh_min_version: 4.2.0

    tier: 0

    parameters:
        - get_configuration:
            type: fixture
            brief: Get configuration from the module.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing
        - restart_wazuh:
            type: fixture
            brief: Restart wazuh, ossec.log and start a new monitor.
        - connect_to_sockets:
            type: fixture
            brief: Function scope version of 'connect_to_sockets' which connects to the specified sockets for the test.

    assertions:
        - Verify that a valid configuration is loaded.
        - Verify that wrong loaded configurations are fixed with limit values.
        - Verify that each message field received matches the loaded configuration fields.

    input_description: Five test cases are defined in the module. These include some configurations stored in
                       the 'wazuh_conf.yaml'.

    expected_output:
        - 'Real message was: .*'
        - 'Expected value in enabled tag: .*. Value received: .*'
        - 'Expected value in threads tag: .*.  Value received: .*'
        - 'Expected value in max_sessions tag: .*.  Value received: .*'
        - 'Expected value in session_timeout tag: .*.  Value received: .*'

    tags:
        - settings
        - analysisd
    '''

    if 'invalid_threads_conf' == test_metadata['tags']:
        test_metadata['threads'] = '128'
    elif 'invalid_users_conf' == test_metadata['tags']:
        test_metadata['max_sessions'] = '500'
    elif 'invalid_timeout_conf' == test_metadata['tags']:
        test_metadata['session_timeout'] = '31536000'

    receiver_sockets[0].send(msg_get_config, True)
    msg_recived = receiver_sockets[0].receive().decode()

    matched = re.match(r'.*{"enabled":"(\S+)","threads":(\d+),"max_sessions":(\d+),"session_timeout":(\d+)}}',
                       msg_recived)
    assert matched is not None, f'Real message was: "{msg_recived}"'

    assert matched.group(1) == test_metadata['enabled'], f"""Expected value in enabled tag:
           '{test_metadata['enabled']}'. Value received: '{matched.group(1)}'"""

    assert matched.group(2) == test_metadata['threads'], f"""Expected value in threads tag:
           '{test_metadata['threads']}'. Value received: '{matched.group(2)}'"""

    assert matched.group(3) == test_metadata['max_sessions'], f"""Expected value in max_sessions tag:
           '{test_metadata['max_sessions']}'. Value received: '{matched.group(3)}'"""

    assert matched.group(4) == test_metadata['session_timeout'], f"""Expected value in session_timeout tag:
           '{test_metadata['session_timeout']}'. Value received: '{matched.group(4)}'"""

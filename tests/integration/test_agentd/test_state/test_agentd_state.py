'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: The 'wazuh-agentd' program is the client-side daemon that communicates with the server.
       These tests will check if the content of the 'wazuh-agentd' daemon statistics file is valid.
       The statistics files are documents that show real-time information about the Wazuh environment.

components:
    - agentd

targets:
    - agent

daemons:
    - wazuh-agentd
    - wazuh-remoted

os_platform:
    - linux
    - windows

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
    - Windows 10
    - Windows Server 2019
    - Windows Server 2016

references:
    - https://documentation.wazuh.com/current/user-manual/reference/statistics-files/wazuh-agentd-state.html

tags:
    - stats_file
'''

import json
import pytest
from pathlib import Path
import sys
import time

from wazuh_testing.constants.platforms import WINDOWS
from wazuh_testing.modules.agentd.configuration import AGENTD_DEBUG, AGENTD_WINDOWS_DEBUG
from wazuh_testing.modules.agentd.utils import parse_state_file
from wazuh_testing.tools.simulators.remoted_simulator import RemotedSimulator
from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template

from . import CONFIGS_PATH, TEST_CASES_PATH
from utils import wait_keepalive, wait_ack, wait_state_update, wait_agent_notification

# Marks
pytestmark = [pytest.mark.agent, pytest.mark.linux, pytest.mark.win32, pytest.mark.tier(level=0)]

# Configuration and cases data.
configs_path = Path(CONFIGS_PATH, 'wazuh_conf.yaml')
cases_path = Path(TEST_CASES_PATH, 'wazuh_state_config_tests.yaml')

# Test configurations.
config_parameters, test_metadata, test_cases_ids = get_test_cases_data(cases_path)
test_configuration = load_configuration_template(configs_path, config_parameters, test_metadata)

if sys.platform == WINDOWS:
    local_internal_options = {AGENTD_WINDOWS_DEBUG: '2'}
else:
    local_internal_options = {AGENTD_DEBUG: '2'}

daemons_handler_configuration = {'all_daemons': True}


def start_remoted_server(test_metadata) -> None:
    """"Start RemotedSimulator if test case need it"""
    if 'remoted' in test_metadata and test_metadata['remoted']:
        remoted_server = RemotedSimulator()
        remoted_server.start()
    else:
        remoted_server = None
    return remoted_server


@pytest.mark.parametrize('test_configuration, test_metadata', zip(test_configuration, test_metadata), ids=test_cases_ids)
def test_agentd_state(test_configuration, test_metadata, set_wazuh_configuration, remove_state_file, configure_local_internal_options,
                      truncate_monitored_files, clean_keys, add_keys, daemons_handler):
    '''
    description: Check that the statistics file 'wazuh-agentd.state' is created automatically
                 and verify that the content of its fields is correct.

    wazuh_min_version: 4.2.0

    tier: 0

    parameters:
        - test_configuration:
            type: data
            brief: Configuration used in the test.
        - test_metadata:
            type: data
            brief: Configuration cases.
        - set_wazuh_configuration:
            type: fixture
            brief: Configure a custom environment for testing.
        - remove_state_file:
            type: fixture
            brief: Removes the wazuh-agentd.state file
        - configure_local_internal_options:
            type: fixture
            brief: Set internal configuration for testing.
        - truncate_monitored_files:
            type: fixture
            brief: Reset the 'ossec.log' file and start a new monitor.
        - clean_keys:
            type: fixture
            brief: Cleans keys file content
        - add_keys:
            type: fixture
            brief: Adds keys to keys file
        - daemons_handler:
            type: fixture
            brief: Handler of Wazuh daemons.

    assertions:
        - Verify that the 'wazuh-agentd.state' statistics file has been created.
        - Verify that the information stored in the 'wazuh-agentd.state' statistics file
          is consistent with the connection status to the 'wazuh-remoted' daemon.

    input_description: An external YAML file (wazuh_conf.yaml) includes configuration settings for the agent.
                       Different test cases that are contained in an external YAML file (wazuh_state_tests.yaml)
                       that includes the parameters and their expected responses.

    expected_output:
        - r'pending'
        - r'connected'
    '''

    # Start RemotedSimulator if test case need it
    remoted_server = start_remoted_server(test_metadata)

    # Check fields for every expected output type
    for expected_output in test_metadata['output']:
        check_fields(expected_output, remoted_server)

    #Shutdown simulator
    if remoted_server:
        remoted_server.destroy()


def wait_for_custom_message_response(expected_status: str, remoted_server: RemotedSimulator, timeout: int = 350):
    """Request remoted_server the status of the agent

    Args:
        parameters:
        - expected_status:
            type: string
            brief: Expected status reported from RemotedSimulator
        - remoted_server:
            type: RemotedSimulator
            brief: RemotedSimulator instance
        - timeout:
            type: int
            brief: Timeout to find the message with the requested information
    Returns:
        dict with state info
    """
    custom_message = f'#!-req {remoted_server.request_counter} agent getstate'
    remoted_server.send_custom_message(custom_message)
    # Start count to set the timeout.
    start_time = time.time()

    while time.time() - start_time < timeout:
        if remoted_server.custom_message_sent:
            if expected_status in (response := remoted_server.last_message_ctx.get('message')):
                response = response[response.find('{'):]
                response = json.loads(response)
                response = response['data']
                return response

    return None


def check_fields(expected_output, remoted_server):
    """Check every field agains expected data

    Args:
        - expected_output:
            type: dict
            brief: expected output block
        - remoted_server:
            type: RemotedSimulator
            brief: RemotedSimulator instance
    """
    checks = {
        'last_ack': {'handler': check_last_ack, 'precondition': [wait_ack]},
        'last_keepalive': {'handler': check_last_keepalive, 'precondition': [wait_keepalive]},
        'msg_count': {'handler': check_msg_count, 'precondition': [wait_keepalive]},
        'status': {'handler': check_status, 'precondition': []}
    }

    if expected_output['type'] == 'file':
        get_state_callback = parse_state_file
    else:
        get_state_callback = wait_for_custom_message_response

    for field, expected_value in expected_output['fields'].items():
        # Check if expected value is valiable and mandatory
        if expected_value != '':
            for precondition in checks[field].get('precondition'):
                precondition()
            assert checks[field].get('handler')(expected_value, get_state_callback, expected_output['fields']['status'], remoted_server)


def check_last_ack(expected_value: str=None, get_state_callback=None, expected_status: str=None, remoted_server: RemotedSimulator=None):
    """Check `last_ack` field

    Args:
        - expected_value:
            type: string
            brief: expected output in test case
        - get_state_callback:
            type: function
            brief: Callback to get state
        - expected_status:
            type: string
            brief: Expected status reported from RemotedSimulator
        - remoted_server:
            type: RemotedSimulator
            brief: RemotedSimulator instance

    Returns:
        boolean: `True` if check was successfull. Otherwise asserts the test
    """
    if get_state_callback == parse_state_file:
        wait_state_update()
        current_value = get_state_callback()['last_ack']
    else:
        current_value = get_state_callback(expected_status, remoted_server)
        if current_value:
            current_value = current_value['last_ack']
        else:
            wait_ack()
    if expected_value == '':
        return expected_value == current_value

    return True


def check_last_keepalive(expected_value: str=None, get_state_callback=None, expected_status: str=None, remoted_server: RemotedSimulator=None):
    """Check `last_keepalive` field

    Args:
        - expected_value:
            type: string
            brief: expected output in test case
        - get_state_callback:
            type: function
            brief: Callback to get state
        - expected_status:
            type: string
            brief: Expected status reported from RemotedSimulator
        - remoted_server:
            type: RemotedSimulator
            brief: RemotedSimulator instance

    Returns:
        boolean: `True` if check was successfull. Otherwise the test asserts
    """
    if get_state_callback == parse_state_file:
        wait_state_update()
        current_value = get_state_callback()['last_keepalive']
    else:
        current_value = get_state_callback(expected_status, remoted_server)
        if current_value:
            current_value = current_value['last_keepalive']
        else:
            wait_ack()
    if expected_value == '':
        return expected_value == current_value

    return True


def check_msg_count(expected_value: str=None, get_state_callback=None, expected_status: str=None, remoted_server: RemotedSimulator=None):
    """Check `msg_count` field

    Args:
        - expected_value:
            type: string
            brief: expected output in test case
        - get_state_callback:
            type: function
            brief: Callback to get state
        - expected_status:
            type: string
            brief: Expected status reported from RemotedSimulator
        - remoted_server:
            type: RemotedSimulator
            brief: RemotedSimulator instance

    Returns:
        boolean: `True` if check was successfull. Otherwise the test asserts
    """
    if get_state_callback == parse_state_file:
        wait_state_update()
        current_value = get_state_callback()['msg_count']
    else:
        current_value = get_state_callback(expected_status, remoted_server)
        if current_value:
            current_value = current_value['msg_count']
    if expected_value == '':
        return expected_value == current_value

    wait_agent_notification(current_value)
    return True


def check_status(expected_value: str=None, get_state_callback=None, expected_status: str=None, remoted_server: RemotedSimulator=None):
    """Check `status` field

    Args:
        - expected_value:
            type: string
            brief: expected output in test case
        - get_state_callback:
            type: function
            brief: Callback to get state
        - expected_status:
            type: string
            brief: Expected status reported from RemotedSimulator
        - remoted_server:
            type: RemotedSimulator
            brief: RemotedSimulator instance

    Returns:
        boolean: `True` if check was successfull. Otherwise the test asserts
    """
    current_value = None

    if expected_value != 'pending':
        wait_keepalive()
        if get_state_callback == parse_state_file:
            # Sleep while file is updated
            time.sleep(5)
            wait_state_update()
            current_value = get_state_callback()['status']
        else:
            current_value = get_state_callback(expected_status, remoted_server)
            if current_value:
                current_value = current_value['status']
            else:
                wait_keepalive()
                return True
    else:
        # Sleep while file is updated
        time.sleep(5)
        wait_state_update()
        current_value = get_state_callback()['status']

    return expected_value == current_value

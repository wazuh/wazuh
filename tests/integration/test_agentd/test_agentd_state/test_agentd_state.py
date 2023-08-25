'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

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

import pytest
from pathlib import Path
import sys
from time import sleep

from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.constants.paths.variables import AGENTD_STATE
from wazuh_testing.constants.paths.configurations import WAZUH_CLIENT_KEYS_PATH, WAZUH_LOCAL_INTERNAL_OPTIONS
from wazuh_testing.constants.platforms import WINDOWS
from wazuh_testing.modules.agentd.configuration import AGENTD_DEBUG, AGENTD_WINDOWS_DEBUG
from wazuh_testing.modules.agentd.patterns import AGENTD_UPDATING_STATE_FILE, AGENTD_SENDING_KEEP_ALIVE, AGENTD_RECEIVED_ACK, AGENTD_RECEIVED_ACK 
from wazuh_testing.tools.monitors.file_monitor import FileMonitor
from wazuh_testing.tools.simulators.remoted_simulator import RemotedSimulator
from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template, change_internal_options
from wazuh_testing.utils import file, callbacks
from wazuh_testing.utils.services import check_if_process_is_running, control_service

from . import CONFIGS_PATH, TEST_CASES_PATH

# Marks
pytestmark = pytest.mark.tier(level=0)

from . import CONFIGS_PATH, TEST_CASES_PATH

# Marks
pytestmark = pytest.mark.tier(level=0)

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

print(test_configuration)

def start_remoted_server(test_metadata) -> None:
    """"Start RemotedSimulator if test case need it"""
    if 'remoted' in test_metadata and test_metadata['remoted']:
        remoted_server = RemotedSimulator()
        return remoted_server

def add_custom_key():
    """Set test client.keys file"""
    with open(WAZUH_CLIENT_KEYS_PATH, 'w+') as client_keys:
        client_keys.write("100 ubuntu-agent any TopSecret")

@pytest.mark.parametrize('test_configuration, test_metadata', zip(test_configuration, test_metadata), ids=test_cases_ids)
def test_agentd_state(test_configuration, test_metadata, remove_state_file, configure_local_internal_options, truncate_monitored_files):
    '''
    description: Check that the statistics file 'wazuh-agentd.state' is created automatically
                 and verify that the content of its fields is correct.

    wazuh_min_version: 4.2.0

    tier: 0

    parameters:
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - test_case:
            type: list
            brief: List of tests to be performed.

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

    # Stop service
    control_service('stop')

    # Add dummy key in order to communicate with RemotedSimulator
    add_custom_key()

    # Start service
    control_service('start')

    import pdb; pdb.set_trace()

    # Check fields for every expected output type
    for expected_output in test_metadata['output']:
        check_fields(expected_output)
    
def parse_state_file():
    """Parse state file

    Returns:
        state info
    """
    # Wait until state file is dumped
    wait_state_update()
    state = {}
    with open(AGENTD_STATE) as state_file:
        for line in state_file:
            line = line.rstrip('\n')
            # Remove empty lines or comments
            if not line or line.startswith('#'):
                continue
            (key, value) = line.split('=', 1)
            # Remove value's quotes
            state[key] = value.strip("'")

    return state


def remoted_get_state(remoted_server):
    """Get state via remoted

    Send getstate request to agent (via RemotedSimulator) and return state info as dict.

    Returns:
        state info
    """
    remoted_server.request('agent getstate')
    sleep(2)
    response = json.loads(remoted_server.request_answer)
    return response['data']


def check_fields(expected_output):
    """Check every field agains expected data

    Args:
        expected_output (dict): expected output block
    """
    checks = {
        'last_ack': {'handler': check_last_ack, 'precondition': [wait_ack]},
        'last_keepalive': {'handler': check_last_keepalive,
                           'precondition': [wait_keepalive]},
        'msg_count': {'handler': check_last_keepalive,
                      'precondition': [wait_keepalive]},
        'status': {'handler': check_status, 'precondition': []}
        }

    if expected_output['type'] == 'file':
        get_state = parse_state_file
    else:
        get_state = remoted_get_state

    for field, expected_value in expected_output['fields'].items():
        # Check if expected value is valiable and mandatory

        if expected_value != '':
            for precondition in checks[field].get('precondition'):
                precondition()
        assert checks[field].get('handler')(expected_value, get_state_callback=get_state)


def check_last_ack(expected_value=None, get_state_callback=None):
    """Check `field` status

    Args:
        expected_value (string, optional): value to check against.
                                           Defaults to None.
        get_state_callback (function, optional): callback to get state.
                                                 Defaults to None.

    Returns:
        boolean: `True` if check was successfull. `False` otherwise
    """
    if get_state_callback:
        current_value = get_state_callback()['last_ack']
        if expected_value == '':
            return expected_value == current_value

    received_msg = "Received message: '#!-agent ack '"

    with open(WAZUH_LOG_PATH) as log:
        for line in log:
            if current_value.replace('-', '/') in line and received_msg in line:
                return True
    return False


def check_last_keepalive(expected_value=None, get_state_callback=None):
    """Check `field` status

    Args:
        expected_value (string, optional): value to check against.
                                           Defaults to None.
        get_state_callback (function, optional): callback to get state.
                                                 Defaults to None.

    Returns:
        boolean: `True` if check was successfull. `False` otherwise
    """
    if get_state_callback:
        current_value = get_state_callback()['last_keepalive']
        if expected_value == '':
            return expected_value == current_value

    keep_alive_msg = 'Sending keep alive'
    agent_notification_msg = 'Sending agent notification'

    with open(WAZUH_LOG_PATH, 'r') as log:
        for line in log:
            if current_value.replace('-', '/') in line and (keep_alive_msg in line or agent_notification_msg in line):
                return True
    return False


def check_msg_count(expected_value=None, get_state_callback=None):
    """Check `field` status

    Args:
        expected_value (string, optional): value to check against.
                                           Defaults to None.
        get_state_callback (function, optional): callback to get state.
                                                 Defaults to None.

    Returns:
        boolean: `True` if check was successfull. `False` otherwise
    """
    if get_state_callback:
        current_value = get_state_callback()['msg_count']
        if expected_value == '':
            return expected_value == current_value

    sent_messages = 0

    with open(WAZUH_LOG_PATH, 'r') as log:
        for line in log:
            if 'Sending keep alive' in line:
                sent_messages += 1

    return sent_messages >= current_value


def check_status(expected_value=None, get_state_callback=None):
    """Check `field` status

    Args:
        expected_value (string, optional): value to check against.
                                           Defaults to None.
        get_state_callback (function, optional): callback to get state.
                                                 Defaults to None.

    Returns:
        boolean: `True` if check was successfull. `False` otherwise
    """
    if expected_value != 'pending':
        wait_keepalive()
        if get_state_callback == parse_state_file:
            wait_state_update()
    current_value = get_state_callback()['status']
    return expected_value == current_value


def wait_connect(update_position=False):
    """
        Watch ossec.log until received "Connected to the server" message is found
    """
    wazuh_log_monitor = FileMonitor(WAZUH_LOG_PATH)
    wazuh_log_monitor.start(callback=callbacks.generate_callback(AGENTD_CONNECTED_TO_SERVER))
    assert (wazuh_log_monitor.callback_result != None), f'Connected to the server message not found'


def wait_ack():
    """
        Watch ossec.log until received ack message is found
    """
    wazuh_log_monitor = FileMonitor(WAZUH_LOG_PATH)
    wazuh_log_monitor.start(callback=callbacks.generate_callback(AGENTD_RECEIVED_ACK))
    assert (wazuh_log_monitor.callback_result != None), f'Received ack message not found'


def wait_keepalive():
    """
        Watch ossec.log until "Sending keep alive" message is found
    """
    wazuh_log_monitor = FileMonitor(WAZUH_LOG_PATH)
    wazuh_log_monitor.start(callback=callbacks.generate_callback(AGENTD_SENDING_KEEP_ALIVE))
    assert (wazuh_log_monitor.callback_result != None), f'Sending keep alive not found'


def wait_state_update():
    """
        Watch ossec.log until "Updating state file" message is found
    """
    wazuh_log_monitor = FileMonitor(WAZUH_LOG_PATH)
    wazuh_log_monitor.start(callback=callbacks.generate_callback(AGENTD_UPDATING_STATE_FILE))
    assert (wazuh_log_monitor.callback_result != None), f'State file update not found'

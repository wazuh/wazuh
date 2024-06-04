'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: A Wazuh cluster is a group of Wazuh managers that work together to enhance the availability
       and scalability of the service. These tests will check the agent enrollment in a multi-server
       environment and how the agent manages the connections to the servers depending on their status.

components:
    - agentd

targets:
    - agent

daemons:
    - wazuh-agentd
    - wazuh-authd
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
    - https://documentation.wazuh.com/current/user-manual/registering/index.html

tags:
    - enrollment
'''
import pytest
from pathlib import Path
import sys

from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.constants.platforms import WINDOWS
from wazuh_testing.constants.ports import DEFAULT_SSL_REMOTE_CONNECTION_PORT
from wazuh_testing.modules.agentd.configuration import AGENTD_DEBUG, AGENTD_WINDOWS_DEBUG, AGENTD_TIMEOUT
from wazuh_testing.modules.agentd.patterns import *
from wazuh_testing.tools.monitors.file_monitor import FileMonitor
from wazuh_testing.tools.simulators.authd_simulator import AuthdSimulator
from wazuh_testing.utils import callbacks
from wazuh_testing.utils.client_keys import add_client_keys_entry
from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template

from . import CONFIGS_PATH, TEST_CASES_PATH

# Marks
pytestmark = [pytest.mark.agent, pytest.mark.linux, pytest.mark.win32, pytest.mark.tier(level=0)]

# Configuration and cases data.
configs_path = Path(CONFIGS_PATH, 'wazuh_conf.yaml')
cases_path = Path(TEST_CASES_PATH, 'cases_reconnection_protocol.yaml')

# Test configurations.
config_parameters, test_metadata, test_cases_ids = get_test_cases_data(cases_path)
test_configuration = load_configuration_template(configs_path, config_parameters, test_metadata)

if sys.platform == WINDOWS:
    local_internal_options = {AGENTD_WINDOWS_DEBUG: '2'}
else:
    local_internal_options = {AGENTD_DEBUG: '2'}
local_internal_options.update({AGENTD_TIMEOUT: '5'})

daemons_handler_configuration = {'all_daemons': True}

# Tests
"""
How does this test work:
    - PROTOCOL: tcp/udp
    - DELETE_KEYS_FILE: whatever start with an empty client.keys file or not
    - SIMULATOR MODES: for each simulator will define a mode
    - AUTHD_PREV_MODE: represents the previous state of the authd daemon,
        - ACCEPT means it already has keys, REJECT means no keys
    - AUTHD: mode for the authd simulator
    - LOG_MONITOR_STR: (list of lists) Expected string to be monitored for each simulator
"""
@pytest.mark.parametrize('test_configuration, test_metadata', zip(test_configuration, test_metadata), ids=test_cases_ids)
def test_agentd_multi_server(test_configuration, test_metadata, set_wazuh_configuration, configure_local_internal_options, truncate_monitored_files,
                             remove_keys_file, start_remoted_simulators, daemons_handler):
    '''
    description: Check the agent's enrollment and connection to a manager in a multi-server environment.
                 Initialize an environment with multiple simulated servers in which the agent is forced to enroll
                 under different test conditions, verifying the agent's behavior through its log files.

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
        - configure_local_internal_options:
            type: fixture
            brief: Set internal configuration for testing.
        - truncate_monitored_files:
            type: fixture
            brief: Reset the 'ossec.log' file and start a new monitor.
        - remove_keys_file:
            type: fixture
            brief: Deletes keys file if test configuration request it
        - start_remoted_simulators:
            type: fixture
            brief: Starts remoted simulators as requested
        - daemons_handler:
            type: fixture
            brief: Handler of Wazuh daemons.

    assertions:
        - Agent without keys. Verify that all servers will refuse the connection to the 'wazuh-remoted' daemon
          but will accept enrollment. The agent should try to connect and enroll each of them.
        - Agent without keys. Verify that the first server only has enrollment available, and the third server
          only has the 'wazuh-remoted' daemon available. The agent should enroll in the first server and
          connect to the third one.
        - Agent without keys. Verify that the agent should enroll and connect to the first server, and then
          the first server will disconnect. The agent should connect to the second server with the same key.
        - Agent without keys. Verify that the agent should enroll and connect to the first server, and then
          the first server will disconnect. The agent should try to enroll in the first server again,
          and then after failure, move to the second server and connect.
        - Agent with keys. Verify that the agent should enroll and connect to the last server.
        - Agent with keys. Verify that the first server is available, but it disconnects, and the second and
          third servers are not responding. The agent on disconnection should try the second and third servers
          and go back finally to the first server.

    input_description: An external YAML file (wazuh_conf.yaml) includes configuration settings for the agent.
                       Different test cases are found in the test module and include parameters for
                       the environment setup, the requests to be made, and the expected result.

    expected_output:
        - r'Requesting a key from server'
        - r'Valid key received'
        - r'Trying to connect to server'
        - r'Connected to enrollment service'
        - r'Received message'
        - r'Unable to connect to enrollment service at'

    tags:
        - simulator
        - ssl
        - keys
    '''
    remoted_server_address = "127.0.0.1"
    remoted_server_ports = [DEFAULT_SSL_REMOTE_CONNECTION_PORT,1516,1517]

    # Configure keys
    if(test_metadata['SIMULATOR_MODES']['AUTHD'] == 'ACCEPT'):
        authd_server = AuthdSimulator(server_ip = remoted_server_address, mode = test_metadata['SIMULATOR_MODES']['AUTHD'])
        authd_server.start()
    else:
        if(test_metadata['SIMULATOR_MODES']['AUTHD_PREV_MODE'] == 'ACCEPT'):
            authd_server = None
            add_client_keys_entry("001", "ubuntu-agent", "any", "SuperSecretKey")

    # Start FileMonitor
    log_monitor = FileMonitor(WAZUH_LOG_PATH)

    # Iterate the servers from which we are expecting logs
    for server in range(len(test_metadata['LOG_MONITOR_STR'])):
        # Iterate the patterns expected for server
        for pattern in range(len(test_metadata['LOG_MONITOR_STR'][server])):
            # Build regex from expected pattern
            regex, values = get_regex(test_metadata['LOG_MONITOR_STR'][server][pattern],
                              remoted_server_address,
                              remoted_server_ports[server])
            # Look for expected log
            log_monitor.start(callback=callbacks.generate_callback(regex,values), timeout = 150)
            assert (log_monitor.callback_result != None), (regex,values)

    if(authd_server):
        authd_server.destroy()


def get_regex(pattern, server_address, server_port):
    """Return a regex and the values to complete it

    Args:
        pattern (str): String refering to the framework patterns.
        server_address (str): String with server ip.
        server_port (str): String with server port.

    Returns:
        regex (regex): refered by framework patter.
        values (dict): values to complete regex
    """
    if(pattern == 'AGENTD_TRYING_CONNECT' or pattern == 'AGENTD_UNABLE_TO_CONNECT'):
        regex = globals()[pattern]
        values = {'IP': str(server_address), 'PORT':str(server_port)}
    elif (pattern == 'AGENTD_REQUESTING_KEY'):
        regex = globals()[pattern]
        values = {'IP': str(server_address)}
    elif (pattern == 'AGENTD_CONNECTED_TO_ENROLLMENT'):
        regex = globals()[pattern]
        values = {'IP': '', 'PORT': ''}
    else:
        regex = globals()[pattern]
        values = {}
    return regex, values

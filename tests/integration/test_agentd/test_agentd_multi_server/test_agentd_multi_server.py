'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

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
from wazuh_testing.modules.agentd.configuration import AGENTD_DEBUG, AGENTD_WINDOWS_DEBUG, AGENTD_TIMEOUT
from wazuh_testing.tools.monitors.file_monitor import FileMonitor
from wazuh_testing.tools.simulators.authd_simulator import AuthdSimulator
from wazuh_testing.tools.simulators.remoted_simulator import RemotedSimulator
from wazuh_testing.utils import callbacks
from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template
from wazuh_testing.utils.services import control_service

from . import CONFIGS_PATH, TEST_CASES_PATH
from .. import get_regex, kill_server, add_custom_key

# Marks
pytestmark = pytest.mark.tier(level=0)

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

# Tests
"""
How does this test work:
    - PROTOCOL: tcp/udp
    - CLEAN_KEYS: whatever start with an empty client.keys file or not
    - SIMULATOR MODES: for each simulator will define a mode
    - AUTHD_PREV_MODE: represents the previous state of the authd daemon,
        - ACCEPT means it already has keys, REJECT means no keys
    - AUTHD: mode for the authd simulator
    - LOG_MONITOR_STR: (list of lists) Expected string to be monitored for each simulator
"""
@pytest.mark.parametrize('test_configuration, test_metadata', zip(test_configuration, test_metadata), ids=test_cases_ids)
def test_agentd_multi_server(test_configuration, test_metadata, set_wazuh_configuration, configure_local_internal_options, truncate_monitored_files, 
                             remove_keys_file):
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

    # Servers paremeters
    remoted_server_addresses = ["127.0.0.0","127.0.0.1","127.0.0.2"]
    remoted_server_ports = [1514,1516,1517]
    remoted_servers = [None,None,None]
    
    # Stop target Agent
    control_service('stop')

    # Configure keys
    if(test_metadata['SIMULATOR_MODES']['AUTHD'] == 'ACCEPT'):
        authd_server = AuthdSimulator(server_ip = remoted_server_addresses[0], mode = test_metadata['SIMULATOR_MODES']['AUTHD'])
        authd_server.start()
    else:
        if(test_metadata['SIMULATOR_MODES']['AUTHD_PREV_MODE'] == 'ACCEPT'):
            authd_server = None
            add_custom_key()

    # Start target Agent
    control_service('start')
    
    # Start Remoted Simulators
    for i in range(len(remoted_server_addresses)):
        if(test_metadata['SIMULATOR_MODES'][i] != 'CLOSE'):
            remoted_servers[i] = RemotedSimulator(protocol = test_metadata['PROTOCOL'], server_ip = remoted_server_addresses[i], 
                                        port = remoted_server_ports[i], mode = test_metadata['SIMULATOR_MODES'][i])
            remoted_servers[i].start()

    # Start FileMonitor
    log_monitor = FileMonitor(WAZUH_LOG_PATH)

    # Iterate the servers from which we are expecting logs
    for server in range(len(test_metadata['LOG_MONITOR_STR'])):
        # Iterate the patterns expected for server
        for pattern in range(len(test_metadata['LOG_MONITOR_STR'][server])):
            # Build regex from expected pattern
            regex, values = get_regex(test_metadata['LOG_MONITOR_STR'][server][pattern],
                              remoted_server_addresses[server],
                              remoted_server_ports[server])
            # Look for expected log
            log_monitor.start(callback=callbacks.generate_callback(regex,values))
            assert (log_monitor.callback_result != None), regex

    # Shutdown simulators
    for i in range(len(remoted_servers)):
        kill_server(remoted_servers[i])
    kill_server(authd_server)
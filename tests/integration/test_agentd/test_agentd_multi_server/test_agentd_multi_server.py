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
from datetime import timedelta
import pytest
from pathlib import Path
import sys

from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.constants.platforms import WINDOWS
from wazuh_testing.modules.agentd.configuration import AGENTD_DEBUG, AGENTD_WINDOWS_DEBUG, AGENTD_TIMEOUT
from wazuh_testing.modules.agentd.patterns import AGENTD_TRYING_CONNECT, AGENTD_CONNECTED_TO_SERVER 
from wazuh_testing.tools.monitors.file_monitor import FileMonitor
from wazuh_testing.tools.simulators.remoted_simulator import RemotedSimulator
from wazuh_testing.utils import callbacks
from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template

from . import CONFIGS_PATH, TEST_CASES_PATH
from .. import parse_time_from_log_line, wait_connect, wait_server_rollback, add_custom_key, check_connection_try, kill_server

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

daemons_handler_configuration = {'all_daemons': True}

# Tests
"""
How does this test work:

    - PROTOCOL: tcp/udp
    - CLEAN_KEYS: whatever start with an empty client.keys file or not
    - SIMULATOR_NUMBERS: Number of simulator to be instantiated, this should match wazuh_conf.yaml
    - SIMULATOR MODES: for each number of simulator will define a list of "stages"
    that defines the state that remoted simulator should have in that state
    Length of the stages should be the same for all simulators.
    Authd simulator will only accept one enrollment for stage
    - LOG_MONITOR_STR: (list of lists) Expected string to be monitored in all stages
"""
# fixtures
@pytest.fixture(scope="module", params=configurations, ids=case_ids)
def get_configuration(request):
    """Get configurations from the module"""
    return request.param


@pytest.fixture(scope="module")
def add_hostnames(request):
    """Add to OS hosts file, names and IP's of test servers."""
    HOSTFILE_PATH = os.path.join(os.environ['SystemRoot'], 'system32', 'drivers', 'etc', 'hosts') \
        if os.sys.platform == 'win32' else '/etc/hosts'
    hostfile = None
    with open(HOSTFILE_PATH, "r") as f:
        hostfile = f.read()
    for server in SERVER_HOSTS:
        if server not in hostfile:
            with open(HOSTFILE_PATH, "a") as f:
                f.write(f'{SERVER_ADDRESS}  {server}\n')
    yield

    with open(HOSTFILE_PATH, "w") as f:
        f.write(hostfile)


@pytest.fixture(scope="module")
def configure_authd_server(request, get_configuration):
    """Initialize multiple simulated remoted connections.

    Args:
        get_configuration (fixture): Get configurations from the module.
    """
    global monitored_sockets
    monitored_sockets = QueueMonitor(authd_server.queue)
    authd_server.start()
    authd_server.set_mode('REJECT')
    global remoted_servers
    for i in range(0, get_configuration['metadata']['SIMULATOR_NUMBER']):
        remoted_servers.append(RemotedSimulator(server_address=SERVER_ADDRESS, remoted_port=REMOTED_PORTS[i],
                                                protocol=get_configuration['metadata']['PROTOCOL'],
                                                mode='CONTROLLED_ACK', client_keys=CLIENT_KEYS_PATH))
        # Set simulator mode for that stage
        if get_configuration['metadata']['SIMULATOR_MODES'][i][0] != 'CLOSE':
            remoted_servers[i].set_mode(get_configuration['metadata']['SIMULATOR_MODES'][i][0])

    yield
    # hearing on enrollment server
    for i in range(0, get_configuration['metadata']['SIMULATOR_NUMBER']):
        remoted_servers[i].stop()
    remoted_servers = []
    authd_server.shutdown()


@pytest.fixture(scope="function")
def set_authd_id(request):
    """Set agent id to 101 in the authd simulated connection."""
    authd_server.agent_id = 101


@pytest.fixture(scope="function")
def clean_keys(request, get_configuration):
    """Clear the client.key file used by the simulated remoted connections.

    Args:
        get_configuration (fixture): Get configurations from the module.
    """
    if get_configuration['metadata'].get('CLEAN_KEYS', True):
        truncate_file(CLIENT_KEYS_PATH)
        sleep(1)
    else:
        with open(CLIENT_KEYS_PATH, 'w') as f:
            f.write("100 ubuntu-agent any TopSecret")
        sleep(1)


def restart_agentd():
    """Restart agentd daemon with debug mode active."""
    control_service('stop', daemon="wazuh-agentd")
    truncate_file(LOG_FILE_PATH)
    control_service('start', daemon="wazuh-agentd", debug_mode=True)


# Tests
def wait_until(x, log_str):
    """Callback function to wait for a message in a log file.

    Args:
        x (str): String containing message.
        log_str (str): Log file string.
    """
    return x if log_str in x else None


# @pytest.mark.parametrize('test_case', [case for case in tests])
@pytest.mark.skip(reason='https://github.com/wazuh/wazuh-qa/issues/3536')
def test_agentd_multi_server(add_hostnames, configure_authd_server, set_authd_id, clean_keys, configure_environment,
                             get_configuration):
    '''
    description: Check the agent's enrollment and connection to a manager in a multi-server environment.
                 Initialize an environment with multiple simulated servers in which the agent is forced to enroll
                 under different test conditions, verifying the agent's behavior through its log files.

    wazuh_min_version: 4.2.0

    tier: 0

    parameters:
        - add_hostnames:
            type: fixture
            brief: Adds to the 'hosts' file the names and the IP addresses of the testing servers.
        - configure_authd_server:
            type: fixture
            brief: Initializes a simulated 'wazuh-authd' connection.
        - set_authd_id:
            type: fixture
            brief: Sets the agent id to '101' in the 'wazuh-authd' simulated connection.
        - clean_keys:
            type: fixture
            brief: Clears the 'client.keys' file used by the simulated remote connections.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.

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
        - r'Server responded. Releasing lock.'
        - r'Unable to connect to enrollment service at'

    tags:
        - simulator
        - ssl
        - keys
    '''
    log_monitor = FileMonitor(LOG_FILE_PATH)

    for stage in range(0, len(get_configuration['metadata']['LOG_MONITOR_STR'])):

        authd_server.set_mode(get_configuration['metadata']['SIMULATOR_MODES']['AUTHD'][stage])
        authd_server.clear()

        for i in range(0, get_configuration['metadata']['SIMULATOR_NUMBER']):
            # Set simulator mode for that stage
            if get_configuration['metadata']['SIMULATOR_MODES'][i][stage] != 'CLOSE':
                remoted_servers[i].set_mode(get_configuration['metadata']['SIMULATOR_MODES'][i][stage])
            else:
                remoted_servers[i].stop()

        if stage == 0:
            # Restart at beginning of test
            restart_agentd()

        for index, log_str in enumerate(get_configuration['metadata']['LOG_MONITOR_STR'][stage]):
            try:
                log_monitor.start(timeout=tcase_timeout, callback=lambda x: wait_until(x, log_str))
            except TimeoutError:
                assert False, f"Expected message '{log_str}' never arrived! Stage: {stage+1}, message number: {index+1}"

        for i in range(0, get_configuration['metadata']['SIMULATOR_NUMBER']):
            # Clean after every stage
            if get_configuration['metadata']['SIMULATOR_MODES'][i][stage] == 'CLOSE':
                remoted_servers[i].start()

        authd_server.clear()
    return
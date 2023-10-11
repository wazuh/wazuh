'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests will check if the 'remote enrollment' option of the 'wazuh-authd' daemon
       settings is working properly. The 'wazuh-authd' daemon can automatically add
       a Wazuh agent to a Wazuh manager and provide the key to the agent.
       It is used along with the 'agent-auth' application.

components:
    - authd

targets:
    - manager

daemons:
    - wazuh-authd
    - wazuh-db
    - wazuh-modulesd

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
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/auth.html#remote-enrollment

tags:
    - enrollment
'''
import os
import pytest

from wazuh_testing.tools import monitoring, LOG_FILE_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import SocketController, FileMonitor
from wazuh_testing.tools.sockets import wait_for_tcp_port
from wazuh_testing.tools.wazuh import DEFAULT_SSL_REMOTE_ENROLLMENT_PORT
from contextlib import contextmanager

# Marks
pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]


# Configurations

parameters = [
    {'REMOTE_ENROLLMENT': 'no', 'CLUSTER_DISABLED': 'yes', 'NODE_TYPE': 'master'},
    {'REMOTE_ENROLLMENT': 'yes', 'CLUSTER_DISABLED': 'yes', 'NODE_TYPE': 'master'},
    {'REMOTE_ENROLLMENT': 'no', 'CLUSTER_DISABLED': 'no', 'NODE_TYPE': 'master'},
    {'REMOTE_ENROLLMENT': 'yes', 'CLUSTER_DISABLED': 'no', 'NODE_TYPE': 'master'},
    {'REMOTE_ENROLLMENT': 'no', 'CLUSTER_DISABLED': 'no', 'NODE_TYPE': 'worker'},
    {'REMOTE_ENROLLMENT': 'yes', 'CLUSTER_DISABLED': 'no', 'NODE_TYPE': 'worker'}
]

metadata = [
    {'remote_enrollment': 'no', 'node_type': 'no',  'id': 'no_remote_enrollment_standalone'},
    {'remote_enrollment': 'yes', 'node_type': 'no',  'id': 'yes_remote_enrollment_standalone'},
    {'remote_enrollment': 'no', 'node_type': 'master',  'id': 'no_remote_enrollment_cluster_master'},
    {'remote_enrollment': 'yes', 'node_type': 'master',  'id': 'yes_remote_enrollment_cluster_master'},
    {'remote_enrollment': 'no', 'node_type': 'worker',  'id': 'no_remote_enrollment_cluster_worker'},
    {'remote_enrollment': 'yes', 'node_type': 'worker', 'id': 'yes_remote_enrollment_cluster_worker'}
]

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_authd_configuration.yaml')
configurations = load_wazuh_configurations(configurations_path, __name__, params=parameters, metadata=metadata)

# Variables
log_monitor_paths = []

receiver_sockets_params = [(("localhost", DEFAULT_SSL_REMOTE_ENROLLMENT_PORT), 'AF_INET', 'SSL_TLSv1_2')]

monitored_sockets_params = [('wazuh-modulesd', None, True), ('wazuh-db', None, True), ('wazuh-authd', None, True)]

receiver_sockets, monitored_sockets, log_monitors = None, None, None  # Set in the fixtures

cluster_socket_address = ('localhost', 1516)
remote_enrollment_address = ('localhost', 1515)

AGENT_ID = 0
AGENT_NAME = 'test_agent'
INPUT_MESSAGE = "OSSEC A:'{}_{}'"


@pytest.fixture(scope="module", params=configurations, ids=[f"{x['id']}" for x in metadata])
def get_configuration(request):
    """Get configurations from the module"""
    yield request.param


@contextmanager
def not_raises(exception):
    try:
        yield
    except exception:
        raise pytest.fail("DID RAISE {0}".format(exception))


def test_remote_enrollment(get_configuration, configure_environment, restart_wazuh_daemon_function, tear_down):
    '''
    description:
        Checks if the 'wazuh-authd' daemon remote enrollment is enabled/disabled according
        to the configuration. By default, remote enrollment is enabled. When disabled,
        the 'authd' 'TLS' port (1515 by default) won't be listening to new connections,
        but requests to the local socket will still be attended.

    wazuh_min_version:
        4.2.0

    tier: 0

    parameters:
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - restart_authd:
            type: fixture
            brief: Restart the 'wazuh-authd' daemon, clear the 'ossec.log' file and start a new file monitor.
        - tear_down:
            type: fixture
            brief: cleans the client.keys file

    assertions:
        - Verify that the port '1515' opens or closes depending on the value of the 'remote_enrollment' option.
        - Verify that when a 'worker' node receives an enrollment request, it tries to connect to the 'master' node.

    input_description:
        Different test cases are found in the test module and include
        parameters for the environment setup, the requests
        to be made, and the expected result.

    expected_output:
        - r'Accepting connections on port 1515. No password required.' (When the 'wazuh-authd' daemon)
        - r'OSSEC K:' (When the agent has enrolled in the manager)
        - r'.*Port 1515 was set as disabled.*' (When remote enrollment is disabled)
        - r'ERROR: Cannot communicate with the master'

    tags:
        - keys
        - ssl
    '''
    expectation = not_raises(ConnectionRefusedError)
    expected_answer = 'OSSEC K:'

    test_metadata = get_configuration['metadata']
    remote_enrollment_enabled = test_metadata['remote_enrollment'] == 'yes'

    if remote_enrollment_enabled:
        expected_log = "Accepting connections on port 1515. No password required."
        wait_for_tcp_port(1515)
    else:
        expected_log = ".*Port 1515 was set as disabled.*"
        expectation = pytest.raises(ConnectionRefusedError)

    FileMonitor(LOG_FILE_PATH).start(timeout=5,
                                     callback=monitoring.make_callback(pattern=expected_log,
                                                                       prefix=monitoring.AUTHD_DETECTOR_PREFIX),
                                     error_message=f'Expected log not found: {expected_log}')
    with expectation:
        ssl_socket = SocketController(remote_enrollment_address, family='AF_INET', connection_protocol='SSL_TLSv1_2')

        ssl_socket.open()

        if test_metadata['node_type'] == 'worker':
            expected_answer = 'ERROR: Cannot comunicate with master'
        global AGENT_ID
        ssl_socket.send(INPUT_MESSAGE.format(AGENT_NAME, AGENT_ID), size=False)
        AGENT_ID = AGENT_ID + 1
        response = ssl_socket.receive().decode()

        assert expected_answer in response

        ssl_socket.close()

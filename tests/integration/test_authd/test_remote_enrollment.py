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
import socket, time
from pathlib import Path

from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.utils import callbacks
from wazuh_testing.modules.authd import PREFIX
from wazuh_testing.tools.socket_controller import SocketController
from wazuh_testing.tools.monitors import file_monitor
from wazuh_testing.utils.wazuh import DEFAULT_SSL_REMOTE_ENROLLMENT_PORT
from wazuh_testing.utils.configuration import load_configuration_template, get_test_cases_data
from contextlib import contextmanager

from . import CONFIGURATIONS_FOLDER_PATH, TEST_CASES_FOLDER_PATH

# Marks
pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]


# Configurations
test_configuration_path = Path(CONFIGURATIONS_FOLDER_PATH, 'config_remote_enrollment.yaml')
test_cases_path = Path(TEST_CASES_FOLDER_PATH, 'cases_remote_enrollment.yaml')
test_configuration, test_metadata, test_cases_ids = get_test_cases_data(test_cases_path)
test_configuration = load_configuration_template(test_configuration_path, test_configuration, test_metadata)

# Variables
log_monitor_paths = []

receiver_sockets_params = [(("localhost", DEFAULT_SSL_REMOTE_ENROLLMENT_PORT), 'AF_INET', 'SSL_TLSv1_2')]

monitored_sockets_params = [('wazuh-modulesd', None, True), ('wazuh-db', None, True), ('wazuh-authd', None, True)]

receiver_sockets, monitored_sockets, log_monitors = None, None, None  # Set in the fixtures

cluster_socket_address = ('localhost', 1516)
remote_enrollment_address = ('localhost', 1515)

daemons_handler_configuration = {'all_daemons': True, 'ignore_errors': True}

AGENT_ID = 0
AGENT_NAME = 'test_agent'
INPUT_MESSAGE = "OSSEC A:'{}_{}'"


def wait_for_tcp_port(port, host='localhost', timeout=10):
    """Wait until a port starts accepting TCP connections.
    Args:
        port (int): Port number.
        host (str): Host address on which the port should be listening. Default 'localhost'
        timeout (float): In seconds. How long to wait before raising errors.
    Raises:
        TimeoutError: The port isn't accepting connection after time specified in `timeout`.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            sock.connect((host, port))
            sock.close()
            return
        except ConnectionRefusedError:
            time.sleep(1)


    raise TimeoutError(f'Waited too long for the port {port} on host {host} to start accepting messages')

@contextmanager
def not_raises(exception):
    try:
        yield
    except exception:
        raise pytest.fail("DID RAISE {0}".format(exception))

@pytest.mark.parametrize('test_configuration,test_metadata', zip(test_configuration, test_metadata), ids=test_cases_ids)
def test_remote_enrollment(test_configuration, test_metadata, set_wazuh_configuration, daemons_handler, tear_down):
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

    remote_enrollment_enabled = test_metadata['remote_enrollment'] == 'yes'

    if remote_enrollment_enabled:
        expected_log = "Accepting connections on port 1515. No password required."
        wait_for_tcp_port(1515)
    else:
        expected_log = ".*Port 1515 was set as disabled.*"
        expectation = pytest.raises(ConnectionRefusedError)

    file_monitor.FileMonitor(WAZUH_LOG_PATH).start(timeout=5,
                                     callback=callbacks.generate_callback(f'{PREFIX}{expected_log}'))
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

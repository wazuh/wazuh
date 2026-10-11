'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests will check if the 'remote enrollment' option of the 'wazuh-manager-authd' daemon
       settings is working properly. The 'wazuh-manager-authd' daemon can automatically add
       a Wazuh agent to a Wazuh manager and provide the key to the agent.

components:
    - authd

targets:
    - manager

daemons:
    - wazuh-manager-authd
    - wazuh-manager-db
    - wazuh-manager-modulesd

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
import pytest
import socket
import time
from pathlib import Path

from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.constants.ports import DEFAULT_SSL_CLUSTER_PORT
from wazuh_testing.utils import callbacks
from wazuh_testing.modules.authd import PREFIX
from wazuh_testing.tools.socket_controller import SocketController
from wazuh_testing.tools.monitors import file_monitor
from wazuh_testing.constants.ports import DEFAULT_SSL_REMOTE_ENROLLMENT_PORT
from wazuh_testing.constants.daemons import AUTHD_DAEMON, WAZUH_DB_DAEMON, MODULES_DAEMON
from wazuh_testing.utils.configuration import load_configuration_template, get_test_cases_data
from contextlib import nullcontext as does_not_raise

from . import CONFIGURATIONS_FOLDER_PATH, TEST_CASES_FOLDER_PATH

# Marks
pytestmark = [pytest.mark.server, pytest.mark.tier(level=0)]


# Configurations
test_configuration_path = Path(CONFIGURATIONS_FOLDER_PATH, 'config_remote_enrollment.yaml')
test_cases_path = Path(TEST_CASES_FOLDER_PATH, 'cases_remote_enrollment.yaml')
test_configuration, test_metadata, test_cases_ids = get_test_cases_data(test_cases_path)
test_configuration = load_configuration_template(test_configuration_path, test_configuration, test_metadata)

# Variables
receiver_sockets_params = [(("localhost", DEFAULT_SSL_REMOTE_ENROLLMENT_PORT), 'AF_INET', 'ssl_tls')]

monitored_sockets_params = [(WAZUH_DB_DAEMON, None, True), (MODULES_DAEMON, None, True), (AUTHD_DAEMON, None, True)]

receiver_sockets, monitored_sockets = None, None  # Set in the fixtures

cluster_socket_address = ('localhost', DEFAULT_SSL_CLUSTER_PORT)
remote_enrollment_address = ('localhost', DEFAULT_SSL_REMOTE_ENROLLMENT_PORT)

# Test daemons to restart.
daemons_handler_configuration = {'all_daemons': True}

AGENT_ID = 0
AGENT_NAME = 'test_agent'
INPUT_MESSAGE = "OSSEC A:'{}_{}'\n"


def wait_for_tcp_port(port, host='localhost', timeout=30, interval=0.5):
    """Wait until a TCP port accepts connections.

    A daemon can log that it started before it binds its port, so the log line alone is not a
    reliable readiness signal right after a restart.

    Args:
        port (int): Port to connect to.
        host (str): Host to connect to. Default `localhost`.
        timeout (int): Max seconds to wait for the port to accept connections.
        interval (float): Seconds between attempts.

    Returns:
        bool: True if the port accepted a connection before the timeout, False otherwise.
    """
    end_time = time.time() + timeout
    while time.time() < end_time:
        try:
            with socket.create_connection((host, int(port)), timeout=1):
                return True
        except OSError:
            time.sleep(interval)

    return False


@pytest.mark.parametrize('test_configuration,test_metadata', zip(test_configuration, test_metadata), ids=test_cases_ids)
def test_remote_enrollment(test_configuration, test_metadata, set_wazuh_configuration,
                           truncate_monitored_files, daemons_handler):
    '''
    description:
        Checks if the 'wazuh-manager-authd' daemon remote enrollment is enabled/disabled according
        to the configuration. By default, remote enrollment is enabled. When disabled,
        the 'authd' 'TLS' port (1515 by default) won't be listening to new connections,
        but requests to the local socket will still be attended.

    wazuh_min_version:
        5.0.0

    tier: 0

    parameters:
        - test_configuration:
            type: dict
            brief: Configuration loaded from `configuration_templates`.
        - test_metadata:
            type: dict
            brief: Test case metadata.
        - set_wazuh_configuration:
            type: fixture
            brief: Load basic wazuh configuration.
        - daemons_handler:
            type: fixture
            brief: Restarts wazuh or a specific daemon passed.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate all the log files and json alerts files before and after the test execution.

    assertions:
        - Verify that the port '1515' opens or closes depending on the value of the 'remote_enrollment' option.
        - Verify that when a 'worker' node receives an enrollment request, it tries to connect to the 'master' node.

    input_description:
        Different test cases are found in the test module and include
        parameters for the environment setup, the requests
        to be made, and the expected result.

    expected_output:
        - r'Accepting connections on port 1515. No password required.' (When the 'wazuh-manager-authd' daemon)
        - r'OSSEC K:' (When the agent has enrolled in the manager)
        - r'.*Port 1515 was set as disabled.*' (When remote enrollment is disabled)
        - r'ERROR: Cannot communicate with the master'

    tags:
        - keys
        - ssl
    '''
    expectation = does_not_raise()
    expected_answer = 'OSSEC K:'

    remote_enrollment_enabled = test_metadata['remote_enrollment'] == 'yes'

    if remote_enrollment_enabled:
        expected_log = "Accepting connections on port 1515. No password required."
        assert wait_for_tcp_port(DEFAULT_SSL_REMOTE_ENROLLMENT_PORT, timeout=30), \
            f"Port {DEFAULT_SSL_REMOTE_ENROLLMENT_PORT} did not start accepting connections in time"
    else:
        expected_log = ".*Port 1515 was set as disabled.*"
        expectation = pytest.raises(ConnectionRefusedError)

    log_monitor = file_monitor.FileMonitor(WAZUH_LOG_PATH)
    log_monitor.start(timeout=30, callback=callbacks.generate_callback(f'{PREFIX}{expected_log}'))
    assert log_monitor.callback_result, f'Expected log not found: {expected_log}'
    with expectation:
        ssl_socket = SocketController(remote_enrollment_address, family='AF_INET', connection_protocol='ssl_tls')

        ssl_socket.open()

        if test_metadata['node_type'] == 'worker':
            expected_answer = 'ERROR: Cannot communicate with master'
        global AGENT_ID
        ssl_socket.send(INPUT_MESSAGE.format(AGENT_NAME, AGENT_ID), size=False)
        AGENT_ID = AGENT_ID + 1
        response = ssl_socket.receive().decode()

        assert expected_answer in response

        ssl_socket.close()

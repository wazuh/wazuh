'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: This module verifies the correct behavior of authd under different messages in a Cluster scenario (for Worker)

components:
    - authd

targets:
    - manager

daemons:
    - wazuh-authd
    - wazuh-clusterd

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

tags:
    - enrollment
'''
import time
from pathlib import Path

import pytest
from wazuh_testing.constants.paths.sockets import MODULESD_C_INTERNAL_SOCKET_PATH
from wazuh_testing.constants.ports import DEFAULT_SSL_REMOTE_ENROLLMENT_PORT
from wazuh_testing.constants.daemons import AUTHD_DAEMON, CLUSTER_DAEMON
from wazuh_testing.tools.mitm import WorkerMID
from wazuh_testing.utils.configuration import load_configuration_template, get_test_cases_data
from wazuh_testing.utils.cluster import CLUSTER_DATA_HEADER_SIZE

from . import CONFIGURATIONS_FOLDER_PATH, TEST_CASES_FOLDER_PATH

# Marks
pytestmark = [pytest.mark.server, pytest.mark.tier(level=0)]


# Configurations
test_configuration_path = Path(CONFIGURATIONS_FOLDER_PATH, 'config_authd_worker.yaml')
test_cases_path = Path(TEST_CASES_FOLDER_PATH, 'cases_authd_worker.yaml')
test_configuration, test_metadata, test_cases_ids = get_test_cases_data(test_cases_path)
test_configuration = load_configuration_template(test_configuration_path, test_configuration, test_metadata)


# Variables
ossec_authd_socket_path = ("localhost", DEFAULT_SSL_REMOTE_ENROLLMENT_PORT)
receiver_sockets_params = [(ossec_authd_socket_path, 'AF_INET', 'SSL_TLSv1_2')]

mitm_master = WorkerMID(address=MODULESD_C_INTERNAL_SOCKET_PATH, family='AF_UNIX', connection_protocol='TCP')
monitored_sockets_params = [(CLUSTER_DAEMON, mitm_master, True), (AUTHD_DAEMON, None, True)]
receiver_sockets, monitored_sockets = None, None  # Set in the fixtures
daemons_handler_configuration = {'all_daemons': True, 'ignore_errors': True}

# Tests
@pytest.mark.parametrize('test_configuration,test_metadata', zip(test_configuration, test_metadata), ids=test_cases_ids)
def test_ossec_auth_messages(test_configuration, test_metadata, set_wazuh_configuration,
                             truncate_monitored_files, daemons_handler, configure_sockets_environment,
                             wait_for_authd_startup, connect_to_sockets):
    '''
    description:
        Checks that every message from the agent is correctly formatted for master,
        and every master response is correctly parsed for agent.

    wazuh_min_version:
        4.2.0

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
        - truncate_monitored_files:
            type: fixture
            brief: Truncate all the log files and json alerts files before and after the test execution.
        - daemons_handler:
            type: fixture
            brief: Handler of Wazuh daemons.
        - configure_sockets_environment:
            type: fixture
            brief: Configure the socket listener to receive and send messages on the sockets.
        - connect_to_sockets:
            type: fixture
            brief: Bind to the configured sockets at module scope.
        - wait_for_authd_startup:
            type: fixture
            brief: Waits until Authd is accepting connections.

    assertions:
        - The 'port_input' from agent is formatted to 'cluster_input' for master
        - The 'cluster_output' response from master is correctly parsed to 'port_output' for agent

    input_description:
        Different test cases are contained in an external YAML file (worker_messages.yaml) which includes
        the different possible registration requests and the expected responses.

    expected_output:
        - Registration request responses on Authd socket
    '''

    # Push expected info to mitm queue
    mitm_master.set_cluster_messages(test_metadata['cluster_input'], test_metadata['cluster_output'])
    # Reopen socket (socket is closed by manager after sending message with client key)
    mitm_master.restart()
    receiver_sockets[0].open()
    expected = test_metadata['port_output']
    message = test_metadata['port_input']
    receiver_sockets[0].send(message, size=False)
    timeout = time.time() + 10
    response = ''
    while response == '':
        response = receiver_sockets[0].receive().decode()
        if time.time() > timeout:
            raise ConnectionResetError('Manager did not respond to sent message!')
    clusterd_queue = monitored_sockets[0]
    # callback lambda function takes out tcp header and decodes binary to string
    clusterd_queue.start(callback=(lambda y: y), timeout=1, accumulations=2)
    results = clusterd_queue.callback_result
    assert response[:len(expected)] == expected, \
        'Failed test case: Response was: {} instead of: {}'.format(response, expected)
    # Assert monitored sockets
    assert results[0][CLUSTER_DATA_HEADER_SIZE:] == test_metadata['cluster_input'], 'Expected clusterd input message does not match'
    assert results[1][CLUSTER_DATA_HEADER_SIZE:] == test_metadata['cluster_output'], 'Expected clusterd output message does not match'

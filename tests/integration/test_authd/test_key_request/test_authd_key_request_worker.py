'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: This module verifies the correct behavior of key request under different messages in a
       Cluster scenario (for Worker)

tier: 0

modules:
    - authd

components:
    - manager

daemons:
    - wazuh-authd
    - wazuh-clusterd

os_platform:
    - linux

os_version:
    - Amazon Linux 1
    - Amazon Linux 2
    - Arch Linux
    - CentOS 6
    - CentOS 7
    - CentOS 8
    - Debian Buster
    - Debian Stretch
    - Debian Jessie
    - Debian Wheezy
    - Red Hat 6
    - Red Hat 7
    - Red Hat 8
    - Ubuntu Bionic
    - Ubuntu Trusty
    - Ubuntu Xenial

tags:
    - key request
'''
from pathlib import Path

import pytest
from wazuh_testing.constants.paths.sockets import MODULESD_C_INTERNAL_SOCKET_PATH, MODULESD_KREQUEST_SOCKET_PATH
from wazuh_testing.tools.mitm import WorkerMID
from wazuh_testing.utils.configuration import load_configuration_template, get_test_cases_data
from wazuh_testing.utils.cluster import CLUSTER_DATA_HEADER_SIZE

from . import CONFIGURATIONS_FOLDER_PATH, TEST_CASES_FOLDER_PATH, SCRIPTS_FOLDER_PATH

# Marks
pytestmark = [pytest.mark.server, pytest.mark.tier(level=0)]

# Configurations
test_configuration_path = Path(CONFIGURATIONS_FOLDER_PATH, 'config_authd_key_request_worker.yaml')
test_cases_path = Path(TEST_CASES_FOLDER_PATH, 'cases_authd_key_request_worker.yaml')
test_configuration, test_metadata, test_cases_ids = get_test_cases_data(test_cases_path)
test_configuration = load_configuration_template(test_configuration_path, test_configuration, test_metadata)

script_path = SCRIPTS_FOLDER_PATH
script_filename = 'fetch_keys.py'

# Variables
receiver_sockets_params = [(MODULESD_KREQUEST_SOCKET_PATH, 'AF_UNIX', 'UDP')]
mitm_master = WorkerMID(address=MODULESD_C_INTERNAL_SOCKET_PATH, family='AF_UNIX', connection_protocol='TCP')
monitored_sockets_params = [('wazuh-clusterd', mitm_master, True), ('wazuh-authd', None, True)]
receiver_sockets, monitored_sockets = None, None


# Tests
@pytest.mark.parametrize('test_configuration,test_metadata', zip(test_configuration, test_metadata), ids=test_cases_ids)
def test_authd_key_request_worker(test_configuration, test_metadata, set_wazuh_configuration,
                                  configure_sockets_environment, copy_tmp_script,
                                  connect_to_sockets):
    '''
    description:
        Checks that every message from the worker is correctly formatted for master,
        and every master response is correctly parsed for worker.

    wazuh_min_version:
        4.4.0

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
        - configure_sockets_environment:
            type: fixture
            brief: Configure the socket listener to receive and send messages on the sockets.
        - copy_tmp_script:
            type: fixture
            brief: Copy the script to a temporary folder for testing.
        - connect_to_sockets:
            type: fixture
            brief: Bind to the configured sockets at module scope.

    assertions:
        - The 'request_input' from agent is formatted to 'cluster_input' for master
        - The 'cluster_output' response from master is correctly parsed to 'port_output' for agent

    input_description:
        Different test cases are contained in an external YAML file (key_request_worker_messages.yaml) which includes
        the different possible key requests and the expected responses.

    expected_output:
        - Registration request responses on Authd socket
    '''
    key_request_sock = receiver_sockets[0]
    clusterd_queue = monitored_sockets[0]

    # Push expected info to mitm queue
    mitm_master.set_cluster_messages(test_metadata['cluster_input'], test_metadata['cluster_output'])
    mitm_master.restart()
    message = test_metadata['request_input']
    key_request_sock.send(message, size=False)
    # callback lambda function takes out tcp header and decodes binary to string
    clusterd_queue.start(callback=(lambda y: y), timeout=10, accumulations=2)
    results = clusterd_queue.callback_result
    # Assert monitored sockets
    assert results[0][CLUSTER_DATA_HEADER_SIZE:] == test_metadata['cluster_input'], 'Expected clusterd input message does not match'
    assert results[1][CLUSTER_DATA_HEADER_SIZE:] == test_metadata['cluster_output'], 'Expected clusterd output message does not match'

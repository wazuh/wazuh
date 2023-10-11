'''
copyright: Copyright (C) 2015-2021, Wazuh Inc.

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
import os

import pytest
from wazuh_testing.cluster import FERNET_KEY, CLUSTER_DATA_HEADER_SIZE, cluster_msg_build
from wazuh_testing.tools import WAZUH_PATH, CLUSTER_LOGS_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.monitoring import ManInTheMiddle
from wazuh_testing.tools.file import read_yaml

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]


# Configurations

class WorkerMID(ManInTheMiddle):

    def __init__(self, address, family='AF_UNIX', connection_protocol='TCP', func: callable = None):
        self.cluster_input = None
        self.cluster_output = None
        super().__init__(address, family, connection_protocol, self.verify_message)

    def set_cluster_messages(self, cluster_input, cluster_output):
        self.cluster_input = cluster_input
        self.cluster_output = cluster_output

    def verify_message(self, data: bytes):
        if len(data) > CLUSTER_DATA_HEADER_SIZE:
            message = data[CLUSTER_DATA_HEADER_SIZE:]
            response = cluster_msg_build(command=b'send_sync', counter=2, payload=bytes(self.cluster_output.encode()),
                                         encrypt=False)[0]
            print(f'Received message from wazuh-authd: {message}')
            print(f'Response to send: {self.cluster_output}')
            self.pause()
            return response
        else:
            raise ConnectionResetError('Invalid cluster message!')

    def pause(self):
        self.event.set()

    def restart(self):
        self.event.clear()


test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
message_tests = read_yaml(os.path.join(test_data_path, 'key_request_worker_messages.yaml'))
configurations_path = os.path.join(test_data_path, 'wazuh_authd_configuration.yaml')
params = [{'FERNET_KEY': FERNET_KEY}]
metadata = [{'fernet_key': FERNET_KEY}]
configurations = load_wazuh_configurations(configurations_path, __name__, params=params, metadata=metadata)
script_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'files')
script_filename = 'fetch_keys.py'

# Variables
log_monitor_paths = [CLUSTER_LOGS_PATH]
cluster_socket_path = os.path.join(os.path.join(WAZUH_PATH, 'queue', 'cluster', 'c-internal.sock'))
kreq_sock_path = os.path.join(WAZUH_PATH, 'queue', 'sockets', 'krequest')
receiver_sockets_params = [(kreq_sock_path, 'AF_UNIX', 'UDP')]
test_case_ids = [f"{test_case['name'].lower().replace(' ', '-')}" for test_case in message_tests]

mitm_master = WorkerMID(address=cluster_socket_path, family='AF_UNIX', connection_protocol='TCP')

monitored_sockets_params = [('wazuh-clusterd', mitm_master, True), ('wazuh-authd', None, True)]
receiver_sockets, monitored_sockets, log_monitors = None, None, None  # Set in the fixtures


# Fixtures


@pytest.fixture(scope='module', params=configurations, ids=['Worker'])
def get_configuration(request):
    """Get configurations from the module"""
    yield request.param


@pytest.fixture(scope='function', params=message_tests, ids=test_case_ids)
def get_current_test_case(request):
    """Get current test case from the module"""
    return request.param


# Tests
def test_authd_key_request_worker(configure_environment, configure_sockets_environment, copy_tmp_script,
                                  connect_to_sockets_module, get_current_test_case):
    '''
    description:
        Checks that every message from the worker is correctly formatted for master,
        and every master response is correctly parsed for worker.

    wazuh_min_version:
        4.4.0

    parameters:
        - get_configuration:
            type: fixture
            brief: Get the configuration of the test.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
        - configure_sockets_environment:
            type: fixture
            brief: Configure the socket listener to receive and send messages on the sockets.
        - copy_tmp_script:
            type: fixture
            brief: Copy the script to a temporary folder for testing.
        - connect_to_sockets_module:
            type: fixture
            brief: Bind to the configured sockets at module scope.
        - get_current_test_case:
            type: fixture
            brief: gets the current test case from the tests' list

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

    for stage in get_current_test_case['test_case']:
        # Push expected info to mitm queue
        mitm_master.set_cluster_messages(stage['cluster_input'], stage['cluster_output'])
        mitm_master.restart()
        message = stage['request_input']
        key_request_sock.send(message, size=False)
        # callback lambda function takes out tcp header and decodes binary to string
        results = clusterd_queue.get_results(callback=(lambda y: [x[CLUSTER_DATA_HEADER_SIZE:].decode() for x in y]),
                                             timeout=1, accum_results=1)
        # Assert monitored sockets
        assert results[0] == stage['cluster_input'], 'Expected clusterd input message does not match'
        assert results[1] == stage['cluster_output'], 'Expected clusterd output message does not match'

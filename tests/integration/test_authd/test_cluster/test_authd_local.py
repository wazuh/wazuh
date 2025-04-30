'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: This module verifies the correct behavior of 'wazuh-authd' under different messages
       in a Cluster scenario (for Master).

components:
    - authd

targets:
    - manager

daemons:
    - wazuh-authd
    - wazuh-db

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
from pathlib import Path

import json
import pytest
import time

from wazuh_testing.constants.paths.sockets import WAZUH_DB_SOCKET_PATH, AUTHD_SOCKET_PATH
from wazuh_testing.constants.daemons import AUTHD_DAEMON, WAZUH_DB_DAEMON
from wazuh_testing.utils import database
from wazuh_testing.utils.configuration import load_configuration_template, get_test_cases_data

from . import CONFIGURATIONS_FOLDER_PATH, TEST_CASES_FOLDER_PATH

# Marks
pytestmark = [pytest.mark.server, pytest.mark.tier(level=0)]

# Configurations

test_configuration_path = Path(CONFIGURATIONS_FOLDER_PATH, 'config_authd_local.yaml')
test_cases_path = Path(TEST_CASES_FOLDER_PATH, 'cases_authd_local.yaml')
test_configuration, test_metadata, test_cases_ids = get_test_cases_data(test_cases_path)
test_configuration = load_configuration_template(test_configuration_path, test_configuration, test_metadata)

# Variables
receiver_sockets_params = [(AUTHD_SOCKET_PATH, 'AF_UNIX', 'TCP'), (WAZUH_DB_SOCKET_PATH, 'AF_UNIX', 'TCP')]

daemons_handler_configuration = {'all_daemons': True}

# TODO Replace or delete
monitored_sockets_params = [(WAZUH_DB_DAEMON, None, True), (AUTHD_DAEMON, None, True)]
receiver_sockets, monitored_sockets = None, None


# Tests
@pytest.mark.parametrize('test_configuration,test_metadata', zip(test_configuration, test_metadata), ids=test_cases_ids)
def test_authd_local_messages(test_configuration, test_metadata, set_wazuh_configuration, configure_sockets_environment_module,
                              truncate_monitored_files, insert_pre_existent_agents, daemons_handler,
                              wait_for_authd_startup, set_up_groups, connect_to_sockets):
    '''
    description:
        Checks that every input message in trough local authd port generates the adequate response to worker.

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
        - configure_sockets_environment_module:
            type: fixture
            brief: Configure the socket listener to receive and send messages on the sockets at function scope.
        - connect_to_sockets:
            type: fixture
            brief: Bind to the configured sockets at function scope.
        - set_up_groups:
            type: fixture
            brief: Set the pre-defined groups.
        - insert_pre_existent_agents:
            type: fixture
            brief: adds the required agents to the client.keys and global.db
        - daemons_handler:
            type: fixture
            brief: Restarts wazuh or a specific daemon passed.
        - wait_for_authd_startup:
            type: fixture
            brief: Waits until Authd is accepting connections.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate all the log files and json alerts files before and after the test execution.

    assertions:
        - The received output must match with expected
        - The enrollment messages are parsed as expected
        - The agent keys are denied if the hash is the same as the manager's

    input_description:
        Different test cases are contained in an external YAML file (local_enroll_messages.yaml) which includes
        the different possible registration requests and the expected responses.

    expected_output:
        - Registration request responses on Authd socket
    '''
    cases = test_metadata['cases']
    for case in cases:
        # Reopen socket (socket is closed by manager after sending message with client key)
        receiver_sockets[0].open()
        expected = case['output']
        message = case['input']
        receiver_sockets[0].send(message, size=True)
        response = receiver_sockets[0].receive(size=True).decode()
        assert response[:len(expected)] == expected, \
            'Failed: Response was: {} instead of: {}' \
            .format(response, expected)

        if 'expected_group' in case:
            data = json.loads(response)['data']
            query = "global sql SELECT * FROM `agent` WHERE `id` = {}".format(data['id'])

            for i in range(3):
                group = database.query_wdb(query)

                if group:
                    break

                time.sleep(1)

            if not group:
                assert False, 'The agent was not created in the database'

            assert group[0]['group'] == case['expected_group']

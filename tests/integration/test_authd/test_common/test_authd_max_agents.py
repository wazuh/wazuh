'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests verify that wazuh-authd enforces the authd.max_agents internal option during enrollment.

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
    - https://documentation.wazuh.com/current/user-manual/reference/daemons/wazuh-authd.html

tags:
    - enrollment
'''
import re
import time
from pathlib import Path

import pytest

from wazuh_testing.constants.ports import DEFAULT_SSL_REMOTE_ENROLLMENT_PORT
from wazuh_testing.constants.daemons import AUTHD_DAEMON, WAZUH_DB_DAEMON, MODULES_DAEMON
from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.tools.monitors.file_monitor import FileMonitor
from wazuh_testing.utils import callbacks
from wazuh_testing.modules.authd import PREFIX
from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template

from . import CONFIGURATIONS_FOLDER_PATH, TEST_CASES_FOLDER_PATH

# Marks
pytestmark = [pytest.mark.server, pytest.mark.tier(level=0)]

# Paths
test_configuration_path = Path(CONFIGURATIONS_FOLDER_PATH, 'config_authd_common.yaml')
test_cases_path = Path(TEST_CASES_FOLDER_PATH, 'cases_authd_max_agents.yaml')

# Configurations
test_configuration, test_metadata, test_cases_ids = get_test_cases_data(test_cases_path)
test_configuration = load_configuration_template(test_configuration_path, test_configuration, test_metadata)

# Variables
receiver_sockets_params = [(("localhost", DEFAULT_SSL_REMOTE_ENROLLMENT_PORT), 'AF_INET', 'SSL_TLSv1_2')]
monitored_sockets_params = [(MODULES_DAEMON, None, True), (WAZUH_DB_DAEMON, None, True), (AUTHD_DAEMON, None, True)]
receiver_sockets, monitored_sockets = None, None  # Set in the fixtures

daemons_handler_configuration = {'all_daemons': True}

local_internal_options = {'authd.max_agents': '1'}


def _receive_response(authd_socket, timeout_seconds=10):
    timeout = time.time() + timeout_seconds
    response = ''
    while response == '':
        response = authd_socket.receive().decode()
        if time.time() > timeout:
            raise ConnectionResetError('The manager did not respond to the message sent.')
    return response


# Tests
@pytest.mark.parametrize('test_configuration,test_metadata', zip(test_configuration, test_metadata), ids=test_cases_ids)
def test_authd_max_agents(test_configuration, test_metadata, set_wazuh_configuration, configure_local_internal_options,
                          truncate_monitored_files, clean_agents_ctx, configure_sockets_environment, daemons_handler,
                          wait_for_authd_startup, connect_to_sockets, set_up_groups):
    '''
    description:
        Checks that authd enforces the max agents limit during enrollment and reports the expected response and log.

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
        - configure_local_internal_options:
            type: fixture
            brief: Configure the local internal options file.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate all the log files before and after the test execution.
        - clean_agents_ctx:
            type: fixture
            brief: Clean agents files.
        - configure_sockets_environment:
            type: fixture
            brief: Configure environment for sockets.
        - daemons_handler:
            type: fixture
            brief: Handler of Wazuh daemons.
        - wait_for_authd_startup:
            type: fixture
            brief: Waits until Authd is accepting connections.
        - connect_to_sockets:
            type: fixture
            brief: Module scope version of 'connect_to_sockets' fixture.
        - set_up_groups:
            type: fixture
            brief: Create a testing group for agents and provide the test case list.

    assertions:
        - Verify that the first enrollment succeeds when below the limit.
        - Verify that the second enrollment is rejected when the limit is reached.
        - Verify that the manager log includes the limit reached message.
    '''
    authd_socket = receiver_sockets[0]
    wazuh_log_monitor = FileMonitor(WAZUH_LOG_PATH)

    for stage in test_metadata['stages']:
        authd_socket.open()
        authd_socket.send(stage['input'], size=False)
        response = _receive_response(authd_socket)
        expected = stage['output']

        assert response[:len(expected)] == expected, \
            f"Response was: {response} instead of: {expected}"

        logs = stage.get('log')
        if logs:
            if isinstance(logs, str):
                logs = [logs]
            for log in logs:
                log = re.escape(log)
                wazuh_log_monitor.start(callback=callbacks.generate_callback(fr'{PREFIX}{log}'),
                                        timeout=10, encoding='utf-8')
                assert wazuh_log_monitor.callback_result, 'Error event not detected'

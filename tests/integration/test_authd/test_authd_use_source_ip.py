'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: This module verifies the correct behavior of the setting 'use_source_ip'.

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

tags:
    - enrollment
'''
import os
import ssl
import time
import pytest
from pathlib import Path

from wazuh_testing.constants.paths.logs import WAZUH_PATH
from wazuh_testing.utils.configuration import load_configuration_template, get_test_cases_data
from wazuh_testing.modules.authd.utils import validate_authd_response

from . import CONFIGURATIONS_FOLDER_PATH, TEST_CASES_FOLDER_PATH

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]

# Configurations
test_configuration_path = Path(CONFIGURATIONS_FOLDER_PATH, 'config_authd_use_source_ip.yaml')
test_cases_path = Path(TEST_CASES_FOLDER_PATH, 'cases_authd_use_source_ip.yaml')
test_configuration, test_metadata, test_cases_ids = get_test_cases_data(test_cases_path)
test_configuration = load_configuration_template(test_configuration_path, test_configuration, test_metadata)

# Variables

log_monitor_paths = []
monitored_sockets_params = [('wazuh-modulesd', None, True), ('wazuh-db', None, True), ('wazuh-authd', None, True)]
receiver_sockets, monitored_sockets, log_monitors = None, None, None  # Set in the fixtures
daemons_handler_configuration = {'all_daemons': True, 'ignore_errors': True}

# Fixtures
@pytest.fixture(scope='function')
def configure_receiver_sockets(request, test_metadata):
    """
    Get configurations from the module
    """
    global receiver_sockets_params
    if test_metadata['ipv6'] == 'yes':
        receiver_sockets_params = [(("localhost", 1515), 'AF_INET6', 'SSL_TLSv1_2')]
    else:
        receiver_sockets_params = [(("localhost", 1515), 'AF_INET', 'SSL_TLSv1_2')]
    return receiver_sockets_params

# Test
@pytest.mark.parametrize('test_configuration,test_metadata', zip(test_configuration, test_metadata), ids=test_cases_ids)
def test_authd_use_source_ip(test_configuration, test_metadata, set_wazuh_configuration, configure_receiver_sockets,
                             configure_sockets_environment, clean_client_keys_file_function, daemons_handler,
                             wait_for_authd_startup_function, connect_to_sockets_function, tear_down):
    '''
    description:
        Checks that every input message in authd port generates the adequate output

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
        - configure_sockets_environment:
            type: fixture
            brief: Configure the socket listener to receive and send messages on the sockets.
        - clean_client_keys_file_function:
            type: fixture
            brief: Cleans any previous key in client.keys file at function scope.
        - daemons_handler:
            type: fixture
            brief: Handler of Wazuh daemons.
        - wait_for_authd_startup_function:
            type: fixture
            brief: Waits until Authd is accepting connections.
        - connect_to_sockets_function:
            type: fixture
            brief: Bind to the configured sockets at function scope.
        - test_case:
            type: list
            brief: List all the test cases for the test.
        - tear_down:
            type: fixture
            brief: Roll back the daemon and client.keys state after the test ends.

    assertions:
        - The manager uses the agent's IP as requested
        - Setting an IP overrides the configuration
        - If the IP is not defined and the setting is disabled, use 'any'

    input_description:
        Different test cases are contained in an external YAML file (test_authd_use_source_ip.yaml) which includes
        the different possible registration requests and the expected responses.

    expected_output:
        - Registration request responses on Authd socket
    '''

    # Reopen socket (socket is closed by manager after sending message with client key)
    receiver_sockets[0].open()

    message = test_metadata['input']
    receiver_sockets[0].send(message, size=False)
    timeout = time.time() + 10
    response = ''
    while response == '':
        response = receiver_sockets[0].receive().decode()
        if time.time() > timeout:
            assert response != '', 'The manager did not respond to the message sent.'
    if test_metadata['use_source_ip'] == 'yes' and test_metadata['ip_specified'] == 'no':
        if test_metadata['ipv6'] == 'yes':
            expected = {"status": "success", "name": "user1", "ip": "0000:0000:0000:0000:0000:0000:0000:0001"}
        else:
            expected = {"status": "success", "name": "user1", "ip": "127.0.0.1"}
    else:
        expected = test_metadata['output']
    result, err_msg = validate_authd_response(response, expected)
    assert result == 'success', f"Failed: {err_msg} Complete response: '{response}'"

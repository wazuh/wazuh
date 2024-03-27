'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: This module verifies the correct behavior of 'authd' under different name/IP combinations.

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
import socket
import time
import pytest
from pathlib import Path

from wazuh_testing.utils.configuration import load_configuration_template, get_test_cases_data
from wazuh_testing.constants.ports import DEFAULT_SSL_REMOTE_ENROLLMENT_PORT
from wazuh_testing.constants.daemons import AUTHD_DAEMON, WAZUH_DB_DAEMON, MODULES_DAEMON
from wazuh_testing.modules.authd.utils import validate_authd_response

from . import CONFIGURATIONS_FOLDER_PATH, TEST_CASES_FOLDER_PATH

# Marks

pytestmark = [pytest.mark.server, pytest.mark.tier(level=0)]

# Configurations
test_configuration_path = Path(CONFIGURATIONS_FOLDER_PATH, 'config_authd_common.yaml')
test_cases_path = Path(TEST_CASES_FOLDER_PATH, 'cases_authd_valid_name_ip.yaml')
test_configuration, test_metadata, test_cases_ids = get_test_cases_data(test_cases_path)
test_configuration = load_configuration_template(test_configuration_path, test_configuration, test_metadata)

# Variables
receiver_sockets_params = [(("localhost", DEFAULT_SSL_REMOTE_ENROLLMENT_PORT), 'AF_INET', 'SSL_TLSv1_2')]
monitored_sockets_params = [(MODULES_DAEMON, None, True), (WAZUH_DB_DAEMON, None, True), (AUTHD_DAEMON, None, True)]
receiver_sockets, monitored_sockets = None, None  # Set in the fixtures
hostname = socket.gethostname()

daemons_handler_configuration = {'daemons': [AUTHD_DAEMON], 'ignore_errors': True}


# Test
@pytest.mark.parametrize('test_configuration,test_metadata', zip(test_configuration, test_metadata), ids=test_cases_ids)
def test_authd_valid_name_ip(test_configuration, test_metadata, set_wazuh_configuration, configure_sockets_environment_module,
                             connect_to_sockets_module,
                             truncate_monitored_files, daemons_handler, wait_for_authd_startup):
    '''
    description:
        Checks that every input message in authd port generates the adequate output.

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
            brief: Configure the socket listener to receive and send messages on the sockets.
        - daemons_handler:
            type: fixture
            brief: Handler of Wazuh daemons.
        - wait_for_authd_startup:
            type: fixture
            brief: Waits until Authd is accepting connections.
        - connect_to_sockets_module:
            type: fixture
            brief: Bind to the configured sockets at module scope.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate all the log files and json alerts files before and after the test execution.

    assertions:
        - The manager registers agents with valid IP and name
        - The manager rejects invalid input

    input_description:
        Different test cases are contained in an external YAML file (test_authd_valid_name_ip.yaml) which includes
        the different possible registration requests and the expected responses.

    expected_output:
        - Registration request responses on Authd socket
    '''

    # Reopen socket (socket is closed by manager after sending message with client key).
    receiver_sockets[0].open()

    # Set 'hostname' in test case's expected output message.
    if test_metadata['insert_hostname_in_query'] == True:
        test_metadata['input'] = test_metadata['input'].format(hostname)
        if 'message' in test_metadata['output']:
            test_metadata['output']['message'] = test_metadata['output'].get('message').format(hostname)

    # Send the message to the socket.
    receiver_sockets[0].send(test_metadata['input'], size=False)
    # Set the timeout and the empty response str.
    timeout = time.time() + 10
    response = ''

    # Wait the socket response or raise an error if timeout.
    while response == '':
        if time.time() > timeout:
            raise ConnectionResetError('Manager did not respond to sent message!')
        response = receiver_sockets[0].receive().decode()

    # Get the validated authd response.
    result, err_msg = validate_authd_response(response, test_metadata['output'])

    # ASSERTIONS.
    if test_metadata['expected_fail'] == True:
        with pytest.raises(Exception):
            assert "ERROR" in result, f"No error raised. Complete response: '{response}'"
    else:
        assert result == 'success', f"Failed with {err_msg} Complete response: '{response}'"

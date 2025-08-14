'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: This module verifies the correct behavior of the setting 'use_password'.

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
import time
import pytest
from pathlib import Path

from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.constants.ports import DEFAULT_SSL_REMOTE_ENROLLMENT_PORT
from wazuh_testing.constants.daemons import AUTHD_DAEMON, WAZUH_DB_DAEMON, MODULES_DAEMON
from wazuh_testing.utils.configuration import load_configuration_template, get_test_cases_data

from . import CONFIGURATIONS_FOLDER_PATH, TEST_CASES_FOLDER_PATH

# Marks

pytestmark = [pytest.mark.server, pytest.mark.tier(level=0)]

# Configurations
test_configuration_path = Path(CONFIGURATIONS_FOLDER_PATH, 'config_authd_use_password.yaml')
test_cases_path = Path(TEST_CASES_FOLDER_PATH, 'cases_authd_use_password.yaml')
test_configuration, test_metadata, test_cases_ids = get_test_cases_data(test_cases_path)
test_configuration = load_configuration_template(test_configuration_path, test_configuration, test_metadata)

# Variables
DEFAULT_TEST_PASSWORD = 'TopSecret'
AGENT_INPUT = "OSSEC A:'{}'"
AGENT_INPUT_WITH_PASS = "OSSEC PASS: {} OSSEC A:'{}'"
INVALID_REQUEST_MESSAGE = 'ERROR: Invalid request for new agent'
INVALID_PASSWORD_MESSAGE = 'ERROR: Invalid password'
SUCCESS_MESSAGE = "OSSEC K:'001 {} any "

receiver_sockets_params = [(("localhost", DEFAULT_SSL_REMOTE_ENROLLMENT_PORT), 'AF_INET', 'SSL_TLSv1_2')]
monitored_sockets_params = [(MODULES_DAEMON, None, True), (WAZUH_DB_DAEMON, None, True), (AUTHD_DAEMON, None, True)]
receiver_sockets, monitored_sockets = None, None

# Test daemons to restart.
daemons_handler_configuration = {'all_daemons': True}


# Functions

def read_random_pass():
    """
    Search for the random password creation in Wazuh logs
    """
    passw = None
    try:
        with open(WAZUH_LOG_PATH, 'r') as log_file:
            lines = log_file.readlines()
            for line in lines:
                if "Random password" in line:
                    passw = line.split()[-1]
            log_file.close()
    except IOError as exception:
        raise
    return passw


# Test
@pytest.mark.parametrize('test_configuration,test_metadata', zip(test_configuration, test_metadata), ids=test_cases_ids)
def test_authd_use_password(test_configuration, test_metadata, set_wazuh_configuration,
                             reset_password, truncate_monitored_files, daemons_handler, configure_sockets_environment,
                             wait_for_authd_startup, connect_to_sockets):
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
        - configure_sockets_environment:
            type: fixture
            brief: Configure the socket listener to receive and send messages on the sockets.
        - reset_password:
            type: fixture
            brief: Write the password file.
        - daemons_handler:
            type: fixture
            brief: Restarts wazuh or a specific daemon passed.
        - wait_for_authd_startup:
            type: fixture
            brief: Waits until Authd is accepting connections.
        - connect_to_sockets:
            type: fixture
            brief: Bind to the configured sockets at function scope.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate all the log files and json alerts files before and after the test execution.

    assertions:
        - The random password works as expected.
        - A wrong password is rejected.
        - A request with password and use_password = 'no' is rejected.

    input_description:
        Different test cases are contained in an external YAML file (test_authd_use_password.yaml) which
        includes the different possible registration requests and the expected responses.

    expected_output:
        - Registration request responses on 'authd' socket.
    '''

    # Reopen socket (socket is closed by manager after sending message with client key)
    receiver_sockets[0].open()

    # Creating input message
    if test_metadata['insert_random_pass_in_query'] == 'yes':
        message = AGENT_INPUT_WITH_PASS.format(read_random_pass(), test_metadata['user'])
    elif test_metadata['pass'] != None:
        message = AGENT_INPUT_WITH_PASS.format(test_metadata['pass'], test_metadata['user'])
    else:
        message = AGENT_INPUT.format(test_metadata['user'])

    message += '\n'
    receiver_sockets[0].send(message, size=False)
    timeout = time.time() + 10
    response = ''
    while response == '':
        response = receiver_sockets[0].receive().decode()
        if time.time() > timeout:
            raise ConnectionResetError('Manager did not respond to sent message!')

    # Creating output message
    if test_metadata['use_password'] == 'yes':
        if test_metadata['random_pass'] != None and test_metadata['insert_random_pass_in_query'] != None:
            expected = SUCCESS_MESSAGE.format(test_metadata['user'])
        elif test_metadata['pass'] == DEFAULT_TEST_PASSWORD:
            expected = SUCCESS_MESSAGE.format(test_metadata['user'])
        else:
            expected = INVALID_PASSWORD_MESSAGE
    # use_password = 'no'
    else:
        if test_metadata['pass'] != None or test_metadata['insert_random_pass_in_query'] != None:
            expected = INVALID_REQUEST_MESSAGE
        else:
            expected = SUCCESS_MESSAGE.format(test_metadata['user'])

    assert response[:len(expected)] == expected, 'Failed: Response is different from expected'

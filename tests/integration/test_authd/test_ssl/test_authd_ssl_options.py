'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests will check if the 'SSL' (Secure Socket Layer) protocol-related settings of
       the 'wazuh-authd' daemon are working correctly. The 'wazuh-authd' daemon can
       automatically add a Wazuh agent to a Wazuh manager and provide the key
       to the agent. 

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
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/auth.html

tags:
    - enrollment
'''
import ssl
from pathlib import Path

import pytest

from wazuh_testing.utils.configuration import load_configuration_template, get_test_cases_data
from wazuh_testing.constants.ports import DEFAULT_SSL_REMOTE_ENROLLMENT_PORT
from wazuh_testing.constants.daemons import AUTHD_DAEMON, WAZUH_DB_DAEMON, MODULES_DAEMON
from wazuh_testing.tools.socket_controller import SocketController

from . import CONFIGURATIONS_FOLDER_PATH, TEST_CASES_FOLDER_PATH

# Marks

pytestmark = [pytest.mark.server, pytest.mark.tier(level=0)]

# Configurations
test_configuration_path = Path(CONFIGURATIONS_FOLDER_PATH, 'config_authd_ssl_options.yaml')
test_cases_path = Path(TEST_CASES_FOLDER_PATH, 'cases_authd_ssl_options.yaml')
test_configuration, test_metadata, test_cases_ids = get_test_cases_data(test_cases_path)
test_configuration = load_configuration_template(test_configuration_path, test_configuration, test_metadata)

# Variables
receiver_sockets_params = [(("localhost", DEFAULT_SSL_REMOTE_ENROLLMENT_PORT), 'AF_INET', 'SSL_TLSv1_2')]
monitored_sockets_params = [(MODULES_DAEMON, None, True), (WAZUH_DB_DAEMON, None, True), (AUTHD_DAEMON, None, True)]
receiver_sockets, monitored_sockets = None, None

daemons_handler_configuration = {'all_daemons': True}


# Tests
@pytest.mark.parametrize('test_configuration,test_metadata', zip(test_configuration, test_metadata), ids=test_cases_ids)
def test_ossec_auth_configurations(test_configuration, test_metadata, set_wazuh_configuration,
                                   truncate_monitored_files, daemons_handler,
                                   configure_sockets_environment, wait_for_authd_startup):
    '''
    description:
        Checks if the 'SSL' settings of the 'wazuh-authd' daemon work correctly by enrolling agents
        that use different values for these settings. Different types of encryption and secure
        connection protocols are tested, in addition to the 'ssl_auto_negotiate' option
        that automatically chooses the protocol to be used.

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
        - daemons_handler:
            type: fixture
            brief: Handler of Wazuh daemons.
        - wait_for_authd_startup:
            type: fixture
            brief: Waits until Authd is accepting connections.
        - configure_sockets_environment:
            type: fixture
            brief: Configure environment for sockets and MITM.

    assertions:
        - Verify that the response messages are consistent with the enrollment requests received.

    input_description:
        Different test cases are contained in an external YAML file (enroll_ssl_options_tests.yaml)
        that includes enrollment events and the expected output.

    expected_output:
        - Multiple values located in the 'enroll_ssl_options_tests.yaml' file.

    tags:
        - keys
        - ssl
    '''
    ciphers = test_metadata['ciphers']
    protocol = test_metadata['protocol']
    expect = test_metadata['expect']

    if protocol == 'ssl_tlsv1_1':
        pytest.skip('TLS 1.1 is deprecated and not working on several pyOpenSSL versions.')


    address, family, connection_protocol = receiver_sockets_params[0]
    SSL_socket = SocketController(address, family=family, connection_protocol=connection_protocol,
                                  open_at_start=False)

    SSL_socket.set_ssl_configuration(ciphers=ciphers, connection_protocol=protocol)

    try:
        SSL_socket.open()
    except ssl.SSLError as exception:
        if expect == 'open_error':
            # We expected the error here, check message.
            assert test_metadata['error'] in exception.strerror, 'Expected message does not match!'
            return
        else:
            # We did not expect this error, fail test.
            raise

    SSL_socket.send(test_metadata['input'], size=False)

    if expect == 'output':
        # Output is expected
        expected = test_metadata['output']
        if expected:
            response = SSL_socket.receive().decode()
            print(expected)
            print(response)
            assert response, 'Failed connection'
            assert response[:len(expected)] == expected, 'Failed test case'

    # Finally close the socket. TODO: This must be handled on a fixture.
    SSL_socket.close()

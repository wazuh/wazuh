'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests will check if the 'SSL' (Secure Socket Layer) protocol-related settings of
       the 'wazuh-authd' daemon are working correctly. The 'wazuh-authd' daemon can
       automatically add a Wazuh agent to a Wazuh manager and provide the key
       to the agent. It is used along with the 'agent-auth' application.

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
import os
import ssl
import time

import pytest
import yaml
from wazuh_testing.fim import generate_params
from wazuh_testing.tools import LOG_FILE_PATH
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.configuration import set_section_wazuh_conf, write_wazuh_conf
from wazuh_testing.tools.file import truncate_file, read_yaml
from wazuh_testing.tools.monitoring import SocketController, FileMonitor
from wazuh_testing.tools.services import control_service, check_daemon_status

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]


# Configurations

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
configurations_path = os.path.join(test_data_path, 'wazuh_authd_configuration.yaml')
ssl_configuration_tests = read_yaml(os.path.join(test_data_path, 'enroll_ssl_options_tests.yaml'))

# Ossec.conf configurations
DEFAULT_CIPHERS = "HIGH:!ADH:!EXP:!MD5:!RC4:!3DES:!CAMELLIA:@STRENGTH"
DEFAULT_AUTO_NEGOTIATE = 'no'
conf_params = {'CIPHERS': [], 'SSL_AUTO_NEGOTIATE': []}

for case in ssl_configuration_tests:
    conf_params['CIPHERS'].append(case.get('CIPHERS', DEFAULT_CIPHERS))
    conf_params['SSL_AUTO_NEGOTIATE'].append(case.get('SSL_AUTO_NEGOTIATE', DEFAULT_AUTO_NEGOTIATE))

p, m = generate_params(extra_params=conf_params, modes=['scheduled'] * len(ssl_configuration_tests))
configurations = load_wazuh_configurations(configurations_path, __name__, params=p, metadata=m)

# Certifcates configurations


# Variables
log_monitor_paths = []

receiver_sockets_params = [(("localhost", 1515), 'AF_INET', 'SSL_TLSv1_2')]

monitored_sockets_params = [('wazuh-modulesd', None, True), ('wazuh-db', None, True), ('wazuh-authd', None, True)]

receiver_sockets, monitored_sockets, log_monitors = None, None, None  # Set in the fixtures
# fixtures

test_index = 0


def get_current_test():
    """
    Get the current test case.
    """
    global test_index
    current = test_index
    test_index += 1
    return current


@pytest.fixture(scope="module", params=configurations)
def get_configuration(request):
    """Get configurations from the module"""
    return request.param


def override_wazuh_conf(configuration):
    """
    Write a particular Wazuh configuration for the test case.
    """
    # Stop Wazuh
    control_service('stop', daemon='wazuh-authd')
    time.sleep(1)
    check_daemon_status(running_condition=False, target_daemon='wazuh-authd')
    truncate_file(LOG_FILE_PATH)

    # Configuration for testing
    test_config = set_section_wazuh_conf(configuration.get('sections'))
    # Set new configuration
    write_wazuh_conf(test_config)

    time.sleep(1)
    # Start Wazuh
    control_service('start', daemon='wazuh-authd')

    """Wait until authd has begun"""

    def callback_agentd_startup(line):
        if 'Accepting connections on port 1515' in line:
            return line
        return None

    log_monitor = FileMonitor(LOG_FILE_PATH)
    log_monitor.start(timeout=30, callback=callback_agentd_startup)


def test_ossec_auth_configurations(get_configuration, configure_environment, configure_sockets_environment):
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
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - configure_environment:
            type: fixture
            brief: Configure a custom environment for testing.
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
    current_test = get_current_test()
    config = ssl_configuration_tests[current_test]['test_case']
    ciphers = config['ciphers']
    protocol = config['protocol']
    expect = config['expect']

    if protocol == 'ssl_tlsv1_1':
        pytest.skip('TLS 1.1 is deprecated and not working on several pyOpenSSL versions.')

    override_wazuh_conf(get_configuration)

    address, family, connection_protocol = receiver_sockets_params[0]
    SSL_socket = SocketController(address, family=family, connection_protocol=connection_protocol,
                                  open_at_start=False)

    SSL_socket.set_ssl_configuration(ciphers=ciphers, connection_protocol=protocol)

    try:
        SSL_socket.open()
    except ssl.SSLError as exception:
        if expect == 'open_error':
            # We expected the error here, check message.
            assert config['error'] in exception.strerror, 'Expected message does not match!'
            return
        else:
            # We did not expect this error, fail test.
            raise

    SSL_socket.send(config['input'], size=False)

    if expect == 'output':
        # Output is expected
        expected = config['output']
        if expected:
            response = SSL_socket.receive().decode()
            assert response, 'Failed connection stage: {}'.format(config['stage'])
            assert response[:len(expected)] == expected, 'Failed test case stage: {}'.format(config['stage'])

    # Finally close the socket. TODO: This must be handled on a fixture.
    SSL_socket.close()

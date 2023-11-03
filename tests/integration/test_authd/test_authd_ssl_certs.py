'''
copyright: Copyright (C) 2015-2021, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests will check if the 'wazuh-authd' daemon is able to handle secure connections using
       the 'SSL' (Secure Socket Layer) protocol. The 'wazuh-authd' daemon can automatically add
       a Wazuh agent to a Wazuh manager and provide the key to the agent.
       It is used along with the 'agent-auth' application.

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
    - https://documentation.wazuh.com/current/user-manual/registering/host-verification-registration.html

tags:
    - enrollment
'''
import os
import ssl
import time
from pathlib import Path

import pytest

from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template
from wazuh_testing.tools.socket_controller import SocketController
from wazuh_testing.tools.certificate_controller import CertificateController

from . import CONFIGURATIONS_FOLDER_PATH, TEST_CASES_FOLDER_PATH

# Marks

pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]

# Paths
test_configuration_path = Path(CONFIGURATIONS_FOLDER_PATH, 'config_authd_ssl_certs.yaml')
test_cases_path = Path(TEST_CASES_FOLDER_PATH, 'cases_authd_ssl_certs.yaml')

# Configurations
test_configuration, test_metadata, test_cases_ids = get_test_cases_data(test_cases_path)
test_configuration = load_configuration_template(test_configuration_path, test_configuration, test_metadata)

SSL_AGENT_CA = '/var/ossec/etc/test_rootCA.pem'
SSL_AGENT_CERT = '/tmp/test_sslagent.cert'
SSL_AGENT_PRIVATE_KEY = '/tmp/test_sslagent.key'

AGENT_ID = 0
AGENT_NAME = 'test_agent'
AGENT_IP = '127.0.0.1'
WRONG_IP = '10.0.0.240'
INPUT_MESSAGE = "OSSEC A:'{}_{}'"
OUPUT_MESSAGE = "OSSEC K:'"

# Simulation options
# a. Unverified Host:
# - No certificate
# - Valid Certificate
# - Incorrect Certificate
# b. Verified Host:
# - No cerificate
# - No certificate
# - Valid Certificate
# - Incorrect Certificate
# - Valid certificate, Incorrect Host
# Variables

receiver_sockets_params = [((AGENT_IP, 1515), 'AF_INET', 'SSL_TLSv1_2')]

monitored_sockets_params = [('wazuh-modulesd', None, True), ('wazuh-db', None, True), ('wazuh-authd', None, True)]

receiver_sockets, monitored_sockets = None, None


# fixtures
@pytest.fixture(scope="function")
def generate_ca_certificate(test_metadata):
    # Generate root key and certificate
    controller = CertificateController()
    option = test_metadata['sim_option']
    if option not in ['NO_CERT']:
        # Wheter manager will recognize or not this key
        will_sign = True if option in ['VALID CERT', 'INCORRECT HOST'] else False
        controller.generate_agent_certificates(SSL_AGENT_PRIVATE_KEY, SSL_AGENT_CERT,
                                               WRONG_IP if option == 'INCORRECT HOST' else AGENT_IP, signed=will_sign)
    controller.store_ca_certificate(controller.get_root_ca_cert(), SSL_AGENT_CA)


# Tests
@pytest.mark.parametrize('test_configuration,test_metadata', zip(test_configuration, test_metadata), ids=test_cases_ids)
def test_authd_ssl_certs(test_configuration, test_metadata, set_wazuh_configuration,
                         restart_authd_function, wait_for_authd_startup_function,
                         generate_ca_certificate, tear_down):
    '''
    description:
        Checks if the 'wazuh-authd' daemon can manage 'SSL' connections with agents
        and the 'host verification' feature is working properly. For this purpose,
        it generates and signs the necessary certificates and builds the
        enrollment requests using them.

    wazuh_min_version:
        4.2.0

    tier: 0

    parameters:
        - get_configuration:
            type: fixture
            brief: Get configurations from the module.
        - generate_ca_certificate:
            type: fixture
            brief: Build the 'CA' (Certificate of Authority) and sign the certificate used by the testing agent.
        - tear_down:
            type: fixture
            brief: cleans the client.keys file

    assertions:
        - Verify that the agent can only connect to the 'wazuh-authd' daemon socket using a valid certificate.
        - Verify that using a valid certificate the agent can only enroll using the IP address linked to it.

    input_description:
        Different test cases are found in the test module and include
        parameters for the environment setup, the requests
        to be made, and the expected result.

    expected_output:
        - r'OSSEC K:' (When the agent has enrolled in the manager)

    tags:
        - keys
        - ssl
    '''
    verify_host = (test_metadata['verify_host'] == 'yes')
    option = test_metadata['sim_option']
    print(option)
    address, family, connection_protocol = receiver_sockets_params[0]
    SSL_socket = SocketController(address, family=family, connection_protocol=connection_protocol, open_at_start=False)
    if option != 'NO CERT':
        SSL_socket.set_ssl_configuration(certificate=SSL_AGENT_CERT, keyfile=SSL_AGENT_PRIVATE_KEY)
    try:
        SSL_socket.open()
        if option in ['NO CERT', 'INCORRECT CERT']:
            raise AssertionError(f'Agent was enable to connect without using any certificate or an incorrect one!')
    except ssl.SSLError as exception:
        if option in ['NO CERT', 'INCORRECT CERT']:
            # Expected to happen
            return
        else:
            raise AssertionError(f'Option {option} expected successful socket connection but it failed')
    global AGENT_ID
    SSL_socket.send(INPUT_MESSAGE.format(AGENT_NAME, AGENT_ID), size=False)
    AGENT_ID = AGENT_ID + 1
    try:
        response = ''
        timeout = time.time() + 10
        while response == '':
            response = SSL_socket.receive().decode()
            if time.time() > timeout:
                raise ConnectionResetError('Manager did not respond to sent message!')
        if option in ['INCORRECT HOST'] and verify_host:
            raise AssertionError(f'An incorrect host was able to register using the verify_host option')
    except ConnectionResetError as exception:
        if option in ['INCORRECT HOST'] and verify_host:
            # Expected
            return
        else:
            raise
    assert response[:len(OUPUT_MESSAGE)] == OUPUT_MESSAGE, (
        f'Option {option} response from manager did not match expected')
    return

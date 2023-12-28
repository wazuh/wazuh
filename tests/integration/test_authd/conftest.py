"""
Copyright (C) 2015-2023, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""
import shutil
import pytest
import time
import os

from wazuh_testing import logger
from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH, WAZUH_API_LOG_FILE_PATH, WAZUH_API_JSON_LOG_FILE_PATH
from wazuh_testing.constants.paths.configurations import DEFAULT_AUTHD_PASS_PATH, DEFAULT_AUTHD_PASS_PATH, WAZUH_CLIENT_KEYS_PATH
from wazuh_testing.utils import file
from wazuh_testing.utils.callbacks import generate_callback
from wazuh_testing.utils.agent_groups import create_group, delete_group
from wazuh_testing.tools.monitors import file_monitor
from wazuh_testing.modules.authd import PREFIX
from wazuh_testing.constants.daemons import AUTHD_DAEMON
from wazuh_testing.utils import mocking
from wazuh_testing.utils.services import control_service
from wazuh_testing.constants.api import WAZUH_API_PORT
from wazuh_testing.constants.ports import DEFAULT_SSL_REMOTE_ENROLLMENT_PORT
from wazuh_testing.modules.api.patterns import API_STARTED_MSG
from wazuh_testing.tools.certificate_controller import CertificateController
from . import utils


AUTHD_STARTUP_TIMEOUT = 30

@pytest.fixture()
def stop_authd():
    """
    Stop Authd.
    """
    control_service("stop", daemon=AUTHD_DAEMON)


@pytest.fixture()
def wait_for_authd_startup():
    """Wait until authd has begun with function scope"""
    log_monitor = file_monitor.FileMonitor(WAZUH_LOG_PATH)
    log_monitor.start(timeout=AUTHD_STARTUP_TIMEOUT, encoding="utf-8",
                      callback=generate_callback(rf'{PREFIX}Accepting connections on port 1515'))
    assert log_monitor.callback_result


@pytest.fixture(scope='module')
def wait_for_api_startup_module():
    """Monitor the API log file to detect whether it has been started or not.

    Raises:
        RuntimeError: When the log was not found.
    """
    # Set the default values
    logs_format = 'plain'
    host = '0.0.0.0'
    port = WAZUH_API_PORT

    # Check if specific values were set or set the defaults
    file_to_monitor = WAZUH_API_JSON_LOG_FILE_PATH if logs_format == 'json' else WAZUH_API_LOG_FILE_PATH
    monitor_start_message = file_monitor.FileMonitor(file_to_monitor)
    monitor_start_message.start(
        callback=generate_callback(API_STARTED_MSG, {
            'host': str(host),
            'port': str(port)
        })
    )

    if monitor_start_message.callback_result is None:
        raise RuntimeError('The API was not started as expected.')


@pytest.fixture()
def insert_pre_existent_agents(test_metadata, stop_authd):
    """
    Create some agents and add them to the DB and keys file.
    """
    agents = test_metadata['pre_existent_agents']
    time_now = int(time.time())

    for agent in agents:
        if agent:
            id = agent['id'] if 'id' in agent else '001'
            name = agent['name'] if 'name' in agent else f"TestAgent{id}"
            ip = agent['ip'] if 'ip' in agent else 'any'
            key = agent['key'] if 'key' in agent else 'TopSecret'
            connection_status = agent['connection_status'] if 'connection_status' in agent else 'never_connected'
            if 'disconnection_time' in agent and 'delta' in agent['disconnection_time']:
                disconnection_time = time_now + agent['disconnection_time']['delta']
            elif 'disconnection_time' in agent and 'value' in agent['disconnection_time']:
                disconnection_time = agent['disconnection_time']['value']
            else:
                disconnection_time = time_now
            if 'registration_time' in agent and 'delta' in agent['registration_time']:
                registration_time = time_now + agent['registration_time']['delta']
            elif 'registration_time' in agent and 'value' in agent['registration_time']:
                registration_time = agent['registration_time']['value']
            else:
                registration_time = time_now

            mocking.create_mocked_agent(id=id, name=name, ip=ip, date_add=registration_time,
                                        connection_status=connection_status, disconnection_time=disconnection_time,
                                        client_key_secret=key)

    yield

    for agent in agents:
        if agent:
            mocking.delete_mocked_agent(agent['id'])


@pytest.fixture()
def copy_tmp_script(request):
    """
    Copy the script named 'script_filename' and found in 'script_path' to a temporary folder for use in the test.
    """
    try:
        script_filename = getattr(request.module, 'script_filename')
    except AttributeError as script_filename_not_set:
        logger.debug('script_filename is not set')
        raise script_filename_not_set

    try:
        script_path = getattr(request.module, 'script_path')
    except AttributeError as script_path_not_set:
        logger.debug('script_path is not set')
        raise script_path_not_set

    shutil.copy(os.path.join(script_path, script_filename), os.path.join("/tmp", script_filename))


@pytest.fixture()
def configure_receiver_sockets(request, test_metadata):
    """
    Get configurations from the module and set receiver sockets.
    """
    if test_metadata['ipv6'] == 'yes':
        receiver_sockets_params = [(("localhost", DEFAULT_SSL_REMOTE_ENROLLMENT_PORT), 'AF_INET6', 'SSL_TLSv1_2')]
    else:
        receiver_sockets_params = [(("localhost", DEFAULT_SSL_REMOTE_ENROLLMENT_PORT), 'AF_INET', 'SSL_TLSv1_2')]

    setattr(request.module, 'receiver_sockets_params', receiver_sockets_params)


@pytest.fixture()
def set_authd_pass(test_metadata):
    """
    Configure the file 'authd.pass' as needed for the test.
    """
    # Write the content in the authd.pass file.
    file.write_file(DEFAULT_AUTHD_PASS_PATH, test_metadata['password'])

    yield

    # Delete the file as by default if it doesn't exist.
    file.remove_file(DEFAULT_AUTHD_PASS_PATH)


@pytest.fixture()
def reset_password(test_metadata):
    """
    Write the password file.
    """
    DEFAULT_TEST_PASSWORD = 'TopSecret'
    set_password = None
    try:
        if test_metadata['use_password'] == 'yes':
            set_password = 'defined'
            if test_metadata['random_pass'] == 'yes':
                set_password = 'random'
        else:
            set_password = 'undefined'
    except KeyError:
        pass

    # in case of random pass, remove /etc/authd.pass
    if set_password == 'random' or set_password == 'undefined':
        try:
            os.remove(DEFAULT_AUTHD_PASS_PATH)
        except FileNotFoundError:
            pass
        except IOError:
            raise
    # in case of defined pass, set predefined pass in  /etc/authd.pass
    elif set_password == 'defined':
        # Write authd.pass
        try:
            with open(DEFAULT_AUTHD_PASS_PATH, 'w') as pass_file:
                pass_file.write(DEFAULT_TEST_PASSWORD)
                pass_file.close()
        except IOError as exception:
            raise


@pytest.fixture(scope="function")
def generate_ca_certificate(test_metadata):
    """
    Generate custom CA certificate.
    """
    SSL_AGENT_CA = '/var/ossec/etc/test_rootCA.pem'
    SSL_AGENT_CERT = '/tmp/test_sslagent.cert'
    SSL_AGENT_PRIVATE_KEY = '/tmp/test_sslagent.key'
    AGENT_IP = '127.0.0.1'
    WRONG_IP = '10.0.0.240'
    # Generate root key and certificate
    controller = CertificateController()
    option = test_metadata['sim_option']
    if option not in ['NO_CERT']:
        # Wheter manager will recognize or not this key
        will_sign = True if option in ['VALID CERT', 'INCORRECT HOST'] else False
        controller.generate_agent_certificates(SSL_AGENT_PRIVATE_KEY, SSL_AGENT_CERT,
                                               WRONG_IP if option == 'INCORRECT HOST' else AGENT_IP, signed=will_sign)
    controller.store_ca_certificate(controller.get_root_ca_cert(), SSL_AGENT_CA)


@pytest.fixture(scope="function")
def set_up_groups(test_metadata, request):
    """
    Create and delete groups for test.
    """
    groups = test_metadata['groups']
    for group in groups:
        if(group):
            create_group(group)
    yield
    for group in groups:
        if(group):
            delete_group(group)


@pytest.fixture()
def clean_agents_ctx(stop_authd):
    """
    Clean agents files.
    """
    file.truncate_file(WAZUH_CLIENT_KEYS_PATH)
    utils.clean_rids()
    utils.clean_agents_timestamp()
    utils.clean_diff()

    yield

    file.truncate_file(WAZUH_CLIENT_KEYS_PATH)
    utils.clean_rids()
    utils.clean_agents_timestamp()
    utils.clean_diff()

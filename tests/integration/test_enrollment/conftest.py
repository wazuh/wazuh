'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.
        Created by Wazuh, Inc. <info@wazuh.com>.
        This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
'''
import pytest
import os
import sys

from wazuh_testing.constants.daemons import AGENT_DAEMON
from wazuh_testing.constants.paths.configurations import WAZUH_CLIENT_KEYS_PATH, DEFAULT_AUTHD_PASS_PATH
from wazuh_testing.tools.simulators.authd_simulator import AuthdSimulator
from wazuh_testing.utils.file import write_file, remove_file
from wazuh_testing.utils.services import control_service

MANAGER_ADDRESS = '127.0.0.1'


@pytest.fixture(scope='module')
def shutdown_agentd(request):
    """Stop wazuh-agentd process."""
    control_service('stop', daemon=AGENT_DAEMON)


@pytest.fixture()
def restart_agentd(test_metadata):
    """
    Restart Agentd and control if it is expected to fail or not.
    """
    try:
        control_service('restart', daemon=AGENT_DAEMON)
    except Exception:
        pass

    yield

    control_service('stop', daemon=AGENT_DAEMON)


@pytest.fixture()
def set_keys(test_metadata):
    """
    Writes the keys file with the content defined in the configuration.
    Args:
        test_metadata (dict): Current test case metadata.
    """
    for key in test_metadata.get('pre_existent_keys', []):
        write_file(WAZUH_CLIENT_KEYS_PATH, key)


@pytest.fixture()
def set_password(test_metadata):
    """Writes the password file with the content defined in the configuration.
    Args:
        test_metadata (dict): Current test case metadata.
    """
    if 'password_file_content' in test_metadata:
        write_file(DEFAULT_AUTHD_PASS_PATH, test_metadata['password_file_content'])

    yield

    if 'password_file_content' in test_metadata:
        remove_file(DEFAULT_AUTHD_PASS_PATH)


@pytest.fixture()
def configure_socket_listener(request, test_metadata):
    """
    Configures the socket listener to start listening on the socket.
    """

    address_family = 'AF_INET6' if 'ipv6' in test_metadata else 'AF_INET'
    manager_address = '::1' if 'ipv6' in test_metadata else MANAGER_ADDRESS

    socket_listener = AuthdSimulator(server_ip = manager_address, family=address_family, secret="TopSecret")
    socket_listener.start()
    socket_listener.clear()

    setattr(request.module, 'socket_listener', socket_listener)

    yield

    socket_listener.shutdown()


@pytest.fixture(autouse=True)
def autostart_simulators() -> None:
    yield

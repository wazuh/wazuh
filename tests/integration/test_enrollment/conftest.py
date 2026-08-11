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
from wazuh_testing.tools.simulators.remoted_simulator import RemotedSimulator
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
def clean_keys():
    """Truncate client.keys before the case runs.

    Without this, a case that actually enrolls (e.g. "expected_connection: True") leaves a
    real key on disk for every later case in the same module -- keys.keysize > 0 then skips
    w_agentd_keys_init()'s enrollment attempt (start_agent.c) regardless of what that later
    case's own server address is, so it never even tries to connect/resolve.
    """
    with open(WAZUH_CLIENT_KEYS_PATH, 'w'):
        pass


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

    A real (non-empty) pre-existing key means this case re-enrolls at runtime rather than at
    first startup: with a key already on disk, w_agentd_keys_init() (start_agent.c) never
    attempts enrollment itself (that path is gated on keys.keysize == 0). The only current
    trigger that re-enrolls anyway is bridge_on_reenroll_required() (https_client_bridge.c),
    fired when the HTTPS control connection gets a live 401 -- so a RemotedSimulator rejecting
    auth is started here to produce that rejection, standing in for the real manager.
    """

    address_family = 'AF_INET6' if 'ipv6' in test_metadata else 'AF_INET'
    manager_address = '::1' if 'ipv6' in test_metadata else MANAGER_ADDRESS

    socket_listener = AuthdSimulator(server_ip = manager_address, family=address_family, secret="TopSecret")
    socket_listener.start()
    socket_listener.clear()

    setattr(request.module, 'socket_listener', socket_listener)

    has_real_pre_existent_key = any(test_metadata.get('pre_existent_keys', []))
    remoted_server = None
    if has_real_pre_existent_key:
        remoted_server = RemotedSimulator(mode='REJECT_AUTH')
        remoted_server.start()

    yield

    if remoted_server:
        remoted_server.destroy()
    socket_listener.shutdown()


@pytest.fixture(autouse=True)
def autostart_simulators() -> None:
    yield

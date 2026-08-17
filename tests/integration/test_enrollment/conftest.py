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
    Writes the keys file with the content defined in the configuration, clearing
    any pre-existent_keys-less case's file first.

    Always clears WAZUH_CLIENT_KEYS_PATH before writing: w_agentd_keys_init()
    (start_agent.c) skips enrollment entirely at startup once keys.keysize > 0,
    so a case with no 'pre_existent_keys' relies on starting from an empty file
    -- otherwise it silently inherits whatever a previous parametrized case in
    the same module enrolled with (daemons_handler_module only restarts the
    daemon set once per module, not per case).

    Args:
        test_metadata (dict): Current test case metadata.
    """
    remove_file(WAZUH_CLIENT_KEYS_PATH)

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
def configure_remoted_listener(test_metadata):
    """
    For scenarios that start with a real pre-existent key, w_agentd_keys_init()
    (start_agent.c) sees keys.keysize > 0 and skips enrollment entirely at
    startup -- under HTTPS, sending the K:-hash enrollment message only ever
    happens later, from bridge_reenroll_thread() once two consecutive 401s
    escalate through AuthGate.reportAuthFailure() (ControlStateMachine treats a
    dropped/refused connection alone as a mere TransientFailure and never
    escalates it). Start a rejecting RemotedSimulator so that escalation
    actually happens; cases with no pre-existent key don't need it, since their
    enrollment runs synchronously before the HTTPS client -- and thus before
    this simulator -- ever starts.
    """
    has_real_key = any(key.strip() for key in test_metadata.get('pre_existent_keys', []))

    remoted_server = RemotedSimulator(mode='REJECT_AUTH') if has_real_key else None
    if remoted_server:
        remoted_server.start()

    yield

    if remoted_server:
        remoted_server.destroy()


@pytest.fixture()
def configure_socket_listener(request, test_metadata):
    """
    Configures the socket listener to start listening on the socket.
    """

    address_family = 'AF_INET6' if 'ipv6' in test_metadata else 'AF_INET'
    manager_address = '::1' if 'ipv6' in test_metadata else MANAGER_ADDRESS

    # No explicit secret: let it fall back to AuthdSimulator's own default
    # (DEFAULT_AUTHD_SECRET, client_keys.py) -- a valid 32/48/64-hex-char key. The old
    # hardcoded "TopSecret" (9 chars, not even hex) fails bridge_key_is_valid() on the
    # real agent's HTTPS client (https_client_bridge.c) once it's written to
    # client.keys, so the agent never got past enrollment: no HTTPS client, no
    # /control traffic, nothing the rest of the test could observe.
    socket_listener = AuthdSimulator(server_ip = manager_address, family=address_family)
    socket_listener.start()
    socket_listener.clear()

    setattr(request.module, 'socket_listener', socket_listener)

    yield

    socket_listener.shutdown()


@pytest.fixture(autouse=True)
def autostart_simulators() -> None:
    yield

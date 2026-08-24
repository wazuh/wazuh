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
def configure_socket_listener(request, test_metadata):
    """
    Configures the manager-side listener the agent enrolls against, over the same HTTPS
    port as ``/control`` etc. If the test case supplies ``password_file_content``
    (mirroring what ``set_password`` writes to the agent's own password file), the same
    string is set as ``enroll_password`` so both sides derive the same enrollment key.

    For scenarios that start with a real pre-existent key, w_agentd_keys_init()
    (start_agent.c) sees keys.keysize > 0 and skips enrollment entirely at startup, so
    the agent only re-enrolls later, once two consecutive 401s on /control escalate
    through AuthGate.reportAuthFailure() (ControlStateMachine treats a dropped/refused
    connection alone as a mere TransientFailure and never escalates it) -- the listener
    starts in REJECT_AUTH for those cases so that escalation actually happens; the same
    instance still serves /enroll normally, so the re-enrollment attempt succeeds.
    """

    manager_address = '::1' if 'ipv6' in test_metadata else MANAGER_ADDRESS
    has_real_key = any(key.strip() for key in test_metadata.get('pre_existent_keys', []))

    socket_listener = RemotedSimulator(server_ip=manager_address,
                                       mode='REJECT_AUTH' if has_real_key else 'ACCEPT')
    if 'password_file_content' in test_metadata:
        socket_listener.enroll_password = test_metadata['password_file_content']
    socket_listener.start()
    socket_listener.clear()

    setattr(request.module, 'socket_listener', socket_listener)

    yield

    socket_listener.destroy()


@pytest.fixture(autouse=True)
def autostart_simulators() -> None:
    yield

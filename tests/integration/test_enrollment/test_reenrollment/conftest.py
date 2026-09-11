'''
copyright: Copyright (C) 2015-2026, Wazuh Inc.
        Created by Wazuh, Inc. <info@wazuh.com>.
        This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

Fixtures for the re-enrollment policy suite (wazuh/wazuh#39064).

The whole suite needs one thing the other enrollment suites do not: an agent that is *already*
enrolled, holding both halves of a credential the manager also holds. A re-enrollment bearer is
signed with the agent's own ``etc/reenroll.secret``, so a test that did not seed both sides could
only ever provoke ``unknown_agent`` -- which is one of the outcomes under test, and would make
every other one unreachable.
'''
import os

import pytest

from wazuh_testing.constants.daemons import AGENT_DAEMON
from wazuh_testing.constants.paths.configurations import (AGENT_REENROLL_SECRET_PATH,
                                                          DEFAULT_AUTHD_PASS_PATH,
                                                          WAZUH_CLIENT_KEYS_PATH)
from wazuh_testing.tools.simulators.remoted_simulator import (DEFAULT_MANAGER_ENDPOINT_PREFIX,
                                                              RemotedSimulator)
from wazuh_testing.utils import jwt_enroll
from wazuh_testing.utils.file import remove_file, write_file
from wazuh_testing.utils.services import control_service

MANAGER_ADDRESS = '127.0.0.1'

# The identity every case starts from. The key is what client.keys holds and the secret is what
# reenroll.secret holds; both are fixed rather than random so a failing run can be reproduced
# from the log alone.
AGENT_ID = '001'
AGENT_NAME = 'reenrolling-agent'
AGENT_KEY = 'a' * 64
AGENT_REENROLL_SECRET = 'b1' * 32


def write_identity(agent_id=AGENT_ID, key=AGENT_KEY, secret=AGENT_REENROLL_SECRET):
    """Write the agent's half of an enrolled identity: client.keys and reenroll.secret.

    The secret file's format is the store's own: ``<id> <secret>\\n``, split on the FIRST space
    (reenroll_secret.c). Written without the daemon running, so the modes do not matter here --
    the agent re-creates the file with its own when it rotates.
    """
    write_file(WAZUH_CLIENT_KEYS_PATH, f'{agent_id} {AGENT_NAME} any {key}\n')
    write_file(AGENT_REENROLL_SECRET_PATH, f'{agent_id} {secret}\n')


@pytest.fixture()
def enrolled_agent():
    """An agent that already holds an identity, and no fleet-wide password.

    Removing authd.pass matters: with one on disk the agent has a credential to fall back on, and
    the cases about an agent that has run out of credentials would silently pass for the wrong
    reason.
    """
    remove_file(DEFAULT_AUTHD_PASS_PATH)
    write_identity()

    yield

    remove_file(WAZUH_CLIENT_KEYS_PATH)
    remove_file(AGENT_REENROLL_SECRET_PATH)
    remove_file(DEFAULT_AUTHD_PASS_PATH)


@pytest.fixture()
def manager():
    """A started RemotedSimulator that holds the manager's half of that same identity.

    Yields the instance so a test can change its knobs mid-run -- several of these cases are
    about what the agent does when a refusal stops happening, which needs the manager to change
    its mind while the agent is running.
    """
    simulator = RemotedSimulator(server_ip=MANAGER_ADDRESS, prefix=DEFAULT_MANAGER_ENDPOINT_PREFIX)
    simulator.set_reenroll_secret(AGENT_ID, AGENT_REENROLL_SECRET)
    simulator.start()
    simulator.clear()

    yield simulator

    simulator.destroy()


@pytest.fixture()
def restart_agentd():
    """Start agentd for one case and stop it afterwards, whatever the case did."""
    try:
        control_service('restart', daemon=AGENT_DAEMON)
    except Exception:
        pass

    yield

    try:
        control_service('stop', daemon=AGENT_DAEMON)
    except Exception:
        pass


def stored_secret():
    """The secret the agent currently holds, or None if it has none."""
    if not os.path.exists(AGENT_REENROLL_SECRET_PATH):
        return None
    with open(AGENT_REENROLL_SECRET_PATH, 'r') as handle:
        content = handle.read().strip()
    return content.split(' ', 1)[1] if ' ' in content else None


def stored_agent_id():
    """The agent id in client.keys, or None if there is no usable entry."""
    if not os.path.exists(WAZUH_CLIENT_KEYS_PATH):
        return None
    with open(WAZUH_CLIENT_KEYS_PATH, 'r') as handle:
        first = handle.readline().strip()
    return first.split(' ', 1)[0] if first else None


def bearer_kid(request):
    """The `kid` of the enrollment bearer a recorded /enroll request carried, or None.

    The single most informative thing about a re-enrollment: a `kid` equal to the agent's own id
    proves the agent signed with its stored secret rather than falling back to a password, which
    no assertion about the response body can establish.
    """
    headers = {name.lower(): value for name, value in (request or {}).get('headers', {}).items()}
    header = headers.get('authorization', '')
    if not header.startswith('Bearer '):
        return None
    peeked = jwt_enroll.peek_kid(header[len('Bearer '):].strip())
    return peeked.text if peeked is not None else None

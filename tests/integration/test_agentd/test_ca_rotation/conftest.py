'''
copyright: Copyright (C) 2015-2026, Wazuh Inc.
        Created by Wazuh, Inc. <info@wazuh.com>.
        This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

Fixtures for the CA bundle rotation suite (wazuh/wazuh#39321).

What this suite needs that no other one does is a manager the agent can actually VERIFY. A CA
refresh is issued only over a channel the agent already trusts -- that is the whole basis for
believing the bundle that comes back -- so a simulator serving an unrelated self-signed
certificate, which is what every other suite uses, would make every case here vacuous: the agent
would never reach the code under test.

``use_bootstrap_chain`` gives the simulator the real manager's shape instead: a CA, and a
listener certificate that CA signed, with a SubjectAlternativeName covering the address being
served. Seed that CA as the agent's anchor and the agent verifies, exactly as it does in the
field, against a store the test can then watch being replaced.

The anchor is deliberately seeded in its PRE-#39321 shape -- ``0750`` directory, root-owned file
-- rather than in the shape the refresh needs. w_token_bootstrap_repair_anchor_ownership()
(token_bootstrap.c) is supposed to correct exactly that on every root start, so seeding the
corrected shape would quietly excuse the suite from the upgrade path every existing install
takes. If that repair ever regresses, these tests stop being able to install anything.
'''
import grp
import os
import pwd
import time

import pytest

from wazuh_testing.constants.daemons import AGENT_DAEMON
from wazuh_testing.constants.paths.configurations import (AGENT_REENROLL_SECRET_PATH,
                                                          BASE_CONF_PATH,
                                                          DEFAULT_AUTHD_PASS_PATH,
                                                          WAZUH_CLIENT_KEYS_PATH)
from wazuh_testing.tools.simulators.remoted_simulator import (DEFAULT_MANAGER_ENDPOINT_PREFIX,
                                                              RemotedSimulator)
from wazuh_testing.utils.file import remove_file, write_file
from wazuh_testing.utils.services import control_service

MANAGER_ADDRESS = '127.0.0.1'

# The identity every case starts from. Fixed rather than random so a failing run can be
# reproduced from the log alone; the key must be 64 hex characters or the HTTPS client refuses to
# start at all (bridge_key_is_valid(), https_client_bridge.c).
AGENT_ID = '001'
AGENT_NAME = 'rotating-agent'
AGENT_KEY = 'c3' * 32

# The trust store and the marker beside it (defs.h: AGENT_ANCHOR_CA, AGENT_ANCHOR_MARKER).
CERTS_DIR = os.path.join(BASE_CONF_PATH, 'certs')
ANCHOR_PATH = os.path.join(CERTS_DIR, 'root-ca.pem')
MARKER_PATH = os.path.join(CERTS_DIR, '.anchor-committed')

# The metadata block w_ca_publication_render() writes ahead of the certificates, per RFC 7468 2:
# text before the first encapsulation boundary, so the store stays a plain PEM any tool can read.
PUBLICATION_BANNER = '## wazuh-ca-bundle'
PUBLICATION_PREFIX = '## generation:'

# No publication recorded. Distinct from 0: a store carrying no block at all is one this agent
# did not write -- a fresh bootstrap, or an upgrade from before the feature -- and the agent
# re-anchors on the first publication it is offered rather than treating it as "nothing to do".
UNKNOWN_PUBLICATION = -1


def render_publication(generation):
    """The metadata block for `generation`, byte-for-byte as the agent renders it."""
    return f'{PUBLICATION_BANNER}\n{PUBLICATION_PREFIX} {generation}\n'.encode()


def write_anchor(pem, generation=None):
    """Install `pem` as the agent's trust store, optionally recording a publication with it.

    Written root-owned under a 0750 directory: the pre-#39321 shape, so every case also proves
    the repair on the next root start. `generation=None` leaves the store with no block, which
    is the "never recorded one" state.
    """
    os.makedirs(CERTS_DIR, exist_ok=True)
    os.chmod(CERTS_DIR, 0o750)
    os.chown(CERTS_DIR, 0, grp.getgrnam('wazuh').gr_gid)

    block = render_publication(generation) if generation is not None else b''
    with open(ANCHOR_PATH, 'wb') as handle:
        handle.write(block + pem)

    os.chmod(ANCHOR_PATH, 0o640)
    os.chown(ANCHOR_PATH, 0, grp.getgrnam('wazuh').gr_gid)


def store_bytes():
    """Everything the trust store holds, or None when there is no store."""
    if not os.path.exists(ANCHOR_PATH):
        return None
    with open(ANCHOR_PATH, 'rb') as handle:
        return handle.read()


def store_publication():
    """The publication the trust store records, or UNKNOWN_PUBLICATION if it records none.

    Reads the file the same way w_ca_publication_read() does -- stop at the first encapsulation
    boundary -- so a `## generation:` that somehow appeared below the certificates is not found
    here either.
    """
    content = store_bytes()
    if content is None:
        return UNKNOWN_PUBLICATION

    for line in content.decode(errors='replace').splitlines():
        if line.startswith('-----BEGIN'):
            break
        if line.startswith(PUBLICATION_PREFIX):
            try:
                return int(line[len(PUBLICATION_PREFIX):].strip())
            except ValueError:
                return UNKNOWN_PUBLICATION
    return UNKNOWN_PUBLICATION


def certificate_count():
    """How many certificates the trust store holds."""
    content = store_bytes()
    return 0 if content is None else content.count(b'-----BEGIN CERTIFICATE-----')


def store_owner():
    """(uid, gid, mode) of the trust store, for the cases that assert the repair ran."""
    info = os.stat(ANCHOR_PATH)
    return info.st_uid, info.st_gid, info.st_mode & 0o7777


def runtime_uid():
    """The uid agentd drops to, which must end up owning the store it replaces."""
    return pwd.getpwnam('wazuh').pw_uid


@pytest.fixture()
def manager():
    """A started RemotedSimulator the agent can verify, holding the identity it presents.

    ``use_bootstrap_chain`` is what makes this suite possible: the /cacerts body becomes the CA
    that signed the listener's own certificate, so seeding it as the anchor puts the agent in the
    posture a refresh requires. Yielded so a case can publish mid-run -- every one of these is
    about what the agent does when the manager's bundle changes underneath it.
    """
    simulator = RemotedSimulator(server_ip=MANAGER_ADDRESS,
                                 prefix=DEFAULT_MANAGER_ENDPOINT_PREFIX,
                                 use_bootstrap_chain=True)
    simulator.start()
    simulator.clear()

    yield simulator

    simulator.destroy()


@pytest.fixture()
def anchored_agent(manager):
    """An agent already enrolled and already anchored on this manager's CA.

    Depends on `manager` rather than taking the CA as an argument: the material is minted on
    first access, before the listener exists, so the anchor and the certificate the agent will be
    offered cannot disagree.

    Every credential that could provoke an enrollment is removed. Enrollment is off in the
    configuration too, but a leftover re-enrollment secret outranks client.keys
    (w_enrollment_build_request()), and an agent spending a case re-enrolling is an agent not
    rotating its CA.
    """
    remove_file(DEFAULT_AUTHD_PASS_PATH)
    remove_file(AGENT_REENROLL_SECRET_PATH)
    write_file(WAZUH_CLIENT_KEYS_PATH, f'{AGENT_ID} {AGENT_NAME} any {AGENT_KEY}\n')
    write_anchor(manager.cacerts_pem)

    yield

    remove_file(WAZUH_CLIENT_KEYS_PATH)
    remove_file(AGENT_REENROLL_SECRET_PATH)
    # Both, always. A marker left behind with no anchor beside it is tampering as far as the
    # agent is concerned, and the next suite to run would find an agent that refuses to start.
    remove_file(ANCHOR_PATH)
    remove_file(MARKER_PATH)


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


def wait_for(predicate, timeout, interval=0.2):
    """Poll until true or the timeout elapses; return what it last saw."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return predicate()

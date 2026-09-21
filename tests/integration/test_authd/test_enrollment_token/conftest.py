"""
Copyright (C) 2015-2024, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""
import grp
import json
import os
import pwd
import time

import pytest

from . import utils


@pytest.fixture()
def clean_enrollment_tokens():
    """Leave `etc/enrollment_tokens.json` absent before and after the test.

    Every case states what the store must hold, so none of them may inherit tokens from the
    previous one. Removing the file rather than emptying it matters: an absent store is the only
    thing authd reads as "no tokens" at startup -- `etoken_store_reload_if_changed()` deliberately
    keeps its in-memory replica when the file disappears under a running daemon, because during a
    cluster sync the file is legitimately gone for an instant.

    Requested before `daemons_handler` in every test so the removal lands while authd is still
    stopped, and cleaned up afterwards so the suite leaves the manager as it found it.
    """
    utils.file_remove_quietly(utils.ENROLLMENT_TOKENS_PATH)

    yield

    utils.file_remove_quietly(utils.ENROLLMENT_TOKENS_PATH)


@pytest.fixture()
def remove_created_agents():
    """Collect the ids of the agents a test enrolls and delete them afterwards.

    The test appends every id authd answers with; the teardown purges them over a connection of its
    own, since the test's own socket is closed by then. Failures are swallowed: an agent that is
    already gone (or an authd that is already stopped) must not turn a passing test red.
    """
    created_agents = []

    yield created_agents

    for agent_id in created_agents:
        try:
            utils.authd_socket_request({'function': 'remove',
                                        'arguments': {'id': agent_id, 'purge': True}})
        except Exception:
            pass


@pytest.fixture()
def write_enrollment_token_store():
    """Return a callable that plants a valid store file, standing in for a cluster sync.

    A factory rather than plain setup on purpose: the case it serves is about the mtime driven
    reload, so the file has to appear while authd is *already* running, and the daemons are brought
    up by `daemons_handler`/`configure_sockets_environment` -- which run after every plain fixture
    would have written it. Removal is `clean_enrollment_tokens`' job.

    The entry is a complete version 1 record with exactly one anchor (a pin, no embedded CA), which
    is what `etoken_parse_entry()` requires; ownership and mode match what the master writes, so
    authd can still read it after dropping privileges.
    """
    def _write(token_id=utils.SYNCED_TOKEN_ID, secret=utils.SYNCED_TOKEN_SECRET,
               pin=utils.SYNCED_TOKEN_PIN, adr=utils.ENDPOINT_ADDRESS, ttl=3600,
               description='synced'):
        now = int(time.time())
        store = {
            'version': 1,
            'tokens': [
                {
                    'id': token_id,
                    'secret': secret,
                    'adr': adr,
                    'pin': pin,
                    'ca': None,
                    'created': now,
                    'expires': now + ttl,
                    'max_uses': 0,
                    'uses': 0,
                    'revoked': False,
                    'description': description,
                }
            ],
        }

        # Created 0640 from the start rather than chmod()ed afterwards, so the file is never
        # readable by everyone, not even for an instant -- the same rule the master follows when it
        # renames a freshly written store into place.
        descriptor = os.open(utils.ENROLLMENT_TOKENS_PATH,
                             os.O_WRONLY | os.O_CREAT | os.O_TRUNC, utils.STORE_MODE)
        with os.fdopen(descriptor, 'w', encoding='utf-8') as store_file:
            json.dump(store, store_file)

        os.chmod(utils.ENROLLMENT_TOKENS_PATH, utils.STORE_MODE)
        try:
            owner = pwd.getpwnam(utils.STORE_OWNER).pw_uid
            group = grp.getgrnam(utils.STORE_OWNER).gr_gid
            os.chown(utils.ENROLLMENT_TOKENS_PATH, owner, group)
        except (KeyError, PermissionError) as exception:
            pytest.fail(f'Could not give {utils.ENROLLMENT_TOKENS_PATH} to '
                        f'{utils.STORE_OWNER}: {exception}. authd drops privileges and could not '
                        f'read the store.')

        return token_id

    return _write

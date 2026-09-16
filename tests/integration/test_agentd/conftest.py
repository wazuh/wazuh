# Copyright (C) 2015-2024, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest
import time

from wazuh_testing.constants.paths.variables import AGENTD_STATE
from wazuh_testing.constants.paths.configurations import (AGENT_REENROLL_SECRET_PATH,
                                                         WAZUH_CLIENT_KEYS_PATH)
from wazuh_testing.utils.client_keys import add_client_keys_entry


@pytest.fixture()
def remove_state_file() -> None:
    # Remove state file to check if agent behavior is as expected
    os.remove(AGENTD_STATE) if os.path.exists(AGENTD_STATE) else None


def _drop_reenroll_secret() -> None:
    """Remove etc/reenroll.secret, the credential that outranks client.keys.

    A successful /enroll hands the agent one (wazuh/wazuh#39064) and
    w_enrollment_build_request() prefers it over every other credential, so a module that
    resets only client.keys does not get an agent without an identity -- it gets one that
    re-enrolls as whatever agent the leftover secret names. Against the fresh
    RemotedSimulator these tests start, that is answered `unknown_agent`, and the agent has
    to shred the secret and climb a step of the retry ramp before it can enroll for real.
    It still gets there, but it spends time these tests' 150s waits have not budgeted for,
    and the identity under test is not the one the case set up.

    The leak is across modules, not within one: the first suite to enrol leaves the secret
    behind for every later one.
    """
    if os.path.exists(AGENT_REENROLL_SECRET_PATH):
        os.remove(AGENT_REENROLL_SECRET_PATH)


@pytest.fixture()
def clean_keys() -> None:
    # Cleans content of client.keys file
    with open(WAZUH_CLIENT_KEYS_PATH, 'w'):
        pass
    _drop_reenroll_secret()
    time.sleep(1)


@pytest.fixture()
def add_keys() -> None:
    # Add content of client.keys file. No explicit key: add_client_keys_entry
    # generates a random 64-hex-char one, which is what bridge_key_is_valid()
    # (https_client_bridge.c) requires for AES-CMAC -- "SuperSecretKey" is
    # neither hex nor 32/48/64 chars, so the HTTPS client would refuse to
    # start at all.
    add_client_keys_entry("001", "ubuntu-agent", "any")
    # The planted entry is the identity under test; a secret left by an earlier module would
    # outrank it. See _drop_reenroll_secret().
    _drop_reenroll_secret()


@pytest.fixture()
def remove_keys_file(test_metadata) -> None:
    # Remove keys file if needed
    if(test_metadata['DELETE_KEYS_FILE']):
        os.remove(WAZUH_CLIENT_KEYS_PATH) if os.path.exists(WAZUH_CLIENT_KEYS_PATH) else None
        _drop_reenroll_secret()


@pytest.fixture(autouse=True)
def autostart_simulators() -> None:
    yield

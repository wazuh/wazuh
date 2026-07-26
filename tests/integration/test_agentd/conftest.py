# Copyright (C) 2015-2024, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest
import time

from wazuh_testing.constants.paths.variables import AGENTD_STATE
from wazuh_testing.constants.paths.configurations import WAZUH_CLIENT_KEYS_PATH
from wazuh_testing.utils.client_keys import add_client_keys_entry


@pytest.fixture()
def remove_state_file() -> None:
    # Remove state file to check if agent behavior is as expected
    os.remove(AGENTD_STATE) if os.path.exists(AGENTD_STATE) else None


@pytest.fixture()
def clean_keys() -> None:
    # Cleans content of client.keys file
    with open(WAZUH_CLIENT_KEYS_PATH, 'w'):
        pass
    time.sleep(1)


@pytest.fixture()
def add_keys() -> None:
    # Add content of client.keys file. Must be valid AES-CMAC hex (32/48/64 chars):
    # the HTTPS client (wazuh/wazuh#37831) validates this at startup, unlike the legacy
    # symmetric cipher, which accepted any string (e.g. the old 'SuperSecretKey' literal).
    add_client_keys_entry("001", "ubuntu-agent", "any", "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6")


@pytest.fixture()
def remove_keys_file(test_metadata) -> None:
    # Remove keys file if needed
    if(test_metadata['DELETE_KEYS_FILE']):
        os.remove(WAZUH_CLIENT_KEYS_PATH) if os.path.exists(WAZUH_CLIENT_KEYS_PATH) else None


@pytest.fixture(autouse=True)
def autostart_simulators() -> None:
    yield

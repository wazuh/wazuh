# Copyright (C) 2015-2024, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest
import time
import sys

from wazuh_testing.constants.platforms import WINDOWS
from wazuh_testing.constants.paths.variables import AGENTD_STATE
from wazuh_testing.constants.paths.configurations import WAZUH_CLIENT_KEYS_PATH, WAZUH_CONF_PATH
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
    # Add content of client.keys file
    add_client_keys_entry("001", "ubuntu-agent", "any", "SuperSecretKey")


@pytest.fixture()
def remove_keys_file(test_metadata) -> None:
    # Remove keys file if needed
    if(test_metadata['DELETE_KEYS_FILE']):
        os.remove(WAZUH_CLIENT_KEYS_PATH) if os.path.exists(WAZUH_CLIENT_KEYS_PATH) else None


@pytest.fixture(autouse=True)
def autostart_simulators() -> None:
    yield

@pytest.fixture(scope="session", autouse=True)
def fix_ossec_conf_multiple_roots():
    """Temporary fix: DEB/RPM packages install ossec.conf with two <ossec_config> root
    blocks. The test framework's XML parser only supports a single root element, so we
    merge both blocks by removing the closing tag of the first block and the opening tag
    of the second block before the test session begins.
    """
    if sys.platform == WINDOWS:
        return

    try:
        with open(WAZUH_CONF_PATH, 'r') as f:
            content = f.read()

        # Only act when two root blocks are present
        if content.count('</ossec_config>') < 2:
            return

        # Remove the boundary between the two blocks: </ossec_config>...<ossec_config>
        import re
        fixed = re.sub(r'</ossec_config>\s*<ossec_config>', '', content, count=1)

        with open(WAZUH_CONF_PATH, 'w') as f:
            f.write(fixed)
    except OSError:
        # Not installed or no permission — tests will fail on their own if needed
        pass

# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest
import time

from wazuh_testing.constants.paths.variables import AGENTD_STATE
from wazuh_testing.constants.paths.configurations import WAZUH_CLIENT_KEYS_PATH
from wazuh_testing.tools.simulators.remoted_simulator import RemotedSimulator
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

@pytest.fixture()
def start_remoted_simulators(test_metadata) -> None:
    # Servers paremeters
    remoted_server_addresses = ["127.0.0.0","127.0.0.1","127.0.0.2"]
    remoted_server_ports = [1514,1516,1517]
    remoted_servers = [None,None,None]

    # Start Remoted Simulators
    for i in range(len(remoted_server_addresses)):
        if(test_metadata['SIMULATOR_MODES'][i] != 'CLOSE'):
            remoted_servers[i] = RemotedSimulator(protocol = test_metadata['PROTOCOL'], server_ip = remoted_server_addresses[i], 
                                        port = remoted_server_ports[i], mode = test_metadata['SIMULATOR_MODES'][i])
            remoted_servers[i].start()
    
    yield remoted_servers

    # Shutdown simulators
    for i in range(len(remoted_servers)):
        if(remoted_servers[i]):
            remoted_servers[i].destroy()
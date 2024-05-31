# Copyright (C) 2015-2024, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import pytest

from wazuh_testing.constants.ports import DEFAULT_SSL_REMOTE_CONNECTION_PORT
from wazuh_testing.tools.simulators.remoted_simulator import RemotedSimulator


@pytest.fixture()
def start_remoted_simulators(test_metadata) -> None:
    # Servers paremeters
    remoted_server_address = "127.0.0.1"
    remoted_server_ports = [DEFAULT_SSL_REMOTE_CONNECTION_PORT,1516,1517]
    remoted_servers = [None,None,None]

    # Start Remoted Simulators
    for i in range(len(remoted_server_ports)):
        if(test_metadata['SIMULATOR_MODES'][i] != 'CLOSE'):
            remoted_servers[i] = RemotedSimulator(protocol = test_metadata['PROTOCOL'], server_ip = remoted_server_address,
                                        port = remoted_server_ports[i], mode = test_metadata['SIMULATOR_MODES'][i])
            remoted_servers[i].start()

    yield remoted_servers

    # Shutdown simulators
    for i in range(len(remoted_servers)):
        if(remoted_servers[i]):
            remoted_servers[i].destroy()

"""
 Copyright (C) 2015-2024, Wazuh Inc.
 Created by Wazuh, Inc. <info@wazuh.com>.
 This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""

import pytest
import time

from pathlib import Path
from wazuh_testing.tools.monitors.file_monitor import FileMonitor
from wazuh_testing.tools.simulators.agent_simulator import connect
from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template
from wazuh_testing.modules.remoted.configuration import REMOTED_DEBUG

from . import CONFIGS_PATH, TEST_CASES_PATH


# Set pytest marks.
pytestmark = [pytest.mark.server, pytest.mark.tier(level=2)]

# Cases metadata and its ids.
cases_path = Path(TEST_CASES_PATH, 'cases_agents_switching_protocols.yaml')
config_path = Path(CONFIGS_PATH, 'config_agents_switching_protocols.yaml')
test_configuration, test_metadata, cases_ids = get_test_cases_data(cases_path)
test_configuration = load_configuration_template(config_path, test_configuration, test_metadata)

daemons_handler_configuration = {'all_daemons': True}

local_internal_options = {REMOTED_DEBUG: '2'}


def connect_agents_changing_protocol(agents,agents_connections, protocol, port):
    # Create sender threads. One for each agent
    for idx, agent in enumerate(agents):
        sender, injector = connect(agent, protocol = protocol, manager_port = port) #
        agents_connections[agent.id] = {'agent': agent, 'sender': sender, 'injector': injector}


def stop_all(connections):
    """Stop all active agents

    Args:
        connections (dict): contains the agents, the injectors and the senders for each agent.
    """
    for agent in connections:
        connections[agent]['injector'].stop_receive()


# Test function.
@pytest.mark.parametrize('test_configuration, test_metadata',  zip(test_configuration, test_metadata), ids=cases_ids)
def test_agents_switching_protocols(test_configuration, test_metadata, configure_local_internal_options, truncate_monitored_files,
                            set_wazuh_configuration, daemons_handler, simulate_agents):

    '''
    description: Checks if the agents can reconnect without issues to the manager after switching their protocol.
                 For this purpose, the test will establish a connection with simulated agents. Then, they will be
                 stopped and it will wait until the manager consider that agents are disconnected. Finally, it will
                 connect the agents switching their protocol.

    parameters:
        - test_configuration
            type: dict
            brief: Configuration applied to ossec.conf.
        - test_metadata:
            type: dict
            brief: Test case metadata.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate all the log files and json alerts files before and after the test execution.
        - configure_local_internal_options:
            type: fixture
            brief: Configure the Wazuh local internal options using the values from `local_internal_options`.
        - daemons_handler:
            type: fixture
            brief: Restart service once the test finishes stops the daemons.
        - simulate_agents
            type: fixture
            brief: create agents
        - set_wazuh_configuration:
            type: fixture
            brief: Apply changes to the ossec.conf configuration.

    '''

    agents = simulate_agents
    agents_connections = {}

    try:
        protocol = test_metadata['protocol1']
        connect_agents_changing_protocol(agents, agents_connections, protocol, test_metadata['port'])

        stop_all(agents_connections)

        # The test must wait until the manager considers the agents as disconnected. This time is
        # set using the `agents_disconnection_time` option from the `global` section of the conf.
        time.sleep(test_metadata['time']*2)

        protocol = test_metadata['protocol2']
        connect_agents_changing_protocol(agents, agents_connections, protocol, test_metadata['port'])

    finally:
        stop_all(agents_connections)

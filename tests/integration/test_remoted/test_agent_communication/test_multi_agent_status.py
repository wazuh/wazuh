"""
 Copyright (C) 2015-2024, Wazuh Inc.
 Created by Wazuh, Inc. <info@wazuh.com>.
 This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""

import pytest

from pathlib import Path
from wazuh_testing.tools.simulators.agent_simulator import connect
from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template
from wazuh_testing.modules.remoted.configuration import REMOTED_DEBUG
from . import CONFIGS_PATH, TEST_CASES_PATH


# Set pytest marks.
pytestmark = [pytest.mark.server, pytest.mark.tier(level=2)]

# Cases metadata and its ids.
cases_path = Path(TEST_CASES_PATH, 'cases_multi_agent_status.yaml')
config_path = Path(CONFIGS_PATH, 'config_multi_agent_status.yaml')
test_configuration, test_metadata, cases_ids = get_test_cases_data(cases_path)
test_configuration = load_configuration_template(config_path, test_configuration, test_metadata)

daemons_handler_configuration = {'all_daemons': True}

local_internal_options = {REMOTED_DEBUG: '2'}


# Test function.
@pytest.mark.parametrize('test_configuration, test_metadata',  zip(test_configuration, test_metadata), ids=cases_ids)
def test_multi_agent_status(test_configuration, test_metadata, configure_local_internal_options, truncate_monitored_files,
                            set_wazuh_configuration, daemons_handler, simulate_agents):

    '''
    description: Check multiple agents status after sending the start-up and keep-alive events via TCP, UDP or both.
                 For this purpose, the test will create all the agents and select the protocol using Round-Robin. Then,
                 every agent uses a sender and it waits until 'active' status appears after an startup and keep-alive
                 events, for each one.
                 It requires review and a rework for the agent simulator. Sometimes it does not work properly when it
                 sends keep-alives messages causing the agent to never being in active status.


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
    senders = []
    injectors = []

    for agent in agents:
        sender, injector = connect(agent,manager_port = test_metadata['port'], protocol = test_metadata['protocol'], wait_status='active')
        senders.append(sender)
        injectors.append(injector)

    for injector in injectors:
        injector.stop_receive()

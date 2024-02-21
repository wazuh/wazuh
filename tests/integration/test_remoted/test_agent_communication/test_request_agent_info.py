"""
 Copyright (C) 2015-2024, Wazuh Inc.
 Created by Wazuh, Inc. <info@wazuh.com>.
 This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""

import pytest
import time

from pathlib import Path
from wazuh_testing.tools.simulators.agent_simulator import connect
from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template
from wazuh_testing.modules.remoted.configuration import REMOTED_DEBUG
from wazuh_testing.constants.paths.sockets import REMOTED_SOCKET_PATH
from wazuh_testing.utils import sockets
from . import CONFIGS_PATH, TEST_CASES_PATH


# Set pytest marks.
pytestmark = [pytest.mark.server, pytest.mark.tier(level=2)]

# Cases metadata and its ids.
cases_path = Path(TEST_CASES_PATH, 'cases_request_agent_info.yaml')
config_path = Path(CONFIGS_PATH, 'config_request_agent_info.yaml')
test_configuration, test_metadata, cases_ids = get_test_cases_data(cases_path)
test_configuration = load_configuration_template(config_path, test_configuration, test_metadata)

daemons_handler_configuration = {'all_daemons': True}

local_internal_options = {REMOTED_DEBUG: '2'}


# Test function.
@pytest.mark.parametrize('test_configuration, test_metadata',  zip(test_configuration, test_metadata), ids=cases_ids)
def test_request_agent_info(test_configuration, test_metadata, configure_local_internal_options, truncate_monitored_files,
                            set_wazuh_configuration, daemons_handler, simulate_agents):

    '''
    description: Check that there are no problems when the manager tries to communicate with an agent to ask for
                 configuration or state files using the remoted socket. For this purpose, the test will create agents
                 and then, for each agent, it will wait until the agent key is loaded by remoted. After that, a request
                 is sent depending on the test case, and it checks if the response is the expected one for that case.
                 If the agent is disconnected, it raises an error.
                 As the test has nothing to do with shared configuration files, we removed those rootcheck txt files
                 from default agent group to reduce the time required by the test to make the checks.


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
    agent = simulate_agents[0]

    command_request = test_metadata['command_request']
    expected_answer = test_metadata['expected_answer']
    if "disconnected" not in command_request:
        sender, injector = connect(agent, protocol = test_metadata['protocol'])
    else:
        # Give time for the remoted socket to be ready.
        time.sleep(15)

    msg_request = f'{agent.id} {command_request}'
    response = sockets.send_request_socket(query = msg_request, socket_path = REMOTED_SOCKET_PATH)

    assert expected_answer.encode() in response, "Remoted unexpected answer"

    if "disconnected" not in command_request:
        injector.stop_receive()

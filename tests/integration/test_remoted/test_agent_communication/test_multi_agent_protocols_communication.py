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
from wazuh_testing.constants.paths.logs import ARCHIVES_LOG_PATH
from wazuh_testing.tools.monitors.file_monitor import FileMonitor
from wazuh_testing.utils.callbacks import generate_callback
from wazuh_testing.tools.thread_executor import ThreadExecutor
from . import CONFIGS_PATH, TEST_CASES_PATH


# Set pytest marks.
pytestmark = [pytest.mark.server, pytest.mark.tier(level=2)]

# Cases metadata and its ids.
cases_path = Path(TEST_CASES_PATH, 'cases_multi_agent_protocols_communication.yaml')
config_path = Path(CONFIGS_PATH, 'config_multi_agent_protocols_communication.yaml')
test_configuration, test_metadata, cases_ids = get_test_cases_data(cases_path)
test_configuration = load_configuration_template(config_path, test_configuration, test_metadata)

daemons_handler_configuration = {'all_daemons': True}

local_internal_options = {REMOTED_DEBUG: '2'}

injectors = []


def send_event(event, protocol, manager_port, agent):
    """Send an event to the manager"""

    sender, injector = connect(agent, manager_port = manager_port, protocol = protocol)
    injectors.append(injector)
    sender.send_event(event)
    return injector

# Test function.
@pytest.mark.parametrize('test_configuration, test_metadata',  zip(test_configuration, test_metadata), ids=cases_ids)
def test_multi_agent_protocols_communication(test_configuration, test_metadata, configure_local_internal_options, truncate_monitored_files,
                            set_wazuh_configuration, daemons_handler, simulate_agents):

    '''
    description: Check agent-manager communication with several agents simultaneously via TCP, UDP or both.
                 For this purpose, the test will create all the agents and select the protocol using Round-Robin. Then,
                 an event and a message will be created for each agent created. Finally, it will search for
                 those events within the messages sent to the manager.


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


    manager_port = test_metadata['port']
    protocol = test_metadata['protocol']
    search_patterns = []
    send_event_threads = []

    # Read the events log data
    log_monitor_archives = FileMonitor(ARCHIVES_LOG_PATH)

    for agent in agents:

        # Generate custom events for each agent
        search_pattern = f"test message from agent {agent.id}"
        agent_custom_message = f"1:/test.log:Feb 23 17:18:20 manager sshd[40657]: {search_pattern}"
        event = agent.create_event(agent_custom_message)

        # Save the search pattern to check it later
        search_patterns.append(search_pattern)

        # Create sender event threads
        send_event_threads.append(ThreadExecutor(send_event, {'event': event, 'protocol': protocol,
                                                            'manager_port': manager_port, 'agent': agent}))

    # Wait 10 seconds until remoted is fully initialized
    time.sleep(10)

    # Start sender event threads
    for thread in send_event_threads:
        thread.start()

    # Wait until sender event threads finish
    for thread in send_event_threads:
        thread.join()

    log_monitor_archives.start(timeout=30, callback=generate_callback(r".*"))
    assert log_monitor_archives.callback_result

    for injector in injectors:
        injector.stop_receive()

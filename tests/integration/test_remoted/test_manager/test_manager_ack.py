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
from wazuh_testing.utils.callbacks import generate_callback
from wazuh_testing.modules.remoted import patterns
from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template
from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.modules.remoted.configuration import REMOTED_DEBUG
from wazuh_testing.tools.monitors import queue_monitor

from . import CONFIGS_PATH, TEST_CASES_PATH


# Set pytest marks.
pytestmark = [pytest.mark.server, pytest.mark.tier(level=1)]

# Cases metadata and its ids.
cases_path = Path(TEST_CASES_PATH, 'cases_manager_ack.yaml')
config_path = Path(CONFIGS_PATH, 'config_manager_ack.yaml')
test_configuration, test_metadata, cases_ids = get_test_cases_data(cases_path)
test_configuration = load_configuration_template(config_path, test_configuration, test_metadata)

daemons_handler_configuration = {'all_daemons': True}

local_internal_options = {REMOTED_DEBUG: '2'}


# Test function.
@pytest.mark.parametrize('test_configuration, test_metadata',  zip(test_configuration, test_metadata), ids=cases_ids)
def test_manager_ack(test_configuration, test_metadata, configure_local_internal_options, truncate_monitored_files,
                            set_wazuh_configuration, daemons_handler, simulate_agents):

    '''
    description: Check if the manager sends the ACK message after receiving
                 the start-up message from the agent.

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
            brief: Starts/Restarts the daemons indicated in `daemons_handler_configuration` before each test,
                   once the test finishes, stops the daemons.
        - simulate_agents
            type: fixture
            brief: create agents
        - set_wazuh_configuration:
            type: fixture
            brief: Apply changes to the ossec.conf configuration.

    '''

    log_monitor = FileMonitor(WAZUH_LOG_PATH)

    agent = simulate_agents[0]

    #injectors = []
    time.sleep(1)
    sender, injector = connect(agent, protocol = test_metadata['protocol'])

    # Wait until remoted has loaded the new agent key
    log_monitor.start(callback=generate_callback(patterns.KEY_UPDATE))
    assert log_monitor.callback_result

    # Send the start-up message
    sender.send_event(agent.startup_msg)

    # Check ACK manager message
    log_queue_monitor = queue_monitor.QueueMonitor(agent.rcv_msg_queue)
    log_queue_monitor.start(callback=generate_callback(patterns.ACK_MESSAGE))
    assert log_monitor.callback_result

    # Close all threads
    injector.stop_receive()

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
from wazuh_testing.modules.remoted import patterns
from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.tools.monitors.file_monitor import FileMonitor
from wazuh_testing.tools.monitors import queue_monitor
from wazuh_testing.utils.callbacks import generate_callback

from . import CONFIGS_PATH, TEST_CASES_PATH


# Set pytest marks.
pytestmark = [pytest.mark.server, pytest.mark.tier(level=2)]

# Cases metadata and its ids.
cases_path = Path(TEST_CASES_PATH, 'cases_protocols_communication.yaml')
config_path = Path(CONFIGS_PATH, 'config_protocols_communication.yaml')
test_configuration, test_metadata, cases_ids = get_test_cases_data(cases_path)
test_configuration = load_configuration_template(config_path, test_configuration, test_metadata)

daemons_handler_configuration = {'all_daemons': True}

local_internal_options = {REMOTED_DEBUG: '2'}


# Test function.
@pytest.mark.parametrize('test_configuration, test_metadata',  zip(test_configuration, test_metadata), ids=cases_ids)
def test_protocols_communication(test_configuration, test_metadata, configure_local_internal_options,
                                 truncate_monitored_files, set_wazuh_configuration, daemons_handler,
                                 simulate_agents):
    '''
    description: Check agent-manager communication via TCP, UDP or both.
                 The test connects a simulated agent on the configured protocol and port, then
                 verifies that remoted loaded the agent key (KEY_UPDATE in wazuh log) and that
                 the manager responds to the startup message with an ACK.

    parameters:
        - test_configuration:
            type: dict
            brief: Configuration applied to ossec.conf.
        - test_metadata:
            type: dict
            brief: Test case metadata.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate all monitored log files before and after the test execution.
        - configure_local_internal_options:
            type: fixture
            brief: Configure the Wazuh local internal options using the values from `local_internal_options`.
        - daemons_handler:
            type: fixture
            brief: Restart all wazuh services once the test finishes.
        - simulate_agents:
            type: fixture
            brief: Create simulated agents.
        - set_wazuh_configuration:
            type: fixture
            brief: Apply changes to the ossec.conf configuration.
    '''
    log_monitor = FileMonitor(WAZUH_LOG_PATH)
    agent = simulate_agents[0]

    sender, injector = connect(agent, protocol=test_metadata['protocol1'],
                               manager_port=test_metadata['port'], wait_status='')

    log_monitor.start(callback=generate_callback(patterns.KEY_UPDATE), timeout=60)
    assert log_monitor.callback_result, (
        f"Remoted did not load the agent key via {test_metadata['protocol1']} "
        f"on port {test_metadata['port']} — agent-manager communication failed."
    )

    sender.send_event(agent.startup_msg)
    ack_monitor = queue_monitor.QueueMonitor(agent.rcv_msg_queue)
    ack_monitor.start(callback=generate_callback(patterns.ACK_MESSAGE), timeout=30)

    injector.stop_receive()

    assert ack_monitor.callback_result, (
        f"Manager did not send ACK for startup message via {test_metadata['protocol1']} "
        f"on port {test_metadata['port']} — event did not reach the manager."
    )

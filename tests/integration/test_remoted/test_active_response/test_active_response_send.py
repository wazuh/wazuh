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
from wazuh_testing.utils.sockets import send_active_response_message
from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template
from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.modules.remoted.configuration import REMOTED_DEBUG
from wazuh_testing.tools.monitors import queue_monitor

from . import CONFIGS_PATH, TEST_CASES_PATH


# Set pytest marks.
pytestmark = [pytest.mark.server, pytest.mark.tier(level=1)]

# Cases metadata and its ids.
cases_path = Path(TEST_CASES_PATH, 'cases_ar.yaml')
config_path = Path(CONFIGS_PATH, 'config_ar.yaml')
test_configuration, test_metadata, cases_ids = get_test_cases_data(cases_path)
test_configuration = load_configuration_template(config_path, test_configuration, test_metadata)

daemons_handler_configuration = {'all_daemons': True}

local_internal_options = {REMOTED_DEBUG: '2'}

ACTIVE_RESPONSE_EXAMPLE_COMMAND = 'dummy-ar admin 1.1.1.1 1.1 44 (any-agent) any->/testing/testing.txt - -'

# Test function.
@pytest.mark.parametrize('test_configuration, test_metadata',  zip(test_configuration, test_metadata), ids=cases_ids)
def test_active_response_ar_sending(test_configuration, test_metadata, configure_local_internal_options, truncate_monitored_files,
                            set_wazuh_configuration, daemons_handler, simulate_agents):

    '''
    description: Check if the 'wazuh-remoted' daemon sends active response commands to the Wazuh agent.
                 For this purpose, the test will establish a connection with a simulated agent using
                 different ports and transport protocols. Then, it will send an active response to that
                 agent, and finally, the test will verify that the events indicating that the active
                 response has been sent by the manager and received it by the agent are generated.

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

    time.sleep(1)
    sender, injector = connect(agent, protocol = test_metadata['protocol'], manager_port = test_metadata['port'])
    active_response_message = fr"(local_source) [] NRN {agent.id} {ACTIVE_RESPONSE_EXAMPLE_COMMAND}"
    send_active_response_message(active_response_message)

    log_monitor.start(callback=generate_callback(patterns.ACTIVE_RESPONSE_RECEIVED))

    assert log_monitor.callback_result

    log_monitor.start(callback=generate_callback(patterns.ACTIVE_RESPONSE_SENT))

    assert log_monitor.callback_result

    log_queue_monitor = queue_monitor.QueueMonitor(agent.rcv_msg_queue)
    log_queue_monitor.start(callback=generate_callback(regex=patterns.EXECD_MESSAGE,
                                                       replacement={"message": ACTIVE_RESPONSE_EXAMPLE_COMMAND}))
    assert log_monitor.callback_result
    injector.stop_receive()

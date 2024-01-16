"""
 Copyright (C) 2015-2024, Wazuh Inc.
 Created by Wazuh, Inc. <info@wazuh.com>.
 This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""

import pytest
import time

from pathlib import Path
from wazuh_testing.tools.monitors.file_monitor import FileMonitor
from wazuh_testing.utils.callbacks import generate_callback
from wazuh_testing.tools.simulators.agent_simulator import connect
from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template
from wazuh_testing.tools import thread_executor
from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.modules.remoted.configuration import REMOTED_DEBUG
from wazuh_testing.modules.remoted.patterns import KEY_UPDATE

from . import CONFIGS_PATH, TEST_CASES_PATH


# Set pytest marks.
pytestmark = [pytest.mark.server, pytest.mark.tier(level=1)]

# Cases metadata and its ids.
cases_path = Path(TEST_CASES_PATH, 'cases_agent_pending_status.yaml')
config_path = Path(CONFIGS_PATH, 'config_agent_pending_status.yaml')
test_configuration, test_metadata, cases_ids = get_test_cases_data(cases_path)
test_configuration = load_configuration_template(config_path, test_configuration, test_metadata)

daemons_handler_configuration = {'all_daemons': True}

local_internal_options = {REMOTED_DEBUG: '2'}


def send_initialization_events(agent, sender):
    """Send the start-up and keep-alive events"""

    sender.send_event(agent.startup_msg)
    # Wait 1 seconds to ensure that the message has ben sent before closing the socket.
    time.sleep(3)




# Test function.
@pytest.mark.parametrize('test_configuration, test_metadata',  zip(test_configuration, test_metadata), ids=cases_ids)
def test_agent_pending_status(test_configuration, test_metadata, configure_local_internal_options, truncate_monitored_files,
                            set_wazuh_configuration, restart_wazuh_expect_error, simulate_agents):

    '''
    description: Validate agent status after sending only the start-up

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
        - restart_wazuh_expect_error:
            type: fixture
            brief: Restart service when expected error is None, once the test finishes stops the daemons.
        - simulate_agents
            type: fixture
            brief: create agents
        - set_wazuh_configuration:
            type: fixture
            brief: Apply changes to the ossec.conf configuration.

    '''

    log_monitor = FileMonitor(WAZUH_LOG_PATH)

    agents = simulate_agents


    send_event_threads = []
    injectors = []

    log_monitor.start(callback=generate_callback(KEY_UPDATE))
    assert log_monitor.callback_result


    # Create sender threads. One for each agent
    for idx, agent in enumerate(agents):
        sender, injector = connect(agent, protocol = test_metadata['protocol'], manager_port = test_metadata['port'])
        injectors.append(injector)
        send_event_threads.append(thread_executor.ThreadExecutor(send_initialization_events, {'agent': agent, 'sender': sender}))


    # Run sender threads
    for thread in send_event_threads:
        thread.start()

    time.sleep(3)

    ## Wait until sender threads finish
    for thread in send_event_threads:
        thread.join()

    # Check agent pending status for earch agent
    for agent in agents:
        assert agent.get_connection_status() == 'pending'

    # Close all threads
    for index, injector in enumerate(injectors):
        injector.stop_receive()

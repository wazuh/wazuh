"""
 Copyright (C) 2015-2024, Wazuh Inc.
 Created by Wazuh, Inc. <info@wazuh.com>.
 This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""

import pytest
import os
import psutil
import time

from pathlib import Path
from wazuh_testing.constants.paths.configurations import WAZUH_CONF_PATH
from wazuh_testing.tools.monitors.file_monitor import FileMonitor
from wazuh_testing.tools.simulators.agent_simulator import connect
from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template
from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.constants.paths.sockets import QUEUE_RIDS_PATH
from wazuh_testing.constants.daemons import REMOTE_DAEMON
from wazuh_testing.modules.remoted.configuration import REMOTED_DEBUG

from . import CONFIGS_PATH, TEST_CASES_PATH


# Set pytest marks.
pytestmark = [pytest.mark.server, pytest.mark.tier(level=1)]

# Cases metadata and its ids.
cases_path = Path(TEST_CASES_PATH, 'cases_rids.yaml')
config_path = Path(CONFIGS_PATH, 'config_rids.yaml')
test_configuration, test_metadata, cases_ids = get_test_cases_data(cases_path)
test_configuration = load_configuration_template(config_path, test_configuration, test_metadata)

daemons_handler_configuration = {'all_daemons': True}

local_internal_options = {REMOTED_DEBUG: '2'}


def get_remoted_pid():
    for process in psutil.process_iter():
        if process.name() == REMOTE_DAEMON:
            return process.pid
    return None


# Test function.
@pytest.mark.parametrize('test_configuration, test_metadata',  zip(test_configuration, test_metadata), ids=cases_ids)
def test_rids(test_configuration, test_metadata, configure_local_internal_options, truncate_monitored_files,
                            set_wazuh_configuration, daemons_handler, simulate_agents):

    '''
    description: Check that RIDS is opened and closed as expected. To do this, it creates injectors(agents and senders)
                 to be able to communicate with the manager. Then, it stops the agents' listening and checks if RIDS is
                 closed(when it`s needed).

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

    agents = simulate_agents
    injectors = []
    agent_rids_paths = []

    for agent in agents:
        _, injector = connect(agent)
        injectors.append(injector)

    process = psutil.Process(get_remoted_pid())
    opened = process.open_files()

    time.sleep(30)

    # Check that rids is open

    for i in range(10):
        for agent in agents:
            agent_rids_path = os.path.join(QUEUE_RIDS_PATH, agent.id)
            rids_for_agent_open = False
            opened = process.open_files()
            for path in opened:
                if agent_rids_path in path:
                    rids_for_agent_open = True
                    break
        if not rids_for_agent_open:
            time.sleep(30)
    if not rids_for_agent_open:
        assert rids_for_agent_open, f"Agent fd should be open {agent.id}"

    check_close = test_metadata['check_close']
    if True in check_close:
        # Close threads with check close
        for index, injector in enumerate(injectors):
            if check_close[index]:
                injector.stop_receive()


        for agent_index, agent in enumerate(agents):
            agent_rids_paths.append(os.path.join(QUEUE_RIDS_PATH, agents[agent_index].id))

        for i in range(10):
            for path in agent_rids_paths:
                rids_for_agent_open = False

                opened = process.open_files()

                for pathOp in opened:
                    if path in pathOp:
                        rids_for_agent_open = True
                        break

            if  rids_for_agent_open:
                # Wait that the thread close the rids
                time.sleep(30)


        # Check that rids is close
        for agent_index, agent in enumerate(agents):
            agent_rids_path = os.path.join(QUEUE_RIDS_PATH, agents[agent_index].id)
            rids_for_agent_open = False

            for path in opened:
                if agent_rids_path in path:
                    rids_for_agent_open = True
                    break

            if check_close[agent_index]:
                assert not rids_for_agent_open, f"Agent fd should be close {agents[agent_index].id}"
            else:
                assert rids_for_agent_open, f"Agent fd should be open {agents[agent_index].id}"
                # Close thread without check close
                injectors[agent_index].stop_receive()
    else:
        # Close all threads
        for index, injector in enumerate(injectors):
            injector.stop_receive()

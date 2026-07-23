"""
 Copyright (C) 2015-2024, Wazuh Inc.
 Created by Wazuh, Inc. <info@wazuh.com>.
 This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""

import re
import time
import pytest

from datetime import datetime
from pathlib import Path
from wazuh_testing.tools.simulators.agent_simulator import connect
from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template
from wazuh_testing.modules.remoted.configuration import REMOTED_DEBUG
from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.tools.monitors.file_monitor import FileMonitor
from wazuh_testing.utils.callbacks import generate_callback
from wazuh_testing.modules.remoted import patterns
from wazuh_testing.utils.agent_groups import create_group, delete_group, add_agent_to_group

from . import CONFIGS_PATH, TEST_CASES_PATH


# Set pytest marks.
pytestmark = [pytest.mark.server, pytest.mark.tier(level=2)]

# Cases metadata and its ids.
cases_path = Path(TEST_CASES_PATH, 'cases_shared_config_staggered.yaml')
config_path = Path(CONFIGS_PATH, 'config_shared_config_staggered.yaml')
test_configuration, test_metadata, cases_ids = get_test_cases_data(cases_path)
test_configuration = load_configuration_template(config_path, test_configuration, test_metadata)

daemons_handler_configuration = {'all_daemons': True}

local_internal_options = {REMOTED_DEBUG: '2'}

# Leading timestamp of a Wazuh log line, e.g. "2024/07/23 15:04:05 ...".
LOG_TIMESTAMP_REGEX = re.compile(r'^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})')
# Matches "End sending file '.../merged.mg' to agent 'ID'."
END_SEND_REGEX = re.compile(r'End sending file.*to agent')


def get_distribution_timestamps():
    """Return the timestamps of every 'End sending file to agent' log line."""
    timestamps = []
    with open(WAZUH_LOG_PATH, 'r') as log_file:
        for line in log_file:
            if END_SEND_REGEX.search(line):
                match = LOG_TIMESTAMP_REGEX.match(line)
                if match:
                    timestamps.append(datetime.strptime(match.group(1), '%Y/%m/%d %H:%M:%S'))
    return timestamps


# Test function.
@pytest.mark.parametrize('test_configuration, test_metadata', zip(test_configuration, test_metadata), ids=cases_ids)
def test_shared_config_staggered_distribution(test_configuration, test_metadata, configure_local_internal_options,
                                              truncate_monitored_files, set_wazuh_configuration, daemons_handler,
                                              simulate_agents):
    '''
    description: Check that the manager progressively distributes an updated group configuration when
                 'shared_config_batch_size'/'shared_config_interval' throttling is enabled, instead of pushing it
                 to every agent of the group at once. This also staggers the restarts agents perform on receipt.

                 The test simulates several agents, adds them to a group and then modifies the group configuration.
                 It asserts that the "End sending file to agent" events recorded in the log are spread over a time
                 window consistent with the configured rate, rather than happening simultaneously.

    parameters:
        - test_configuration:
            type: dict
            brief: Configuration applied to ossec.conf.
        - test_metadata:
            type: dict
            brief: Test case metadata.
        - configure_local_internal_options:
            type: fixture
            brief: Configure the Wazuh local internal options using the values from `local_internal_options`.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate all the log files and json alerts files before and after the test execution.
        - set_wazuh_configuration:
            type: fixture
            brief: Apply changes to the ossec.conf configuration.
        - daemons_handler:
            type: fixture
            brief: Restart service once the test finishes stops the daemons.
        - simulate_agents:
            type: fixture
            brief: Create the simulated agents.

    assertions:
        - Verify that the manager pushes the updated configuration to every agent of the group.
        - Verify that the distribution is spread over at least 'min_distribution_span' seconds.
    '''
    agents = simulate_agents
    agents_number = test_metadata['agents_number']
    protocol = test_metadata['protocol']
    group = 'staggered_group'

    injectors = []

    wazuh_log_monitor = FileMonitor(WAZUH_LOG_PATH)

    # Connect every agent and complete its handshake with a start-up and a keep-alive message.
    for agent in agents:
        sender, injector = connect(agent=agent, protocol=protocol)
        injectors.append(injector)

        sender.send_event(agent.startup_msg)
        wazuh_log_monitor.start(callback=generate_callback(regex=patterns.START_UP,
                                                           replacement={"agent_name": agent.name,
                                                                        "agent_ip": '127.0.0.1'}))
        assert wazuh_log_monitor.callback_result, f"Agent {agent.id} did not complete its start-up."

        sender.send_event(agent.keep_alive_event)

    # Let the agents settle as 'synced' before the group configuration changes.
    time.sleep(5)

    # Modify the group configuration: this marks every agent of the group as out of sync.
    create_group(group)
    for agent in agents:
        add_agent_to_group(group, agent.id)

    try:
        # Truncate so we only count the pushes triggered by the group change from now on.
        with open(WAZUH_LOG_PATH, 'w'):
            pass

        # Trigger the re-sync: every agent reports its now stale merged.mg checksum.
        senders = [connect(agent=agent, protocol=protocol) for agent in agents]
        injectors.extend(injector for _, injector in senders)
        for (sender, _), agent in zip(senders, agents):
            sender.send_event(agent.keep_alive_event)

        # Wait long enough for the paced distribution to complete for every agent.
        max_wait = test_metadata['min_distribution_span'] + test_metadata['shared_config_interval'] * agents_number + 30
        deadline = time.time() + max_wait
        timestamps = []
        while time.time() < deadline:
            timestamps = get_distribution_timestamps()
            if len(timestamps) >= agents_number:
                break
            time.sleep(1)

        assert len(timestamps) >= agents_number, \
            f"Expected the config pushed to {agents_number} agents, but only saw {len(timestamps)} pushes."

        distribution_span = (max(timestamps) - min(timestamps)).total_seconds()
        assert distribution_span >= test_metadata['min_distribution_span'], \
            f"Distribution span {distribution_span}s is below the expected minimum " \
            f"{test_metadata['min_distribution_span']}s; the throttling did not stagger the pushes."
    finally:
        delete_group(group)
        for injector in injectors:
            injector.stop_receive()

# Copyright (C) 2015-2024, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import pytest

from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.modules.modulesd import patterns
from wazuh_testing.tools.monitors.file_monitor import FileMonitor
from wazuh_testing.utils import callbacks
from wazuh_testing.utils.manage_agents import remove_agents
from wazuh_testing.utils.services import control_service
from wazuh_testing.tools.simulators.agent_simulator import create_agents


@pytest.fixture()
def wait_for_rootcheck_start():
    # Wait for module rootcheck starts
    wazuh_log_monitor = FileMonitor(WAZUH_LOG_PATH)
    wazuh_log_monitor.start(callback=callbacks.generate_callback(patterns.MODULESD_STARTED, {
                              'integration': 'rootcheck'
                          }))
    assert (wazuh_log_monitor.callback_result == None), f'Error invalid configuration event not detected'


@pytest.fixture()
def simulate_agents(request):
    agents = []
    for _ in range(request.getfixturevalue("test_metadata")["agents_number"]):
       agent = create_agents(1, 'localhost')[0]

    yield agents
    # Delete simulated agents
    control_service('start')
    for agent in agents:
        remove_agents(agent.id,'wazuhdb')
    control_service('stop')

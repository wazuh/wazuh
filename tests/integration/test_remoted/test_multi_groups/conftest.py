"""
 Copyright (C) 2015-2024, Wazuh Inc.
 Created by Wazuh, Inc. <info@wazuh.com>.
 This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""

import pytest
import time

from wazuh_testing.tools.simulators import agent_simulator
from wazuh_testing.utils.agent_groups import create_group, delete_group, add_agent_to_group


@pytest.fixture()
def prepare_environment(request, simulate_agents):
    """Configure a custom environment for testing."""
    agent = simulate_agents[0]
    agent_id = agent.id
    sender, injector = agent_simulator.connect(agent)

    create_group('testing_group')
    add_agent_to_group('testing_group', agent_id)
    time.sleep(20)

    yield
    delete_group('testing_group')
    injector.stop_receive()

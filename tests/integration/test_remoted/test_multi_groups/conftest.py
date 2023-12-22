"""
 Copyright (C) 2015-2023, Wazuh Inc.
 Created by Wazuh, Inc. <info@wazuh.com>.
 This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""

import pytest
import time
import os

from wazuh_testing.tools.simulators import agent_simulator
from wazuh_testing.utils import file
from wazuh_testing.constants.paths.sockets import QUEUE_GROUPS_PATH


@pytest.fixture(scope='function')
def prepare_environment(request, simulate_agents):
    """Configure a custom environment for testing."""


    agent = simulate_agents[0]
    agent_id = agent.id
    sender, injector = agent_simulator.connect(agent)

    agent_simulator.new_agent_group()
    agent_simulator.add_agent_to_group('testing_group', agent_id)
    time.sleep(20)

    yield
    agent_simulator.remove_agent_group('testing_group')
    file.remove_file(os.path.join(QUEUE_GROUPS_PATH, agent_id))
    injector.stop_receive()

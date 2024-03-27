'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: The 'rootcheck' tool allows to define policies in order to check if the agents
       meet the requirement specified. The rootcheck engine can check if a process is running, if a file is
       present and if the content of a file contains a pattern,
       or if a Windows registry key contains a string or is simply present.

components:
    - rootcheck

targets:
    - manager

daemons:
    - wazuh-analysisd

os_platform:
    - linux

os_version:
    - Arch Linux
    - Amazon Linux 2
    - Amazon Linux 1
    - CentOS 8
    - CentOS 7
    - Debian Buster
    - Red Hat 8
    - Ubuntu Focal
    - Ubuntu Bionic

references:
    - https://documentation.wazuh.com/current/user-manual/capabilities/policy-monitoring/rootcheck
    - https://documentation.wazuh.com/current/user-manual/reference/daemons/wazuh-analysisd.html

tags:
    - rootcheck
'''

import pytest
import time
from pathlib import Path

from wazuh_testing.utils import configuration
from wazuh_testing.utils.services import control_service
from wazuh_testing.utils.db_queries import agent_db

from . import CONFIGS_PATH, TEST_CASES_PATH

# Marks
pytestmark = [pytest.mark.server, pytest.mark.tier(level=0)]

# Configuration and cases data.
test_configs_path = Path(CONFIGS_PATH, 'config_template.yaml')
test_cases_path = Path(TEST_CASES_PATH, 'cases_configuration.yaml')

# Test configurations.
test_configuration, test_metadata, test_cases_ids = configuration.get_test_cases_data(test_cases_path)
test_configuration = configuration.load_configuration_template(test_configs_path, test_configuration, test_metadata)

# Test daemons to restart.
daemons_handler_configuration = {'all_daemons': True}

# Test function.
@pytest.mark.parametrize('test_configuration, test_metadata',
                         zip(test_configuration, test_metadata), ids=test_cases_ids)
def test_rootcheck_delete(test_configuration, test_metadata, set_wazuh_configuration,
                   daemons_handler, wait_for_rootcheck_start, truncate_monitored_files,
                   simulate_agents):
    '''
    Testing with daemons_handler,
    description: Check if the 'rootcheck' modules is working properly, that is, by checking if the logs
                 are deleted correctly.
                 For this purpose, the test will create a specific number of agents, and enable the rootcheck module.
                 The rootcheck events will be sent for 60 seconds. After the time has passed, the rootcheck module
                 gets disabled and check if the logs are deleted from the database when sending the delete
                 table request.

    wazuh_min_version: 4.2.0

    tier: 0

    parameters:
        - test_configuration:
            type: dict
            brief: Configuration loaded from `configuration_templates`.
        - test_metadata:
            type: dict
            brief: Test case metadata.
        - set_wazuh_configuration:
            type: fixture
            brief: Apply changes to the ossec.conf configuration.
        - wait_for_rootcheck_startup:
            type: fixture
            brief: Wait until the 'wazuh-analysisd' has begun and the 'alerts.json' file is created.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate wazuh logs.
        - daemons_handler:
            type: fixture
            brief: Handler of Wazuh daemons.
        - simulate_agents:
            type: fixture
            brief: Handler simulates agents.

    assertions:
        - Verify that the rootcheck events are deletet from the database
    input_description: Different test cases are contained in an external YAML file (cases_configuration.yaml)
                       which includes configuration settings for the 'rootcheck' module.
    expected_output:
        - Wazuh DB returned an error trying to delete the agent
        - Rootcheck events were not deleted
    '''
    injectors = []
    agents = simulate_agents

    for agent in agents:
        agent.modules['rootcheck']['status'] = 'enabled'
        _, injector = connect(agent)
        injectors.append(injector)
        agents.append(agent)

    # Let rootcheck events to be sent for 60 seconds
    time.sleep(60)

    for injector in injectors:
        injector.stop_receive()

    # Service needs to be restarted
    control_service('start')

    for agent in agents:
        response = agent_db.rootcheck_delete(agent.id)
        assert response.startswith(b'ok'), "Wazuh DB returned an error " \
                                            "trying to delete the agent"

    # Wait 5 seconds
    time.sleep(5)

    # Service needs to be stopped otherwise db lock will be held by Wazuh db
    control_service('stop')

    # Check that logs have been deleted
    for agent in agents:
        rows = agent_db.update_pm_event(agent.id)
        assert len(rows) == 0, 'Rootcheck events were not deleted'


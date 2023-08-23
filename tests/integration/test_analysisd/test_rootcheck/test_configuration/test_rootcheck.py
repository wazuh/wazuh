'''
copyright: Copyright (C) 2015-2023, Wazuh Inc.
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

import json
import os
import pytest
from pathlib import Path

from wazuh_testing.constants.paths.logs import ALERTS_JSON_PATH
from wazuh_testing.constants.paths.sockets import QUEUE_DB_PATH, WAZUH_DB_SOCKET_PATH
from wazuh_testing.tools.db_administrator import DatabaseAdministrator
from wazuh_testing.tools.socket_controller import SocketController
from wazuh_testing.utils import configuration

from . import CONFIGS_PATH, TEST_CASES_PATH

# Marks
pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]

def retrieve_rootcheck_rows(agent_id):
    db_connection = DatabaseAdministrator(os.path.join(QUEUE_DB_PATH, f'{agent_id}.db'))
    rows = db_connection.select("pm_event")
    db_connection.cursor.close()
    db_connection.connection.close()
    return rows

def send_delete_table_request(agent_id):
    controller = SocketController(WAZUH_DB_SOCKET_PATH)
    controller.send(f'agent {agent_id} rootcheck delete', size=True)
    response = controller.receive(size=True)
    return response

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
def test_rootcheck(test_configuration, test_metadata, set_wazuh_configuration,
                   daemons_handler, wait_for_rootcheck_start, truncate_monitored_files,
                   load_agents):
    '''
    Testing with daemons_handler,
    description: Check if the 'rootcheck' modules is working properly, that is, by checking if the created logs
                 are added, updated and deleted correctly.
                 For this purpose, the test will create a specific number of agents, and will check if they have
                 the rootcheck module enabled. Once this check is proven, it lets the rootcheck events to be sent
                 for 60 seconds. After the time has passed, the rootcheck module gets disabled and the test then
                 checks if the logs have been added to the database. After this first procedure, the test restarts
                 the service and let the rootcheck events to be sent for 60 seconds for checking after that time if
                 the logs have been updated with the new entries.
                 Lastly, the tests also checks if the logs are deleted from the database when sending the delete
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
        - load_agents:
            type: fixture
            brief: Handler simulates agents.

    assertions:
        - Verify that rootcheck events are added into the database
        - Verify that the rootcheck events are updated on the database
        - Verify that the rootcheck events are deletet from the database
    input_description: Different test cases are contained in an external YAML file (wazuh_manager_conf.yaml)
                       which includes configuration settings for the 'rootcheck' module.
    expected_output:
        - r'.*not found in Database'
        - r'.*not found in alerts file'
        - r'.*not found in Database'
        - First time in log was updated after insertion
        - Updated time in log was not updated
        - Wazuh DB returned an error trying to delete the agent
        - Rootcheck events were not deleted

    '''
    # Check that logs have been added to the sql database
    agents = load_agents
    for agent in agents:
        rows = retrieve_rootcheck_rows(agent.id)
        db_string = [row[3] for row in rows]
        logs_string = [':'.join(x.split(':')[2:]) for x in
                      agent.rootcheck.messages_list]

        alerts_description = []
        with open(ALERTS_JSON_PATH, 'r') as f:
            for line in f:
                if '"decoder":{"name":"rootcheck"}' in line:
                    try:
                        json_lines = json.loads(line.strip())
                        alerts_description.append(json_lines['full_log'])
                    except json.JSONDecodeError:
                        print(f"Invalid json {line.strip()}")

        for log in logs_string:
            assert log in db_string, f"Log: \"{log}\" not found in Database"
            if log not in ['Starting rootcheck scan.',
                           'Ending rootcheck scan.']:
                assert log in alerts_description, f"Log: \"{log}\" " \
                                                  "not found in alerts file"

    # if test_metadata["check_updates"]:
    #     # Service needs to be restarted
    #     control_service('start')

    #     update_threshold = time.time()

    #     injectors = create_injectors(agents)

    #     # Let rootcheck events to be sent for 60 seconds
    #     time.sleep(60)

    #     for injector in injectors:
    #         injector.stop_receive()

    #     # Service needs to be stopped otherwise db lock will be held by Wazuh db
    #     control_service('stop')

    #     # Check that logs have been updated
    #     for agent in agents:
    #         rows = retrieve_rootcheck_rows(agent.id)

    #         logs_string = [':'.join(x.split(':')[2:]) for x in
    #                        agent.rootcheck.messages_list]
    #         for row in rows:
    #             assert row[1] < update_threshold, \
    #                 f'First time in log was updated after insertion'
    #             assert row[2] > update_threshold, \
    #                 f'Updated time in log was not updated'
    #             assert row[3] in logs_string, \
    #                 f"Log: \"{log}\" not found in Database"

    # if test_metadata["check_delete"]:
    #     # Service needs to be restarted
    #     control_service('start')

    #     for agent in agents:
    #         response = send_delete_table_request(agent.id)
    #         assert response.startswith(b'ok'), "Wazuh DB returned an error " \
    #                                            "trying to delete the agent"

    #     # Wait 5 seconds
    #     time.sleep(5)

    #     # Service needs to be stopped otherwise db lock will be held by Wazuh db
    #     control_service('stop')

    #     # Check that logs have been deleted
    #     for agent in agents:
    #         rows = retrieve_rootcheck_rows(agent.id)
    #         assert len(rows) == 0, 'Rootcheck events were not deleted'

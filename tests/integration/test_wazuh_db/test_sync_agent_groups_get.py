'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
type: integration
brief: Wazuh-db is the daemon in charge of the databases with all the Wazuh persistent information, exposing a socket
       to receive requests and provide information. The Wazuh core uses list-based databases to store information
       related to agent keys, and FIM/Rootcheck event data.
       This test checks the usage of the sync-agent-groups-get command used to allow the cluster getting the
       information to be synchronized..
tier: 0
modules:
    - wazuh_db
components:
    - manager
daemons:
    - wazuh-db
os_platform:
    - linux
os_version:
    - Arch Linux
    - Amazon Linux 2
    - Amazon Linux 1
    - CentOS 8
    - CentOS 7
    - CentOS 6
    - Ubuntu Focal
    - Ubuntu Bionic
    - Ubuntu Xenial
    - Ubuntu Trusty
    - Debian Buster
    - Debian Stretch
    - Debian Jessie
    - Debian Wheezy
    - Red Hat 8
    - Red Hat 7
    - Red Hat 6
references:
    - https://documentation.wazuh.com/current/user-manual/reference/daemons/wazuh-db.html
tags:
    - wazuh_db
'''
import os
import time
import pytest
import json

from wazuh_testing.constants.paths import WAZUH_PATH
from wazuh_testing.utils.database import query_wdb, delete_dbs
from wazuh_testing.utils.db_queries import global_db
from wazuh_testing.constants.executions import TIER0, SERVER
from wazuh_testing.utils.file import get_list_of_content_yml


# Marks
pytestmark = [pytest.mark.linux, TIER0, SERVER]

# Configurations
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'test_configuration/data')
messages_file = os.path.join(os.path.join(test_data_path, 'test_cases'), 'cases_sync_agent_groups_get.yaml')
module_tests = get_list_of_content_yml(messages_file)

log_monitor_paths = []
wdb_path = os.path.join(os.path.join(WAZUH_PATH, 'queue', 'db', 'wdb'))
receiver_sockets_params = [(wdb_path, 'AF_UNIX', 'TCP')]
monitored_sockets_params = [('wazuh-db', None, True)]
receiver_sockets = None  # Set in the fixtures


# Fixtures

# Insert agents into DB  and assign them into a group
@pytest.fixture(scope='function')
def pre_insert_agents_into_group():

    global_db.insert_agent_into_group(2)

    yield

    global_db.clean_agents_from_db()
    global_db.clean_groups_from_db()
    global_db.clean_belongs()


@pytest.fixture(scope='module')
def clean_databases():
    yield
    delete_dbs()


# Tests
@pytest.mark.parametrize('test_case',
                         [case['test_case'] for module_data in module_tests for case in module_data[0]],
                         ids=[f"{module_name}: {case['name']}"
                              for module_data, module_name in module_tests
                              for case in module_data]
                         )
def test_sync_agent_groups(restart_wazuh_daemon, test_case, create_groups, pre_insert_agents_into_group,
                           clean_databases):
    '''
    description: Check that commands about sync_aget_groups_get works properly.
    wazuh_min_version: 4.4.0
    parameters:
        - restart_wazuh_daemon:
            type: fixture
            brief: Truncate ossec.log and restart Wazuh.
        - test_case:
            type: fixture
            brief: List of test_case stages (dicts with input, output and agent_id and expected_groups keys).
        - pre_insert_agents_into_group:
            type: fixture
            brief: fixture in charge of insert agents and groups into DB.
        - clean_databases:
            type: fixture
            brief: Delete all databases after test execution.
    assertions:
        - Verify that the socket response matches the expected output.
    input_description:
        - Test cases are defined in the sync_agent_groups_get.yaml file.
    expected_output:
        - an array with all the agents that match with the search criteria
    tags:
        - wazuh_db
        - wdb_socket
    '''
    # Set each case
    output = test_case["output"]

    # Check if it requires any special configuration
    if 'pre_input' in test_case:
        for command in test_case['pre_input']:
            query_wdb(command)

    # Check if it requires the global hash.
    if '[GLOBAL_HASH]' in output:
        global_hash = global_db.calculate_global_hash()
        output = output.replace('[GLOBAL_HASH]', global_hash)

    time.sleep(1)
    response = query_wdb(test_case["input"])

    # Validate response
    assert str(response) == output, "Did not get expected response: {output}, recieved: {response}"

    # Validate if the status of the group has change
    if "new_status" in test_case:
        agent_id = json.loads(test_case["agent_id"])
        for id in agent_id:
            response = query_wdb(f'global get-agent-info {id}')
            assert test_case["new_status"] == response[0]['group_sync_status']

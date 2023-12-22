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
import time
import pytest
import json
from pathlib import Path

from wazuh_testing.utils.database import query_wdb
from wazuh_testing.utils.db_queries.global_db import calculate_global_hash
from wazuh_testing.constants.executions import TIER0, SERVER, LINUX
from wazuh_testing.utils import configuration

from . import TEST_CASES_FOLDER_PATH

# Marks
pytestmark = [LINUX, TIER0, SERVER]

# Configurations
t_cases_path = Path(TEST_CASES_FOLDER_PATH, 'cases_sync_agent_groups_get.yaml')
t_config_parameters, t_config_metadata, t_case_ids = configuration.get_test_cases_data(t_cases_path)

# Test daemons to restart.
daemons_handler_configuration = {'all_daemons': True}

# Tests
@pytest.mark.parametrize('test_metadata', t_config_metadata, ids=t_case_ids)
def test_sync_agent_groups(daemons_handler, test_metadata, create_groups, pre_insert_agents_into_group,
                           clean_databases):
    '''
    description: Check that commands about sync_aget_groups_get works properly.
    wazuh_min_version: 4.4.0
    parameters:
        - daemons_handler:
            type: fixture
            brief: Truncate ossec.log and restart Wazuh.
        - test_metadata:
            type: fixture
            brief: List of test_metadata stages (dicts with input, output and agent_id and expected_groups keys).
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
    output = test_metadata["output"]

    # Check if it requires any special configuration
    if 'pre_input' in test_metadata:
        for command in test_metadata['pre_input']:
            query_wdb(command)

    # Check if it requires the global hash.
    if '[GLOBAL_HASH]' in output:
        global_hash = calculate_global_hash()
        output = output.replace('[GLOBAL_HASH]', global_hash)

    time.sleep(1)
    response = query_wdb(test_metadata["input"])

    # Validate response
    assert str(response) == output, "Did not get expected response: {output}, recieved: {response}"

    # Validate if the status of the group has change
    if "new_status" in test_metadata:
        agent_id = json.loads(test_metadata["agent_id"])
        for id in agent_id:
            response = query_wdb(f'global get-agent-info {id}')
            assert test_metadata["new_status"] == response[0]['group_sync_status']

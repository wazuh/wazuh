'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: Wazuh-db is the daemon in charge of the databases with all the Wazuh persistent information, exposing a socket
       to receive requests and provide information. The Wazuh core uses list-based databases to store information
       related to agent keys, and FIM/Rootcheck event data.
       This test checks the usage of the get-groups-integrity command used to determine if the agent groups are synced
       or if a sync is needed.

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
from pathlib import Path
import time
import pytest

from wazuh_testing.utils.database import query_wdb
from wazuh_testing.utils.db_queries.global_db import insert_agent_in_db, remove_db_agent
from wazuh_testing.utils import configuration

from . import TEST_CASES_FOLDER_PATH

# Marks
pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]

# Configurations
t_cases_path = Path(TEST_CASES_FOLDER_PATH, 'cases_get_groups_integrity_messages.yaml')
t_config_parameters, t_config_metadata, t_case_ids = configuration.get_test_cases_data(t_cases_path)


# Tests
@pytest.mark.parametrize('test_metadata', t_config_metadata, ids=t_case_ids)
def test_get_groups_integrity(test_metadata, create_groups):
    '''
    description: Check that every input message using the 'get-groups-integrity' command in wazuh-db socket generates
                 the proper output to wazuh-db socket. To do this, it performs a query to the socket with a command
                 taken from the list of test_metadata's 'input' field, and compare the result with the test_metadata's
                 'output' field.

    wazuh_min_version: 4.4.0

    parameters:
        - test_metadata:
            type: fixture
            brief: List of test_metadata stages (dicts with input, output and agent_id and expected_groups keys).
        - create_groups:
            type: fixture
            brief: Create required groups

    assertions:
        - Verify that the socket response matches the expected output.

    input_description:
        - Test cases are defined in the get_groups_integrity_messages.yaml file. This file contains the agent id's to
          register, as well as the group_sync_status that each agent will have, as well as the expected output and
          result for the test.

    expected_output:
        - f"Assertion Error - expected {output}, but got {response}"
        - f'Unexpected response: got {response}, but expected {output}'
        - 'Unable to add agent'

    tags:
        - wazuh_db
        - wdb_socket
    '''
    output = test_metadata["output"]
    agent_ids = test_metadata["agent_ids"]
    agent_status = test_metadata["agent_status"]

    # Insert test Agents
    for index, id in enumerate(agent_ids):
        response = insert_agent_in_db(id=id+1, connection_status="disconnected",
                                      registration_time=str(time.time()))
        command = f'global set-agent-groups {{"mode":"append","sync_status":"{agent_status[index]}","source":"remote",\
                    "data":[{{"id":{id},"groups":["Test_group{id}"]}}]}}'
        response = query_wdb(command)

    # Get database hash
    if "invalid_hash" in test_metadata:
        hash = test_metadata["invalid_hash"]
    else:
        response = query_wdb('global sync-agent-groups-get {"last_id": 0, "condition": "all", "get_global_hash": true,'
                             '"set_synced": false, "agent_delta_registration": 0}')
        response = response[0]
        hash = response["hash"]
        if "no_hash" in test_metadata:
            response = str(response)
            assert output in response, f'Unexpected response: got {response}, but expected {output}'
            return

    # Get groups integrity
    response = query_wdb(f"global get-groups-integrity {hash}")
    if isinstance(response, list):
        response = response[0]

    # validate output
    assert response == output, f"Assertion Error - expected {output}, but got {response}"

    # Remove test agents
    for id in agent_ids:
        remove_db_agent(id)

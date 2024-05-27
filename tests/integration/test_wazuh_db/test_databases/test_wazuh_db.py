'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: Wazuh-db is the daemon in charge of the databases with all the Wazuh persistent information, exposing a socket
       to receive requests and provide information. The Wazuh core uses list-based databases to store information
       related to agent keys, and FIM/Rootcheck event data.
       Wazuh-db confirms that is able to save, update and erase the necessary information into the corresponding
       databases, using the proper commands and response strings.

components:
    - wazuh_db

targets:
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
    - Debian Buster
    - Red Hat 8
    - Ubuntu Focal
    - Ubuntu Bionic

references:
    - https://documentation.wazuh.com/current/user-manual/reference/daemons/wazuh-db.html

tags:
    - wazuh_db
'''
from pathlib import Path
import re
import pytest

from wazuh_testing.constants.paths.sockets import WAZUH_DB_SOCKET_PATH
from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.constants.daemons import WAZUH_DB_DAEMON
from wazuh_testing.tools.monitors import file_monitor
from wazuh_testing.utils.callbacks import make_callback
from wazuh_testing.modules.wazuh_db import WAZUH_DB_PREFIX
from wazuh_testing.utils import configuration
from wazuh_testing.utils.database import query_wdb
from wazuh_testing.utils.db_queries.agent_db import agent_integrity_check

from . import TEST_CASES_FOLDER_PATH

# Marks
pytestmark = [pytest.mark.server, pytest.mark.tier(level=0)]

# Configurations
t1_cases_path = Path(TEST_CASES_FOLDER_PATH, 'cases_agent_messages.yaml')
t1_config_parameters, t1_config_metadata, t1_case_ids = configuration.get_test_cases_data(t1_cases_path)

t2_cases_path = Path(TEST_CASES_FOLDER_PATH, 'cases_global_messages.yaml')
t2_config_parameters, t2_config_metadata, t2_case_ids = configuration.get_test_cases_data(t2_cases_path)

t3_cases_path = Path(TEST_CASES_FOLDER_PATH, 'cases_tasks_messages.yaml')
t3_config_parameters, t3_config_metadata, t3_case_ids = configuration.get_test_cases_data(t3_cases_path)

# Variables
receiver_sockets_params = [(WAZUH_DB_SOCKET_PATH, 'AF_UNIX', 'TCP')]
WAZUH_DB_CHECKSUM_CALCULUS_TIMEOUT = 20

# mitm_analysisd = ManInTheMiddle(address=analysis_path, family='AF_UNIX', connection_protocol='UDP')
# monitored_sockets_params is a List of daemons to start with optional ManInTheMiddle to monitor
# List items -> (wazuh_daemon: str,(
#                mitm: ManInTheMiddle
#                daemon_first: bool))
# Example1 -> ('wazuh-clusterd', None)              Only start wazuh-clusterd with no MITM
# Example2 -> ('wazuh-clusterd', (my_mitm, True))   Start MITM and then wazuh-clusterd
monitored_sockets_params = [(WAZUH_DB_DAEMON, None, True)]

receiver_sockets, monitored_sockets, log_monitors = None, None, None  # Set in the fixtures

# Test daemons to restart.
daemons_handler_configuration = {'all_daemons': True}


def regex_match(regex, string):
    regex = regex.replace('*', '.*')
    regex = regex.replace('[', '')
    regex = regex.replace(']', '')
    regex = regex.replace('(', '')
    regex = regex.replace(')', '')
    string = string.replace('[', '')
    string = string.replace(']', '')
    string = string.replace('(', '')
    string = string.replace(')', '')
    return re.match(regex, string)


def validate_wazuh_db_response(expected_output, response):
    """ Method to validate the Wazuh-DB response.

    Args:
        expected_output(str/list): the desired response from the test case
        response(str/list): the actual response from the socket

    Returns:
        bool: The result fo comparing the expected output with the actual response
    """
    if isinstance(response, list):
        if len(expected_output) != len(response):
            return False

        result = True
        for index, item in enumerate(response):
            if expected_output[index] != item:
                result = False
        return result
    else:
        return expected_output == response


@pytest.mark.parametrize('test_metadata', t1_config_metadata, ids=t1_case_ids)
def test_wazuh_db_messages_agent(test_metadata, configure_sockets_environment_module, connect_to_sockets_module,
                                 clean_databases, clean_registered_agents, insert_agents_test):
    '''
    description: Check that every input agent message in wazuh-db socket generates the proper output to wazuh-db
                 socket. To do this, it performs a query to the socket with a command taken from the input list of
                 stages (test_case, input field) and compare the result with the input list of stages (test_case,
                 output field).

    wazuh_min_version: 4.2.0

    tier: 0

    parameters:
        - test_metadata:
            type: dict
            brief: Test case metadata.
        - configure_sockets_environment_module:
            type: fixture
            brief: Configure environment for sockets and MITM.
        - connect_to_sockets_module:
            type: fixture
            brief: Module scope version of 'connect_to_sockets' fixture.
        - clean_databases:
            type: fixture
            brief: Delete databases.
        - clean_registered_agents:
            type: fixture
            brief: Remove all agents of wazuhdb.
        - insert_agents_test:
            type: fixture
            brief: Insert agents. Only used for the agent queries.

    assertions:
        - Verify that the socket response matches the expected output.

    input_description:
        - Test cases are defined in the agent_messages.yaml file. This file contains the command to insert and clear
          information of registered agents in the database. Also, it contains a case to check messages from not
          registered agents.

    expected_output:
        - r'Failed test case stage .*'
        - r'Error when executing .* in daemon'
        - 'Unable to add agent'
        - 'Unable to upgrade agent'

    tags:
        - wazuh_db
        - wdb_socket
    '''
    for index, stage in enumerate(test_metadata['test_case']):
        if 'ignore' in stage and stage['ignore'] == 'yes':
            continue

        command = stage['input']
        expected_output = stage['output']
        response = query_wdb(command, False, True)
        if 'use_regex' in stage and stage['use_regex'] == 'yes':
            match = True if regex_match(expected_output, response) else False
        else:
            match = validate_wazuh_db_response(expected_output, response)
        assert match, 'Failed test case stage {}: {}. Expected: {}. Response: {}' \
            .format(index + 1, stage['stage'], expected_output, response)


@pytest.mark.parametrize('test_metadata', t2_config_metadata, ids=t2_case_ids)
def test_wazuh_db_messages_global(test_metadata, daemons_handler_module, connect_to_sockets_module,
                                  clean_databases, clean_registered_agents):
    '''
    description: Check that every global input message in wazuh-db socket generates the proper output to wazuh-db
                 socket. To do this, it performs a query to the socket with a command taken from the input list of
                 stages (test_case, input field) and compare the result with the input list of stages (test_case,
                 output field).

    wazuh_min_version: 4.2.0

    tier: 0

    parameters:
        - test_metadata:
            type: dict
            brief: Test case metadata.
        - daemons_handler_module:
            type: fixture
            brief: Handler of Wazuh daemons.
        - connect_to_sockets_module:
            type: fixture
            brief: Module scope version of 'connect_to_sockets' fixture.
        - clean_databases:
            type: fixture
            brief: Delete databases.
        - clean_registered_agents:
            type: fixture
            brief: Remove all agents of wazuhdb.

    assertions:
        - Verify that the socket response matches the expected output of the yaml input file.

    input_description:
        - Test cases are defined in the global_messages.yaml file. This file contains cases to insert, upgrade, label,
          select, get-all-agents, sync-agent-info-get, sync-agent-info-set, belongs table, reset connection status,
          get-agents-by-connection-status, disconnect-agents, delete and keepalive commands in global database.

    expected_output:
        - r'Failed test case stage .*'
        - r'Error when executing * in daemon'

    tags:
        - wazuh_db
        - wdb_socket
    '''
    for index, stage in enumerate(test_metadata['test_case']):
        if 'ignore' in stage and stage['ignore'] == 'yes':
            continue

        command = stage['input']
        expected_output = stage['output']

        response = query_wdb(command, False, True)

        if 'use_regex' in stage and stage['use_regex'] == 'yes':
            match = True if regex_match(expected_output, response) else False
        else:
            match = validate_wazuh_db_response(expected_output, response)
        assert match, 'Failed test case stage {}: {}. Expected: {}. Response: {}' \
            .format(index + 1, stage['stage'], expected_output, response)


@pytest.mark.skip(reason="Unstable after changes introduced in #21997 and #21977. This needs to be investigated.")
def test_wazuh_db_range_checksum(configure_sockets_environment_module, connect_to_sockets_module,
                                 clean_databases, clean_registered_agents, prepare_range_checksum_data):
    '''
    description: Calculates the checksum range during the synchronization of the DBs the first time and avoids the
                 checksum range the next time. To do this, it performs a query to the database with the command that
                 contains agent checksum information and calculates the checksum range.

    wazuh_min_version: 4.2.0

    tier: 0

    parameters:
        - configure_sockets_environment_module:
            type: fixture
            brief: Configure environment for sockets and MITM.
        - connect_to_sockets_module:
            type: fixture
            brief: Module scope version of 'connect_to_sockets' fixture.
        - clean_databases:
            type: fixture
            brief: Delete databases.
        - clean_registered_agents:
            type: fixture
            brief: Remove all agents of wazuhdb.
        - prepare_range_checksum_data:
            type: fixture
            brief: Execute syscheck command with a specific payload to query the database.

    assertions:
        - Verify that the checksum range can be calculated the first time and the checksum range was avoid the second
          time.

    input_description:
        - The input of this test is the agent payload defined in the prepare_range_checksum_data fixture.

    expected_output:
        - r'range checksum Time:  .*'
        - 'Checksum Range was not calculated the first time'
        - 'range checksum avoided'
        - 'Checksum Range was not avoided the second time'

    tags:
        - wazuh_db
        - wdb_socket
    '''
    log_monitor = file_monitor.FileMonitor(WAZUH_LOG_PATH)

    # Checksum Range calculus expected the first time
    agent_integrity_check()
    log_monitor.start(callback=make_callback('range checksum: Time: ', prefix=WAZUH_DB_PREFIX,
                                             escape=True), timeout=WAZUH_DB_CHECKSUM_CALCULUS_TIMEOUT)
    assert log_monitor.callback_result, 'Checksum Range wasn´t calculated the first time'

    # Checksum Range avoid expected the next times
    agent_integrity_check()
    log_monitor.start(callback=make_callback('range checksum avoided', prefix=WAZUH_DB_PREFIX,
                                             escape=True), timeout=WAZUH_DB_CHECKSUM_CALCULUS_TIMEOUT)
    assert log_monitor.callback_result, 'Checksum Range wasn´t avoided the second time'


@pytest.mark.parametrize('test_metadata', t3_config_metadata, ids=t3_case_ids)
def test_wazuh_db_messages_tasks(test_metadata, daemons_handler_module, connect_to_sockets_module,
                                  clean_databases, clean_registered_agents):
    '''
    description: Check that every global input message in wazuh-db socket generates the proper output to wazuh-db
                 socket. To do this, it performs a query to the socket with a command taken from the input list of
                 stages (test_case, input field) and compare the result with the input list of stages (test_case,
                 output field).

    wazuh_min_version: 4.2.0

    tier: 0

    parameters:
        - test_metadata:
            type: dict
            brief: Test case metadata.
        - daemons_handler_module:
            type: fixture
            brief: Handler of Wazuh daemons.
        - connect_to_sockets_module:
            type: fixture
            brief: Module scope version of 'connect_to_sockets' fixture.
        - clean_databases:
            type: fixture
            brief: Delete databases.
        - clean_registered_agents:
            type: fixture
            brief: Remove all agents of wazuhdb.

    assertions:
        - Verify that the socket response matches the expected output of the yaml input file.

    input_description:
        - Test cases are defined in the global_messages.yaml file. This file contains cases to insert, upgrade, label,
          select, get-all-agents, sync-agent-info-get, sync-agent-info-set, belongs table, reset connection status,
          get-agents-by-connection-status, disconnect-agents, delete and keepalive commands in global database.

    expected_output:
        - r'Failed test case stage .*'
        - r'Error when executing * in daemon'

    tags:
        - wazuh_db
        - wdb_socket
    '''
    for index, stage in enumerate(test_metadata['test_case']):
        if 'ignore' in stage and stage['ignore'] == 'yes':
            continue

        command = stage['input']
        expected_output = stage['output']

        response = query_wdb(command, False, True)

        if 'use_regex' in stage and stage['use_regex'] == 'yes':
            match = True if regex_match(expected_output, response) else False
        else:
            match = validate_wazuh_db_response(expected_output, response)
        assert match, 'Failed test case stage {}: {}. Expected: {}. Response: {}' \
            .format(index + 1, stage['stage'], expected_output, response)

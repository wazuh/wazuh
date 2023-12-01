'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

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
import time
import pytest
import json
import random

from wazuh_testing.constants.paths.sockets import WAZUH_DB_SOCKET_PATH
from wazuh_testing.utils.database import delete_dbs
from wazuh_testing.tools.wazuh_manager import remove_all_agents
from wazuh_testing.utils.services import control_service
from wazuh_testing.utils.callbacks import make_callback
from wazuh_testing.modules.wazuh_db import WAZUH_DB_PREFIX
from wazuh_testing.utils import configuration

from . import TEST_CASES_FOLDER_PATH

# Marks
pytestmark = [pytest.mark.linux, pytest.mark.tier(level=0), pytest.mark.server]

# Configurations
t1_cases_path = Path(TEST_CASES_FOLDER_PATH, 'cases_agent_messages.yaml')
t1_config_parameters, t1_config_metadata, t1_case_ids = configuration.get_test_cases_data(t1_cases_path)

t2_cases_path = Path(TEST_CASES_FOLDER_PATH, 'cases_global_messages.yaml')
t2_config_parameters, t2_config_metadata, t2_case_ids = configuration.get_test_cases_data(t2_cases_path)

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
monitored_sockets_params = [('wazuh-db', None, True)]

receiver_sockets, monitored_sockets, log_monitors = None, None, None  # Set in the fixtures


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


@pytest.fixture(scope='module')
def clean_registered_agents():
    remove_all_agents('wazuhdb')
    time.sleep(5)


@pytest.fixture(scope='module')
def wait_range_checksum_avoided(line):
    """Callback function to wait until the manager avoided the checksum calculus by using the last saved one."""
    if 'range checksum avoided' in line:
        return line
    return None


def wait_range_checksum_calculated(line):
    """Callback function to wait until the manager calculates the new checksum."""
    if 'range checksum: Time: ' in line:
        return line
    return None


@pytest.fixture(scope='function')
def prepare_range_checksum_data():
    AGENT_ID = 1
    insert_agent(AGENT_ID)
    command = f"agent {AGENT_ID} syscheck save2 "
    payload = {'path': "file",
               'timestamp': 1575421292,
               'attributes': {
                   'type': 'file',
                   'size': 0,
                   'perm': 'rw-r--r--',
                   'uid': '0',
                   'gid': '0',
                   'user_name': 'root',
                   'group_name': 'root',
                   'inode': 16879,
                   'mtime': 1575421292,
                   'hash_md5': 'd41d8cd98f00b204e9800998ecf8427e',
                   'hash_sha1': 'da39a3ee5e6b4b0d3255bfef95601890afd80709',
                   'hash_sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
                   'checksum': 'f65b9f66c5ef257a7566b98e862732640d502b6f'}}

    payload['path'] = '/home/test/file1'
    execute_wazuh_db_query(command+json.dumps(payload))
    payload['path'] = '/home/test/file2'
    execute_wazuh_db_query(command+json.dumps(payload))

    yield

    remove_agent(AGENT_ID)


@pytest.fixture(scope='function')
def pre_insert_agents():
    """Insert agents. Only used for the global queries."""
    AGENTS_CANT = 14000
    AGENTS_OFFSET = 20
    for id in range(AGENTS_OFFSET, AGENTS_OFFSET + AGENTS_CANT):
        insert_agent(id)

    yield

    for id in range(AGENTS_OFFSET, AGENTS_OFFSET + AGENTS_CANT):
        remove_agent(id)


@pytest.fixture(scope='function')
def insert_agents_test():
    """Insert agents. Only used for the agent queries"""
    agent_list = [1, 2, 3]
    for agent in agent_list:
        insert_agent(agent)

    yield

    for agent in agent_list:
        remove_agent(agent)


@pytest.fixture(scope='module')
def restart_wazuh(request):
    control_service('restart')

    yield

    delete_dbs()
    control_service('stop')


def execute_wazuh_db_query(command, single_response=True):
    """Function to send a command to the wazuh-db socket.

    Args:
        command(str): Message to send to the socket.
        single_response(bool): If set to False, all the 'due' responses
                               will be appended to a response array
    Returns:
        str: A response from the socket
    """
    receiver_sockets[0].send(command, size=True)
    if single_response:
        return receiver_sockets[0].receive(size=True).decode()
    else:
        response_array = []
        while True:
            response = receiver_sockets[0].receive(size=True).decode()
            response_array.append(response)
            status = response.split()[0]
            if status != 'due':
                break

        return response_array[0] if len(response_array) == 1 else response_array


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


def insert_agent(agent_id, agent_name='TestName'):
    """Function that wraps the needed queries to register an agent.

    Args:
        agent_id(int): Unique identifier of an agent.

    Raises:
        AssertionError: If the agent couldn't be inserted in the DB
    """
    insert_data = json.dumps({'id': agent_id,
                              'name': f"{agent_name}{agent_id}",
                              'date_add': 1599223378
                              })

    update_data = json.dumps({'id': agent_id,
                              'sync_status': 'syncreq',
                              'connection_status': 'active',
                              'status_code': 0
                              })

    command = f"global insert-agent {insert_data}"
    data = execute_wazuh_db_query(command).split()
    assert data[0] == 'ok', f"Unable to add agent {agent_id} - {data[1]}"

    command = f"global update-keepalive {update_data}"
    data = execute_wazuh_db_query(command).split()
    assert data[0] == 'ok', f"Unable to update agent {agent_id} - {data[1]}"


def remove_agent(agent_id):
    """Function that wraps the needed queries to remove an agent.

    Args:
        agent_id(int): Unique identifier of an agent
    """
    data = execute_wazuh_db_query(f"global delete-agent {agent_id}").split()
    assert data[0] == 'ok', f"Unable to remove agent {agent_id} - {data[1]}"


@pytest.fixture(scope='function')
def pre_set_sync_info():
    """Assign the last_attempt value to last_completion in sync_info table to force the synced status"""

    command = "agent 000 sql UPDATE sync_info SET last_completion = 10, last_attempt = 10 " \
              "where component = 'syscollector-packages'"
    receiver_sockets[0].send(command, size=True)
    response = receiver_sockets[0].receive(size=True).decode()
    data = response.split()
    assert data[0] == 'ok', 'Unable to set sync_info table'


@pytest.fixture(scope='function')
def pre_insert_packages():
    """Insert a set of dummy packages into sys_programs table"""

    PACKAGES_NUMBER = 20000
    for pkg_n in range(PACKAGES_NUMBER):
        command = f"agent 000 sql INSERT OR REPLACE INTO sys_programs \
        (scan_id,scan_time,format,name,priority,section,size,vendor,install_time,version,\
        architecture,multiarch,source,description,location,triaged,cpe,msu_name,checksum,item_id)\
        VALUES(0,'2021/04/07 22:00:00','deb','test_package_{pkg_n}','optional','utils',{random.randint(200,1000)},\
        'Wazuh wazuh@wazuh.com',NULL,'{random.randint(1,10)}.0.0','all',NULL,NULL,'Test package {pkg_n}',\
        NULL,0,NULL,NULL,'{random.getrandbits(128)}','{random.getrandbits(128)}')"
        receiver_sockets[0].send(command, size=True)
        response = receiver_sockets[0].receive(size=True).decode()
        data = response.split()
        assert data[0] == 'ok', f"Unable to insert package {pkg_n}"



@pytest.mark.parametrize('test_metadata', t1_config_metadata, ids=t1_case_ids)
def test_wazuh_db_messages_agent(restart_wazuh, clean_registered_agents, configure_sockets_environment,
                                 connect_to_sockets_module, insert_agents_test, test_metadata):
    '''
    description: Check that every input agent message in wazuh-db socket generates the proper output to wazuh-db
                 socket. To do this, it performs a query to the socket with a command taken from the input list of
                 stages (test_case, input field) and compare the result with the input list of stages (test_case,
                 output field).

    wazuh_min_version: 4.2.0

    tier: 0

    parameters:
        - restart_wazuh:
            type: fixture
            brief: Reset the 'ossec.log' file and start a new monitor.
        - clean_registered_agents:
            type: fixture
            brief: Remove all agents of wazuhdb.
        - configure_sockets_environment:
            type: fixture
            brief: Configure environment for sockets and MITM.
        - connect_to_sockets_module:
            type: fixture
            brief: Module scope version of 'connect_to_sockets' fixture.
        - insert_agents_test:
            type: fixture
            brief: Insert agents. Only used for the agent queries.
        - test_case:
            type: fixture
            brief: List of test_case stages (dicts with input, output and stage keys).

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

        response = execute_wazuh_db_query(command, False)

        if 'use_regex' in stage and stage['use_regex'] == 'yes':
            match = True if regex_match(expected_output, response) else False
        else:
            match = validate_wazuh_db_response(expected_output, response)
        assert match, 'Failed test case stage {}: {}. Expected: {}. Response: {}' \
            .format(index + 1, stage['stage'], expected_output, response)


@pytest.mark.parametrize('test_metadata', t2_config_metadata, ids=t2_case_ids)
def test_wazuh_db_messages_global(connect_to_sockets_module, restart_wazuh, test_metadata):
    '''
    description: Check that every global input message in wazuh-db socket generates the proper output to wazuh-db
                 socket. To do this, it performs a query to the socket with a command taken from the input list of
                 stages (test_case, input field) and compare the result with the input list of stages (test_case,
                 output field).

    wazuh_min_version: 4.2.0

    tier: 0

    parameters:
        - restart_wazuh:
            type: fixture
            brief: Reset the 'ossec.log' file and start a new monitor.
        - connect_to_sockets_module:
            type: fixture
            brief: Module scope version of 'connect_to_sockets' fixture.
        - test_case:
            type: fixture
            brief: List of test_case stages (dicts with input, output and stage keys).

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

        response = execute_wazuh_db_query(command, False)

        if 'use_regex' in stage and stage['use_regex'] == 'yes':
            match = True if regex_match(expected_output, response) else False
        else:
            match = validate_wazuh_db_response(expected_output, response)
        assert match, 'Failed test case stage {}: {}. Expected: {}. Response: {}' \
            .format(index + 1, stage['stage'], expected_output, response)


@pytest.mark.skip(reason="It will be blocked by #2217, when it is solved we can enable again this test")
def test_wazuh_db_chunks(restart_wazuh, configure_sockets_environment, clean_registered_agents,
                         connect_to_sockets_module, pre_insert_agents):
    '''
    description: Check that commands by chunks work properly when the agents' amount exceeds the response maximum size.
                 To do this, it sends a command to the wazuh-db socket and checks the response from the socket.

    wazuh_min_version: 4.2.0

    tier: 0

    parameters:
        - restart_wazuh:
            type: fixture
            brief: Reset the 'ossec.log' file and start a new monitor.
        - configure_sockets_environment:
            type: fixture
            brief: Configure environment for sockets and MITM.
        - clean_registered_agents:
            type: fixture
            brief: Remove all agents of wazuhdb.
        - connect_to_sockets_module:
            type: fixture
            brief: Module scope version of 'connect_to_sockets' fixture.
        - pre_insert_agents:
            type: fixture
            brief: Insert agents. Only used for the global queries.

    assertions:
        - Verify that the socket status response matches with 'due' to fail.

    input_description:
        - Test cases are defined in the global_messages.yaml file. Status response is expected from 'global
          get-all-agents last_id 0', 'global sync-agent-info-get last_id 0', 'global get-agents-by-connection-status 0
          active' and r'global disconnect-agents 0 .* syncreq' commands.

    expected_output:
        - r'Failed chunks check on .*'

    tags:
        - wazuh_db
        - wdb_socket
    '''
    def send_chunk_command(command):
        response = execute_wazuh_db_query(command)
        status = response.split()[0]

        assert status == 'due', 'Failed chunks check on < {} >. Expected: {}. Response: {}' \
            .format(command, 'due', status)

    # Check get-all-agents chunk limit
    send_chunk_command('global get-all-agents last_id 0')
    # Check sync-agent-info-get chunk limit
    send_chunk_command('global sync-agent-info-get last_id 0')
    # Check get-agents-by-connection-status chunk limit
    send_chunk_command('global get-agents-by-connection-status 0 active')
    # Check disconnect-agents chunk limit
    send_chunk_command('global disconnect-agents 0 {} syncreq'.format(str(int(time.time()) + 1)))


def test_wazuh_db_range_checksum(restart_wazuh, configure_sockets_environment, connect_to_sockets_module,
                                 prepare_range_checksum_data, file_monitoring, request):
    '''
    description: Calculates the checksum range during the synchronization of the DBs the first time and avoids the
                 checksum range the next time. To do this, it performs a query to the database with the command that
                 contains agent checksum information and calculates the checksum range.

    wazuh_min_version: 4.2.0

    tier: 0

    parameters:
        - restart_wazuh:
            type: fixture
            brief: Reset the 'ossec.log' file and start a new monitor.
        - configure_sockets_environment:
            type: fixture
            brief: Configure environment for sockets and MITM.
        - connect_to_sockets_module:
            type: fixture
            brief: Module scope version of 'connect_to_sockets' fixture.
        - prepare_range_checksum_data:
            type: fixture
            brief: Execute syscheck command with a specific payload to query the database.
        - file_monitoring:
            type: fixture
            brief:  Handle the monitoring of a specified file.
        - request:
            type: fixture
            brief:  Provide information of the requesting test function.

    assertions:
        - Verify that the checksum range can be calculated the first time and the checksum range was avoid the second
          time.

    input_description:
        - The input of this test is the agent payload defined in the prepare_range_checksum_data fixture.

    expected_output:
        - r'range checksum Time:  .*'
        - 'Checksum Range wasn´t calculated the first time'
        - 'range checksum avoided'
        - 'Checksum Range wasn´t avoided the second time'

    tags:
        - wazuh_db
        - wdb_socket
    '''
    command = """agent 1 syscheck integrity_check_global {\"begin\":\"/home/test/file1\",\"end\":\"/home/test/file2\",
                 \"checksum\":\"2a41be94762b4dc57d98e8262e85f0b90917d6be\",\"id\":1}"""
    log_monitor = request.module.log_monitor
    # Checksum Range calculus expected the first time
    execute_wazuh_db_query(command)
    log_monitor.start(callback=make_callback('range checksum: Time: ', prefix=WAZUH_DB_PREFIX,
                                             escape=True), timeout=WAZUH_DB_CHECKSUM_CALCULUS_TIMEOUT)
    assert log_monitor.callback_result, 'Checksum Range wasn´t calculated the first time'

    # Checksum Range avoid expected the next times
    execute_wazuh_db_query(command)
    log_monitor.start(callback=make_callback('range checksum avoided', prefix=WAZUH_DB_PREFIX,
                                             escape=True), timeout=WAZUH_DB_CHECKSUM_CALCULUS_TIMEOUT)
    assert log_monitor.callback_result, 'Checksum Range wasn´t avoided the second time'


def test_wazuh_db_timeout(configure_sockets_environment,
                          connect_to_sockets_module,
                          pre_insert_packages,
                          pre_set_sync_info):
    """Check that effectively the socket is closed after timeout is reached"""
    wazuh_db_send_sleep = 2
    command = 'agent 000 package get'
    receiver_sockets[0].send(command, size=True)

    # Waiting Wazuh-DB to process command
    time.sleep(wazuh_db_send_sleep)

    socket_closed = False
    cmd_counter = 0
    status = 'due'
    while not socket_closed and status == 'due':
        cmd_counter += 1
        response = receiver_sockets[0].receive(size=True).decode()
        if response == '':
            socket_closed = True
        else:
            status = response.split()[0]

    assert socket_closed, f"Socket never closed. Received {cmd_counter} commands. Last command: {response}"

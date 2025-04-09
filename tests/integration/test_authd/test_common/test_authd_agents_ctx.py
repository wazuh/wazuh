'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: These tests will check if the 'wazuh-authd' daemon correctly handles the enrollment requests
       from agents with pre-existing IP addresses or names. The 'wazuh-authd' daemon can automatically
       add a Wazuh agent to a Wazuh manager and provide the key to the agent. It is used along with
       the 'agent-auth' application.

components:
    - authd

targets:
    - manager

daemons:
    - wazuh-authd
    - wazuh-db
    - wazuh-modulesd

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
    - https://documentation.wazuh.com/current/user-manual/reference/daemons/wazuh-authd.html
    - https://documentation.wazuh.com/current/user-manual/reference/tools/agent_groups.html

tags:
    - enrollment
'''
from pathlib import Path

import pytest
import time
from wazuh_testing.constants.paths.sockets import AUTHD_SOCKET_PATH
from wazuh_testing.constants.ports import DEFAULT_SSL_REMOTE_ENROLLMENT_PORT
from wazuh_testing.utils.agent_groups import check_agent_groups
from wazuh_testing.utils.db_queries.global_db import delete_agent
from wazuh_testing.utils.client_keys import check_client_keys

from . import CONFIGURATIONS_FOLDER_PATH, TEST_CASES_FOLDER_PATH, utils
from wazuh_testing.utils.configuration import get_test_cases_data, load_configuration_template

# Marks
pytestmark = [pytest.mark.server, pytest.mark.tier(level=0)]

# Paths
test_configuration_path = Path(CONFIGURATIONS_FOLDER_PATH, 'config_authd_common.yaml')
test_cases_path = Path(TEST_CASES_FOLDER_PATH, 'cases_authd_agents_ctx.yaml')

# Configurations
test_configuration, test_metadata, test_cases_ids = get_test_cases_data(test_cases_path)
test_configuration = load_configuration_template(test_configuration_path, test_configuration, test_metadata)

# Variables
daemons_handler_configuration = {'all_daemons': True}

receiver_sockets_params = [(("localhost", DEFAULT_SSL_REMOTE_ENROLLMENT_PORT), 'AF_INET', 'SSL_TLSv1_2'), (AUTHD_SOCKET_PATH, 'AF_UNIX', 'TCP')]

receiver_sockets = None  # Set in the fixtures
test_group = "TestGroup"
timeout = 10
sleep = 5


# Functions
def register_agent_main_server(receiver_sockets, Name, Group=None, IP=None):
    """Register an agent on server mode."""
    message = "OSSEC A:'{}'".format(Name)
    if Group:
        message += " G:'{}'".format(Group)
    if IP:
        message += " IP:'{}'".format(IP)

    message += '\n'
    receiver_sockets[0].open()
    receiver_sockets[0].send(message, size=False)
    timeout = time.time() + 10
    response = ''
    while response == '':
        response = receiver_sockets[0].receive().decode()
        if time.time() > timeout:
            raise ConnectionResetError('Manager did not respond to sent message!')
    time.sleep(sleep)
    return response


def register_agent_local_server(receiver_sockets, Name, Group=None, IP=None):
    """Register an agent on local mode."""
    message = ('{"arguments":{"force":{"enabled":true,"disconnected_time":{"enabled":true,"value":"0"},'
               '"key_mismatch":true,"after_registration_time":"0"}')
    message += ',"name":"{}"'.format(Name)
    if Group:
        message += ',"groups":"{}"'.format(Group)
    if IP:
        message += ',"ip":"{}"'.format(IP)
    else:
        message += ',"ip":"any"'
    message += '},"function":"add"}'

    receiver_sockets[1].open()
    receiver_sockets[1].send(message, size=True)
    response = receiver_sockets[1].receive(size=True).decode()
    time.sleep(sleep)
    return response


# Tests
@pytest.mark.parametrize('test_configuration,test_metadata', zip(test_configuration, test_metadata), ids=test_cases_ids)
def test_ossec_authd_agents_ctx(test_configuration, test_metadata, set_wazuh_configuration, truncate_monitored_files,
                                clean_agents_ctx, daemons_handler, wait_for_authd_startup, connect_to_sockets, set_up_groups):
    '''
    description:
        Check if when the 'wazuh-authd' daemon receives an enrollment request from an agent
        that has an IP address or name that is already registered, 'authd' creates a record
        for the new agent and deletes the old one. In this case, the enrollment requests
        are sent to an IP v4 network socket.

    wazuh_min_version:
        4.2.0

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
            brief: Load basic wazuh configuration.
        - truncate_monitored_files:
            type: fixture
            brief: Truncate all the log files and json alerts files before and after the test execution.
        - clean_agents_ctx
            type: fixture
            brief: Clean agents files.
        - daemons_handler:
            type: fixture
            brief: Handler of Wazuh daemons.
        - connect_to_sockets:
            type: fixture
            brief: Module scope version of 'connect_to_sockets' fixture.
        - wait_for_authd_startup:
            type: fixture
            brief: Waits until Authd is accepting connections.
        - set_up_groups:
            type: fixture
            brief: Create a testing group for agents and provide the test case list.

    assertions:
        - Verify that agents using an already registered IP address can successfully enroll.
        - Verify that agents using an already registered name can successfully enroll.

    input_description:
        Different test cases are contained in an external YAML file (wazuh_conf.yaml)
        which includes configuration settings for the 'wazuh-authd' daemon.

    expected_output:
        - r'Accepting connections on port 1515' (When the 'wazuh-authd' daemon is ready to accept enrollments)
        - r'OSSEC K:' (When the agent has enrolled in the manager)
    tags:
        - keys
        - ssl
    '''
    server = test_metadata["server_type"]

    if server == "main":
        SUCCESS_RESPONSE = "OSSEC K:'"
        register_agent = register_agent_main_server
    elif server == "local":
        SUCCESS_RESPONSE = '{"error":0,'
        register_agent = register_agent_local_server
    else:
        raise Exception('Invalid registration server')


    # Register a first agent, then register an agent with duplicate IP.
    # Check that client.keys, agent-groups, agent-timestamp and agent diff were updated correctly

    # Register first agent
    response = register_agent(receiver_sockets, 'userA', test_group, '192.0.0.0')

    utils.create_rids('001')  # Simulate rids was created
    utils.create_diff('userA')  # Simulate diff folder was created

    assert response[:len(SUCCESS_RESPONSE)] == SUCCESS_RESPONSE, 'Wrong response received'
    assert check_client_keys('001', True), 'Agent key was never created'
    assert check_agent_groups('001', test_group), 'Did not recieve the expected group: {test_group} for the agent'
    assert utils.check_agent_timestamp('001', 'userA', '192.0.0.0', True), 'Agent_timestamp was never created'
    assert utils.check_rids('001', True), 'Rids file was never created'
    assert utils.check_diff('userA', True), 'Agent diff folder was never created'

    # Register agent with duplicate IP
    response = register_agent(receiver_sockets, 'userC', test_group, '192.0.0.0')
    assert response[:len(SUCCESS_RESPONSE)] == SUCCESS_RESPONSE, 'Wrong response received'
    assert check_client_keys('002', True), 'Agent key was never created'
    assert check_client_keys('001', False), 'Agent key was not removed'
    assert check_agent_groups('002', test_group), 'Did not recieve the expected group: {test_group} for the agent'
    assert check_agent_groups('001', test_group), 'Agent has groups when agent should not exist'
    assert utils.check_agent_timestamp('002', 'userC', '192.0.0.0', True), 'Agent_timestamp was never created'
    assert utils.check_agent_timestamp('001', 'userA', '192.0.0.0', False), 'Agent_timestamp was not removed'
    assert utils.check_rids('001', False), 'Rids file was was not removed'
    assert utils.check_diff('userA', False), 'Agent diff folder was not removed'

    # Register a first agent, then register an agent with duplicate Name.
    # Check that client.keys, agent-groups, agent-timestamp and agent diff were updated correctly

    utils.clean_diff()

    utils.create_diff('userB')  # Simulate diff folder was created
    utils.create_rids('003')  # Simulate rids was created

    response = register_agent(receiver_sockets, 'userB', test_group)

    assert response[:len(SUCCESS_RESPONSE)] == SUCCESS_RESPONSE, 'Wrong response received'
    assert check_client_keys('003', True), 'Agent key was never created'
    assert check_agent_groups('003', test_group), 'Did not recieve the expected group: {test_group} for the agent'
    assert utils.check_agent_timestamp('003', 'userB', 'any', True), 'Agent_timestamp was never created'
    assert utils.check_rids('003', True), 'Rids file was never created'
    assert utils.check_diff('userB', True), 'Agent diff folder was never created'

    # Register agent with duplicate Name
    response = register_agent(receiver_sockets, 'userB', test_group)
    assert response[:len(SUCCESS_RESPONSE)] == SUCCESS_RESPONSE, 'Wrong response received'
    assert check_client_keys('004', True), 'Agent key was never created'
    assert check_client_keys('003', False), 'Agent key was not removed'
    assert check_agent_groups('004', test_group), 'Did not recieve the expected group: {test_group} for the agent'
    assert check_agent_groups('003', test_group), 'Agent has groups when agent should not exist'
    assert utils.check_agent_timestamp('004', 'userB', 'any', True), 'Agent_timestamp was never created'
    assert utils.check_agent_timestamp('003', 'userB', 'any', False), 'Agent_timestamp was not removed'
    assert utils.check_rids('003', False), 'Rids file was was not removed'
    assert utils.check_diff('userB', False), 'Agent diff folder was not removed'

    delete_agent()

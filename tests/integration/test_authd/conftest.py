"""
Copyright (C) 2015-2024, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""
import pytest
import time

from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.utils.callbacks import generate_callback
from wazuh_testing.utils.agent_groups import create_group, delete_group
from wazuh_testing.tools.monitors import file_monitor
from wazuh_testing.modules.authd import PREFIX
from wazuh_testing.constants.daemons import AUTHD_DAEMON
from wazuh_testing.utils import mocking
from wazuh_testing.utils.services import control_service


AUTHD_STARTUP_TIMEOUT = 30

@pytest.fixture()
def stop_authd():
    """
    Stop Authd.
    """
    control_service("stop", daemon=AUTHD_DAEMON)


@pytest.fixture()
def wait_for_authd_startup():
    """Wait until authd has begun with function scope"""
    log_monitor = file_monitor.FileMonitor(WAZUH_LOG_PATH)
    log_monitor.start(timeout=AUTHD_STARTUP_TIMEOUT, encoding="utf-8",
                      callback=generate_callback(rf'{PREFIX}Accepting connections on port 1515'))
    assert log_monitor.callback_result


@pytest.fixture()
def insert_pre_existent_agents(test_metadata, stop_authd):
    """
    Create some agents and add them to the DB and keys file.
    """
    agents = test_metadata['pre_existent_agents']
    time_now = int(time.time())

    for agent in agents:
        if agent:
            id = agent['id'] if 'id' in agent else '001'
            name = agent['name'] if 'name' in agent else f"TestAgent{id}"
            ip = agent['ip'] if 'ip' in agent else 'any'
            key = agent['key'] if 'key' in agent else 'TopSecret'
            connection_status = agent['connection_status'] if 'connection_status' in agent else 'never_connected'
            if 'disconnection_time' in agent and 'delta' in agent['disconnection_time']:
                disconnection_time = time_now + agent['disconnection_time']['delta']
            elif 'disconnection_time' in agent and 'value' in agent['disconnection_time']:
                disconnection_time = agent['disconnection_time']['value']
            else:
                disconnection_time = time_now
            if 'registration_time' in agent and 'delta' in agent['registration_time']:
                registration_time = time_now + agent['registration_time']['delta']
            elif 'registration_time' in agent and 'value' in agent['registration_time']:
                registration_time = agent['registration_time']['value']
            else:
                registration_time = time_now

            mocking.create_mocked_agent(id=id, name=name, ip=ip, date_add=registration_time,
                                        connection_status=connection_status, disconnection_time=disconnection_time,
                                        client_key_secret=key)

    yield

    for agent in agents:
        if agent:
            mocking.delete_mocked_agent(agent['id'])


@pytest.fixture()
def set_up_groups(test_metadata, request):
    """
    Create and delete groups for test.
    """
    groups = test_metadata['groups']
    for group in groups:
        if(group):
            create_group(group)
    yield
    for group in groups:
        if(group):
            delete_group(group)

"""
Copyright (C) 2015-2024, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""
import pytest
import random

from wazuh_testing.utils import database
from wazuh_testing.utils.db_queries.global_db import create_or_update_agent, delete_agent
from wazuh_testing.utils.db_queries import agent_db


@pytest.fixture()
def prepare_range_checksum_data():
    AGENT_ID = "1"
    name = f"TestName{AGENT_ID}"
    create_or_update_agent(agent_id=AGENT_ID, name=name, date_add='1599223378', sync_status='syncreq')
    agent_db.agent_checksum_data(AGENT_ID, '/home/test/file1')
    agent_db.agent_checksum_data(AGENT_ID, '/home/test/file2')

    yield

    delete_agent(AGENT_ID)


@pytest.fixture()
def insert_agents_test():
    """Insert agents. Only used for the agent queries"""
    agent_list = [1, 2, 3]
    for agent in agent_list:
        name = f"TestName{agent}"
        create_or_update_agent(agent_id=agent, name=name, date_add='1599223378', sync_status='syncreq')

    yield

    for agent in agent_list:
        delete_agent(agent)


@pytest.fixture()
def pre_set_sync_info():
    """Assign the last_attempt value to last_completion in sync_info table to force the synced status"""

    command = "agent 000 sql UPDATE sync_info SET last_completion = 10, last_attempt = 10 " \
              "where component = 'syscollector-packages'"
    response = database.query_wdb(command, False)
    data = response.split()
    assert data[0] == 'ok', 'Unable to set sync_info table'


@pytest.fixture()
def pre_insert_packages():
    """Insert a set of dummy packages into sys_programs table"""

    PACKAGES_NUMBER = 20000
    for pkg_n in range(PACKAGES_NUMBER):
        agent_db.insert_package(scan_id='0', scan_time='2021/04/07 22:00:00', format='deb', name=f'test_package_{pkg_n}',
                                priority='optional', section='utils', size=f'{random.randint(200,1000)}', vendor='Wazuh wazuh@wazuh.com',
                                install_time='NULL', version=f'{random.randint(1,10)}.0.0', architecture='all', multiarch='NULL', source='NULL',
                                description=f'Test package {pkg_n}', location='NULL',
                                checksum=f'{random.getrandbits(128)}', item_id=f'{random.getrandbits(128)}')

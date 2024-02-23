"""
Copyright (C) 2015-2024, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""
import pytest
import os
import time
import random

from wazuh_testing.utils.agent_groups import create_group, delete_group
from wazuh_testing.utils.file import remove_file, recursive_directory_creation
from wazuh_testing.utils import database
from wazuh_testing.utils.db_queries.global_db import create_or_update_agent, set_agent_group, delete_agent, insert_metadata_value, remove_metadata_value
from wazuh_testing.utils.db_queries import agent_db


@pytest.fixture()
def create_groups(test_metadata):
    if 'pre_required_group' in test_metadata:
        groups = test_metadata['pre_required_group'].split(',')

        for group in groups:
            create_group(group)

    yield

    if 'pre_required_group' in test_metadata:
        groups = test_metadata['pre_required_group'].split(',')

        for group in groups:
            delete_group(group)


@pytest.fixture()
def pre_insert_agents_into_group():
    for i in range(2):
        id = i + 1
        name = 'Agent-test' + str(id)
        date = time.time()
        create_or_update_agent(agent_id=id, name=name, date_add=date)
        set_agent_group(sync_status="syncreq", id=id, group=[f"Test_group{id}"])

    yield

    delete_agent()


@pytest.fixture()
def remove_backups(request: pytest.FixtureRequest):
    backups_path = getattr(request.module, 'backups_path')
    "Creates backups folder in case it does not exist."
    remove_file(backups_path)
    recursive_directory_creation(backups_path)
    os.chmod(backups_path, 0o777)
    yield
    remove_file(backups_path)
    recursive_directory_creation(backups_path)
    os.chmod(backups_path, 0o777)


@pytest.fixture(scope='module')
def clean_databases():
    yield
    database.delete_dbs()


@pytest.fixture(scope='module')
def clean_registered_agents():
    delete_agent()
    time.sleep(5)


@pytest.fixture()
def add_database_values(request):
    test_values = getattr(request.module, 'test_values')
    "Add test values to database"
    insert_metadata_value(test_values[0],test_values[1])
    yield
    remove_metadata_value(test_values[0])


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
def pre_insert_agents():
    """Insert agents. Only used for the global queries."""
    AGENTS_CANT = 14000
    AGENTS_OFFSET = 20
    for id in range(AGENTS_OFFSET, AGENTS_OFFSET + AGENTS_CANT):
        name = f"TestName{id}"
        create_or_update_agent(agent_id=id, name=name, date_add='1599223378', sync_status='syncreq')

    yield

    for id in range(AGENTS_OFFSET, AGENTS_OFFSET + AGENTS_CANT):
        delete_agent(id)


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

"""
Copyright (C) 2015-2024, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""
import pytest
import os

from wazuh_testing.utils.agent_groups import create_group, delete_group
from wazuh_testing.utils.db_queries import global_db
from wazuh_testing.utils.file import remove_file, recursive_directory_creation
from wazuh_testing.utils import database
from wazuh_testing.utils.manage_agents import remove_all_agents

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

    global_db.insert_agent_into_group(2)

    yield

    global_db.clean_agents_from_db()
    global_db.clean_groups_from_db()
    global_db.clean_belongs()


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


@pytest.fixture()
def remove_agents():
    yield
    remove_all_agents('manage_agents')

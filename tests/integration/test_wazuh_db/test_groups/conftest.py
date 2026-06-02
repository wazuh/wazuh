"""
Copyright (C) 2015-2024, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""
import pytest
import time

from wazuh_testing.utils.database import query_wdb
from wazuh_testing.utils.db_queries.global_db import set_agent_group


def _query_ok(command):
    response = query_wdb(command)
    assert response == 'ok', f"Unexpected response for {command!r}: {response}"


def _query_sql_ok(command):
    response = query_wdb(command)
    assert response == [], f"Unexpected SQL response for {command!r}: {response}"


def _create_group(group):
    response = query_wdb(f'global find-group {group}')
    if response == []:
        _query_ok(f'global insert-agent-group {group}')
        response = query_wdb(f'global find-group {group}')
    assert isinstance(response, list) and response, f"Group {group!r} was not inserted into global.db: {response}"


def _insert_agent(agent_id, name):
    # Register agents 100s in the past so the default sync-agent-groups-get filter (date_add < now)
    # reliably includes them, while staying well under the 10000s registration delta used by other cases.
    date_add = int(time.time()) - 100
    _query_ok(f'global insert-agent {{"id":{agent_id},"name":"{name}","ip":"any","date_add":{date_add}}}')


def _clean_agents():
    _query_sql_ok('global sql DELETE FROM belongs')
    _query_sql_ok('global sql DELETE FROM agent WHERE id != 0')


@pytest.fixture()
def create_groups(test_metadata):
    # global.db is shared across all group tests and clean_databases only runs at module teardown, so
    # start every test from a clean agent table to avoid cross-test state pollution.
    _clean_agents()

    _create_group('default')

    if 'pre_required_group' in test_metadata:
        groups = test_metadata['pre_required_group'].split(',')

        for group in groups:
            _create_group(group)

    yield

    if 'pre_required_group' in test_metadata:
        groups = test_metadata['pre_required_group'].split(',')

        for group in groups:
            query_wdb(f'global delete-group {group}')


@pytest.fixture()
def pre_insert_agents_into_group():
    _clean_agents()

    for i in range(2):
        id = i + 1
        name = 'Agent-test' + str(id)
        _insert_agent(id, name)
        response = set_agent_group(sync_status="syncreq", id=id, group=f"Test_group{id}")
        assert response == 'ok', f"Unable to assign Test_group{id} to agent {id}: {response}"

    yield

    _clean_agents()

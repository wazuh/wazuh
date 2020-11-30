#!/usr/bin/env python
# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys
from unittest.mock import patch, MagicMock

import pytest

with patch('wazuh.common.ossec_uid'):
    with patch('wazuh.common.ossec_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        sys.modules['api'] = MagicMock()
        import wazuh.rbac.decorators

        del sys.modules['wazuh.rbac.orm']
        del sys.modules['api']

        from wazuh.tests.util import get_fake_database_data, RBAC_bypasser, InitWDBSocketMock

        wazuh.rbac.decorators.expose_resources = RBAC_bypasser
        from wazuh import tasks, WazuhError
        from wazuh.core.tasks import WazuhDBQueryTasks


test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')


def fake_final_query(self):
    """
    :return: The final mitre query
    """
    return self._default_query() + f" WHERE task_id IN ({self.query}) LIMIT {self.limit} OFFSET :offset"

# Tests

@patch('wazuh.core.utils.WazuhDBConnection', return_value=InitWDBSocketMock(sql_schema_file='schema_tasks_test.sql'))
@patch.object(WazuhDBQueryTasks, '_final_query', fake_final_query)
def test_get_task_status_no_filter(mock_task_db):
    """Check system's tasks (No filters)
    """
    result = tasks.get_task_status()
    cur = get_fake_database_data('schema_tasks_test.sql').cursor()
    cur.execute("SELECT COUNT(DISTINCT task_id) FROM tasks")
    rows = cur.fetchone()

    assert result.total_affected_items == rows[0]


@patch('wazuh.core.utils.WazuhDBConnection', return_value=InitWDBSocketMock(sql_schema_file='schema_tasks_test.sql'))
@patch.object(WazuhDBQueryTasks, '_final_query', fake_final_query)
@pytest.mark.parametrize("task_id, total", [
    (['1'], 1),
    (['2'], 1),
    (['1', '2'], 2),
    (['99'], 0)
])
def test_get_task_status_task_id(mock_task_db, task_id, total):
    """Check system's tasks (task_id)

    Parameters
    ----------
    task_id : str
        Specific task id
    total : int
        Total records for agent id
    """
    result = tasks.get_task_status(task_list=task_id)

    assert result.total_affected_items == total


@patch('wazuh.core.utils.WazuhDBConnection', return_value=InitWDBSocketMock(sql_schema_file='schema_tasks_test.sql'))
@patch.object(WazuhDBQueryTasks, '_final_query', fake_final_query)
@pytest.mark.parametrize("agent_id", [
    ('002'),
    ('001')
])
def test_get_task_status_agent_id(mock_task_db, agent_id):
    """Check system's tasks (agent_id)

    Parameters
    ----------
    agent_id : str
        Specific agent id
    """
    cur = get_fake_database_data('schema_tasks_test.sql').cursor()
    cur.execute("SELECT COUNT(DISTINCT task_id) FROM tasks WHERE "
                f"(agent_id='{int(agent_id)}' COLLATE NOCASE)")
    rows = cur.fetchone()
    expected_total_items = rows[0]

    result = tasks.get_task_status(agent_id=agent_id)

    assert result.total_affected_items == expected_total_items


@patch('wazuh.core.utils.WazuhDBConnection', return_value=InitWDBSocketMock(sql_schema_file='schema_tasks_test.sql'))
@patch.object(WazuhDBQueryTasks, '_final_query', fake_final_query)
@pytest.mark.parametrize("search, total", [
    ('upgrade_module', 6),
    ('invalid', 0),
    ('worker2', 5),
    ('worker1', 0)
])
def test_get_task_status_search(mock_task_db, search, total):
    """Check system's tasks (search)

    Parameters
    ----------
    search : str
        Term to be search
    total : int
        Total records for the specific search
    """
    result = tasks.get_task_status(search={'value': search, 'negation': 0})

    assert result.total_affected_items == total


@patch('wazuh.core.utils.WazuhDBConnection', return_value=InitWDBSocketMock(sql_schema_file='schema_tasks_test.sql'))
@patch.object(WazuhDBQueryTasks, '_final_query', fake_final_query)
@pytest.mark.parametrize("select, total, agents", [
    (['node'], 6, ['1', '2', '3'])
])
def test_get_task_status_select(mock_task_db, select, total, agents):
    """Check system's tasks (select)

    Parameters
    ----------
    select : list
        Select which fields to return (separated by comma)
    total : int
        Total records for the specific search
    """
    result = tasks.get_task_status(select=select)

    assert result.total_affected_items == total
    for specified_select in select:
        for element in result.affected_items:
            assert specified_select in element.keys()


@patch('wazuh.core.utils.WazuhDBConnection', return_value=InitWDBSocketMock(sql_schema_file='schema_tasks_test.sql'))
@patch.object(WazuhDBQueryTasks, '_final_query', fake_final_query)
@pytest.mark.parametrize("status", [
    ('Legacy'),
    ('Failed'),
    ('Invalid')
])
def test_get_task_status_status(mock_task_db, status):
    """Check system's tasks (status)

    Parameters
    ----------
    status : str
        Status of tasks to be shown
    """
    cur = get_fake_database_data('schema_tasks_test.sql').cursor()
    cur.execute("SELECT COUNT(DISTINCT task_id) FROM tasks WHERE "
                f"(status='{status}' COLLATE NOCASE)")
    rows = cur.fetchone()
    expected_total_items = rows[0]
    result = tasks.get_task_status(status=status)

    assert result.total_affected_items == expected_total_items


@patch('wazuh.core.utils.WazuhDBConnection', return_value=InitWDBSocketMock(sql_schema_file='schema_tasks_test.sql'))
@patch.object(WazuhDBQueryTasks, '_final_query', fake_final_query)
@pytest.mark.parametrize("node", [
    ('worker2'),
    ('master-node'),
    ('worker1')
])
def test_get_task_status_node(mock_task_db, node):
    """Check system's tasks (node)

    Parameters
    ----------
    node : str
        Search for the tasks of a specific node
    """
    cur = get_fake_database_data('schema_tasks_test.sql').cursor()
    cur.execute("SELECT COUNT(DISTINCT task_id) FROM tasks WHERE "
                f"(node='{node}' COLLATE NOCASE)")
    rows = cur.fetchone()
    expected_total_items = rows[0]
    result = tasks.get_task_status(node=node)

    assert result.total_affected_items == expected_total_items


@patch('wazuh.core.utils.WazuhDBConnection', return_value=InitWDBSocketMock(sql_schema_file='schema_tasks_test.sql'))
@patch.object(WazuhDBQueryTasks, '_final_query', fake_final_query)
@pytest.mark.parametrize("command", [
    ('upgrade'),
    ('invalid')
])
def test_get_task_status_command(mock_task_db, command):
    """Check system's tasks (command)

    Parameters
    ----------
    command : list
        Search for tasks with a specific command
    """
    cur = get_fake_database_data('schema_tasks_test.sql').cursor()
    cur.execute("SELECT COUNT(DISTINCT task_id) FROM tasks WHERE "
                f"(command='{command}' COLLATE NOCASE)")
    rows = cur.fetchone()
    expected_total_items = rows[0]
    result = tasks.get_task_status(command=command)

    assert result.total_affected_items == expected_total_items


@patch('wazuh.core.utils.WazuhDBConnection', return_value=InitWDBSocketMock(sql_schema_file='schema_tasks_test.sql'))
@patch.object(WazuhDBQueryTasks, '_final_query', fake_final_query)
@pytest.mark.parametrize("module", [
    ('upgrade_module'),
    ('invalid')
])
def test_get_task_status_module(mock_task_db, module):
    """Check system's tasks (module)

    Parameters
    ----------
    module : str
        Search tasks with a specific module
    """
    cur = get_fake_database_data('schema_tasks_test.sql').cursor()
    cur.execute("SELECT COUNT(DISTINCT task_id) FROM tasks WHERE "
                f"(module='{module}' COLLATE NOCASE)")
    rows = cur.fetchone()
    expected_total_items = rows[0]
    result = tasks.get_task_status(module=module)

    assert result.total_affected_items == expected_total_items


@patch('wazuh.core.utils.WazuhDBConnection', return_value=InitWDBSocketMock(sql_schema_file='schema_tasks_test.sql'))
@patch.object(WazuhDBQueryTasks, '_final_query', fake_final_query)
def test_get_task_status_sort(mock_wdb):
    """Test sort filter."""
    result_asc = tasks.get_task_status(sort={"fields": ["task_id"], "order": "asc"}, limit=10)
    assert result_asc.affected_items[0]['task_id'] < result_asc.affected_items[1]['task_id']

    result_desc = tasks.get_task_status(sort={"fields": ["task_id"], "order": "desc"}, limit=10)
    assert result_desc.affected_items[0]['task_id'] > result_desc.affected_items[1]['task_id']

    assert result_asc.affected_items[0]['task_id'] < result_desc.affected_items[0]['task_id']


@pytest.mark.parametrize('offset, limit', [
    (0, 0),
    (0, 1),
    (1, 3),
    (9, 0),
    (15, 9)
])
@patch('wazuh.core.utils.WazuhDBConnection', return_value=InitWDBSocketMock(sql_schema_file='schema_tasks_test.sql'))
@patch.object(WazuhDBQueryTasks, '_final_query', fake_final_query)
def test_get_task_status_offset_limit(mock_wdb, offset, limit):
    """Test if data are retrieved properly from Tasks database."""
    # Check error when limit = 0
    try:
        result = tasks.get_task_status(offset=offset, limit=limit)
    except WazuhError as e:
        if e.code == 1406:
            return
        else:
            raise e

    # check result length
    try:
        assert len(result.affected_items) == limit
    except AssertionError:
        assert len(result.affected_items) <= 6

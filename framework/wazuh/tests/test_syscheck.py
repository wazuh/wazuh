#!/usr/bin/env python
# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys
from sqlite3 import connect
from unittest.mock import patch, MagicMock

import pytest

with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators

        del sys.modules['wazuh.rbac.orm']

        from wazuh.tests.util import RBAC_bypasser

        wazuh.rbac.decorators.expose_resources = RBAC_bypasser
        from wazuh.syscheck import run
        from wazuh.syscheck import AffectedItemsWazuhResult

callable_list = list()
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
test_agent_data_path = os.path.join(test_data_path, 'agent')


# Retrieve used parameters in mocked method
def set_callable_list(*params, **kwargs):
    callable_list.append((params, kwargs))


# Get a fake database
def get_fake_syscheck_db(sql_file):
    def create_memory_db(*args, **kwargs):
        syscheck_db = connect(':memory:')
        cur = syscheck_db.cursor()
        with open(os.path.join(test_data_path, sql_file)) as f:
            cur.executescript(f.read())
        return syscheck_db

    return create_memory_db


test_result = [
    {'affected_items': ['001', '002'], 'total_affected_items': 2, 'failed_items': {}, 'total_failed_items': 0},
    {'affected_items': ['003', '008'], 'total_affected_items': 2, 'failed_items': {'001'}, 'total_failed_items': 1},
    {'affected_items': ['001'], 'total_affected_items': 1, 'failed_items': {'002', '003'},
     'total_failed_items': 2},
    # This result is used for exceptions
    {'affected_items': [], 'total_affected_items': 0, 'failed_items': {'001'}, 'total_failed_items': 1},
]


@pytest.mark.parametrize('agent_list, failed_items, status_list, expected_result', [
    (['002', '001'], [{'items': []}], ['active', 'active'], test_result[0]),
    (['003', '001', '008'], [{'items': [{'id': '001', 'status': ['disconnected']}]}],
     ['active', 'disconnected', 'active'], test_result[1]),
    (['001', '002', '003'], [{'items': [{'id': '002', 'status': ['disconnected']},
                                        {'id': '003', 'status': ['disconnected']}]}],
     ['active', 'disconnected', 'disconnected'], test_result[2]),
])
@patch('wazuh.core.common.CLIENT_KEYS', new=os.path.join(test_agent_data_path, 'client.keys'))
@patch('wazuh.syscheck.WazuhDBQueryAgents.__exit__')
@patch('wazuh.syscheck.WazuhDBQueryAgents.__init__', return_value=None)
@patch('wazuh.syscheck.WazuhQueue._connect')
@patch('wazuh.syscheck.WazuhQueue.send_msg_to_agent', side_effect=set_callable_list)
@patch('wazuh.syscheck.WazuhQueue.close')
def test_syscheck_run(close_mock, send_mock, connect_mock, agent_init_mock, agent_exit_mock,
                      agent_list, failed_items, status_list, expected_result):
    """Test function `run` from syscheck module.

    Parameters
    ----------
    agent_list : list
        List of agent IDs.
    agent_list : list
        List of failed items.
    status_list : list
        List of agent statuses.
    expected_result : list
        List of dicts with expected results for every test.
    """
    with patch('wazuh.syscheck.WazuhDBQueryAgents.run', return_value=failed_items[0]):
        result = run(agent_list=agent_list)
        for args, kwargs in callable_list:
            assert (isinstance(a, str) for a in args)
            assert (isinstance(k, str) for k in kwargs)
        assert isinstance(result, AffectedItemsWazuhResult)
        assert result.affected_items == expected_result['affected_items']
        assert result.total_affected_items == expected_result['total_affected_items']
        if result.failed_items:
            assert next(iter(result.failed_items.values())) == expected_result['failed_items']
        else:
            assert result.failed_items == expected_result['failed_items']
        assert result.total_failed_items == expected_result['total_failed_items']

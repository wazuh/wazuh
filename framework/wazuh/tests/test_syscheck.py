#!/usr/bin/env python
# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys
from sqlite3 import connect
from unittest.mock import patch, MagicMock

import pytest

from wazuh.tests.util import InitWDBSocketMock

with patch('wazuh.core.common.ossec_uid'):
    with patch('wazuh.core.common.ossec_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators

        del sys.modules['wazuh.rbac.orm']

        from wazuh.tests.util import RBAC_bypasser
        wazuh.rbac.decorators.expose_resources = RBAC_bypasser
        from wazuh.syscheck import run, clear, last_scan, files
        from wazuh.syscheck import AffectedItemsWazuhResult
        from wazuh import WazuhError, WazuhInternalError
        from wazuh.core import common

callable_list = list()
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')


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


@pytest.mark.parametrize('agent_list, status_list, expected_result', [
    (['002', '001'], [{'status': status} for status in ['active', 'active']], test_result[0]),
    (['003', '001', '008'], [{'status': status} for status in ['active', 'disconnected', 'active']], test_result[1]),
    (['001', '002', '003'], [{'status': status} for status in ['active', 'disconnected', 'disconnected']],
     test_result[2]),
])
@patch('wazuh.syscheck.OssecQueue._connect')
@patch('wazuh.syscheck.OssecQueue.send_msg_to_agent', side_effect=set_callable_list)
@patch('wazuh.syscheck.OssecQueue.close')
def test_syscheck_run(close_mock, send_mock, connect_mock, agent_list, status_list, expected_result):
    """Test function `run` from syscheck module.

    Parameters
    ----------
    agent_list : list
        List of agent IDs.
    status_list : list
        List of agent statuses.
    expected_result : list
        List of dicts with expected results for every test.
    """
    with patch('wazuh.syscheck.Agent.get_basic_information', side_effect=status_list):
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


@pytest.mark.parametrize('agent_list, status_list, expected_result', [
    (['001'], {'status': 'active'}, test_result[3])
])
@patch('wazuh.syscheck.OssecQueue', side_effect=WazuhError(1000))
def test_syscheck_run_exception(ossec_queue_mock, agent_list, status_list, expected_result):
    """Test function `run` from syscheck module.

    It will force an exception.

    Parameters
    ----------
    agent_list : list
        List of agent IDs.
    status_list : list
        List of agent statuses.
    expected_result : list
        List of dicts with expected results for every test.
    """
    with patch('wazuh.syscheck.Agent.get_basic_information', return_value=status_list):
        result = run(agent_list=agent_list)
        assert isinstance(result, AffectedItemsWazuhResult)
        assert result.affected_items == expected_result['affected_items']
        assert result.total_affected_items == expected_result['total_affected_items']
        if result.failed_items:
            assert next(iter(result.failed_items.values())) == expected_result['failed_items']
        assert result.total_failed_items == expected_result['total_failed_items']


@pytest.mark.parametrize('agent_list, expected_result, agent_info_list', [
    (['001', '002'], test_result[0], ['001', '002']),
    (['003', '001', '008'], test_result[1], ['003', '008'])
])
@patch('wazuh.core.wdb.WazuhDBConnection.__init__', return_value=None)
@patch('wazuh.core.wdb.WazuhDBConnection.execute', return_value=None)
def test_syscheck_clear(wdb_execute_mock, wdb_init_mock, agent_list, expected_result, agent_info_list):
    """Test function `clear` from syscheck module.

    Parameters
    ----------
    agent_list : list
        List of agent IDs.
    expected_result : list
        List of dicts with expected results for every test.
    agent_info_list : list
        List of agent IDs that `syscheck.get_agents_info` will return when mocked.
    """
    with patch('wazuh.syscheck.get_agents_info', return_value=agent_info_list):
        result = clear(agent_list=agent_list)
        assert isinstance(result, AffectedItemsWazuhResult)
        assert result.affected_items == expected_result['affected_items']
        assert result.total_affected_items == expected_result['total_affected_items']
        if result.failed_items:
            assert next(iter(result.failed_items.values())) == expected_result['failed_items']
        else:
            assert result.failed_items == expected_result['failed_items']
        assert result.total_failed_items == expected_result['total_failed_items']


@pytest.mark.parametrize('agent_list, expected_result, agent_info_list', [
    (['001'], test_result[3], ['001']),
])
@patch('wazuh.core.wdb.WazuhDBConnection.__init__', return_value=None)
@patch('wazuh.core.wdb.WazuhDBConnection.execute', side_effect=WazuhError(1000))
def test_syscheck_clear_exception(execute_mock, wdb_init_mock, agent_list, expected_result, agent_info_list):
    """Test function `clear` from syscheck module.

    It will force an exception.

    Parameters
    ----------
    agent_list : list
        List of agent IDs.
    expected_result : list
        List of dicts with expected results for every test.
    agent_info_list : list
        List of agent IDs that `syscheck.get_agents_info` will return when mocked.
    """
    with patch('wazuh.syscheck.get_agents_info', return_value=agent_info_list):
        result = clear(agent_list=agent_list)
        assert isinstance(result, AffectedItemsWazuhResult)
        assert result.affected_items == expected_result['affected_items']
        assert result.total_affected_items == expected_result['total_affected_items']
        if result.failed_items:
            assert next(iter(result.failed_items.values())) == expected_result['failed_items']
        assert result.total_failed_items == expected_result['total_failed_items']


@pytest.mark.parametrize('agent_id, wazuh_version', [
    (['001'], {'version': 'Wazuh v3.6.0'}),
    (['002'], {'version': 'Wazuh v3.8.3'}),
    (['005'], {'version': 'Wazuh v3.5.3'}),
    (['006'], {'version': 'Wazuh v3.9.4'}),
    (['004'], {}),
])
@patch('sqlite3.connect', side_effect=get_fake_syscheck_db('schema_syscheck_test.sql'))
@patch("wazuh.core.database.isfile", return_value=True)
@patch("wazuh.syscheck.WazuhDBConnection.execute", return_value=[{'end': '', 'start': ''}])
@patch('socket.socket.connect')
def test_syscheck_last_scan(socket_mock, wdb_conn_mock, is_file_mock,  db_mock, agent_id, wazuh_version):
    """Test function `last_scan` from syscheck module.

    Parameters
    ----------
    agent_id : list
        Agent ID.
    wazuh_version : dict
        Dict with the Wazuh version to be applied.
    """
    with patch('wazuh.syscheck.Agent.get_basic_information', return_value=wazuh_version):
        with patch('wazuh.syscheck.glob',
                   return_value=[os.path.join(common.database_path_agents, '{}.db'.format(agent_id[0]))]):
            result = last_scan(agent_id)
            assert isinstance(result, AffectedItemsWazuhResult)
            assert isinstance(result.affected_items, list)
            assert result.total_affected_items == 1


@pytest.mark.parametrize('version', [
    {'version': 'Wazuh v3.6.0'}
])
@patch('wazuh.syscheck.glob', return_value=None)
def test_syscheck_last_scan_internal_error(glob_mock, version):
    """Test function `last_scan` from syscheck module.

    It will expect a WazuhInternalError.

    Parameters
    ----------
    version : dict
        Dict with the Wazuh version to be applied.

    Raises
    ------
    WazuhInternalError
        Raised when there is not a valid database file.
    """
    with patch('wazuh.syscheck.Agent.get_basic_information', return_value=version):
        with pytest.raises(WazuhInternalError):
            last_scan(['001'])


@pytest.mark.parametrize('agent_id, select, filters, distinct', [
    (['001'], None, None, None),
    (['001'], ['file', 'size', 'mtime'], None, False),
    (['001'], None, {'inode': '15470536'}, True),
    (['001'], ['file', 'size'], {'hash': '15470536'}, False),
    (['001'], None, {'date': '2019-05-21 12:10:20'}, True)
])
@patch('socket.socket.connect')
@patch('wazuh.core.common.wdb_path', new=test_data_path)
def test_syscheck_files(socket_mock, agent_id, select, filters, distinct):
    """Test function `files` from syscheck module.

    Parameters
    ----------
    agent_id : list
        Agent ID.
    select :
        List of parameters to show from the query.
    filters : dict
        Dict to filter out the result.
    distinct : bool
        True if all response items must be unique
    """
    select_list = ['date', 'mtime', 'file', 'size', 'perm', 'uname', 'gname', 'md5', 'sha1', 'sha256', 'inode', 'gid', 'uid', 'type', 'changes', 'attributes']
    with patch('wazuh.core.utils.WazuhDBConnection') as mock_wdb:
        mock_wdb.return_value = InitWDBSocketMock(sql_schema_file='schema_syscheck_test.sql')
        result = files(agent_id, select=select, filters=filters)
        assert isinstance(result, AffectedItemsWazuhResult)
        assert isinstance(result.affected_items, list)
        select = select if select else select_list
        for item in result.affected_items:
            assert len(select) == len(item.keys())
            assert (param in select for param in item.keys())
        assert not any(result.affected_items.count(item) > 1 for item in result.affected_items) if distinct else True
        if filters:
            for key, value in filters.items():
                assert (item[key] == value for item in result.affected_items)

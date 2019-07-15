#!/usr/bin/env python
# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from sqlite3 import connect
from unittest.mock import patch, mock_open
import os
import pytest
from wazuh import common
from os.path import join
from wazuh import exception

from wazuh.syscheck import last_scan, run, clear, files

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')


def get_fake_syscheck_db(sql_file):

    def create_memory_db(*args, **kwargs):
        syscheck_db = connect(':memory:')
        cur = syscheck_db.cursor()
        with open(os.path.join(test_data_path, sql_file)) as f:
            cur.executescript(f.read())

        return syscheck_db

    return create_memory_db


@pytest.mark.parametrize('agent_id, version', [
    ('001', {'version': 'Wazuh v3.5.0'}),
    ('002', {'version': 'Wazuh v3.6.2'}),
    ('003', {'version': 'Wazuh v3.7.1'}),
    ('004', {'version': 'Wazuh v3.8.2'}),
    ('005', {'version': 'Wazuh v3.9.1'}),
    ('006', {'version': 'Wazuh v3.10.0'})
])
@patch('sqlite3.connect', side_effect=get_fake_syscheck_db('schema_syscheck_test.sql'))
@patch("wazuh.database.isfile", return_value=True)
@patch("wazuh.agent.Agent._load_info_from_agent_db", return_value=[{ 'end_scan': '', 'start_scan': ''}])
def test_last_scan(wazuh_conn_mock, connec_mock, db_mock, version, agent_id):
    """
    Test last_scan function
    """
    with patch('wazuh.syscheck.Agent.get_basic_information', return_value=version):
        with patch("wazuh.syscheck.glob", return_value=[join(common.database_path_agents, agent_id)+".db"]):
            result = last_scan(agent_id)
        
            assert isinstance(result, dict)
            assert set(result.keys()) == {'start', 'end'}


@patch("wazuh.agent.Agent.get_basic_information", side_effect=KeyError)
def test_failed_last_scan_key_error_agent_version(info_mock):
    """
    Test last_scan function when a ErrorKey appears
    """
    result = last_scan('001')

    assert isinstance(result, dict)
    assert set(result.keys()) == {'start', 'end'}


@patch("wazuh.syscheck.Agent.get_basic_information", return_value={'version': 'Wazuh v3.5.0'})
@patch("wazuh.syscheck.glob", return_value=None)
def test_failed_last_scan_not_agent_db(glob_mock, info_mock):
    """
    Test failed last_scan function when agent don't exist
    """
    with pytest.raises(exception.WazuhException, match=".* 1600 .*"):
        last_scan('001')


@pytest.mark.parametrize('agent_id, all_agents', [
    ('000', False),
    (None, True),
    ('001', False)
])
@patch("builtins.open")
@patch("wazuh.syscheck.OssecQueue")
@patch("wazuh.agent.Agent.get_basic_information", return_value={'status': 'active'})
def test_run(mock_info, mock_ossec_queue, mock_open, agent_id, all_agents):
    """
    Test run function
    """
    run(agent_id, all_agents)


@patch("builtins.open", side_effect=Exception)
def test_failed_run_exception_open(mock_open):
    """
    Test failed run function when an Exception appears when opening a file
    """
    with pytest.raises(exception.WazuhException, match=".* 1601 .*"):
        run('000')


@patch("wazuh.syscheck.Agent.get_basic_information")
def test_failed_run_agent_not_status(mock_info):
    """
    Test failed run function when an agent have status diferent to Active
    """
    with pytest.raises(exception.WazuhException, match=".* 1604 .*"):
        run('001')


@pytest.mark.parametrize('agent_id, all_agents', [
    ('001', False),
    (None, True)
])
@patch("wazuh.syscheck.WazuhDBConnection")
@patch("wazuh.syscheck.Agent.get_basic_information")
@patch("wazuh.syscheck.Agent.get_agents_overview", return_value={'items':[{'id':'001'},{'id':'002'},{'id':'003'}]})
def test_clear(mock_all_agents, mock_info, mock_wbd_conn, agent_id, all_agents):
    """
    Test clear function
    """
    result = clear(agent_id, all_agents)

    assert isinstance(result, str)


@pytest.mark.parametrize('select, filters', [
    (None, {}),
    ({'fields':['file']}, {}),
    (None, {'hash':'md5'})
])
def test_files(select, filters):
    """
    Test files function
    """
    with patch("wazuh.syscheck.Agent._load_info_from_agent_db", return_value=[[{'date':0, 'mtime':0}],1]):
        result = files(select=select, filters=filters)

        assert isinstance(result, dict)
        assert set(result.keys()) == {'totalItems', 'items'}


def test_failed_files():
    """
    Test failed files function when select field isn't valid
    """
    with pytest.raises(exception.WazuhException, match=".* 1724 .*"):
        files(select={'fields':['bad_select']})
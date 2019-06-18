#!/usr/bin/env python
# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2


import os
from sqlite3 import connect
from unittest.mock import patch

import pytest

from wazuh.exception import WazuhException
from wazuh.syscheck import run, clear, last_scan, files


test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')


def get_random_status():
    return {'status': 'random'}


@pytest.mark.parametrize('agent_id', [
    '000',
    '001',
    '002',
    '003'
])
def test_syscheck_run(agent_id):
    result = run(agent_id=agent_id)
    assert isinstance(result, str)


def test_syscheck_run_all():
    result = run(all_agents=True)
    assert isinstance(result, str)


@patch('wazuh.syscheck.Agent.get_basic_information', side_effect=get_random_status)
def test_syscheck_run_status(mocked_status):
    with pytest.raises(WazuhException, match='.* 1604 .*'):
        run(agent_id='001')


@pytest.mark.parametrize('agent_id', [
    '000',
    '001',
    '002',
    '003'
])
def test_syscheck_clear(agent_id):
    result = clear(agent_id=agent_id)
    assert isinstance(result, str)


def test_syscheck_clear_all():
    result = clear(all_agents=True)
    assert isinstance(result, str)


@pytest.mark.parametrize('agent_id', [
    '000',
    '001',
    '002',
    '003'
])
def test_syscheck_last_scan(agent_id):
    result = last_scan(agent_id)
    assert isinstance(result, dict)


@pytest.mark.parametrize('agent_id', [
    '000',
    '001',
    '002',
    '003'
])
def test_syscheck_files(agent_id):
    result = files(agent_id=agent_id)
    assert isinstance(result, dict)


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
def test_last_scan(db_mock, version, agent_id):
    """
    Test last_scan function
    """
    with patch('wazuh.syscheck.Agent.get_basic_information', return_value=version):
        result = last_scan(agent_id)
        
        assert isinstance(result, dict)
        assert set(result.keys()) == {'start', 'end'}

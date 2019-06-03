#!/usr/bin/env python
# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from sqlite3 import connect
from unittest.mock import patch, mock_open
import os
import pytest

from wazuh.syscheck import last_scan

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
def test_last_scan(db_mock, version, agent_id):
    """
    Test last_scan function
    """
    with patch('wazuh.syscheck.Agent.get_basic_information', return_value=version):
        result = last_scan(agent_id)
        
        assert isinstance(result, dict)
        assert set(result.keys()) == {'start', 'end'}

# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import pytest
import sqlite3
import os
from unittest.mock import patch

with patch('wazuh.common.ossec_uid'):
    with patch('wazuh.common.ossec_gid'):
        from wazuh import rootcheck

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')


@pytest.fixture(scope='module')
def test_data():
    rootcheck_db = sqlite3.connect(':memory:')
    cur = rootcheck_db.cursor()
    with open(os.path.join(test_data_path, 'schema_rootcheck_test.sql')) as f:
        cur.executescript(f.read())

    return rootcheck_db


@patch('wazuh.rootcheck.Agent')
@patch('wazuh.rootcheck.glob', return_value=['/var/ossec/var/db/agents/001.db'])
@patch('wazuh.utils.glob.glob', return_value=['/var/ossec/var/db/agents/001.db'])
@patch('wazuh.database.isfile', return_value=True)
def test_print_db(isfile_mock, r_glob_mock, u_glob_mock, agent_mock, test_data):
    """
    Tests print_db function with default parameters
    """
    with patch('sqlite3.connect') as mock_db:
        mock_db.return_value = test_data

        rootcheck_data = rootcheck.print_db('001')

        # check number of returned items
        assert rootcheck_data['totalItems'] == 5

        for r in rootcheck_data['items']:
            # check no null values were returned
            assert all(map(lambda x: x is not None, r.values()))
            # check expected keys are returned
            assert rootcheck.fields.keys() - r.keys() == set()


@pytest.mark.parametrize('select', [
    {'fields': ['status', 'event']},
    {'fields': ['pci', 'cis']},
    {'fields': ['pci', 'status', 'event']}
])
@patch('wazuh.rootcheck.Agent')
@patch('wazuh.rootcheck.glob', return_value=['/var/ossec/var/db/agents/001.db'])
@patch('wazuh.utils.glob.glob', return_value=['/var/ossec/var/db/agents/001.db'])
@patch('wazuh.database.isfile', return_value=True)
def test_print_db_select(isfile_mock, r_glob_mock, u_glob_mock, agent_mock, select, test_data):
    """
    Tests print_db function with select parameter
    """
    with patch('sqlite3.connect') as mock_db:
        mock_db.return_value = test_data

        rootcheck_data = rootcheck.print_db('001', select=select)
        for r in rootcheck_data['items']:
            # check expected keys are returned
            assert set(select['fields']) - r.keys() == set()


@pytest.mark.parametrize('sort, first_event', [
    ({'fields': ['oldDay'], 'order': 'asc'}, "System Audit: CIS - Debian Linux - 2.3 - SSH Configuration - Root login "
                                             "allowed {CIS: 2.3 Debian Linux} {PCI_DSS: 4.1}. File: "
                                             "/etc/ssh/sshd_config. Reference: "
                                             "https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1"
                                             ".0.pdf .") ,
    ({'fields': ['oldDay'], 'order': 'desc'}, "System Audit: CIS - Testing against the CIS Debian Linux Benchmark "
                                              "v1.0. File: /etc/debian_version. Reference: "
                                              "https://benchmarks.cisecurity.org/tools2/linux/CIS_Debian_Benchmark_v1"
                                              ".0.pdf .")
])
@patch('wazuh.rootcheck.Agent')
@patch('wazuh.rootcheck.glob', return_value=['/var/ossec/var/db/agents/001.db'])
@patch('wazuh.utils.glob.glob', return_value=['/var/ossec/var/db/agents/001.db'])
@patch('wazuh.database.isfile', return_value=True)
def test_print_db_sort(isfile_mock, r_glob_mock, u_glob_mock, agent_mock, sort, first_event, test_data):
    """
    Tests print_db function with sort parameter
    """
    with patch('sqlite3.connect') as mock_db:
        mock_db.return_value = test_data

        rootcheck_data = rootcheck.print_db('001', sort=sort)
        assert rootcheck_data['items'][0]['event'] == first_event


@pytest.mark.parametrize("search, totalItems", [
    ({'value': '1.4', 'negation': 0}, 3),
    ({'value': '1.4', 'negation': 1}, 2),
    ({'value': '/opt', 'negation': 0}, 1),
    ({'value': '/opt', 'negation': 1}, 4),
])
@patch('wazuh.rootcheck.Agent')
@patch('wazuh.rootcheck.glob', return_value=['/var/ossec/var/db/agents/001.db'])
@patch('wazuh.utils.glob.glob', return_value=['/var/ossec/var/db/agents/001.db'])
@patch('wazuh.database.isfile', return_value=True)
def test_print_db_search(isfile_mock, r_glob_mock, u_glob_mock, agent_mock, test_data, search, totalItems):
    """
    Tests print_db function with search parameter
    """
    with patch('sqlite3.connect') as mock_db:
        mock_db.return_value = test_data

        rootcheck_data = rootcheck.print_db('001', search=search)
        assert rootcheck_data['totalItems'] == totalItems


@pytest.mark.parametrize("query, totalItems", [
    ('pci=1.5;event~partition', 3),
    ('pci=1.5,event~partition', 4),
    ('oldDay<2h', 1)
])
@patch('wazuh.rootcheck.Agent')
@patch('wazuh.rootcheck.glob', return_value=['/var/ossec/var/db/agents/001.db'])
@patch('wazuh.utils.glob.glob', return_value=['/var/ossec/var/db/agents/001.db'])
@patch('wazuh.database.isfile', return_value=True)
def test_print_db_search(isfile_mock, r_glob_mock, u_glob_mock, agent_mock, test_data, query, totalItems):
    """
    Tests print_db function with search parameter
    """
    with patch('sqlite3.connect') as mock_db:
        mock_db.return_value = test_data

        rootcheck_data = rootcheck.print_db('001', q=query)
        assert rootcheck_data['totalItems'] == totalItems

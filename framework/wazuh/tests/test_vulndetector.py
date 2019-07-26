#!/usr/bin/env python

# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import pytest
import re
import sys
from sqlite3 import connect
from unittest.mock import patch

import wazuh.vulndetector as vulndetector
from wazuh.exception import WazuhException

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..'))
test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')

# get the name of vulnerability_info table fields
vuln_info_fields = vulndetector.fields_vuln_info.keys()
# get the name of vulnerability table fields
vuln_fields = vulndetector.fields_vuln.keys()
# regex for extract fields from query
re_q_elements = re.compile(r'([\w\-.]+)(=|!=|<|>|~)([\w\-.]+)')


def get_fake_db(sql_file):

    def create_memory_db(*args, **kwargs):
        fake_db = connect(':memory:')
        cur = fake_db.cursor()
        with open(os.path.join(test_data_path, sql_file)) as f:
            cur.executescript(f.read())

        return fake_db

    return create_memory_db


def get_num_elements(mock_db, table_name):
    cur = mock_db().cursor()
    cur.execute(f'SELECT COUNT(*) FROM {table_name};')
    result = cur.fetchone()[0]
    return result


@patch('wazuh.database.isfile')
@patch('glob.glob')
@patch('sqlite3.connect', side_effect=get_fake_db('schema_vulndetector_test.sql'))
def test_get_vuln_info(mock_db, mock_glob, mock_isfile):
    """
    Checks data are properly loaded from database
    """
    result = vulndetector.get_vulnerabilities_info()
    total_items = get_num_elements(mock_db, 'VULNERABILITIES_INFO')
    assert(isinstance(result, dict))
    for item in result['items']:
        assert(item.keys() == vuln_info_fields)
    assert(len(result['items']) == total_items)
    assert(result['totalItems'] == total_items)


@pytest.mark.parametrize('limit', [0, 1, 2, 3, 4, 5, 6, 50, 60, 1001, 20000])
@patch('wazuh.database.isfile')
@patch('glob.glob')
@patch('sqlite3.connect', side_effect=get_fake_db('schema_vulndetector_test.sql'))
def test_get_vuln_info_limit(mock_db, mock_glob, mock_isfile, limit):
    """
    Checks limit filter
    """
    try:
        result = vulndetector.get_vulnerabilities_info(limit=limit)
        total_items = get_num_elements(mock_db, 'VULNERABILITIES_INFO')
        assert(isinstance(result, dict))
        for item in result['items']:
            assert(item.keys() == vuln_info_fields)
        if total_items >= limit:
            assert(len(result['items']) == limit)
        else:
            assert(len(result['items']) < limit)
        assert(result['totalItems'] == total_items)
    except WazuhException as e:
        if limit == 0:
            assert(e.code == 1406)
        else:
            assert(e.code == 1405)


@pytest.mark.parametrize('offset', [1, 2, 3, 4])
@patch('wazuh.database.isfile')
@patch('glob.glob')
@patch('sqlite3.connect', side_effect=get_fake_db('schema_vulndetector_test.sql'))
def test_get_vuln_info_offset(mock_db, mock_glob, mock_isfile, offset):
    """
    Checks offset filter
    """
    result = vulndetector.get_vulnerabilities_info(offset=offset)
    total_items = get_num_elements(mock_db, 'VULNERABILITIES_INFO')
    assert(isinstance(result, dict))
    for item in result['items']:
        assert(item.keys() == vuln_info_fields)
    assert(len(result['items']) == (total_items - offset))
    assert(result['totalItems'] == total_items)


@pytest.mark.parametrize('select', [
    {'fields': ['id', 'title']},
    {'fields': ['id', 'title', 'cvss']},
    {'fields': ['id', 'reference', 'os', 'bugzilla_reference']},
    {'fields': ['title', 'reference', 'cwe', 'advisories']},
    {'fields': ['title', 'new_field', 'cwe', 'advisories']}
])
@patch('wazuh.database.isfile')
@patch('glob.glob')
@patch('sqlite3.connect', side_effect=get_fake_db('schema_vulndetector_test.sql'))
def test_get_vuln_info_select(mock_db, mock_glob, mock_isfile, select):
    """
    Checks select filter
    """
    try:
        result = vulndetector.get_vulnerabilities_info(select=select)
        assert(isinstance(result, dict))
        for item in result['items']:
            assert(set(item.keys()) == set(select['fields']))
    except WazuhException as e:
        assert(e.code == 1724)


@pytest.mark.parametrize('search', [
    {'value': 'Medium', 'negation': False},
    {'value': 'Medium', 'negation': True},
    {'value': 'moderate', 'negation': False},
    {'value': 'redhat', 'negation': False},
    {'value': 'CVE-2019', 'negation': False},
    {'value': 'os/2', 'negation': False},
    {'value': 'beos', 'negation': False},
])
@patch('wazuh.database.isfile')
@patch('glob.glob')
@patch('sqlite3.connect', side_effect=get_fake_db('schema_vulndetector_test.sql'))
def test_get_vuln_info_search(mock_db, mock_glob, mock_isfile, search):
    """
    Checks search filter
    """
    result = vulndetector.get_vulnerabilities_info(search=search)
    assert(isinstance(result, dict))
    if not result['items']:
        assert(result['totalItems'] == 0)
    else:
        for item in result['items']:
            assert(item.keys() == vuln_info_fields)


@pytest.mark.parametrize('query', [
    'severity=Low',
    'severity!=Low',
    'id=CVE-2019-9956',
    'id!=CVE-2019-9956',
    'os~red',
    'os~bion',
    'os<=bion'
])
@patch('wazuh.database.isfile')
@patch('glob.glob')
@patch('sqlite3.connect', side_effect=get_fake_db('schema_vulndetector_test.sql'))
def test_get_vuln_info_query(mock_db, mock_glob, mock_isfile, query):
    """
    Checks query filter
    """
    try:
        result = vulndetector.get_vulnerabilities_info(q=query)
        assert(isinstance(result, dict))
        if not result['items']:
            assert(result['totalItems'] == 0)
        else:
            field_name, op, value = re.match(re_q_elements, query).groups()
            for item in result['items']:
                assert(item.keys() == vuln_info_fields)
                if op == '=':
                    assert(item[field_name].lower() == value.lower())
                elif op == '!=':
                    assert(item[field_name].lower() != value.lower())
                elif op == '<':
                    assert(item[field_name].lower() < value.lower())
                elif op == '>':
                    assert(item[field_name].lower() > value.lower())
                elif op == '~':
                    assert(item[field_name].lower() >= value.lower())
                # raise exception otherwise
    except WazuhException as e:
        assert(e.code == 1409)


@patch('wazuh.database.isfile')
@patch('glob.glob')
@patch('sqlite3.connect', side_effect=get_fake_db('schema_vulndetector_test.sql'))
def test_get_num_vuln_by_os(mock_db, mock_glob, mock_isfile):
    """
    Checks get_num_vulnerabilities function
    """
    result = vulndetector.get_num_vulnerabilities()
    assert(isinstance(result, dict))
    if not result['items']:
        assert(result['totalItems'] == 0)
    else:
        total_count = 0
        for item in result['items']:
            assert(set(item.keys()) == {'os', 'count'})
            assert(isinstance(item['count'], int))
            total_count += item['count']
        assert(total_count == result['totalItems'])


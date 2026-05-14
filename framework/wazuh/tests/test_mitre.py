#!/usr/bin/env python

# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys
from unittest.mock import patch, MagicMock

import pytest

with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators

        from wazuh.tests.util import get_fake_database_data, RBAC_bypasser, InitWDBSocketMock

        wazuh.rbac.decorators.expose_resources = RBAC_bypasser
        from wazuh import mitre
        from wazuh.core import mitre as core_mitre
        from wazuh.core.common import DECIMALS_DATE_FORMAT
        from wazuh.core.utils import get_utc_strptime

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')


# Fixtures
@pytest.fixture(scope='module')
def mitre_db():
    """Get fake MITRE database cursor."""
    core_mitre.get_mitre_items.cache_clear()
    return get_fake_database_data('schema_mitre_test.sql').cursor()


# Functions
class CursorByName:
    """Class to return query result including the column name as key."""

    def __init__(self, cursor):
        self._cursor = cursor

    def __iter__(self):
        return self

    def __next__(self):
        row = self._cursor.__next__()
        return {description[0]: row[col] for col, description in enumerate(self._cursor.description)}


def mitre_query(cursor, query):
    """Return list of dictionaries with the query results."""
    cursor.execute(query)
    return [row for row in CursorByName(cursor)]


def sort_entries(entries, sort_key='id'):
    """Sort a list of dictionaries by one of their keys."""
    return sorted(entries, key=lambda k: k[sort_key])


def check_datetime(element, key):
    if key in {'created_time', 'modified_time'}:
        element[key] = get_utc_strptime(element[key], '%Y-%m-%d %H:%M:%S.%f').strftime(DECIMALS_DATE_FORMAT)

    return element[key]


# Tests

@patch('wazuh.core.utils.WazuhDBConnection', return_value=InitWDBSocketMock(sql_schema_file='schema_mitre_test.sql'))
def test_mitre_metadata(mock_mitre_dbmitre, mitre_db):
    """Check MITRE metadata."""
    result = mitre.mitre_metadata()
    rows = mitre_query(mitre_db, 'SELECT * FROM metadata')

    assert result.affected_items
    assert all(item[key] == row[key] for item, row in zip(result.affected_items, rows) for key in row)


@patch('wazuh.core.utils.WazuhDBConnection', return_value=InitWDBSocketMock(sql_schema_file='schema_mitre_test.sql'))
def test_mitre_mitigations(mock_mitre_db, mitre_db):
    """Check MITRE mitigations."""
    result = mitre.mitre_mitigations()
    rows = mitre_query(mitre_db, "SELECT * FROM mitigation")

    assert all(item[key] == check_datetime(row, key) for item, row in zip(sort_entries(result.affected_items),
                                                                          sort_entries(rows)) for key in row)


@patch('wazuh.core.utils.WazuhDBConnection', return_value=InitWDBSocketMock(sql_schema_file='schema_mitre_test.sql'))
def test_mitre_references(mock_mitre_dbmitre, mitre_db):
    """Check MITRE metadata."""
    result = mitre.mitre_references(limit=None)
    rows = mitre_query(mitre_db, 'SELECT * FROM reference')

    sorted_result = sort_entries(sort_entries(sort_entries(result.affected_items, sort_key='id'), sort_key='source'),
                                 sort_key='url')
    sorted_rows = sort_entries(sort_entries(sort_entries(rows, sort_key='id'), sort_key='source'), sort_key='url')

    assert result.affected_items
    assert all(item[key] == check_datetime(row, key) for item, row in zip(sorted_result, sorted_rows) for key in row)


@patch('wazuh.core.utils.WazuhDBConnection', return_value=InitWDBSocketMock(sql_schema_file='schema_mitre_test.sql'))
def test_mitre_tactics(mock_mitre_db, mitre_db):
    """Check MITRE tactics."""
    result = mitre.mitre_tactics()
    rows = mitre_query(mitre_db, "SELECT * FROM tactic")

    assert result.affected_items
    assert all(item[key] == check_datetime(row, key) for item, row in zip(sort_entries(result.affected_items),
                                                                          sort_entries(rows)) for key in row)


@patch('wazuh.core.utils.WazuhDBConnection', return_value=InitWDBSocketMock(sql_schema_file='schema_mitre_test.sql'))
def test_mitre_techniques(mock_mitre_db, mitre_db):
    """Check MITRE techniques."""
    result = mitre.mitre_techniques()
    rows = mitre_query(mitre_db, "SELECT * FROM technique")

    assert result.affected_items
    assert all(item[key] == check_datetime(row, key) for item, row in zip(sort_entries(result.affected_items),
                                                                          sort_entries(rows)) for key in row)


@patch('wazuh.core.utils.WazuhDBConnection', return_value=InitWDBSocketMock(sql_schema_file='schema_mitre_test.sql'))
def test_mitre_groups(mock_mitre_db, mitre_db):
    """Check MITRE groups."""
    result = mitre.mitre_groups()
    rows = mitre_query(mitre_db, "SELECT * FROM `group`")

    assert result.affected_items
    assert all(item[key] == check_datetime(row, key) for item, row in zip(sort_entries(result.affected_items),
                                                                          sort_entries(rows)) for key in row)


@patch('wazuh.core.utils.WazuhDBConnection', return_value=InitWDBSocketMock(sql_schema_file='schema_mitre_test.sql'))
def test_mitre_software(mock_mitre_db, mitre_db):
    """Check MITRE software."""
    result = mitre.mitre_software()
    rows = mitre_query(mitre_db, "SELECT * FROM software")

    assert result.affected_items
    assert all(item[key] == check_datetime(row, key) for item, row in zip(sort_entries(result.affected_items),
                                                                          sort_entries(rows)) for key in row)

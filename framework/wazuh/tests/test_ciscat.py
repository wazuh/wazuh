#!/usr/bin/env python
# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys
from unittest.mock import patch, MagicMock

import pytest

from api.util import parse_api_param
from wazuh.core.exception import WazuhError

with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators
        del sys.modules['wazuh.rbac.orm']
        from wazuh.tests.util import RBAC_bypasser
        wazuh.rbac.decorators.expose_resources = RBAC_bypasser

        from wazuh.tests.util import InitWDBSocketMock
        from wazuh.ciscat import get_ciscat_results

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
db_file = 'schema_ciscat_test.sql'


@pytest.mark.parametrize('limit', [
    1, None
])
@patch('wazuh.core.utils.path.exists', return_value=True)
@patch('wazuh.core.common.WDB_PATH', new=test_data_path)
@patch('socket.socket.connect')
@patch('wazuh.ciscat.get_agents_info', return_value=['001'])
def test_get_ciscat_results(agents_info_mock, socket_mock, exists_mock, limit):
    """Check if limit is correctly applied to get_ciscat_results() function

    Parameters
    ----------
    limit : int
        Number of items to be returned.
    """
    with patch('wazuh.core.utils.WazuhDBConnection') as mock_wdb:
        mock_wdb.return_value = InitWDBSocketMock(sql_schema_file=db_file)
        result = get_ciscat_results(agent_list=['001'], limit=limit).render()['data']
        limit = limit if limit else 2
        assert len(result['affected_items']) == limit and result['total_affected_items'] == 2
        assert len(result['failed_items']) == 0 and result['total_failed_items'] == 0


@patch('wazuh.core.common.WDB_PATH', new=test_data_path)
@patch('socket.socket.connect')
@patch('wazuh.ciscat.get_agents_info', return_value=['001'])
def test_get_ciscat_results_ko(agents_info_mock, socket_mock):
    """Check that expected exception is raised when agent does not exist."""
    with patch('wazuh.core.utils.WazuhDBConnection') as mock_wdb:
        mock_wdb.return_value = InitWDBSocketMock(sql_schema_file=db_file)
        result = get_ciscat_results(agent_list=['002']).render()['data']
        assert result['total_failed_items'] == 1


@pytest.mark.parametrize('select', [
    ['scan.id'], ['score'], ['profile', 'benchmark'], ['notchecked', 'scan.time', 'unknown'], ['fail', 'error'], None
])
@patch('wazuh.core.utils.path.exists', return_value=True)
@patch('wazuh.core.common.WDB_PATH', new=test_data_path)
@patch('socket.socket.connect')
@patch('wazuh.ciscat.get_agents_info', return_value=['001'])
def test_get_ciscat_results_select(agents_info_mock, socket_mock, exists_mock, select):
    """Check that only selected elements are returned

    Parameters
    ----------
    select : list
        Fields to be returned.
    """
    valid_fields = {'scan', 'benchmark', 'profile', 'pass', 'fail', 'error', 'notchecked', 'unknown', 'score'}

    with patch('wazuh.core.utils.WazuhDBConnection') as mock_wdb:
        mock_wdb.return_value = InitWDBSocketMock(sql_schema_file=db_file)
        result = get_ciscat_results(agent_list=['001'], select=select).render()['data']

        # Check returned keys are the ones specified inside 'select' field
        for item in result['affected_items']:
            if select:
                for select_item in select:
                    if '.' in select_item:
                        key, subkey = select_item.split('.')
                        assert subkey in item[key]
                    else:
                        assert select_item in item
            for key in item.keys():
                assert key in valid_fields if key != 'agent_id' else True


@patch('wazuh.core.utils.path.exists', return_value=True)
@patch('wazuh.core.common.WDB_PATH', new=test_data_path)
@patch('socket.socket.connect')
@patch('wazuh.ciscat.get_agents_info', return_value=['001'])
def test_get_ciscat_results_select_ko(agents_info_mock, socket_mock, exists_mock):
    """Check that expected exception is raised when select field is not allowed."""
    with patch('wazuh.core.utils.WazuhDBConnection') as mock_wdb:
        mock_wdb.return_value = InitWDBSocketMock(sql_schema_file=db_file)
        with pytest.raises(WazuhError, match=r'\b1724\b'):
            get_ciscat_results(agent_list=['001'], select=['random']).render()['data']


@pytest.mark.parametrize('search, total_expected_items', [
    ('server', 1),
    ('centos', 1),
    ('CIS', 2),
    ('random', 0),
])
@patch('wazuh.core.utils.path.exists', return_value=True)
@patch('wazuh.core.common.WDB_PATH', new=test_data_path)
@patch('socket.socket.connect')
@patch('wazuh.ciscat.get_agents_info', return_value=['001'])
def test_get_ciscat_results_search(agents_info_mock, socket_mock, exists_mock, search, total_expected_items):
    """Check if the number of items returned is as expected when using the search parameter.

    Parameters
    ----------
    search : str
        String to be searched in the database.
    total_expected_items : int
        Number of expected items to be returned.
    """
    with patch('wazuh.core.utils.WazuhDBConnection') as mock_wdb:
        mock_wdb.return_value = InitWDBSocketMock(sql_schema_file=db_file)
        result = get_ciscat_results(agent_list=['001'], search=parse_api_param(search, 'search')).render()['data']
        assert result['total_affected_items'] == total_expected_items


@pytest.mark.parametrize('query, total_expected_items, expected_scan_id', [
    ('benchmark~Ubuntu', 1, [1]),
    ('benchmark=Ubuntu', 0, []),
    ('', 2, [1, 2]),
    ('pass>90', 2, [1, 2]),
    ('pass>90;fail<60', 1, [2]),
    ('pass>90,fail<60', 2, [1, 2]),
    ('(pass>90,fail<60);profile~workstation', 1, [2]),
])
@patch('wazuh.core.utils.path.exists', return_value=True)
@patch('wazuh.core.common.WDB_PATH', new=test_data_path)
@patch('socket.socket.connect')
@patch('wazuh.ciscat.get_agents_info', return_value=['001'])
def test_get_ciscat_results_query(agents_info_mock, socket_mock, exists_mock, query, total_expected_items,
                                  expected_scan_id):
    """Check if the number of items returned is as expected when using query parameter.

    Parameters
    ----------
    query : str
        Query to be applied in the database
    total_expected_items : int
        Number of expected items to be returned.
    expected_scan_id : list
        Expected IDs of the returned items.
    """
    with patch('wazuh.core.utils.WazuhDBConnection') as mock_wdb:
        mock_wdb.return_value = InitWDBSocketMock(sql_schema_file=db_file)
        result = get_ciscat_results(agent_list=['001'], q=query).render()['data']
        assert result['total_affected_items'] == total_expected_items
        for item in result['affected_items']:
            assert item['scan']['id'] in expected_scan_id


@pytest.mark.parametrize('sort, first_item', [
    ('-benchmark', 1),
    ('+benchmark', 2),
    ('-pass', 2),
    ('+pass', 1),
])
@patch('wazuh.core.utils.path.exists', return_value=True)
@patch('wazuh.core.common.WDB_PATH', new=test_data_path)
@patch('socket.socket.connect')
@patch('wazuh.ciscat.get_agents_info', return_value=['001'])
def test_get_ciscat_results_sort(agents_info_mock, socket_mock, exists_mock, sort, first_item):
    """Check if the the first item returned is expected when using sort parameter

    Parameters
    ----------
    sort : str
        Field and order to sort by
    first_item : int
        Expected string to be contained in the log of the first returned element.
    """
    with patch('wazuh.core.utils.WazuhDBConnection') as mock_wdb:
        mock_wdb.return_value = InitWDBSocketMock(sql_schema_file=db_file)
        result = get_ciscat_results(agent_list=['001'], sort=parse_api_param(sort, 'sort')).render()['data']
        assert result['affected_items'][0]['scan']['id'] == first_item


@pytest.mark.parametrize('filters, expected_scan_id', [
    ({'benchmark': 'CIS Ubuntu Linux 16.04 LTS Benchmark'}, [1]),
    ({'benchmark': 'CIS CentOS Linux Benchmark'}, [2]),
    ({'benchmark': 'Random'}, []),
    ({'pass': 93}, [1]),
    ({'pass': 100}, []),
    ({'pass': 96, 'fail': 53, 'error': 0}, [2]),
    ({'pass': 96, 'fail': 53, 'error': 0}, [2]),
    ({'notchecked': 67, 'unknown': 0, 'score': 61}, [1]),
])
@patch('wazuh.core.utils.path.exists', return_value=True)
@patch('wazuh.core.common.WDB_PATH', new=test_data_path)
@patch('socket.socket.connect')
@patch('wazuh.ciscat.get_agents_info', return_value=['001'])
def test_get_ciscat_results_filters(agents_info_mock, socket_mock, exists_mock, filters, expected_scan_id):
    """Check that filters are correctly applied.

    Parameters
    ----------
    filters : dict
        Filters to be applied and their values.
    expected_scan_id : list
        Expected IDs of the returned items.
    """
    with patch('wazuh.core.utils.WazuhDBConnection') as mock_wdb:
        mock_wdb.return_value = InitWDBSocketMock(sql_schema_file=db_file)
        result = get_ciscat_results(agent_list=['001'], filters=filters).render()['data']
        for item in result['affected_items']:
            assert item['scan']['id'] in expected_scan_id

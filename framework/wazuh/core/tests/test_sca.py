# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from datetime import datetime, timezone
from unittest.mock import patch

import pytest

with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
        from wazuh.core.sca import *
        from wazuh.core import common


@pytest.mark.parametrize('agent_id, offset, limit, sort, search, select, query, count, get_data', [
    ('001', 0, 10, {'order': 'asc'}, {'value': 'test', 'negation': True}, {'id'}, None, False, True),
])
def test_wazuh_db_query_sca__init__(agent_id, offset, limit, sort, search, select, query, count, get_data):
    """Test if method __init__ of WazuhDBQuerySCA works properly.

    Parameters
    ----------
    agent_id: str
        Agent ID to fetch information about.
    offset: int
        First item to return.
    limit: int
        Maximum number of items to return.
    sort: dict
        Criteria used to sort the resulting items.
    search: dict
        Values used to filter the query.
    select: list
        Fields to return.
    query: str
        Query to filter in database.
    count: bool
        Whether to compute the total of items or not.
    get_data: bool
        Whether to return data or not.
    """
    with patch('wazuh.core.utils.WazuhDBQuery.__init__') as mock_wdbq, \
            patch('wazuh.core.utils.WazuhDBBackend.__init__', return_value=None), \
            patch('wazuh.core.agent.Agent.get_basic_information') as mock_get_basic_info:
        WazuhDBQuerySCA(agent_id=agent_id, offset=offset, limit=limit, sort=sort, search=search, select=select,
                        query=query, count=count, get_data=get_data)
        mock_wdbq.assert_called_once()
        mock_get_basic_info.assert_called_once()


@pytest.mark.parametrize('agent_id, offset, limit, sort, search, select, query, count, get_data', [
    ('001', 0, 10, {'order': 'asc'}, {'value': 'test', 'negation': True}, {'id'}, None, False, True),
])
def test_wazuh_db_query_sca__default_count_query(agent_id, offset, limit, sort, search, select, query, count, get_data):
    """Check if WazuhDBQueryTask's method _default_count_query works properly.

    Parameters
    ----------
    agent_id: str
        Agent ID to fetch information about.
    offset: int
        First item to return.
    limit: int
        Maximum number of items to return.
    sort: dict
        Criteria used to sort the resulting items.
    search: dict
        Values used to filter the query.
    select: list
        Fields to return.
    query: str
        Query to filter in database.
    count: bool
        Whether to compute the total of items or not.
    get_data: bool
        Whether to return data or not.
    """
    with patch('wazuh.core.utils.WazuhDBBackend.__init__', return_value=None), \
            patch('wazuh.core.agent.Agent.get_basic_information'):
        wdbq_sca = WazuhDBQuerySCA(agent_id=agent_id, offset=offset, limit=limit, sort=sort, search=search,
                                   select=select, query=query, count=count, get_data=get_data)
        assert wdbq_sca._default_count_query() == f"SELECT COUNT(DISTINCT policy_id)" + " FROM ({0})"


@pytest.mark.parametrize('agent_id, offset, limit, sort, search, select, query, count, get_data', [
    ('001', 0, 10, {'order': 'asc'}, {'value': 'test', 'negation': True},
     {'id', 'start_scan', 'end_scan', 'policy_id', 'pass', 'fail'}, None, False, True),
])
def test_wazuh_db_query_sca__format_data_into_dictionary(agent_id, offset, limit, sort, search, select, query, count,
                                                         get_data):
    """Check if WazuhDBQueryTask's method _format_data_into_dictionary works properly.

    Parameters
    ----------
    agent_id: str
        Agent ID to fetch information about.
    offset: int
        First item to return.
    limit: int
        Maximum number of items to return.
    sort: dict
        Criteria used to sort the resulting items.
    search: dict
        Values used to filter the query.
    select: list
        Fields to return.
    query: str
        Query to filter in database.
    count: bool
        Whether to compute the total of items or not.
    get_data: bool
        Whether to return data or not.
    """

    data = [
        {'id': 10, 'start_scan': 1556125759, 'end_scan': 1556125760, 'policy_id': 'cis_debian', 'pass': 20, 'fail': 6}
    ]

    with patch('wazuh.core.utils.WazuhDBBackend.__init__', return_value=None), \
            patch('wazuh.core.agent.Agent.get_basic_information'):
        wdbq_sca = WazuhDBQuerySCA(agent_id=agent_id, offset=offset, limit=limit, sort=sort, search=search,
                                   select=select, query=query, count=count, get_data=get_data)

    wdbq_sca._data = data
    result = wdbq_sca._format_data_into_dictionary()

    assert result['items'][0]['id'] == 10
    assert result['items'][0]['start_scan'] == datetime(2019, 4, 24, 17, 9, 19, tzinfo=timezone.utc)
    assert result['items'][0]['end_scan'] == datetime(2019, 4, 24, 17, 9, 20, tzinfo=timezone.utc)
    assert result['items'][0]['policy_id'] == 'cis_debian'
    assert result['items'][0]['pass'] == 20
    assert result['items'][0]['fail'] == 6


@pytest.mark.parametrize('test_where', [True, False])
@pytest.mark.parametrize('agent_id, offset, limit, sort, search, select, query, count, get_data', [
    ('001', 0, 10, {'order': 'asc'}, {'value': 'test', 'negation': True}, {'id'}, None, False, True),
])
def test_wazuh_db_query_sca_check__parse_filters(agent_id, offset, limit, sort, search, select, query, count, get_data,
                                                 test_where):
    """Checks if WazuhDBQuerySCACheck's _parse_filters method works properly

    Parameters
    ----------
    agent_id: str
        Agent ID to fetch information about.
    offset: int
        First item to return.
    limit: int
        Maximum number of items to return.
    sort: dict
        Criteria used to sort the resulting items.
    search: dict
        Values used to filter the query.
    select: list
        Fields to return.
    query: str
        Query to filter in database.
    count: bool
        Whether to compute the total of items or not.
    get_data: bool
        Whether to return data or not.
    test_where: bool
        Whether query should have appended ' WHERE ' or ' AND '
    """
    with patch('wazuh.core.utils.WazuhDBBackend.__init__', return_value=None), \
            patch('wazuh.core.agent.Agent.get_basic_information'):
        wdbq_sca_check = WazuhDBQuerySCACheck(agent_id=agent_id, offset=offset, limit=limit, sort=sort, search=search,
                                              select=select, query=query, count=count, get_data=get_data)
    with patch('wazuh.core.utils.WazuhDBQuery._parse_legacy_filters') as mock_parse_legacy, \
            patch('wazuh.core.utils.WazuhDBQuery._parse_query') as mock_parse_query:
        wdbq_sca_check.legacy_filters = {'test': 'value'}
        wdbq_sca_check.q = 'test query'
        if test_where:
            wdbq_sca_check.query += ' WHERE'
        wdbq_sca_check._parse_filters()
        mock_parse_legacy.assert_called_once()
        mock_parse_query.assert_called_once()
        if test_where:
            assert ' WHERE ' in wdbq_sca_check.query[-7:]
        else:
            assert ' AND ' in wdbq_sca_check.query[-5:]


@pytest.mark.parametrize('agent_id, offset, limit, sort, search, select, query, count, get_data', [
    ('001', 0, 10, {'order': 'asc'}, {'value': 'test', 'negation': True}, {'id'}, None, False, True),
])
def test_wazuh_db_query_sca_check__add_limit_to_query(agent_id, offset, limit, sort, search, select, query, count,
                                                      get_data):
    """Check if WazuhDBQuerySCACheck's method _add_limit_to_query works properly.
    Parameters
    ----------
    agent_id: str
        Agent ID to fetch information about.
    offset: int
        First item to return.
    limit: int
        Maximum number of items to return.
    sort: dict
        Criteria used to sort the resulting items.
    search: dict
        Values used to filter the query.
    select: list
        Fields to return.
    query: str
        Query to filter in database.
    count: bool
        Whether to compute the total of items or not.
    get_data: bool
        Whether to return data or not.
    """
    with patch('wazuh.core.utils.WazuhDBBackend.__init__', return_value=None), \
            patch('wazuh.core.agent.Agent.get_basic_information') as mock_get_basic_info:
        wdbq_sca_check = WazuhDBQuerySCACheck(agent_id=agent_id, offset=offset, limit=limit, sort=sort, search=search,
                                              select=select, query=query, count=count, get_data=get_data)

    wdbq_sca_check._add_limit_to_query()
    assert ' LIMIT :inner_limit OFFSET :inner_offset' in wdbq_sca_check.query
    assert wdbq_sca_check.request['inner_offset'] == wdbq_sca_check.offset
    assert wdbq_sca_check.request['inner_limit'] == wdbq_sca_check.limit
    assert wdbq_sca_check.request['offset'] == 0
    assert wdbq_sca_check.request['limit'] == 0


@pytest.mark.parametrize('expected_error', ['1405', '1406'])
@pytest.mark.parametrize('agent_id, offset, limit, sort, search, select, query, count, get_data', [
    ('001', 0, 10, {'order': 'asc'}, {'value': 'test', 'negation': True}, {'id'}, None, False, True),
])
def test_wazuh_db_query_sca_check__add_limit_to_query_ko(agent_id, offset, limit, sort, search, select, query, count,
                                                         get_data, expected_error):
    """Check if WazuhDBQuerySCACheck's method _add_limit_to_query raises exceptions when used incorrectly.

    Parameters
    ----------
    agent_id: str
        Agent ID to fetch information about.
    offset: int
        First item to return.
    limit: int
        Maximum number of items to return.
    sort: dict
        Criteria used to sort the resulting items.
    search: dict
        Values used to filter the query.
    select: list
        Fields to return.
    query: str
        Query to filter in database.
    count: bool
        Whether to compute the total of items or not.
    get_data: bool
        Whether to return data or not.
    expected_error: str
        Expected exception code.
    """
    with patch('wazuh.core.utils.WazuhDBBackend.__init__', return_value=None), \
            patch('wazuh.core.agent.Agent.get_basic_information') as mock_get_basic_info:
        wdbq_sca_check = WazuhDBQuerySCACheck(agent_id=agent_id, offset=offset, limit=limit, sort=sort, search=search,
                                              select=select, query=query, count=count, get_data=get_data)

    wdbq_sca_check.limit = common.MAXIMUM_DATABASE_LIMIT + 1 if expected_error == '1405' else 0

    with pytest.raises(WazuhError, match=f".* {expected_error} .*"):
        wdbq_sca_check._add_limit_to_query()


@pytest.mark.parametrize('data', [(),
                                  ({'id': 10, 'start_scan': 1556125759, 'end_scan': 1556125760,
                                    'policy_id': 'cis_debian', 'pass': 20, 'fail': 6})
                                  ])
@pytest.mark.parametrize('agent_id, offset, limit, sort, search, select, query, count, get_data', [
    ('001', 0, 10, {'order': 'asc'}, {'value': 'test', 'negation': True}, {'id'}, None, False, True),
    ('001', 0, 10, {'order': 'asc'}, {'value': 'test', 'negation': True}, {'id'}, None, True, True),
])
def test_wazuh_db_query_sca_check_run(agent_id, offset, limit, sort, search, select, query, count, get_data, data):
    """Check that WazuhDBQuerySCACheck's method run works properly.

    Parameters
    ----------
    agent_id: str
        Agent ID to fetch information about.
    offset: int
        First item to return.
    limit: int
        Maximum number of items to return.
    sort: dict
        Criteria used to sort the resulting items.
    search: dict
        Values used to filter the query.
    select: list
        Fields to return.
    query: str
        Query to filter in database.
    count: bool
        Whether to compute the total of items or not.
    get_data: bool
        Whether to return data or not.
    data: dict
         Data to simulate a working agent.
    """
    with patch('wazuh.core.utils.WazuhDBBackend.__init__', return_value=None), \
            patch('wazuh.core.agent.Agent.get_basic_information') as mock_get_basic_info:
        wdbq_sca_check = WazuhDBQuerySCACheck(agent_id=agent_id, offset=offset, limit=limit, sort=sort, search=search,
                                              select=select, query=query, count=count, get_data=get_data)
    with patch('wazuh.core.utils.WazuhDBQuery._add_select_to_query') as mock_add_select, \
            patch('wazuh.core.utils.WazuhDBQuery._add_filters_to_query') as mock_add_filters, \
            patch('wazuh.core.utils.WazuhDBQuery._add_search_to_query') as mock_add_search, \
            patch('wazuh.core.sca.WazuhDBQuerySCACheck._add_limit_to_query') as mock_add_limit, \
            patch('wazuh.core.utils.WazuhDBQuery._add_sort_to_query') as mock_add_sort, \
            patch('wazuh.core.utils.WazuhDBQuery._execute_data_query') as mock_execute_data, \
            patch('wazuh.core.utils.WazuhDBQuery._get_total_items') as mock_get_items, \
            patch('wazuh.core.sca.WazuhDBQuerySCA._format_data_into_dictionary') as mock_format_data:
        wdbq_sca_check.data = data
        wdbq_sca_check.run()
        mock_add_select.assert_called_once()
        mock_add_filters.assert_called_once()
        mock_add_search.assert_called_once()

        if count:
            mock_get_items.assert_called_once()
            if not data:
                # If it's only counting the number of items and it's not expecting data in return
                # the execution should end here
                return

        mock_add_limit.assert_called_once()
        mock_add_sort.assert_called_once()
        if data:
            mock_execute_data.assert_called_once()
            mock_format_data.assert_called_once()

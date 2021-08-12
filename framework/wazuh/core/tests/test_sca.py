# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from unittest.mock import patch
import pytest

with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
        from wazuh.core.sca import *


@pytest.mark.parametrize('agent_id, offset, limit, sort, search, select, query, count, get_data', [
    ('001', 0, 10, {'order': 'asc'}, {'value': 'test', 'negation': True}, {'id'}, None, 5, True),
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
            patch('wazuh.core.utils.WazuhDBBackend.__init__', return_value=None) as mock_wdb_backend, \
            patch('wazuh.core.agent.Agent.get_basic_information') as mock_get_basic_info:
        WazuhDBQuerySCA(agent_id=agent_id, offset=offset, limit=limit, sort=sort, search=search, select=select,
                        query=query, count=count, get_data=get_data)
        mock_wdbq.assert_called_once()
        mock_get_basic_info.assert_called_once()


@pytest.mark.parametrize('agent_id, offset, limit, sort, search, select, query, count, get_data', [
    ('001', 0, 10, {'order': 'asc'}, {'value': 'test', 'negation': True}, {'id'}, None, 5, True),
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
            patch('wazuh.core.agent.Agent.get_basic_information') as mock_get_basic_info:
        wdbq_task = WazuhDBQuerySCA(agent_id=agent_id, offset=offset, limit=limit, sort=sort, search=search,
                                    select=select,
                                    query=query, count=count, get_data=get_data)
        assert wdbq_task._default_count_query() == f"SELECT COUNT(DISTINCT policy_id)" + " FROM ({0})"


@pytest.mark.parametrize('agent_id, offset, limit, sort, search, select, query, count, get_data', [
    ('001', 0, 10, {'order': 'asc'}, {'value': 'test', 'negation': True},
     {'id', 'start_scan', 'end_scan', 'policy_id', 'pass', 'fail'}, None, 5, True),
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
            patch('wazuh.core.agent.Agent.get_basic_information') as mock_get_basic_info:
        wdbq_task = WazuhDBQuerySCA(agent_id=agent_id, offset=offset, limit=limit, sort=sort, search=search,
                                    select=select,
                                    query=query, count=count, get_data=get_data)

    wdbq_task._data = data
    result = wdbq_task._format_data_into_dictionary()

    assert result['items'][0]['id'] == 10
    assert result['items'][0]['start_scan'] == datetime(2019, 4, 24, 17, 9, 19)
    assert result['items'][0]['end_scan'] == datetime(2019, 4, 24, 17, 9, 20)
    assert result['items'][0]['policy_id'] == 'cis_debian'
    assert result['items'][0]['pass'] == 20
    assert result['items'][0]['fail'] == 6

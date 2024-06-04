# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from datetime import datetime, timezone
from types import MappingProxyType
from unittest.mock import call, patch, ANY

import pytest

with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
        from wazuh.core import sca as core_sca
        from wazuh.core.exception import WazuhError


@pytest.mark.parametrize('agent_id, offset, limit, sort, search, select, query, count, get_data', [
    ('001', 0, 10, {'order': 'asc'}, {'value': 'test', 'negation': True}, {'id'}, None, False, True),
    ('001', 0, 10, {'order': 'asc'}, {'value': 'test', 'negation': True}, {'id'}, None, False, True),
])
@pytest.mark.parametrize('distinct', [
    True, False
])
@patch('wazuh.core.agent.Agent.get_basic_information')
@patch('wazuh.core.utils.WazuhDBBackend.__init__', return_value=None)
@patch('wazuh.core.utils.WazuhDBQuery.__init__')
def test_WazuhDBQuerySCA__init__(mock_wdbq, mock_backend, mock_get_basic_info, distinct, agent_id, offset, limit, sort,
                                 search, query, count, get_data, select):
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
    distinct: bool
        Look for distinct values.
    """
    wdbq_sca = core_sca.WazuhDBQuerySCA(agent_id=agent_id, offset=offset, limit=limit, sort=sort, search=search,
                                        select=select, query=query, count=count, get_data=get_data, distinct=distinct)
    wdbq_sca.agent_id = agent_id
    wdbq_sca.default_query = 'SELECT {0} FROM sca_policy sca INNER JOIN sca_scan_info si ON sca.id=si.policy_id' \
        if not distinct else 'SELECT DISTINCT {0} FROM sca_policy sca INNER JOIN sca_scan_info si ' \
                             'ON sca.id=si.policy_id'

    mock_get_basic_info.assert_called_once()
    mock_wdbq.assert_called_once_with(ANY, offset=offset, limit=limit, table='sca_policy', sort=sort, search=search,
                                      select=select, fields=core_sca.WazuhDBQuerySCA.DB_FIELDS,
                                      default_sort_field='policy_id', default_sort_order='DESC', filters={},
                                      query=query, count=count, get_data=get_data,
                                      date_fields={'end_scan', 'start_scan'},
                                      min_select_fields={'policy_id'} if not distinct else set(), backend=ANY)
    mock_backend.assert_called_once_with(agent_id)


@pytest.mark.parametrize('agent_id, offset, limit, sort, search, select, query, count, get_data', [
    ('001', 0, 10, {'order': 'asc'}, {'value': 'test', 'negation': True},
     {'id', 'start_scan', 'end_scan', 'policy_id', 'pass', 'fail'}, None, False, True),
])
def test_WazuhDBQuerySCA__format_data_into_dictionary(agent_id, offset, limit, sort, search, select, query, count,
                                                      get_data):
    """Check if WazuhDBQuerySCA's method _format_data_into_dictionary works properly.

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
        wdbq_sca = core_sca.WazuhDBQuerySCA(agent_id=agent_id, offset=offset, limit=limit, sort=sort, search=search,
                                            select=select, query=query, count=count, get_data=get_data)

    wdbq_sca._data = data
    result = wdbq_sca._format_data_into_dictionary()

    assert result['items'][0]['id'] == 10
    assert result['items'][0]['start_scan'] == datetime(2019, 4, 24, 17, 9, 19, tzinfo=timezone.utc)
    assert result['items'][0]['end_scan'] == datetime(2019, 4, 24, 17, 9, 20, tzinfo=timezone.utc)
    assert result['items'][0]['policy_id'] == 'cis_debian'
    assert result['items'][0]['pass'] == 20
    assert result['items'][0]['fail'] == 6


@pytest.mark.parametrize('sca_checks_test_list, expected_default_query', [
    ([1, 2, 3, 4], "SELECT {0} FROM sca_check WHERE id IN (1, 2, 3, 4)"),
    ([], "SELECT {0} FROM sca_check")
])
@pytest.mark.parametrize('select', [
    ['test'], [], None
])
@patch('wazuh.core.sca.WazuhDBQuerySCA.__init__')
def test_WazuhDBQuerySCACheck__init__(mock_wdbqsca, select, sca_checks_test_list, expected_default_query):
    """Test if method __init__ of WazuhDBQuerySCACheck works properly.

    Parameters
    ----------
    select : list or None
        Fields to return.
    sca_checks_test_list : list
        List of SCA checks IDs.
    expected_default_query : str
        Expected default query.
    """
    core_sca.WazuhDBQuerySCACheck(agent_id='000', select=select, sort={'fields': ['title'], 'order': 'asc'},
                                  sca_checks_ids=sca_checks_test_list)
    select = {'id'} if select == [] else select

    mock_wdbqsca.assert_called_once_with(ANY, agent_id='000', offset=0, limit=None,
                                         sort={'fields': ['title'], 'order': 'asc'}, filters={}, search=None,
                                         count=False,
                                         get_data=True, min_select_fields={'id'},
                                         select=select or list(core_sca.SCA_CHECK_DB_FIELDS.keys()),
                                         default_query=expected_default_query, fields=core_sca.SCA_CHECK_DB_FIELDS,
                                         default_sort_field='id', default_sort_order='ASC', query='')


@patch('wazuh.core.utils.WazuhDBBackend.__init__', return_value=None)
@patch('wazuh.core.agent.Agent.get_basic_information')
@patch('os.path.exists', return_value=True)
def test_WazuhDBQuerySCACheck_parse_select_filter(mock_exists, mock_get_basic_info, mock_backend):
    """Test if method _parse_select_filter of WazuhDBQuerySCACheck works properly."""
    wdbq_sca_check = core_sca.WazuhDBQuerySCACheck(agent_id='000', sort={'value': 'test'},
                                                   select=['test'], sca_checks_ids=[])
    try:
        wdbq_sca_check._parse_select_filter(['test'])
    except WazuhError as e:
        assert e.code == 1724
        expected_fields = set(wdbq_sca_check.fields.keys()).union(core_sca.SCA_CHECK_COMPLIANCE_DB_FIELDS.keys()).union(
            core_sca.SCA_CHECK_RULES_DB_FIELDS.keys()) - {'id_check'}
        assert all(field in e.message for field in expected_fields)


@pytest.mark.parametrize('query', [
    'field~test', ''
])
@patch('wazuh.core.sca.WazuhDBQuerySCA.__init__')
def test_WazuhDBQuerySCACheckIDs__init__(mock_wdbqsca, query):
    """Test if method __init__ of WazuhDBQuerySCACheckIDs works properly.

    Parameters
    ----------
    query : str
        Query used to initialize the WazuhDBQuerySCACheckIDs object.
    """
    expected_fields = core_sca.SCA_CHECK_DB_FIELDS | core_sca.SCA_CHECK_COMPLIANCE_DB_FIELDS | \
                      core_sca.SCA_CHECK_RULES_DB_FIELDS
    expected_fields.pop('id_check')

    core_sca.WazuhDBQuerySCACheckIDs(agent_id='000', offset=10, limit=20, filters={'test': 'value'},
                                     search={'value': 'test'},
                                     query=query, policy_id='test_policy_id', sort={})

    mock_wdbqsca.assert_called_once_with(ANY, agent_id='000', offset=10, limit=20, sort={}, filters={'test': 'value'},
                                         search={'value': 'test'}, count=True, get_data=True, select=[],
                                         default_query="SELECT DISTINCT(id) FROM sca_check a "
                                                       "LEFT JOIN sca_check_compliance b ON a.id=b.id_check "
                                                       "LEFT JOIN sca_check_rules c ON a.id=c.id_check",
                                         fields=expected_fields, default_sort_field='id', default_sort_order='ASC',
                                         query=f"policy_id=test_policy_id;{query}" if query
                                         else "policy_id=test_policy_id")


@pytest.mark.parametrize('field, value, expected', [
    ('condition', 'all', False),
    ('condition', 'none', False),
    ('condition', 'any', False),
    ('rationale', 'all', True),
    ('description', 'none', False),
])
@patch('wazuh.core.utils.WazuhDBBackend.__init__', return_value=None)
@patch('wazuh.core.agent.Agent.get_basic_information')
def test_WazuhDBQuerySCACheckIDs_protected_pass_filter(mock_get_basic_info, mock_backend, field, value, expected):
    """Test WazuhDBQuerySCACheckIDs._pass_filter function."""
    query = core_sca.WazuhDBQuerySCACheckIDs(agent_id='000', offset=10, limit=20, filters={'test': 'value'},
                                     search={'value': 'test'}, query='', policy_id='test_policy_id', sort={})

    skipped = query._pass_filter(field, value)
    assert skipped == expected


@pytest.mark.parametrize('sca_checks_test_list', [
    [1, 2, 3, 4], []
])
@pytest.mark.parametrize('table', [
    'sca_check_compliance', 'sca_check_rules'
])
@pytest.mark.parametrize('select', [
    None, ['test']
])
@patch('wazuh.core.sca.WazuhDBQuerySCA.__init__')
def test_WazuhDBQuerySCACheckRelational__init__(mock_wdbqsca, select, table, sca_checks_test_list):
    """Test if method __init__ of WazuhDBQuerySCACheckRelational works properly.

    Parameters
    ----------
    select : list or None
        Fields to select.
    table : str
        Table used to initialize the WazuhDBQuerySCACheckRelational object.
    sca_checks_test_list : list
        List of SCA checks IDs.
    """
    query_sca_check_relational = core_sca.WazuhDBQuerySCACheckRelational(agent_id='000', table=table,
                                                                         id_check_list=sca_checks_test_list,
                                                                         select=select)
    expected_fields = MappingProxyType({'sca_check_rules': core_sca.SCA_CHECK_RULES_DB_FIELDS,
                                        'sca_check_compliance': core_sca.SCA_CHECK_COMPLIANCE_DB_FIELDS})
    expected_default_query = "SELECT {0} FROM " + table
    if sca_checks_test_list:
        expected_default_query += f" WHERE id_check IN {str(sca_checks_test_list).replace('[', '(').replace(']', ')')}"

    assert query_sca_check_relational.sca_check_table == table
    mock_wdbqsca.assert_called_once_with(ANY, agent_id='000', default_query=expected_default_query,
                                         fields=expected_fields[table], offset=0, limit=None, sort=None,
                                         select=select or list(expected_fields[table].keys()), count=False,
                                         get_data=True, default_sort_field='id_check', default_sort_order='ASC',
                                         query=None, search=None, min_select_fields=set())


@pytest.mark.parametrize('select', [
    ['test'], None
])
@patch('wazuh.core.sca.WazuhDBQuerySCA.__enter__')
@patch('wazuh.core.sca.WazuhDBQuerySCA.__init__', return_value=None)
@patch('wazuh.core.sca.WazuhDBQuery.__exit__')
def test_WazuhDBQueryDistinctSCACheck__init__(mock_exit, mock_wdbqsca, mock_enter, select):
    """Test if method __init__ of WazuhDBQueryDistinctSCACheck works properly."""
    mock_enter.return_value.query = "SELECT * FROM sca_check a LEFT JOIN sca_check_compliance b ON a.id=b.id_check LEFT JOIN " \
                                    "sca_check_rules c ON a.id=c.id_check"
    fields = core_sca.SCA_CHECK_DB_FIELDS | core_sca.SCA_CHECK_COMPLIANCE_DB_FIELDS | core_sca.SCA_CHECK_RULES_DB_FIELDS
    fields.pop('id_check')

    core_sca.WazuhDBQueryDistinctSCACheck(agent_id='000', offset=10, limit=20, filters={'test': 'value'},
                                          search={'value': 'test'}, query='test~a', policy_id='test_policy_id',
                                          sort={'fields': ['title'], 'order': 'asc'}, select=select)

    # Assertions
    mock_wdbqsca.assert_has_calls(
        [call(agent_id='000', offset=0, limit=None, sort={'fields': ['title'], 'order': 'asc'},
              query='policy_id=test_policy_id;test~a', count=False, get_data=False, select=[], default_sort_field='id',
              default_sort_order='ASC', filters={'test': 'value'}, fields=fields,
              default_query=core_sca.WazuhDBQueryDistinctSCACheck.INNER_QUERY_PATTERN, search={'value': 'test'}),
         call(ANY, agent_id='000', offset=10, limit=20, sort={'fields': ['title'], 'order': 'asc'}, filters={},
              search={}, count=True, get_data=True, select=select or list(fields.keys()),
              default_query="SELECT DISTINCT {0} FROM " + f"({mock_enter.return_value.query})", fields=fields,
              default_sort_field='id', default_sort_order='ASC', min_select_fields=set(), query='')],
        any_order=False)

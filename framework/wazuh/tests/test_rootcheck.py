#!/usr/bin/env python
# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys
from unittest.mock import patch, MagicMock, call

import pytest

from api.util import parse_api_param
from wazuh.core.exception import WazuhError

with patch('wazuh.common.ossec_uid'):
    with patch('wazuh.common.ossec_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators

        del sys.modules['wazuh.rbac.orm']

        from wazuh.tests.util import RBAC_bypasser
        wazuh.rbac.decorators.expose_resources = RBAC_bypasser
        from wazuh import rootcheck
        from wazuh.core.rootcheck import WazuhDBQueryRootcheck
        from wazuh.core.tests.test_rootcheck import InitRootcheck, send_msg_to_wdb, remove_db, \
            test_data_path as core_data

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
test_data = InitRootcheck()
callable_list = list()


# Retrieve used parameters in mocked method
def set_callable_list(*params, **kwargs):
    callable_list.append((params, kwargs))


test_result = [
    {'affected_items': ['001', '002'], 'total_affected_items': 2, 'failed_items': {}, 'total_failed_items': 0},
    {'affected_items': ['003', '008'], 'total_affected_items': 2, 'failed_items': {'001'}, 'total_failed_items': 1},
    {'affected_items': ['001'], 'total_affected_items': 1, 'failed_items': {'002', '003'},
     'total_failed_items': 2},
    # This result is used for exceptions
    {'affected_items': [], 'total_affected_items': 0, 'failed_items': {'001'}, 'total_failed_items': 1},
]


@pytest.mark.parametrize('agent_list, status_list, expected_result', [
    (['002', '001'], [{'status': status} for status in ['active', 'active']], test_result[0]),
    (['003', '001', '008'], [{'status': status} for status in ['active', 'disconnected', 'active']], test_result[1]),
    (['001', '002', '003'], [{'status': status} for status in ['active', 'disconnected', 'disconnected']],
     test_result[2]),
])
@patch('wazuh.syscheck.OssecQueue._connect')
@patch('wazuh.syscheck.OssecQueue.send_msg_to_agent', side_effect=set_callable_list)
@patch('wazuh.syscheck.OssecQueue.close')
def test_rootcheck_run(close_mock, send_mock, connect_mock, agent_list, status_list, expected_result):
    """Test function `run` from rootcheck module.

    Parameters
    ----------
    agent_list : list
        List of agent IDs.
    status_list : list
        List of agent statuses.
    expected_result : list
        List of dicts with expected results for every test.
    """
    with patch('wazuh.rootcheck.Agent.get_basic_information', side_effect=status_list):
        result = rootcheck.run(agent_list=agent_list)
        for args, kwargs in callable_list:
            assert (isinstance(a, str) for a in args)
            assert (isinstance(k, str) for k in kwargs)
        assert isinstance(result, rootcheck.AffectedItemsWazuhResult)
        assert result.affected_items == expected_result['affected_items']
        assert result.total_affected_items == expected_result['total_affected_items']
        if result.failed_items:
            assert next(iter(result.failed_items.values())) == expected_result['failed_items']
        else:
            assert result.failed_items == expected_result['failed_items']
        assert result.total_failed_items == expected_result['total_failed_items']


@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=[None, None, WazuhError(2004)])
@patch('wazuh.rootcheck.get_agents_info', return_value=['000', '001', '002'])
@patch('socket.socket.connect')
def test_clear(mock_connect, mock_info, mock_wdbconn):
    """Test if function clear() returns expected result and if delete command is executed.

    The databases of 4 agents are requested to be cleared, 3 of them exist.
    2 failed items are expected:
        - 1 non existent agent.
        - 1 exception when running execute() method.
    """
    result = rootcheck.clear(['000', '001', '002', '003']).render()

    assert result['data']['affected_items'] == ['000', '001']
    assert result['data']['total_affected_items'] == 2
    assert result['data']['total_failed_items'] == 2
    mock_wdbconn.assert_has_calls([call('agent 000 rootcheck delete'), call('agent 001 rootcheck delete')])


@patch('wazuh.core.agent.Agent.get_basic_information')
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_get_last_scan(mock_connect, mock_send, mock_info):
    """Check if get_last_scan() returned results have expected format and content"""
    result = rootcheck.get_last_scan(['001']).render()['data']['affected_items'][0]
    assert result['start'] == '2020-10-27 12:19:40' and result['end'] == '2020-10-27 12:29:40'


@pytest.mark.parametrize('limit', [
    1, 3, None
])
@patch('wazuh.core.agent.Agent.get_basic_information')
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_get_rootcheck_agent(mock_connect, mock_send, mock_info, limit):
    """Check if limit is correctly applied to get_rootcheck_agent() function

    Parameters
    ----------
    limit : int
        Number of items to be returned.
    """
    result = rootcheck.get_rootcheck_agent(agent_list=['001'], limit=limit, filters={'status': 'all'}).render()['data']
    limit = limit if limit else 6
    assert len(result['affected_items']) == limit and result['total_affected_items'] == 6
    assert len(result['failed_items']) == 0 and result['total_failed_items'] == 0

    # Check returned keys are allowed (they exist in core/rootcheck -> fields)
    for item in result['affected_items']:
        for key in item.keys():
            assert key in WazuhDBQueryRootcheck.fields


@pytest.mark.parametrize('select', [
    ['log'], ['log', 'pci_dss'], ['status'], None
])
@patch('wazuh.core.agent.Agent.get_basic_information')
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_get_rootcheck_agent_select(mock_connect, mock_send, mock_info, select):
    """Check that only selected elements are returned

    Parameters
    ----------
    select : list
        Fields to be returned.
    """
    result = rootcheck.get_rootcheck_agent(agent_list=['001'], select=select, filters={'status': 'all'}).render()['data']
    select = select if select else list(WazuhDBQueryRootcheck.fields.keys())

    # Check returned keys are specified inside 'select' field
    for item in result['affected_items']:
        for key in item.keys():
            assert key in select


@pytest.mark.parametrize('search, total_expected_items', [
    ('1.5', 4),
    ('1.6', 0),
    ('ssh', 1),
    ('robust', 3),
    ('4.1', 2),
    ('outstanding', 5),
    ('solved', 1)
])
@patch('wazuh.core.agent.Agent.get_basic_information')
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_get_rootcheck_agent_search(mock_connect, mock_send, mock_info, search, total_expected_items):
    """Checks if the number of items returned is as expected when using the search parameter.

    Parameters
    ----------
    search : str
        String to be searched in the database.
    total_expected_items : int
        Number of expected items to be returned.
    """
    result = rootcheck.get_rootcheck_agent(agent_list=['001'], search=parse_api_param(search, 'search'),
                                           filters={'status': 'all'}).render()['data']
    assert result['total_affected_items'] == total_expected_items


@pytest.mark.parametrize('query, total_expected_items', [
    ('cis=1.4 Debian Linux', 3),
    ('log=testing', 1),
    ('log!=testing', 5),
    ('', 6),
    ('log=SSH Configuration', 0),
    ('log~SSH Configuration', 1),
    ('pci_dss<3', 4),
    ('pci_dss>3', 2),
    ('(pci_dss>3,pci_dss<2);log~System', 5),
])
@patch('wazuh.core.agent.Agent.get_basic_information')
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_get_rootcheck_agent_query(mock_connect, mock_send, mock_info, query, total_expected_items):
    """Checks if the number of items returned is as expected when using query parameter.

    Parameters
    ----------
    query : str
        Query to be applied in the database
    total_expected_items : int
        Number of expected items to be returned.
    """
    result = rootcheck.get_rootcheck_agent(agent_list=['001'], q=query, filters={'status': 'all'}).render()['data']
    assert result['total_affected_items'] == total_expected_items


@pytest.mark.parametrize('select, distinct, total_expected_items', [
    (['cis'], True, 3),
    (['cis'], False, 6),
    (['pci_dss'], True, 2),
    (['pci_dss'], False, 6),
    (['cis', 'pci_dss'], True, 3),
    (['log'], True, 6),
])
@patch('wazuh.core.agent.Agent.get_basic_information')
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_get_rootcheck_agent_distinct(mock_connect, mock_send, mock_info, select, distinct, total_expected_items):
    """Checks if the number of items returned is as expected when using distinct and select parameters.

    Parameters
    ----------
    select : list
        Fields to be returned.
    distinct : bool
        Whether to apply distinct filter.
    total_expected_items : int
        Number of expected items to be returned.
    """
    result = rootcheck.get_rootcheck_agent(agent_list=['001'], select=select, distinct=distinct,
                                           filters={'status': 'all'}).render()['data']
    assert result['total_affected_items'] == total_expected_items


@pytest.mark.parametrize('sort, first_item', [
    ('-log', 'Testing'),
    ('+log', '/opt'),
    ('-cis', 'Benchmark v1.0'),
    ('+cis', '/var'),
])
@patch('wazuh.core.agent.Agent.get_basic_information')
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_get_rootcheck_agent_sort(mock_connect, mock_send, mock_info, sort, first_item):
    """Checks if the the first item returned is expected when using sort parameter

    Parameters
    ----------
    sort : str
        Field and order to sort by
    first_item : int
        Expected string to be contained in the log of the first returned element.
    """
    result = rootcheck.get_rootcheck_agent(agent_list=['001'], sort=parse_api_param(sort, 'sort'),
                                           filters={'status': 'all'}).render()['data']

    assert first_item in result['affected_items'][0]['log']


@pytest.mark.parametrize('filters, total_expected_items', [
    ({'status': 'all'}, 6),
    ({'status': 'solved'}, 1),
    ({'status': 'outstanding'}, 5),
    ({'status': 'all', 'cis': '2.3'}, 0),
    ({'status': 'all', 'cis': '1.4 Debian Linux'}, 3),
    ({'status': 'solved', 'cis': '1.4 Debian Linux'}, 0),
    ({'status': 'all', 'pci_dss': '1.5'}, 4),
    ({'status': 'all', 'pci_dss': '4.1'}, 2),
    ({'status': 'solved', 'pci_dss': '4.1'}, 1),
    ({'status': 'all', 'cis': '3.4 Debian Linux', 'pci_dss': '1.5'}, 1),
    ({'status': 'all', 'cis': '3.4 Debian Linux', 'pci_dss': '4.1'}, 0)
])
@patch('wazuh.core.agent.Agent.get_basic_information')
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_get_rootcheck_agent_filters(mock_connect, mock_send, mock_info, filters, total_expected_items):
    """Checks if the number of items returned is as expected when using different filters.

    Parameters
    ----------
    filters : dict
        Strings to filter by.
    total_expected_items : int
        Number of expected items to be returned.
    """
    result = rootcheck.get_rootcheck_agent(agent_list=['001'], filters=filters).render()['data']
    assert result['total_affected_items'] == total_expected_items


remove_db(core_data)

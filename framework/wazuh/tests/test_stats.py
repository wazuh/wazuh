# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import sys
from json import dumps
from unittest.mock import AsyncMock, call, MagicMock, patch

import pytest

with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators
        from wazuh.tests.util import RBAC_bypasser

        del sys.modules['wazuh.rbac.orm']
        wazuh.rbac.decorators.expose_resources = RBAC_bypasser

        import wazuh.stats as stats
        from wazuh.core.results import AffectedItemsWazuhResult
        from api.util import remove_nones_to_dict
        from wazuh.core.tests.test_agent import InitAgent

SOCKET_PATH_DAEMONS_MAPPING = {'/var/wazuh-manager/queue/sockets/remote': 'wazuh-manager-remoted',
                               '/var/wazuh-manager/queue/sockets/analysis': 'wazuh-manager-analysisd'}
DAEMON_SOCKET_PATHS_MAPPING = {'wazuh-manager-remoted': '/var/wazuh-manager/queue/sockets/remote',
                               'wazuh-manager-analysisd': '/var/wazuh-manager/queue/sockets/analysis'}

test_data = InitAgent()


def send_msg_to_wdb(msg, raw=False):
    query = ' '.join(msg.split(' ')[2:])
    result = list(map(remove_nones_to_dict, map(dict, test_data.cur.execute(query).fetchall())))
    return ['ok', dumps(result)] if raw else result


@patch('wazuh.core.common.REMOTED_SOCKET', '/var/wazuh-manager/queue/sockets/remote')
@patch('wazuh.core.common.WDB_SOCKET', '/var/wazuh-manager/queue/db/wdb')
@patch('wazuh.stats.EngineHTTPClient')
@patch('wazuh.stats.get_daemons_stats_socket')
def test_get_daemons_stats(mock_get_daemons_stats_socket, mock_engine_client_cls):
    """Makes sure get_daemons_stats() fit with the expected."""
    mock_engine_client = MagicMock()
    mock_engine_client.get_metrics_dump.return_value = METRICS_DUMP_DATA
    mock_engine_client_cls.return_value = mock_engine_client

    response = stats.get_daemons_stats(['wazuh-manager-remoted', 'wazuh-manager-analysisd', 'wazuh-manager-db'])

    # remoted and db still use the socket; analysisd goes through EngineHTTPClient
    calls = [call('/var/wazuh-manager/queue/sockets/remote'), call('/var/wazuh-manager/queue/db/wdb')]
    mock_get_daemons_stats_socket.assert_has_calls(calls)
    mock_engine_client.get_metrics_dump.assert_called_once()
    mock_engine_client.close.assert_called_once()
    assert isinstance(response, AffectedItemsWazuhResult), 'The result is not AffectedItemsWazuhResult type'
    assert response.total_affected_items == len(response.affected_items)


@patch('wazuh.core.common.REMOTED_SOCKET', '/var/wazuh-manager/queue/sockets/wrong_socket_name')
def test_get_daemons_stats_ko():
    """Makes sure get_daemons_stats() fit with the expected."""
    response = stats.get_daemons_stats(['wazuh-manager-remoted'])

    assert isinstance(response, AffectedItemsWazuhResult), 'The result is not AffectedItemsWazuhResult type'
    assert response.render()['data']['failed_items'][0]['error']['code'] == 1121, 'Expected error code was not returned'


def side_effect_test_get_daemons_stats(daemon_path, agents_list):
    return {'name': SOCKET_PATH_DAEMONS_MAPPING[daemon_path], 'agents': [{'id': a} for a in agents_list]}


@pytest.mark.parametrize('daemons_list, expected_daemons_list', [
    ([], ['wazuh-manager-remoted', 'wazuh-manager-analysisd']),
    (['wazuh-manager-remoted'], ['wazuh-manager-remoted']),
    (['wazuh-manager-remoted', 'wazuh-manager-analysisd'], ['wazuh-manager-remoted', 'wazuh-manager-analysisd'])
])
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
@patch('wazuh.stats.get_agents_info', return_value={'001', '002', '003', '004', '005'})
@patch('wazuh.core.common.REMOTED_SOCKET', '/var/wazuh-manager/queue/sockets/remote')
@patch('wazuh.core.common.ANALYSISD_SOCKET', '/var/wazuh-manager/queue/sockets/analysis')
@patch('wazuh.stats.get_daemons_stats_socket', side_effect=side_effect_test_get_daemons_stats)
def test_get_daemons_stats_agents(mock_get_daemons_stats_socket, mock_get_agents_info, mock_socket_connect,
                                  mock_send_wdb, daemons_list, expected_daemons_list):
    """Makes sure get_daemons_stats_agents() fit with the expected."""
    agents_list = ['001', '004', '999']  # HTTPS: Stats from 001 and 004 obtained regardless of status
    expected_errors_and_items = {'1701': {'999'}}  # Only non-existent agents fail
    result = stats.get_daemons_stats_agents(daemons_list, agents_list)

    # get_daemons_stats_socket called with the expected parameters (agents 001 and 004, order may vary)
    # Check that the calls were made with the correct agents (regardless of order)
    actual_calls = mock_get_daemons_stats_socket.call_args_list
    assert len(actual_calls) == len(expected_daemons_list)
    for daemon in expected_daemons_list:
        # Find call for this daemon
        daemon_calls = [c for c in actual_calls if c[0][0] == DAEMON_SOCKET_PATHS_MAPPING[daemon]]
        assert len(daemon_calls) == 1, f"Expected one call for daemon {daemon}"
        # Check that agents_list contains both 1 and 4 (order doesn't matter)
        agents = daemon_calls[0][1]['agents_list']
        assert set(agents) == {1, 4}, f"Expected agents {{1, 4}}, got {set(agents)}"

    # Check affected_items - sort agents for consistent comparison
    for item in result.affected_items:
        item['agents'].sort(key=lambda x: x['id'])
    expected_items = [{'name': daemon, 'agents': [{'id': 1}, {'id': 4}]} for daemon in expected_daemons_list]
    assert result.affected_items == expected_items
    assert result.total_affected_items == len(expected_daemons_list)

    # Check failed items
    error_codes_in_failed_items = [error.code for error in result.failed_items.keys()]
    failed_items = list(result.failed_items.values())
    errors_and_items = {str(error): failed_items[i] for i, error in enumerate(error_codes_in_failed_items)}
    assert expected_errors_and_items == errors_and_items

    assert isinstance(result, AffectedItemsWazuhResult), 'The result is not an AffectedItemsWazuhResult object'


def side_effect_test_get_daemons_stats_all(daemon_path, agents_list, last_id):
    # side_effect used to return a response with 10 items and 'due' the first time that get_daemons_stats_socket is
    # called, and a response with 10 items and 'ok' the second time
    if last_id:
        last_id += 1
    return {'data': {'name': SOCKET_PATH_DAEMONS_MAPPING[daemon_path],
                     'agents': [{'id': i} for i in range(last_id, last_id + 10)]},
            'message': 'due' if last_id == 0 else 'ok',
            'error': 1 if last_id == 0 else 0}


@pytest.mark.parametrize('daemons_list, expected_daemons_list', [
    ([], ['wazuh-manager-remoted', 'wazuh-manager-analysisd']),
    (['wazuh-manager-remoted'], ['wazuh-manager-remoted']),
    (['wazuh-manager-remoted', 'wazuh-manager-analysisd'], ['wazuh-manager-remoted', 'wazuh-manager-analysisd'])
])
@patch('wazuh.core.common.REMOTED_SOCKET', '/var/wazuh-manager/queue/sockets/remote')
@patch('wazuh.core.common.ANALYSISD_SOCKET', '/var/wazuh-manager/queue/sockets/analysis')
@patch('wazuh.stats.get_daemons_stats_socket', side_effect=side_effect_test_get_daemons_stats_all)
def test_get_daemons_stats_all_agents(mock_get_daemons_stats_socket, daemons_list, expected_daemons_list):
    """Makes sure get_daemons_stats_agents() fit with the expected."""
    result = stats.get_daemons_stats_agents(daemons_list, ['all'])

    # get_daemons_stats_socket called with the expected parameters
    calls = []
    for daemon in expected_daemons_list:
        calls.extend((call(DAEMON_SOCKET_PATHS_MAPPING[daemon], agents_list='all', last_id=0),
                      call(DAEMON_SOCKET_PATHS_MAPPING[daemon], agents_list='all', last_id=9)))
    mock_get_daemons_stats_socket.assert_has_calls(calls)

    # Check affected_items
    expected_affected_items = [{'name': daemon, 'agents': [{'id': i} for i in range(0, 20)]} for daemon in
                               expected_daemons_list]
    assert result.affected_items == expected_affected_items
    assert result.total_affected_items == len(expected_daemons_list)

    # Check failed items
    assert not result.failed_items

    assert isinstance(result, AffectedItemsWazuhResult), 'The result is not an AffectedItemsWazuhResult object'


REPORTED_STATS = {'global': {'files': []}, 'interval': {'files': []}}


def _indexer_returning(reported):
    """A get_indexer_client() context manager whose agent_stats.get_component() answers `reported`."""
    indexer = MagicMock()
    indexer.agent_stats.get_component = AsyncMock(return_value=reported)
    client = MagicMock()
    client.return_value.__aenter__ = AsyncMock(return_value=indexer)
    client.return_value.__aexit__ = AsyncMock(return_value=False)
    return client, indexer


@pytest.mark.asyncio
@pytest.mark.parametrize('component', ['logcollector', 'agent'])
@patch('wazuh.stats.get_agents_info', return_value=['001', '002'])
async def test_get_agents_component_stats_json(mock_agents_info, component):
    """The stored report is served straight from the index, in one request for the whole list."""
    client, indexer = _indexer_returning({'001': REPORTED_STATS})

    with patch('wazuh.stats.get_indexer_client', client):
        response = await stats.get_agents_component_stats_json(agent_list=['001'], component=component)

    assert isinstance(response, AffectedItemsWazuhResult), 'The result is not AffectedItemsWazuhResult type'
    assert response.affected_items == [REPORTED_STATS]
    indexer.agent_stats.get_component.assert_awaited_once_with(['001'], component)


@pytest.mark.asyncio
@patch('wazuh.stats.get_agents_info', return_value=['001', '002'])
async def test_get_agents_component_stats_json_ko(mock_agents_info):
    """An agent that does not exist is 1701, and the indexer is never asked about it."""
    client, indexer = _indexer_returning({})

    with patch('wazuh.stats.get_indexer_client', client):
        response = await stats.get_agents_component_stats_json(agent_list=['003'], component='logcollector')

    assert isinstance(response, AffectedItemsWazuhResult), 'The result is not AffectedItemsWazuhResult type'
    assert response.render()['data']['failed_items'][0]['error']['code'] == 1701, 'Expected error code was not returned'
    indexer.agent_stats.get_component.assert_not_awaited()


@pytest.mark.asyncio
@patch('wazuh.stats.get_agents_info', return_value=['001', '002'])
async def test_get_agents_component_stats_json_without_a_report(mock_agents_info):
    """A known agent that has never pushed is 1762: there is no live query left to fall back to."""
    client, _ = _indexer_returning({'001': None, '002': REPORTED_STATS})

    with patch('wazuh.stats.get_indexer_client', client):
        response = await stats.get_agents_component_stats_json(agent_list=['001', '002'], component='agent')

    assert response.affected_items == [REPORTED_STATS]
    assert response.render()['data']['failed_items'][0]['error']['code'] == 1762


METRICS_DUMP_DATA = {
    "status": 0,
    "name": "engine",
    "uptime": 99,
    "global": [{"name": "router.queue.size", "type": 0, "enabled": True, "value": 500}],
    "spaces": [],
}


@patch('wazuh.stats.EngineHTTPClient')
def test_get_engine_metrics(mock_client_cls):
    mock_client = MagicMock()
    mock_client.get_metrics_dump.return_value = METRICS_DUMP_DATA
    mock_client_cls.return_value = mock_client

    response = stats.get_engine_metrics()

    assert isinstance(response, AffectedItemsWazuhResult)
    assert response.total_affected_items == 1
    assert response.affected_items[0] == METRICS_DUMP_DATA
    assert not response.failed_items


@patch('wazuh.stats.EngineHTTPClient')
def test_get_engine_metrics_ko(mock_client_cls):
    from wazuh.core.exception import WazuhInternalError

    mock_client = MagicMock()
    mock_client.get_metrics_dump.side_effect = WazuhInternalError(2021)
    mock_client_cls.return_value = mock_client

    response = stats.get_engine_metrics()

    assert isinstance(response, AffectedItemsWazuhResult)
    assert response.total_affected_items == 0
    assert response.render()['data']['failed_items'][0]['error']['code'] == 2021

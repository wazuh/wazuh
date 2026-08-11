# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import sys
from json import dumps
from unittest.mock import call, MagicMock, patch

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
    """Makes sure get_daemons_stats_agents() fit with the expected.

    Agent 001 ('Wazuh v4.2.0') is below v5.0.0 in the test fixture, so it has a legacy relay in
    remoted and must be queried normally. Agent 004 (no known version) can't be confirmed as
    legacy, so it must land in failed_items with 1762 instead.
    """
    agents_list = ['001', '004', '999']
    expected_errors_and_items = {'1701': {'999'}, '1762': {'004'}}
    result = stats.get_daemons_stats_agents(daemons_list, agents_list)

    # Only the legacy agent (001) reaches the socket call, for every requested daemon.
    calls = [call(DAEMON_SOCKET_PATHS_MAPPING[daemon], agents_list=[1]) for daemon in expected_daemons_list]
    mock_get_daemons_stats_socket.assert_has_calls(calls, any_order=True)
    assert result.affected_items == [{'name': daemon, 'agents': [{'id': 1}]} for daemon in expected_daemons_list]
    assert result.total_affected_items == len(expected_daemons_list)

    # Check failed items
    error_codes_in_failed_items = [error.code for error in result.failed_items.keys()]
    failed_items = list(result.failed_items.values())
    errors_and_items = {str(error): failed_items[i] for i, error in enumerate(error_codes_in_failed_items)}
    assert expected_errors_and_items == errors_and_items

    assert isinstance(result, AffectedItemsWazuhResult), 'The result is not an AffectedItemsWazuhResult object'


@pytest.mark.parametrize('daemons_list, expected_daemons_list', [
    (['wazuh-manager-remoted'], ['wazuh-manager-remoted']),
])
@patch('wazuh.core.common.REMOTED_SOCKET', '/var/wazuh-manager/queue/sockets/remote')
@patch('wazuh.stats.get_daemons_stats_socket', side_effect=side_effect_test_get_daemons_stats)
@patch('wazuh.stats.get_agents_info', return_value={'001', '010'})
@patch('wazuh.stats.WazuhDBQueryAgents')
def test_get_daemons_stats_agents_mixed_versions(mock_wazuh_db_query_cls, mock_get_agents_info,
                                                  mock_get_daemons_stats_socket, daemons_list, expected_daemons_list):
    """Bidirectional coverage in one response: a named-agent getstats call with both a
    legacy (< v5.0.0) and a migrated (>= v5.0.0) agent in the same batch must serve the former
    (affected_items) and reject the latter (1762, failed_items), side by side -- not just as two
    separate single-agent tests (the shape most likely to reveal a swapped condition).
    """
    mock_db_query = MagicMock()
    mock_db_query.run.return_value = {
        'items': [{'id': '001', 'version': 'Wazuh v4.14.6'}, {'id': '010', 'version': 'v5.0.0'}]
    }
    mock_wazuh_db_query_cls.return_value.__enter__.return_value = mock_db_query

    agents_list = ['001', '010', '999']
    result = stats.get_daemons_stats_agents(daemons_list, agents_list)

    # Only the legacy agent (001) reaches the socket call.
    actual_calls = mock_get_daemons_stats_socket.call_args_list
    assert len(actual_calls) == 1
    assert set(actual_calls[0][1]['agents_list']) == {1}

    assert result.affected_items == [{'name': 'wazuh-manager-remoted', 'agents': [{'id': 1}]}]
    assert result.total_affected_items == 1

    error_codes_in_failed_items = [error.code for error in result.failed_items.keys()]
    failed_items = list(result.failed_items.values())
    errors_and_items = {str(error): failed_items[i] for i, error in enumerate(error_codes_in_failed_items)}
    assert errors_and_items == {'1701': {'999'}, '1762': {'010'}}


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


def side_effect_test_get_daemons_stats_all_fully_migrated(daemon_path, agents_list, last_id):
    """Simulates a fully migrated fleet: every raw page is entirely version-filtered by remoted,
    so 'agents' is always empty but 'last_id' still advances through the raw page boundaries.

    Asserts (not just fails silently) if called more than expected -- a regression that drops the
    'last_id' fast-path would otherwise hang this test in a real infinite loop instead of failing.
    """
    calls = side_effect_test_get_daemons_stats_all_fully_migrated.history
    calls.append(last_id)
    assert len(calls) <= 5, f'pagination did not terminate; last_id history: {calls}'

    if last_id == 0:
        return {'data': {'name': SOCKET_PATH_DAEMONS_MAPPING[daemon_path], 'agents': [], 'last_id': 150},
                'message': 'due', 'error': 1}
    elif last_id == 150:
        return {'data': {'name': SOCKET_PATH_DAEMONS_MAPPING[daemon_path], 'agents': [], 'last_id': 300},
                'message': 'due', 'error': 1}
    else:
        return {'data': {'name': SOCKET_PATH_DAEMONS_MAPPING[daemon_path], 'agents': []},
                'message': 'ok', 'error': 0}


@patch('wazuh.core.common.REMOTED_SOCKET', '/var/wazuh-manager/queue/sockets/remote')
@patch('wazuh.stats.get_daemons_stats_socket', side_effect=side_effect_test_get_daemons_stats_all_fully_migrated)
def test_get_daemons_stats_all_agents_fully_migrated_fleet(mock_get_daemons_stats_socket):
    """A fully migrated fleet (every connected agent >= v5.0.0) must still terminate pagination
    using remoted's raw 'last_id', since the filtered 'agents' list never advances on its own.
    """
    side_effect_test_get_daemons_stats_all_fully_migrated.history = []

    result = stats.get_daemons_stats_agents(['wazuh-manager-remoted'], ['all'])

    calls = mock_get_daemons_stats_socket.call_args_list
    assert len(calls) == 3
    assert [c.kwargs['last_id'] for c in calls] == [0, 150, 300]

    assert result.affected_items == [{'name': 'wazuh-manager-remoted', 'agents': []}]
    assert result.total_affected_items == 1
    assert not result.failed_items


def side_effect_test_get_daemons_stats_all_mixed_due_pages(daemon_path, agents_list, last_id):
    """Mixes a 'due' page with survivors and an explicit last_id, a 'due' page with no survivors
    relying solely on last_id, and a final 'ok' page -- confirms the 'last_id' fast-path and the
    'agents[-1]["id"]' fallback don't fight each other across consecutive pages.
    """
    calls = side_effect_test_get_daemons_stats_all_mixed_due_pages.history
    calls.append(last_id)
    assert len(calls) <= 5, f'pagination did not terminate; last_id history: {calls}'

    if last_id == 0:
        return {'data': {'name': SOCKET_PATH_DAEMONS_MAPPING[daemon_path], 'agents': [{'id': 5}], 'last_id': 150},
                'message': 'due', 'error': 1}
    elif last_id == 150:
        return {'data': {'name': SOCKET_PATH_DAEMONS_MAPPING[daemon_path], 'agents': [], 'last_id': 300},
                'message': 'due', 'error': 1}
    else:
        return {'data': {'name': SOCKET_PATH_DAEMONS_MAPPING[daemon_path], 'agents': []},
                'message': 'ok', 'error': 0}


@patch('wazuh.core.common.REMOTED_SOCKET', '/var/wazuh-manager/queue/sockets/remote')
@patch('wazuh.stats.get_daemons_stats_socket', side_effect=side_effect_test_get_daemons_stats_all_mixed_due_pages)
def test_get_daemons_stats_all_agents_mixed_due_pages(mock_get_daemons_stats_socket):
    """A due page with survivors plus an explicit last_id, followed by an empty due page relying
    only on last_id, followed by a final ok page: pagination must advance correctly at each step.
    """
    side_effect_test_get_daemons_stats_all_mixed_due_pages.history = []

    result = stats.get_daemons_stats_agents(['wazuh-manager-remoted'], ['all'])

    calls = mock_get_daemons_stats_socket.call_args_list
    assert len(calls) == 3
    assert [c.kwargs['last_id'] for c in calls] == [0, 150, 300]

    assert result.affected_items == [{'name': 'wazuh-manager-remoted', 'agents': [{'id': 5}]}]
    assert result.total_affected_items == 1
    assert not result.failed_items


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

# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys
from datetime import date, datetime, timezone
from unittest.mock import MagicMock, mock_open, patch, call

import pytest

with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators
        from wazuh.core import common, stats
        from wazuh.core.exception import WazuhException, WazuhInternalError
        from wazuh.tests.util import RBAC_bypasser

        del sys.modules['wazuh.rbac.orm']
        wazuh.rbac.decorators.expose_resources = RBAC_bypasser

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data', 'stats')


@pytest.mark.parametrize('agent, daemon, expected_value', [
    (1, 'logcollector', common.REMOTED_SOCKET),
    (1, 'agent', common.REMOTED_SOCKET)
])
def test_get_stats_socket_path(agent, daemon, expected_value):
    """Verify get_stats_socket_path function works as expected"""
    assert stats.get_stats_socket_path(agent, daemon) == expected_value


@pytest.mark.parametrize('agent, daemon, next_page, expected_value', [
    (1, 'agent', False, '001 agent getstate'),
    (1, 'agent', True, '001 agent getstate next'),
])
def test_create_stats_command(agent, daemon, next_page, expected_value):
    """Verify create_stats_command function works as expected"""
    assert stats.create_stats_command(agent_id=agent, daemon=daemon, next_page=next_page) == expected_value


@pytest.mark.parametrize('agents_list, expected_socket_response, expected_result', [
    (None,
     {'timestamp': 1658400850,
      'uptime': 1658400850,
      'stats': 'value'},
     {'timestamp': datetime(2022, 7, 21, 10, 54, 10, tzinfo=timezone.utc),
      'uptime': datetime(2022, 7, 21, 10, 54, 10, tzinfo=timezone.utc),
      'stats': 'value'}),

    ([1, 2, 3],
     {'timestamp': 1658400850,
      'agents': [{'id': agent_id, 'uptime': 1658400850} for agent_id in [1, 2, 3]]},
     {'timestamp': datetime(2022, 7, 21, 10, 54, 10, tzinfo=timezone.utc),
      'agents': [{'id': agent_id, 'uptime': datetime(2022, 7, 21, 10, 54, 10, tzinfo=timezone.utc)} for agent_id in
                 [1, 2, 3]]}),

    ('all',
     {'data': {'timestamp': 1658400850,
               'agents': [{'id': agent_id, 'uptime': 1658400850} for agent_id in [1, 2, 3]]}},
     {'data': {'timestamp': datetime(2022, 7, 21, 10, 54, 10, tzinfo=timezone.utc),
               'agents': [{'id': agent_id, 'uptime': datetime(2022, 7, 21, 10, 54, 10, tzinfo=timezone.utc)} for
                          agent_id in [1, 2, 3]]}})
])
@patch('wazuh.core.wazuh_socket.WazuhSocketJSON.close')
@patch('wazuh.core.wazuh_socket.WazuhSocketJSON.send')
@patch('wazuh.core.wazuh_socket.WazuhSocketJSON.__init__', return_value=None)
def test_get_daemons_stats_socket(mock__init__, mock_send, mock_close, agents_list, expected_socket_response,
                                  expected_result):
    """Verify get_daemons_stats_socket(socket : str) function works as expected"""
    socket = '/test_path/socket'
    expected_msg = {'version': 1, 'origin': {'module': 'framework'},
                    'command': 'getagentsstats' if agents_list else 'getstats'}
    if agents_list:
        expected_msg |= {'parameters': {'agents': agents_list}}
        if agents_list == 'all':
            expected_msg['parameters'] |= {'last_id': 0}

    with patch('wazuh.core.wazuh_socket.WazuhSocketJSON.receive',
               return_value=expected_socket_response) as mock_receive:
        result = stats.get_daemons_stats_socket(socket, agents_list=agents_list,
                                                last_id=0 if agents_list == 'all' else None)

        mock__init__.assert_called_once_with(socket)
        mock_send.assert_called_once_with(expected_msg)
        mock_receive.assert_called_once()
        mock_close.assert_called_once()
        assert result == expected_result


@pytest.mark.parametrize('agents_list', [
    None, [1, 2, 3]
])
def test_get_daemons_stats_socket_ko(agents_list):
    """Test get_daemons_stats_socket(socket : str) function exception works"""
    socket = '/test_path/socket'
    with pytest.raises(WazuhInternalError, match=f".* 1121 .*: {socket}"):
        stats.get_daemons_stats_socket(socket, agents_list=agents_list)


@pytest.mark.parametrize("agent_id, daemon, response", [
    ('002', 'agent', '{"error":0, "data":{"test":0}}'),
    (3, 'test', '{"error":0, "data":{"test":0}}'),
])
def test_get_daemons_stats_from_socket(agent_id, daemon, response):
    """Check that get_daemons_stats_from_socket() function uses the expected params and returns expected result"""
    with patch('wazuh.core.wazuh_socket.WazuhSocket.__init__', return_value=None) as mock_socket:
        with patch('wazuh.core.wazuh_socket.WazuhSocket.send', side_effect=None) as mock_send:
            with patch('wazuh.core.wazuh_socket.WazuhSocket.receive', return_value=response.encode()):
                with patch('wazuh.core.wazuh_socket.WazuhSocket.close', side_effect=None):
                    stats.get_daemons_stats_from_socket(agent_id, daemon)

        mock_socket.assert_called_once_with(os.path.join(common.WAZUH_PATH, "queue", "sockets", "remote"))
        mock_send.assert_called_once_with(f"{str(agent_id).zfill(3)} {daemon} getstate".encode())


@pytest.mark.parametrize("agent_id, daemon, responses, expected, expected_socket_calls, expected_arg_calls", [
    ('001', 'logcollector', [
        '{"error":0, "remaining": true, "data":{"global": {"start": "2023-11-27 19:51:54", '
        '"end": "2023-11-27 19:52:54", "files": [1, 2]}, "interval": {}}}'.encode(),
        '{"error":0, "remaining": true, "data":{"global": {"start": "2023-11-27 19:52:54", '
        '"end": "2023-11-27 19:53:54", "files": [3, 4]}, "interval": {}}}'.encode(),
        '{"error":0, "remaining": false, "data":{"global": {"start": "2023-11-27 19:53:54", '
        '"end": "2023-11-27 19:54:54", "files": [5, 6]}, "interval": {}}}'.encode()],
     {"global": {"start": "2023-11-27T19:51:54Z", "end": "2023-11-27T19:54:54Z", "files": [1, 2, 3, 4, 5, 6]},
      "interval": {}},
     3,
     [
         call('001 logcollector getstate'.encode()),
         call('001 logcollector getstate next'.encode()),
         call('001 logcollector getstate next'.encode())]),
    ('001', 'logcollector', [
        '{"error":0, "json_updated": false, "remaining": true, "data":{"global": {"start": "2023-11-27 19:51:54", '
        '"end": "2023-11-27 19:52:54", "files": [1, 2]}, "interval": {}}}'.encode(),
        '{"error":0, "json_updated": true, "remaining": true, "data":{"global": {"start": "2023-11-27 19:52:54", '
        '"end": "2023-11-27 19:53:54", "files": [3, 4]}, "interval": {}}}'.encode(),
        '{"error":0, "json_updated": false, "remaining": false, "data":{"global": {"start": "2023-11-27 19:53:54", '
        '"end": "2023-11-27 19:54:54", "files": [5, 6]}, "interval": {}}}'.encode()],
     {"global": {"start": "2023-11-27T19:53:54Z", "end": "2023-11-27T19:54:54Z", "files": [5, 6]}, "interval": {}},
     3,
     [
         call('001 logcollector getstate'.encode()),
         call('001 logcollector getstate next'.encode()),
         call('001 logcollector getstate'.encode())]),
])
def test_get_daemons_stats_from_socket(agent_id, daemon, responses, expected, expected_socket_calls,
                                       expected_arg_calls):
    """Check that get_daemons_stats_from_socket() function uses the pagination logic"""
    with patch('wazuh.core.wazuh_socket.WazuhSocket.__init__', return_value=None) as mock_socket:
        with patch('wazuh.core.wazuh_socket.WazuhSocket.send', side_effect=None) as mock_send:
            with patch('wazuh.core.wazuh_socket.WazuhSocket.receive', side_effect=responses):
                with patch('wazuh.core.wazuh_socket.WazuhSocket.close', side_effect=None):
                    result = stats.get_daemons_stats_from_socket(agent_id, daemon)

    assert result == expected
    assert mock_send.call_count == expected_socket_calls
    mock_send.assert_has_calls(expected_arg_calls)


@pytest.mark.parametrize("data, expected", [
    ({}, {}),
    ({"start": "2023-11-27 19:51:54", "end": "2023-11-27 19:52:54", "files": [1, 2]},
     {"start": "2023-11-27T19:51:54Z", "end": "2023-11-27T19:52:54Z", "files": [1, 2]})

])
def test_pagination_handler_sets_data(data, expected):
    """Check that the PaginatedDataHandler sets the data correctly """
    test_handler = stats.PaginatedDataHandler()
    test_handler.set_data(data)

    assert expected == test_handler.to_dict()


@pytest.mark.parametrize("initial_data, data, expected", [
    ({}, {}, {}),
    ({}, {"start": "2023-11-27 19:51:54", "end": "2023-11-27 19:52:54", "files": [1, 2]},
     {"start": "2023-11-27T19:51:54Z", "end": "2023-11-27T19:52:54Z", "files": [1, 2]}),
    ({"start": "2023-11-27 19:51:54", "end": "2023-11-27 19:52:54", "files": [1, 2]},
     {"start": "2023-11-27 19:52:54", "end": "2023-11-27 19:53:54", "files": [3, 4]},
     {"start": "2023-11-27T19:51:54Z", "end": "2023-11-27T19:53:54Z", "files": [1, 2, 3, 4]}),
    ({"start": "2023-11-27 19:51:54", "end": "2023-11-27 19:52:54", "files": [1, 2]},
     {},
     {"start": "2023-11-27T19:51:54Z", "end": "2023-11-27T19:52:54Z", "files": [1, 2]})

])
def test_pagination_handler_updates_data(initial_data, data, expected):
    """Check that the PaginatedDataHandler updates the data correctly """
    test_handler = stats.PaginatedDataHandler()
    test_handler.set_data(initial_data)
    test_handler.update_data(data)

    assert expected == test_handler.to_dict()

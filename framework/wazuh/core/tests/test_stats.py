# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys
from datetime import date, datetime, timezone
from unittest.mock import MagicMock, mock_open, patch

import pytest

with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators
        from wazuh.core import common, stats
        from wazuh.core.exception import WazuhError, WazuhException, WazuhInternalError
        from wazuh.tests.util import RBAC_bypasser

        del sys.modules['wazuh.rbac.orm']
        wazuh.rbac.decorators.expose_resources = RBAC_bypasser

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data', 'stats')


@pytest.mark.parametrize('date_', [date(2005, 5, 5)])
def test_totals_(date_):
    """Verify totals_() function works as expected"""
    data_ = '1-2-3-4\n22-34-5-3\n15--107--1483--1257--0'
    with patch("builtins.open", mock_open(read_data=data_)):
        affected = stats.totals_(date_)
        if affected:
            for line in data_:
                data = line.split('-')
                if len(data) == 4:
                    assert int(data[1]) == affected[0]['alerts'][0]['sigid']
                    assert int(data[2]) == affected[0]['alerts'][0]['level'], 'Data do not match'
                    assert int(data[3]) == affected[0]['alerts'][0]['times'], 'Data do not match'
                else:
                    data = line.split('--')
                    if len(data) == 5:
                        assert int(data[0]) == affected[0]['hour'], 'Data do not match'
                        assert int(data[1]) == affected[0]['totalAlerts'], 'Data do not match'
                        assert int(data[2]) == affected[0]['events'], 'Data do not match'
                        assert int(data[3]) == affected[0]['syscheck'], 'Data do not match'
                        assert int(data[4]) == affected[0]['firewall'], 'Data do not match'


def test_totals_ko_():
    """Verify totals_() function exception with data problems works"""
    with patch('wazuh.core.stats.open', side_effect=IOError):
        with pytest.raises(WazuhException, match=".* 1308 .*"):
            stats.totals_(date(1996, 8, 13))

    with patch("builtins.open", mock_open(read_data='15-571-3-2\n15--107--1483')):
        with pytest.raises(WazuhInternalError, match=".* 1309 .*"):
            stats.totals_(date(1996, 8, 13))


@patch('wazuh.core.common.STATS_PATH', new=test_data_path)
def test_weekly_():
    """Verify weekly_() function works as expected"""
    result = stats.weekly_()
    assert 0 == result[0]['Sun']['interactions'], 'Data do not match'
    for day in "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat":
        assert day in [d for r in result for d in r.keys()], 'Data do not match'


@patch('wazuh.core.common.STATS_PATH', new='')
def test_weekly_data():
    """Verify weekly_() function works as expected"""
    result = stats.weekly_()
    days = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]
    for day in days:
        for i in range(24):
            assert 0 == result[days.index(day)][day]['hours'][i]
        assert 0 == result[days.index(day)][day]['interactions']


@patch('wazuh.core.common.STATS_PATH', new=test_data_path)
def test_hourly_():
    """Verify hourly_() function works as expected"""
    result = stats.hourly_()
    assert 24 == result[0]['interactions'], 'Data do not match'
    for hour in range(24):
        assert hour in result[0]['averages'], 'Data do not match'


@patch('wazuh.core.common.STATS_PATH', new='')
def test_hourly_data():
    """Test hourly_() function exceptions works"""
    result = stats.hourly_()
    for average in result[0]['averages']:
        assert average == 0, 'Data do not match'
    assert result[0]['interactions'] == 0


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


def test_get_daemons_stats_():
    """Verify get_daemons_stats_() function works as expected"""
    with patch("builtins.open", mock_open(read_data='# Queue size\nqueue_size=\'0\'')):
        result = stats.get_daemons_stats_('')
        assert result[0] == {'queue_size': 0}


def test_get_daemons_stats_ko():
    """Test get_daemons_stats_() function exceptions works"""
    with patch('wazuh.core.stats.open', side_effect=IOError):
        with pytest.raises(WazuhException, match=".* 1308 .*"):
            stats.get_daemons_stats_('filename')

    with patch('wazuh.core.stats.open'):
        with pytest.raises(WazuhInternalError, match=".* 1104 .*"):
            stats.get_daemons_stats_('filename')


@pytest.mark.parametrize("agent_id, daemon, response", [
    ('000', 'logcollector', '{"error":0, "data":{"test":0}}'),
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

        if agent_id == '000':
            mock_socket.assert_called_once_with(os.path.join(common.WAZUH_PATH, "queue", "sockets", "logcollector"))
            mock_send.assert_called_once_with(b'getstate')
        else:
            mock_socket.assert_called_once_with(os.path.join(common.WAZUH_PATH, "queue", "sockets", "remote"))
            mock_send.assert_called_once_with(f"{str(agent_id).zfill(3)} {daemon} getstate".encode())


def test_get_daemons_stats_from_socket_ko():
    """Check if get_daemons_stats_from_socket() raises expected exceptions."""
    with pytest.raises(WazuhError, match=r'\b1307\b'):
        stats.get_daemons_stats_from_socket(None, None)

    with pytest.raises(WazuhError, match=r'\b1310\b'):
        stats.get_daemons_stats_from_socket('000', 'agent')

    with pytest.raises(WazuhInternalError, match=r'\b1121\b'):
        stats.get_daemons_stats_from_socket('000', 'logcollector')

    with patch('wazuh.core.wazuh_socket.WazuhSocket.__init__', return_value=None):
        with patch('wazuh.core.wazuh_socket.WazuhSocket.send', side_effect=None):
            with patch('wazuh.core.wazuh_socket.WazuhSocket.receive', side_effect=ValueError):
                with pytest.raises(WazuhInternalError, match=r'\b1118\b'):
                    stats.get_daemons_stats_from_socket('000', 'logcollector')

            with patch('wazuh.core.wazuh_socket.WazuhSocket.receive', return_value="err Error message test".encode()):
                with patch('wazuh.core.wazuh_socket.WazuhSocket.close', side_effect=None):
                    with pytest.raises(WazuhError, match=r'\b1117\b'):
                        stats.get_daemons_stats_from_socket('000', 'logcollector')

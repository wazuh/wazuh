# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys
from datetime import date
from unittest.mock import MagicMock, patch

import pytest

with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators
        from wazuh.core import common, stats
        from wazuh.core.exception import (WazuhError, WazuhException,
                                          WazuhInternalError)
        from wazuh.tests.util import RBAC_bypasser

        del sys.modules['wazuh.rbac.orm']
        wazuh.rbac.decorators.expose_resources = RBAC_bypasser

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data', 'stats')


@pytest.mark.parametrize('date_, data_list', [
    (date(2019, 8, 13), ['15-571-3-2', '15--107--1483--1257--0']),
    (date(2019, 8, 13), ['15-571-3-2']),
    (date(2019, 8, 13), ['15--107--1483--1257--0']),
    (date(2019, 8, 13), ['15'])
])
@patch('wazuh.core.stats.common.stats_path', new=test_data_path)
def test_totals_(date_, data_list):
    """Verify totals_() function works as expected"""
    with patch('wazuh.core.stats.open', return_value=data_list):
        failed, affected = stats.totals_(date_)
        if affected:
            for line in data_list:
                data = line.split('-')
                print(data)
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

    with patch('wazuh.core.stats.open', return_value=['15-571-3-2', '15--107--1483']):
        result = stats.totals_(date(1996, 8, 13))
        assert result[0]


@patch('wazuh.core.common.stats_path', new=test_data_path)
def test_weekly_():
    """Verify weekly_() function works as expected"""
    result = stats.weekly_()
    assert 0 == result[0]['Sun']['interactions'], 'Data do not match'
    for day in "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat":
        assert day in [d for r in result for d in r.keys()], 'Data do not match'


@patch('wazuh.core.common.stats_path', new=test_data_path)
def test_hourly_():
    """Verify hourly_() function works as expected"""
    result = stats.hourly_()
    assert 24 == result[0]['interactions'], 'Data do not match'
    for hour in range(24):
        assert hour in result[0]['averages'], 'Data do not match'


@patch('wazuh.core.stats.open')
@patch('wazuh.core.stats.configparser.RawConfigParser.read_file')
@patch('wazuh.core.stats.configparser.RawConfigParser.items', return_value={'hour': "'5'"})
def test_get_daemons_stats_(mock_items, mock_read, mock_open):
    """Verify get_daemons_stats_() function works as expected"""
    result = stats.get_daemons_stats_('filename')
    assert result[0] == {'hour': 5.0}
    mock_open.assert_called_once_with('filename', mode='r')


@patch('wazuh.core.stats.configparser.RawConfigParser.read_file')
def test_get_daemons_stats_ko(mock_readfp):
    """Tests get_daemons_stats_() function exceptions works"""
    with patch('wazuh.core.stats.open', side_effect=IOError):
        with pytest.raises(WazuhException, match=".* 1308 .*"):
            stats.get_daemons_stats_('filename')
    with patch('wazuh.core.stats.open'):
        with patch('wazuh.core.stats.configparser.RawConfigParser.items', return_value={'hour': 5}):
            response = stats.get_daemons_stats_('filename')
            assert isinstance(response, WazuhException), 'The result is not WazuhResult type'
            assert response.code == 1104, 'Response code is not the same'


@pytest.mark.parametrize('component', [
    'logcollector', 'test'
])
@patch('wazuh.core.agent.Agent.get_stats')
@patch('wazuh.core.agent.get_agents_info', return_value=['001'])
def test_get_agents_component_stats_json_(mock_agents_info, mock_getstats, component):
    """Verify get_agents_component_stats_() function works as expected"""
    failed, affected = stats.get_agents_component_stats_json_(agent_list=['001'], component=component)
    mock_getstats.assert_called_once_with(component=component)


@patch('wazuh.core.agent.Agent.get_stats')
@patch('wazuh.core.agent.get_agents_info', return_value=['001'])
def test_get_agents_component_stats_json_ko(mock_agents_info, mock_getstats):
    """Tests get_agents_component_stats_() function exceptions works"""
    failed, affected = stats.get_agents_component_stats_json_(agent_list=['003', '005'], component='logcollector')
    for item in failed:
        assert 1701 == item[1]._code


@pytest.mark.parametrize("agent_id, daemon, response", [
    ('000', 'logcollector', '{"error":0, "data":{"test":0}}'),
    ('002', 'agent', '{"error":0, "data":{"test":0}}'),
    (3, 'test', '{"error":0, "data":{"test":0}}'),
])
def test_get_daemons_stats_from_socket(agent_id, daemon, response):
    """Check that get_daemons_stats_from_socket() function uses the expected params and returns expected result"""
    with patch('wazuh.core.stats.WazuhSocket.__init__', return_value=None) as mock_socket:
        with patch('wazuh.core.stats.WazuhSocket.send', side_effect=None) as mock_send:
            with patch('wazuh.core.stats.WazuhSocket.receive', return_value=response.encode()):
                with patch('wazuh.core.stats.WazuhSocket.close', side_effect=None):
                    stats.get_daemons_stats_from_socket(agent_id, daemon)

        if agent_id == '000':
            mock_socket.assert_called_once_with(os.path.join(common.wazuh_path, "queue", "sockets", "logcollector"))
            mock_send.assert_called_once_with(b'getstate')
        else:
            mock_socket.assert_called_once_with(os.path.join(common.wazuh_path, "queue", "sockets", "request"))
            mock_send.assert_called_once_with(f"{str(agent_id).zfill(3)} {daemon} getstate".encode())


def test_get_daemons_stats_from_socket_ko():
    """Check if get_daemons_stats_from_socket() raises expected exceptions."""
    with pytest.raises(WazuhError, match=r'\b1307\b'):
        stats.get_daemons_stats_from_socket(None, None)

    with pytest.raises(WazuhError, match=r'\b1310\b'):
        stats.get_daemons_stats_from_socket('000', 'agent')

    with pytest.raises(WazuhInternalError, match=r'\b1121\b'):
        stats.get_daemons_stats_from_socket('000', 'logcollector')

    with patch('wazuh.core.stats.WazuhSocket.__init__', return_value=None):
        with patch('wazuh.core.stats.WazuhSocket.send', side_effect=None):
            with patch('wazuh.core.configuration.WazuhSocket.receive', side_effect=ValueError):
                with pytest.raises(WazuhInternalError, match=r'\b1118\b'):
                    stats.get_daemons_stats_from_socket('000', 'logcollector')

            with patch('wazuh.core.configuration.WazuhSocket.receive', return_value="err Error message test".encode()):
                with patch('wazuh.core.stats.WazuhSocket.close', side_effect=None):
                    with pytest.raises(WazuhError, match=r'\b1117\b'):
                        stats.get_daemons_stats_from_socket('000', 'logcollector')

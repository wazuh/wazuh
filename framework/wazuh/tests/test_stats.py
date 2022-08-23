# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import sys
from datetime import date
from unittest.mock import call, MagicMock, patch

import pytest

with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators
        import wazuh.stats as stats
        from wazuh.core.results import AffectedItemsWazuhResult
        from wazuh.tests.util import RBAC_bypasser

        del sys.modules['wazuh.rbac.orm']
        wazuh.rbac.decorators.expose_resources = RBAC_bypasser


def test_totals():
    """Verify totals() function works and returns correct data"""
    with patch('wazuh.stats.totals_', return_value=({})):
        response = stats.totals(date(2019, 8, 13))
        assert response.total_affected_items == len(response.affected_items)
        assert isinstance(response, AffectedItemsWazuhResult), 'The result is not WazuhResult type'


def test_hourly():
    """Makes sure hourly() fit with the expected."""
    response = stats.hourly()
    assert isinstance(response, AffectedItemsWazuhResult), 'The result is not WazuhResult type'
    assert response.total_affected_items == len(response.affected_items)


def test_weekly():
    """Makes sure weekly() fit with the expected."""
    response = stats.weekly()
    assert isinstance(response, AffectedItemsWazuhResult), 'The result is not WazuhResult type'
    assert response.total_affected_items == len(response.affected_items)


@patch('wazuh.core.common.REMOTED_SOCKET', '/var/ossec/queue/sockets/remote')
@patch('wazuh.core.common.ANALYSISD_SOCKET', '/var/ossec/queue/sockets/analysis')
@patch('wazuh.core.common.WDB_SOCKET', '/var/ossec/queue/db/wdb')
@patch('wazuh.stats.get_daemons_stats_socket')
def test_get_daemons_stats(mock_get_daemons_stats_socket):
    """Makes sure get_daemons_stats() fit with the expected."""
    response = stats.get_daemons_stats(['wazuh-remoted', 'wazuh-analysisd', 'wazuh-db'])

    calls = [call('/var/ossec/queue/sockets/remote'), call('/var/ossec/queue/sockets/analysis'),
             call('/var/ossec/queue/db/wdb')]
    mock_get_daemons_stats_socket.assert_has_calls(calls)
    assert isinstance(response, AffectedItemsWazuhResult), 'The result is not AffectedItemsWazuhResult type'
    assert response.total_affected_items == len(response.affected_items)


@patch('wazuh.core.common.REMOTED_SOCKET', '/var/ossec/queue/sockets/wrong_socket_name')
def test_get_daemons_stats_ko():
    """Makes sure get_daemons_stats() fit with the expected."""
    response = stats.get_daemons_stats(['wazuh-remoted'])

    assert isinstance(response, AffectedItemsWazuhResult), 'The result is not AffectedItemsWazuhResult type'
    assert response.render()['data']['failed_items'][0]['error']['code'] == 1121, 'Expected error code was not returned'


@patch('wazuh.stats.get_daemons_stats_', return_value=[{"events_decoded": 1.0}])
def test_deprecated_get_daemons_stats(mock_daemons_stats_):
    """Makes sure deprecated_get_daemons_stats() fit with the expected."""
    response = stats.deprecated_get_daemons_stats('filename')
    assert isinstance(response, AffectedItemsWazuhResult), 'The result is not WazuhResult type'
    assert response.total_affected_items == len(response.affected_items)


@pytest.mark.parametrize('component', [
    'logcollector', 'test'
])
@patch('wazuh.core.agent.Agent.get_stats')
@patch('wazuh.stats.get_agents_info', return_value=['000', '001'])
def test_get_agents_component_stats_json(mock_agents_info, mock_getstats, component):
    """Test `get_agents_component_stats_json` function from agent module."""
    response = stats.get_agents_component_stats_json(agent_list=['001'], component=component)
    assert isinstance(response, AffectedItemsWazuhResult), 'The result is not AffectedItemsWazuhResult type'
    mock_getstats.assert_called_once_with(component=component)


@patch('wazuh.core.agent.Agent.get_stats')
@patch('wazuh.stats.get_agents_info', return_value=['000', '001'])
def test_get_agents_component_stats_json_ko(mock_agents_info, mock_getstats):
    """Test `get_agents_component_stats_json` function from agent module."""
    response = stats.get_agents_component_stats_json(agent_list=['003'], component='logcollector')
    assert isinstance(response, AffectedItemsWazuhResult), 'The result is not AffectedItemsWazuhResult type'
    assert response.render()['data']['failed_items'][0]['error']['code'] == 1701, 'Expected error code was not returned'

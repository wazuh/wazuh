# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import sys
from datetime import date
from unittest.mock import MagicMock, patch

import pytest

with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators
        import wazuh.stats as stats
        from wazuh.core.exception import WazuhInternalError
        from wazuh.core.results import AffectedItemsWazuhResult
        from wazuh.tests.util import RBAC_bypasser

        del sys.modules['wazuh.rbac.orm']
        wazuh.rbac.decorators.expose_resources = RBAC_bypasser


@patch('wazuh.core.results.AffectedItemsWazuhResult.add_failed_item')
def test_totals(mock_add_failed_item):
    """Verify totals() function works and returns correct data"""
    with patch('wazuh.stats.totals_', return_value=(False, {})):
        response = stats.totals(date(2019, 8, 13))
        assert response.total_affected_items == len(response.affected_items)
        assert isinstance(response, AffectedItemsWazuhResult), 'The result is not WazuhResult type'
    with patch('wazuh.stats.totals_', return_value=(True, {})):
        stats.totals(date(2019, 8, 13))
        mock_add_failed_item.assert_called_with(id_=stats.node_id if stats.cluster_enabled else 'manager',
                                                error=WazuhInternalError(1309))


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


@patch('wazuh.stats.get_daemons_stats_', return_value=[{"events_decoded": 1.0}])
def test_get_daemons_stats(mock_daemons_stats_):
    """Makes sure get_daemons_stats() fit with the expected."""
    response = stats.get_daemons_stats('filename')
    assert isinstance(response, AffectedItemsWazuhResult), 'The result is not WazuhResult type'
    assert response.total_affected_items == len(response.affected_items)


@pytest.mark.parametrize('component', [
    'logcollector', 'test'
])
@patch('wazuh.core.agent.Agent.get_stats')
@patch('wazuh.core.agent.get_agents_info', return_value=['001'])
def test_get_agents_component_stats_json(mock_agents_info, mock_getstats, component):
    """Makes sure get_agents_component_stats_json() fit with the expected."""
    response = stats.get_agents_component_stats_json(agent_list=['001'], component=component)
    assert isinstance(response, AffectedItemsWazuhResult), 'The result is not WazuhResult type'
    assert response.total_affected_items == len(response.affected_items)


@patch('wazuh.stats.get_agents_component_stats_json_', return_value=[
    [('001', 1701)],
    ''
    ])
@patch('wazuh.core.results.AffectedItemsWazuhResult.add_failed_item')
def test_get_agents_components_stats_json_ko(mock_add_failed_item, mock_get_agents_component_stats_json_):
    """Makes sure get_agents_component_stats_json() fit with the expected."""
    stats.get_agents_component_stats_json(agent_list=['001'], component='')
    mock_add_failed_item.assert_called_with(id_='001', error=1701)

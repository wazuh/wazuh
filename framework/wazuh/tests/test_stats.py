# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys
from datetime import date
<<<<<<< HEAD
from unittest.mock import patch, MagicMock
=======
from unittest.mock import MagicMock, patch
>>>>>>> master

import pytest

with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
<<<<<<< HEAD
        with patch('wazuh.core.common.manager_conf',
                   new=os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data', 'manager_base.conf')):
            sys.modules['wazuh.rbac.orm'] = MagicMock()
            import wazuh.rbac.decorators
            del sys.modules['wazuh.rbac.orm']

            from wazuh.tests.util import RBAC_bypasser
            wazuh.rbac.decorators.expose_resources = RBAC_bypasser
            from wazuh.stats import *

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data', 'stats')


@pytest.mark.parametrize('date_, data_list', [
    (date(2019, 8, 13), ['15-571-3-2', '15--107--1483--1257--0']),
    (date(2019, 8, 13), ['15-571-3-2']),
    (date(2019, 8, 13), ['15--107--1483--1257--0']),
    (date(2019, 8, 13), ['15'])
])
@patch('wazuh.stats.common.stats_path', new=test_data_path)
def test_totals(date_, data_list):
    """Verify totals() function works returns and correct data

    Checks data type of returned data. Then makes sure that data returned fit
    with the expected.

    Parameters
    ----------
    date_ : str
        Date used to locate file stats.
    data_list : list
        Data to use instead of the original files.
    """
    with patch('wazuh.stats.open', return_value=data_list):
        response = totals(date_)

        assert isinstance(response, AffectedItemsWazuhResult), f'The result is not WazuhResult type'

        if response.affected_items:
            for line in data_list:
                data = line.split('-')
                if len(data) == 4:
                    assert int(data[1]) == response.affected_items[0]['alerts'][0]['sigid'], f'Data do not match'
                    assert int(data[2]) == response.affected_items[0]['alerts'][0]['level'], f'Data do not match'
                    assert int(data[3]) == response.affected_items[0]['alerts'][0]['times'], f'Data do not match'
                else:
                    data = line.split('--')
                    if len(data) == 5:
                        assert int(data[0]) == response.affected_items[0]['hour'], f'Data do not match'
                        assert int(data[1]) == response.affected_items[0]['totalAlerts'], f'Data do not match'
                        assert int(data[2]) == response.affected_items[0]['events'], f'Data do not match'
                        assert int(data[3]) == response.affected_items[0]['syscheck'], f'Data do not match'
                        assert int(data[4]) == response.affected_items[0]['firewall'], f'Data do not match'


def test_totals_ko_data():
    """Tests totals function exception with data problems works"""
    with patch('wazuh.stats.open', side_effect=IOError):
        with pytest.raises(WazuhException, match=".* 1308 .*"):
            totals(date(1996, 8, 13))

    with patch('wazuh.stats.open', return_value=['15-571-3-2', '15--107--1483']):
        result = totals(date(1996, 8, 13))
        assert not result.affected_items
        assert next(iter(result.failed_items)).code == 1309


@pytest.mark.parametrize('effect', [
    None,
    IOError,
])
def test_hourly(effect):
    """Tests hourly() function works and returns correct data

    Parameters
    ----------
    effect : exception
        Exception expected when opening stats file
    """
    with patch('wazuh.stats.open', side_effect=effect):
        response = hourly()
        assert isinstance(response, AffectedItemsWazuhResult), f'The result is not WazuhResult type'

=======
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators
        import wazuh.stats as stats
        from wazuh.core.results import AffectedItemsWazuhResult
        from wazuh.tests.util import RBAC_bypasser
>>>>>>> master

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

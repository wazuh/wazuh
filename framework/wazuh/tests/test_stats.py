# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys
from datetime import date
from unittest.mock import MagicMock, patch

import pytest
from wazuh.core.exception import WazuhException

with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators
        import wazuh.stats as stats
        from wazuh.core.results import AffectedItemsWazuhResult
        from wazuh.tests.util import RBAC_bypasser

        del sys.modules['wazuh.rbac.orm']
        wazuh.rbac.decorators.expose_resources = RBAC_bypasser

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data', 'stats')

# ' @pytest.mark.parametrize('date_, data_list', [
# '     (date(2019, 8, 13), ['15-571-3-2', '15--107--1483--1257--0']),
# '     (date(2019, 8, 13), ['15-571-3-2']),
# '     (date(2019, 8, 13), ['15--107--1483--1257--0']),
# '     (date(2019, 8, 13), ['15'])
# ' ])
# ' @patch('wazuh.stats.common.stats_path', new=test_data_path)
# ' def test_totals(date_, data_list):
# '     """Verify totals() function works returns and correct data
# ' 
# '     Checks data type of returned data. Then makes sure that data returned fit
# '     with the expected.
# ' 
# '     Parameters
# '     ----------
# '     date_ : str
# '         Date used to locate file stats.
# '     data_list : list
# '         Data to use instead of the original files.
# '     """
# '     with patch('wazuh.stats.open', return_value=data_list):
# '         response = stats.totals(date_)
# ' 
# '         assert isinstance(response, AffectedItemsWazuhResult), 'The result is not WazuhResult type'
# ' 
# '         if response.affected_items:
# '             for line in data_list:
# '                 data = line.split('-')
# '                 if len(data) == 4:
# '                     assert int(data[1]) == response.affected_items[0]['alerts'][0]['sigid'], 'Data do not match'
# '                     assert int(data[2]) == response.affected_items[0]['alerts'][0]['level'], 'Data do not match'
# '                     assert int(data[3]) == response.affected_items[0]['alerts'][0]['times'], 'Data do not match'
# '                 else:
# '                     data = line.split('--')
# '                     if len(data) == 5:
# '                         assert int(data[0]) == response.affected_items[0]['hour'], 'Data do not match'
# '                         assert int(data[1]) == response.affected_items[0]['totalAlerts'], 'Data do not match'
# '                         assert int(data[2]) == response.affected_items[0]['events'], 'Data do not match'
# '                         assert int(data[3]) == response.affected_items[0]['syscheck'], 'Data do not match'
# '                         assert int(data[4]) == response.affected_items[0]['firewall'], 'Data do not match'
# ' 
# ' 
# ' def test_totals_ko_data():
# '     """Tests totals function exception with data problems works"""
# '     with patch('wazuh.stats.open', side_effect=IOError):
# '         with pytest.raises(WazuhException, match=".* 1308 .*"):
# '             totals(date(1996, 8, 13))
# ' 
# '     with patch('wazuh.stats.open', return_value=['15-571-3-2', '15--107--1483']):
# '         result = totals(date(1996, 8, 13))
# '         assert not result.affected_items
# '         assert next(iter(result.failed_items)).code == 1309


@patch('wazuh.core.common.stats_path', new=test_data_path)
def test_hourly():
    """Makes sure that data returned by hourly() fit with the expected."""
    response = stats.hourly()
    assert isinstance(response, AffectedItemsWazuhResult), 'The result is not WazuhResult type'
    assert 24 == response.affected_items[0]['interactions'], 'Data do not match'
    for hour in range(24):
        assert hour in response.affected_items[0]['averages'], 'Data do not match'


@patch('wazuh.core.common.stats_path', new=test_data_path)
def test_weekly():
    """Makes sure that data returned by weekly() fit with the expected."""
    response = stats.weekly()
    assert isinstance(response, AffectedItemsWazuhResult), 'The result is not WazuhResult type'
    assert 0 == response.affected_items[0]['Sun']['interactions'], 'Data do not match'
    for day in "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat":
        assert day in {d for affected_item in response.affected_items for d in affected_item.keys()}, \
            'Data do not match'


@patch('wazuh.stats.get_daemons_stats_', return_value=[{"events_decoded": 1.0}])
def test_get_daemons_stats(mock_daemons_stats):
    """Tests get_daemons_stats function works"""
    response = stats.get_daemons_stats('')
    assert isinstance(response, AffectedItemsWazuhResult), 'The result is not WazuhResult type'


@pytest.mark.parametrize('component', [
    'logcollector', 'test'
])
@patch('wazuh.core.agent.Agent.get_stats')
@patch('wazuh.core.stats.agent_core.get_agents_info', return_value=['001'])
def test_get_agents_component_stats_json(mock_agents_info, mock_getstats, component):
    """Test `get_agents_component_stats_json` function from agent module."""
    response = stats.get_agents_component_stats_json(agent_list=['001'], component=component)
    assert isinstance(response, AffectedItemsWazuhResult), 'The result is not WazuhResult type'

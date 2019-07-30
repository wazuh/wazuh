# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from unittest.mock import patch, MagicMock
import pytest

from wazuh.stats import *
from wazuh.exception import WazuhException


@pytest.mark.parametrize('year, month, day, data', [
    (2019, "Aug", 13, ['15-571-3-2', '15--107--1483--1257--0']),
    (2019, "Aug", 13, ['15-571-3-2']),
    (2019, "Aug", 13, ['15--107--1483--1257--0']),
    (2019, "Aug", 13, ['15'])
])
@patch('wazuh.stats.common.stats_path', new='/stats')
def test_totals(year, month, day, data):
    """Tests totals function works"""

    with patch('wazuh.stats.open', return_value=data):
        response = totals(year, month, day)

        assert isinstance(response, list)


@pytest.mark.parametrize('year, month, day, expected_exception', [
    (-1, "Aug", 0, 1307),
    (1, "Aug", 32, 1307),
    ("First", "Aug", 13, 1307),
    (2019, "Test", 13, 1307),
    (2019, 13, 13, 1307),
    (2019, 12, 13, 1307)
])
@patch('wazuh.stats.MONTHS', new=['One', 'Two'])
def test_totals_ko_date(year, month, day, expected_exception):
    """Tests totals function exception with date problems works"""

    with pytest.raises(WazuhException, match=f'.* {expected_exception} .*'):
        totals(year, month, day)


def test_totals_ko_data():
    """Tests totals function exception with data problems works"""

    with patch('wazuh.stats.open', side_effect=IOError):
        with pytest.raises(WazuhException, match=".* 1308 .*"):
            totals(1996, "Aug", 13)

    with patch('wazuh.stats.open', return_value=['15-571-3-2', '15--107--1483']):
        with pytest.raises(WazuhException, match=".* 1309 .*"):
            totals(1996, "Aug", 13)


@pytest.mark.parametrize('effect', [
    None,
    IOError
])
def test_hourly(effect):
    """Tests hourly function works"""

    with patch('wazuh.stats.open', side_effect=effect):
        response = hourly()

        assert isinstance(response, dict)


@pytest.mark.parametrize('effect', [
    None,
    IOError
])
def test_weekly(effect):
    """Tests weekly function works"""

    with patch('wazuh.stats.open', side_effect=effect):
        response = weekly()

        assert isinstance(response, dict)


@patch('wazuh.stats.open')
@patch('wazuh.stats.configparser.RawConfigParser.readfp')
@patch('wazuh.stats.configparser.RawConfigParser.items', return_value={'hour':"'5'"})
def test_get_daemons_stats(mock_items, mock_readfp, mock_open):
    """Tests get_daemons_stats function works"""

    response = get_daemons_stats('filename')

    assert isinstance(response, dict)
    mock_open.assert_called_once_with('filename', 'r')


@patch('wazuh.stats.configparser.RawConfigParser.readfp')
def test_get_daemons_stats_ko(mock_readfp):
    """Tests get_daemons_stats function exceptions works"""

    with patch('wazuh.stats.open', side_effect=Exception):
        with pytest.raises(WazuhException, match=".* 1308 .*"):
            get_daemons_stats('filename')

    with patch('wazuh.stats.open'):
        with patch('wazuh.stats.configparser.RawConfigParser.items', return_value={'hour':5}):
            #with pytest.raises(WazuhException, match=".* 1104 .*"):
            response = get_daemons_stats('filename')

            assert isinstance(response, WazuhException)
            assert response.code == 1104


@patch('wazuh.stats.get_daemons_stats')
def test_analysisd(mock_daemon_stats):
    """Tests analysisd function works"""

    analysisd()

    mock_daemon_stats.assert_called_once_with(common.analysisd_stats)


@patch('wazuh.stats.get_daemons_stats')
def test_remoted(mock_daemon_stats):
    """Tests remoted function works"""

    remoted()

    mock_daemon_stats.assert_called_once_with(common.remoted_stats)

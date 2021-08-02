# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh.core.common import date_format
from unittest.mock import patch, ANY
from datetime import datetime
import pytest

with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
        from wazuh.core import syscheck


@pytest.mark.parametrize('agent', ['002', '080'])
@patch("wazuh.core.syscheck.WazuhDBBackend")
@patch("wazuh.core.syscheck.WazuhDBQuery.__init__")
def test_WazuhDBQuerySyscheck_init(mock_wdbquery, mock_backend, agent):
    """Test if WazuhDBQuery and WazuhDBBackend are called with the expected parameters.

    Parameters
    ----------
    agent: str
        The agent to test.
    """
    syscheck.WazuhDBQuerySyscheck(agent)
    mock_backend.assert_called_with(agent)
    mock_wdbquery.assert_called_with(backend=ANY, default_sort_field='mtime', min_select_fields=set(), count=True,
                                     get_data=True, date_fields={'mtime', 'date'})


@patch("wazuh.core.syscheck.WazuhDBBackend")
def test_WazuhDBSyscheck_format_data_into_dictionary(mock_backend):
    """Test if _format_data_into_dictionary() returns the expected element."""
    test = syscheck.WazuhDBQuerySyscheck('002', offset=0, limit=1000, sort=None, search='test',
                                         select=['end', 'start', 'module', 'date', 'mtime'],
                                         filters={}, table='pm_event', query='',
                                         fields={'end': 'end_scan', 'start': 'start_scan', 'module': 'module',
                                                 'date': 'date', 'mtime': 'mtime'})
    test._add_select_to_query()
    test._data = [{'end': 1603648351, 'start': 1603645251, 'module': 'api', 'date': 1627893702, 'mtime': 1627893600}]
    result = test._format_data_into_dictionary()

    assert result['items'][0]['end'] == datetime.utcfromtimestamp(1603648351) and \
           result['items'][0]['start'] == datetime.utcfromtimestamp(1603645251) and \
           result['items'][0]['module'] == 'api' and \
           result['items'][0]['date'] == datetime.utcfromtimestamp(1627893702) and \
           result['items'][0]['mtime'] == datetime.utcfromtimestamp(1627893600)

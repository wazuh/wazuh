#!/usr/bin/env python
# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
from wazuh import syscollector
from unittest.mock import patch
import pytest
from wazuh import common
import os
from wazuh.exception import WazuhException

# MOCK DATA
item_agent_response = [{'scan_id': 421876105, 'mac': '02:42:ac:14:00:02', 'rx_bytes': 1156817, 'name': 'eth0', 'rx_packets': 3888, 'tx_packets': 1773, 'mtu': 1500, 'rx_dropped': 0, 'tx_bytes': 592450, 'tx_errors': 0, 'scan_time': '2019/07/02 07:14:50', 'tx_dropped': 0, 'type': 'ethernet', 'state': 'up', 'rx_errors': 0}]


@pytest.mark.parametrize("select, valid_select_fields, search, array, response, total", [
    ({'fields':{'rx_bytes', 'mac'}}, {'rx_bytes', 'tx_bytes', 'scan_id', 'mac'}, {}, True, item_agent_response, '1'),
    ({}, {'rx_bytes', 'tx_bytes', 'scan_id', 'mac'}, {}, False, {}, '0'),
    ({}, {'rx_bytes', 'tx_bytes', 'scan_id', 'mac'}, {'fields':{'rx_bytes', 'mac'}}, False, item_agent_response, '1')
])
@patch("wazuh.syscollector.Agent.get_basic_information", return_value=None)
def test_get_item_agent(mock_agent_info, select, valid_select_fields, search, array, response, total):
    with patch ("wazuh.syscollector.Agent._load_info_from_agent_db", return_value=[response, total]):
        results = syscollector.get_item_agent(agent_id='001', offset=0, limit=None, select=select,
                                              search=search, sort={}, filters={}, allowed_sort_fields={},
                                              valid_select_fields=valid_select_fields, table='sys_osinfo', nested=False, array=array)

    assert isinstance(results, dict)


@pytest.mark.parametrize("select, valid_select_fields, sort, allowed_sort_fields, expected_exception", [
    ({'fields':{'hostname'}}, {'hostname'}, {'fields':{'error'}}, {'os_name', 'hostname', 'architecture'}, 1403),
    ({'fields':{'error'}}, {'hostname', 'os_version', 'os_name', 'architecture'}, {'fields':{}}, {}, 1724),
    ({'fields':{}}, {'hostname', 'os_version', 'os_name', 'architecture'}, {'fields':{}}, {}, 1724)
])
@patch("wazuh.syscollector.Agent.get_basic_information", return_value=None)
def test_failed_get_item_agent(mock_agent_info, select, valid_select_fields, sort, allowed_sort_fields, expected_exception):
    with pytest.raises(WazuhException, match=f'.* {expected_exception} .*'):
        syscollector.get_item_agent(agent_id='001', offset=0, limit=500, select=select,
                                    search={}, sort=sort, filters={}, allowed_sort_fields=allowed_sort_fields,
                                    valid_select_fields=valid_select_fields, table='sys_osinfo', nested=False)
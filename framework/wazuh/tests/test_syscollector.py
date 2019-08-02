#!/usr/bin/env python
# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from unittest.mock import patch
import pytest

with patch('wazuh.common.ossec_uid'):
    with patch('wazuh.common.ossec_gid'):
        from wazuh import common
        from wazuh import syscollector
        from wazuh.exception import WazuhException

# MOCK DATA
item_agent_response = [{'scan_id': 421876105, 'mac': '02:42:ac:14:00:02', 'rx_bytes': 1156817, 'name': 'eth0', 'rx_packets': 3888, 'tx_packets': 1773, 'mtu': 1500, 'rx_dropped': 0, 'tx_bytes': 592450, 'tx_errors': 0, 'scan_time': '2019/07/02 07:14:50', 'tx_dropped': 0, 'type': 'ethernet', 'state': 'up', 'rx_errors': 0}]

dict_agent_response = {
    "rx_bytes": 519287,
    "rx_dropped": 0,
    "rx_errors": 0,
    "rx_packets": 1040,
    "scan_id": 463920853,
    "scan_time": "2019/04/26 09:31:17",
    "tx_bytes": 61245,
    "tx_dropped": 0,
    "tx_errors": 0,
    "tx_packets": 573,
    "state": "up",
    "mac": "02:be:86:f1:79:d5",
    "type": "ethernet",
    "name": "enp0s3",
    "mtu": 1500
 }


@pytest.mark.parametrize("select, valid_select_fields, search, array, response, total", [
    ({'fields':{'rx_bytes', 'mac'}}, {'rx_bytes', 'tx_bytes', 'scan_id', 'mac'}, {}, True, item_agent_response, '1'),
    ({}, {'rx_bytes', 'tx_bytes', 'scan_id', 'mac'}, {}, False, {}, '0'),
    ({}, {'rx_bytes', 'tx_bytes', 'scan_id', 'mac'}, {'fields':{'rx_bytes', 'mac'}}, False, item_agent_response, '1')
])
@patch("wazuh.syscollector.Agent.get_basic_information", return_value=None)
def test_get_item_agent(mock_agent_info, select, valid_select_fields, search, array, response, total):
    """
        Tests get_item_agent method
    """
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
    """
        Tests get_item_agent method handle exceptions properly
    """
    with pytest.raises(WazuhException, match=f'.* {expected_exception} .*'):
        syscollector.get_item_agent(agent_id='001', offset=0, limit=500, select=select,
                                    search={}, sort=sort, filters={}, allowed_sort_fields=allowed_sort_fields,
                                    valid_select_fields=valid_select_fields, table='sys_osinfo', nested=False)


@pytest.mark.parametrize("sort, limit, response", [
    ({'fields':['rx_bytes', 'mac'], 'order': 'asc'}, common.database_limit, dict_agent_response),
    ({}, common.database_limit, {}),
    ({}, 1, dict_agent_response)
])
@patch("wazuh.syscollector.Agent.get_agents_overview", return_value={'items':[{'id': '000'}, {'id': '001'}, {'id': '002'}, {'id': '003'}]})
@patch("wazuh.syscollector.sorted", return_value=[dict_agent_response])
@patch("wazuh.syscollector.get_fields_to_nest", return_value=[None, None])
@patch("wazuh.syscollector.plain_dict_to_nested_dict", return_value=dict_agent_response)
def test_get_agent_items_private(mock_plain_dict, mock_fields_nest, mock_sort, mock_agent_overview, sort, limit, response):
    """
        Tests _get_agent_items private method
    """
    with patch ("wazuh.syscollector.get_item_agent", return_value=response):
        results = syscollector._get_agent_items(func=syscollector.get_packages_agent, offset=0, limit=limit, select={},
                                      filters={}, search={}, sort=sort)

        assert isinstance(results, dict)


@patch("wazuh.syscollector.Agent.get_basic_information", return_value=None)
@patch("wazuh.syscollector.Agent.get_agent_attr", return_value='Ubuntu')
@patch("wazuh.syscollector.get_item_agent", return_value={})
def test_get_os_agent(mock_response, mock_os_name, mock_agent_info):
    """
        Tests get_os_agent method
    """
    results = syscollector.get_os_agent('001')

    assert isinstance(results, dict)



@patch("wazuh.syscollector.get_item_agent", return_value={})
def test_get_hardware_agent(mock_response):
    """
        Tests get_hardware_agent method
    """
    results = syscollector.get_hardware_agent('001')

    assert isinstance(results, dict)


@patch("wazuh.syscollector.get_item_agent", return_value={})
def test_get_packages_agent(mock_response):
    """
        Tests get_packages_agent method
    """
    results = syscollector.get_packages_agent('001')

    assert isinstance(results, dict)


@patch("wazuh.syscollector.get_item_agent", return_value={})
def test_get_processes_agent(mock_response):
    """
        Tests get_processes_agent method
    """
    results = syscollector.get_processes_agent('001')

    assert isinstance(results, dict)



@patch("wazuh.syscollector.get_item_agent", return_value={})
def test_get_ports_agent(mock_response):
    """
        Tests get_ports_agent method
    """
    results = syscollector.get_ports_agent('001')

    assert isinstance(results, dict)


@patch("wazuh.syscollector.get_item_agent", return_value={})
def test_get_netaddr_agent(mock_response):
    """
        Tests get_netaddr_agent method
    """
    results = syscollector.get_netaddr_agent('001')

    assert isinstance(results, dict)


@patch("wazuh.syscollector.get_item_agent", return_value={})
def test_get_netproto_agent(mock_response):
    """
        Tests get_netproto_agent method
    """
    results = syscollector.get_netproto_agent('001')

    assert isinstance(results, dict)


@patch("wazuh.syscollector.get_item_agent", return_value={})
def test_get_netiface_agent(mock_response):
    """
        Tests get_netiface_agent method
    """
    results = syscollector.get_netiface_agent('001')

    assert isinstance(results, dict)


@patch("wazuh.syscollector._get_agent_items", return_value={})
def test_get_packages(mock_response):
    """
        Tests get_packages method
    """
    results = syscollector.get_packages()

    assert isinstance(results, dict)


@patch("wazuh.syscollector._get_agent_items", return_value={})
def test_get_os(mock_response):
    """
        Tests get_hardware_agent method
    """
    results = syscollector.get_os()

    assert isinstance(results, dict)


@patch("wazuh.syscollector._get_agent_items", return_value={})
def test_get_hardware(mock_response):
    """
        Tests get_hardware method
    """
    results = syscollector.get_hardware()

    assert isinstance(results, dict)


@patch("wazuh.syscollector._get_agent_items", return_value={})
def test_get_processes(mock_response):
    """
        Tests get_processes method
    """
    results = syscollector.get_processes()

    assert isinstance(results, dict)


@patch("wazuh.syscollector._get_agent_items", return_value={})
def test_get_ports(mock_response):
    """
        Tests get_ports method
    """
    results = syscollector.get_ports()

    assert isinstance(results, dict)


@patch("wazuh.syscollector._get_agent_items", return_value={})
def test_get_netaddr(mock_response):
    """
        Tests get_netaddr method
    """
    results = syscollector.get_netaddr()

    assert isinstance(results, dict)


@patch("wazuh.syscollector._get_agent_items", return_value={})
def test_get_netproto(mock_response):
    """
        Tests get_netproto method
    """
    results = syscollector.get_netproto()

    assert isinstance(results, dict)


@patch("wazuh.syscollector._get_agent_items", return_value={})
def test_get_netiface(mock_response):
    """
        Tests get_netiface method
    """
    results = syscollector.get_netiface()

    assert isinstance(results, dict)
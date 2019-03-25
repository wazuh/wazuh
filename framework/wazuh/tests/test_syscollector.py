# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from unittest.mock import patch
import pytest
from .util import InitWDBSocketMock, test_data_path

from wazuh import syscollector


@pytest.fixture(scope='module')
def test_data():
    return InitWDBSocketMock(sql_schema_file='schema_syscollector_000.sql')


@pytest.mark.parametrize('func, totalItems, single_agent, sort, search, first_item', [
    (syscollector.get_os_agent, None, True, None, None, None),
    (syscollector.get_hardware_agent, None, True, None, None, None),
    (syscollector.get_packages_agent, 2, True, {'fields': ['name'], 'order': 'asc'}, {'value': 'lib', 'negation': 0}, 'libnewt0.52'),
    (syscollector.get_processes_agent, 2, True, {'fields': ['ppid'], 'order': 'asc'}, {'value': 'root', 'negation': 0}, 0),
    (syscollector.get_ports_agent, 1, True, {'fields': ['local_port'], 'order': 'asc'}, {'value': '.2.2', 'negation': 0}, 22),
    (syscollector.get_netaddr_agent, 2, True, {'fields': ['address'], 'order': 'asc'}, {'value': 's3', 'negation': 0}, '10.0.2.15'),
    (syscollector.get_netproto_agent, 2, True, {'fields': ['type'], 'order': 'asc'}, {'value': 's3', 'negation': 0}, 'ipv4'),
    (syscollector.get_netiface_agent, 1, True, {'fields': ['rx_packets'], 'order': 'asc'}, {'value': 's3', 'negation': 0}, 95186),
    (syscollector.get_os, 1, False, {'fields': ['os_name'], 'order': 'asc'}, {'value': 'ubuntu', 'negation': 0}, 'Ubuntu'),
    (syscollector.get_hardware, 1, False, {'fields': ['cpu_cores'], 'order': 'asc'}, {'value': 'intel', 'negation': 0}, 2),
    (syscollector.get_packages, 2, False, {'fields': ['name'], 'order': 'asc'}, {'value': 'lib', 'negation': 0}, 'libnewt0.52'),
    (syscollector.get_processes, 2, False, {'fields': ['ppid'], 'order': 'asc'}, {'value': 'root', 'negation': 0}, 0),
    (syscollector.get_ports, 1, False, {'fields': ['local_port'], 'order': 'asc'}, {'value': '.2.2', 'negation': 0}, 22),
    (syscollector.get_netaddr, 2, False, {'fields': ['address'], 'order': 'asc'}, {'value': 's3', 'negation': 0}, '10.0.2.15'),
    (syscollector.get_netproto, 2, False, {'fields': ['type'], 'order': 'asc'}, {'value': 's3', 'negation': 0}, 'ipv4'),
    (syscollector.get_netiface, 1, False, {'fields': ['rx_packets'], 'order': 'asc'}, {'value': 's3', 'negation': 0}, 95186)
])
@patch('wazuh.syscollector.Agent')
@patch('wazuh.common.wdb_path', test_data_path)
@patch('socket.socket')
def test_print_db(socket_mock, agent_mock, test_data, func, totalItems, single_agent, sort, search, first_item):
    """
    Tests getting syscollector database with sort and search parameters
    """
    agent_mock.return_value.os_name = 'Linux'
    agent_mock.get_agents_overview.return_value = {'totalItems': 1, 'items': [{'id': '001'}]}
    with patch('wazuh.utils.WazuhDBConnection') as mock_db:
        mock_db.return_value = test_data

        if single_agent:
            agent_info = func(agent_id='001', sort=sort, search=search)
        else:
            agent_info = func(sort=sort, search=search)

        if 'totalItems' in agent_info:
            assert agent_info['totalItems'] == totalItems

        if 'items' in agent_info:
            if '_' not in sort['fields'][0]:
                assert agent_info['items'][0][sort['fields'][0]] == first_item
            else:
                field, subfield = sort['fields'][0].split('_')
                assert agent_info['items'][0][field][subfield] == first_item

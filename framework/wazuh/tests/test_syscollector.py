# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from unittest.mock import patch
import sqlite3
import os
import pytest
import re

from wazuh import syscollector

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')


class InitSyscollector:
    def __init__(self):
        self.__conn = self.init_db()

    def init_db(self):
        sys_db = sqlite3.connect(':memory:')
        cur = sys_db.cursor()
        with open(os.path.join(test_data_path, 'schema_syscollector_000.sql')) as f:
            cur.executescript(f.read())
        sys_db.row_factory = lambda c, r: dict(zip([col[0] for col in c.description], r))

        return sys_db

    def execute(self, sql):
        query = re.search(r'^agent \d{3} sql (.+)$', sql).group(1)
        self.__conn.execute(query)
        rows = self.__conn.execute(query).fetchall()
        if len(rows) > 0 and 'COUNT(*)' in rows[0]:
            return rows[0]['COUNT(*)']
        return rows


@pytest.fixture(scope='module')
def test_data():
    return InitSyscollector()


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
    Tests print_db function with default parameters
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

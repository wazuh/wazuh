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


@pytest.mark.parametrize('func, totalItems, single_agent, sort', [
    (syscollector.get_os_agent, None, True, None),
    (syscollector.get_hardware_agent, None, True, None),
    (syscollector.get_packages_agent, 4, True, {'fields': ['name'], 'order': 'asc'}),
    (syscollector.get_processes_agent, 4, True, {'fields': ['ppid'], 'order': 'asc'}),
    (syscollector.get_ports_agent, 4, True, {'fields': ['local_port'], 'order': 'asc'}),
    (syscollector.get_netaddr_agent, 4, True, {'fields': ['address'], 'order': 'asc'}),
    (syscollector.get_netproto_agent, 4, True, {'fields': ['type'], 'order': 'asc'}),
    (syscollector.get_netiface_agent, 2, True, {'fields': ['tx_packets'], 'order': 'asc'}),
    (syscollector.get_os, 1, False, {'fields': ['os_name'], 'order': 'asc'}),
    (syscollector.get_hardware, 1, False, {'fields': ['cpu_cores'], 'order': 'asc'}),
    (syscollector.get_packages, 4, False, {'fields': ['name'], 'order': 'asc'}),
    (syscollector.get_processes, 4, False, {'fields': ['ppid'], 'order': 'asc'}),
    (syscollector.get_ports, 4, False, {'fields': ['local_port'], 'order': 'asc'}),
    (syscollector.get_netaddr, 4, False, {'fields': ['address'], 'order': 'asc'}),
    (syscollector.get_netproto, 4, False, {'fields': ['type'], 'order': 'asc'}),
    (syscollector.get_netiface, 2, False, {'fields': ['rx_packets'], 'order': 'asc'})
])
@patch('wazuh.syscollector.Agent')
@patch('wazuh.common.wdb_path', test_data_path)
@patch('socket.socket')
def test_print_db(socket_mock, agent_mock, test_data, func, totalItems, single_agent, sort):
    """
    Tests print_db function with default parameters
    """
    agent_mock.return_value.os_name = 'Linux'
    agent_mock.get_agents_overview.return_value = {'totalItems': 1, 'items': [{'id': '001'}]}
    with patch('wazuh.utils.WazuhDBConnection') as mock_db:
        mock_db.return_value = test_data

        if single_agent:
            agent_info = func(agent_id='001', sort=sort)
        else:
            agent_info = func(sort=sort)

        if 'totalItems' in agent_info:
            assert agent_info['totalItems'] == totalItems

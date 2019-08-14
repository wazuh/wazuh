#!/usr/bin/env python
# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import sqlite3

import os
import pytest
from freezegun import freeze_time
from shutil import copyfile
from unittest.mock import patch, mock_open

from wazuh import common
from wazuh.agent import Agent
from wazuh.exception import WazuhException

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')


class InitAgent:

    def __init__(self):
        """
        Sets up necessary test environment for agents:
            * One active agent.
            * One pending agent.
            * One never connected agent.
            * One disconnected agent.

        :return: None
        """
        self.global_db = sqlite3.connect(':memory:')
        self.cur = self.global_db.cursor()
        with open(os.path.join(test_data_path, 'schema_global_test.sql')) as f:
            self.cur.executescript(f.read())

        self.never_connected_fields = {'status', 'name', 'ip', 'registerIP', 'node_name', 'dateAdd', 'id'}
        self.pending_fields = self.never_connected_fields | {'manager', 'lastKeepAlive'}
        self.manager_fields = self.pending_fields | {'version', 'os'}
        self.active_fields = self.manager_fields | {'group', 'mergedSum', 'configSum'}
        self.manager_fields -= {'registerIP'}


@pytest.fixture(scope='module')
def test_data():
    return InitAgent()


def check_agent(test_data, agent):
    """
    Checks a single agent is correct
    """
    assert all(map(lambda x: x is not None, agent.values()))
    assert 'status' in agent
    assert 'id' in agent
    if agent['id'] == '000':
        assert agent.keys() == test_data.manager_fields
    elif agent['status'] == 'Active' or agent['status'] == 'Disconnected':
        assert agent.keys() == test_data.active_fields
    elif agent['status'] == 'Pending':
        assert agent.keys() == test_data.pending_fields
    elif agent['status'] == 'Never connected':
        assert agent.keys() == test_data.never_connected_fields
    else:
        raise Exception("Agent status not known: {}".format(agent['status']))


def test_get_agents_overview_default(test_data):
    """
    Test to get all agents using default parameters
    """
    with patch('sqlite3.connect') as mock_db:
        mock_db.return_value = test_data.global_db

        agents = Agent.get_agents_overview()

        # check number of agents
        assert agents['totalItems'] == 6
        # check the return dictionary has all necessary fields

        for agent in agents['items']:
            # check no values are returned as None
            check_agent(test_data, agent)


@pytest.mark.parametrize("select, status, older_than, offset", [
    ({'id', 'dateAdd'}, 'all', None, 0),
    ({'id', 'ip', 'registerIP'}, 'all', None, 1),
    ({'id', 'registerIP'}, 'all', None, 1),
    ({'id', 'ip', 'lastKeepAlive'}, 'Active,Pending', None, 0),
    ({'id', 'ip', 'lastKeepAlive'}, 'Disconnected', None, 1),
    ({'id', 'ip', 'lastKeepAlive'}, 'Disconnected', '1s', 1),
    ({'id', 'ip', 'lastKeepAlive'}, 'Disconnected', '2h', 0),
    ({'id', 'ip', 'lastKeepAlive'}, 'all', '15m', 2),
    ({'id', 'ip', 'lastKeepAlive'}, 'Active', '15m', 0),
    ({'id', 'ip', 'lastKeepAlive'}, 'Active,Pending', '15m', 1),
    ({'id', 'ip', 'lastKeepAlive'}, ['Active', 'Pending'], '15m', 1)
])
def test_get_agents_overview_select(test_data, select, status, older_than, offset):
    """
    Test get_agents_overview function with multiple select parameters
    """
    with patch('sqlite3.connect') as mock_db:
        mock_db.return_value = test_data.global_db

        agents = Agent.get_agents_overview(select={'fields': select}, filters={'status': status, 'older_than': older_than}, offset=offset)
        assert all(map(lambda x: x.keys() == select, agents['items']))


@pytest.mark.parametrize("query", [
    "ip=172.17.0.201",
    "ip=172.17.0.202",
    "ip=172.17.0.202;registerIP=any",
    "status=Disconnected;lastKeepAlive>34m",
    "(status=Active,status=Pending);lastKeepAlive>5m",
])
def test_get_agents_overview_query(test_data, query):
    """
    Test filtering by query
    """
    with patch('sqlite3.connect') as mock_db:
        mock_db.return_value = test_data.global_db

        agents = Agent.get_agents_overview(q=query)
        assert len(agents['items']) == 1


@pytest.mark.parametrize("search, totalItems", [
    ({'value': 'any', 'negation': 0}, 3),
    ({'value': 'any', 'negation': 1}, 3),
    ({'value': '202', 'negation': 0}, 1),
    ({'value': '202', 'negation': 1}, 5),
    ({'value': 'master', 'negation': 1}, 2)
])
def test_get_agents_overview_search(test_data, search, totalItems):
    """
    Test searching by IP and Register IP
    """
    with patch('sqlite3.connect') as mock_db:
        mock_db.return_value = test_data.global_db

        agents = Agent.get_agents_overview(search=search)
        assert len(agents['items']) == totalItems


@pytest.mark.parametrize("status, older_than, totalItems, exception", [
    ('active', '9m', 1, None),
    ('all', '1s', 5, None),
    ('pending,neverconnected', '30m', 1, None),
    (55, '30m', 0, 1729)
])
def test_get_agents_overview_status_olderthan(test_data, status, older_than, totalItems, exception):
    """
    Test filtering by status
    """
    with patch('sqlite3.connect') as mock_db:
        mock_db.return_value = test_data.global_db
        kwargs = {'filters': {'status': status, 'older_than': older_than},
                  'select': {'fields': ['name', 'id', 'status', 'lastKeepAlive', 'dateAdd']}}

        if exception is None:
            agents = Agent.get_agents_overview(**kwargs)
            assert agents['totalItems'] == totalItems
        else:
            with pytest.raises(WazuhException, match=f'.* {exception} .*'):
                Agent.get_agents_overview(**kwargs)


@pytest.mark.parametrize('agent_id, component, configuration, expected_exception', [
    ('100', 'logcollector', 'internal', 1701),
    ('005', 'logcollector', 'internal', 1740),
    ('002', 'logcollector', 'internal', 1735),
    ('000', None, None, 1307),
    ('000', 'random', 'random', 1101),
    ('000', 'analysis', 'internal', 1117),
    ('000', 'analysis', 'internal', 1118),
    ('000', 'analysis', 'random', 1116),
    ('000', 'analysis', 'internal', None)
])
@patch('wazuh.configuration.OssecSocket')
def test_get_config_error(ossec_socket_mock, test_data, agent_id, component, configuration, expected_exception):
    """
    Tests get_config function error cases.
    """
    if expected_exception == 1117:
        ossec_socket_mock.side_effect = Exception('Boom!')

    ossec_socket_mock.return_value.receive.return_value = b'string_without_spaces' if expected_exception == 1118 \
        else (b'random random' if expected_exception is not None else b'ok {"message":"value"}')

    with patch('sqlite3.connect') as mock_db:
        mock_db.return_value = test_data.global_db
        if expected_exception:
            with pytest.raises(WazuhException, match=f'.* {expected_exception} .*'):
                Agent.get_config(agent_id=agent_id, component=component, configuration=configuration)
        else:
            res = Agent.get_config(agent_id=agent_id, component=component, configuration=configuration)
            assert res == {"message": "value"}


@pytest.mark.parametrize('backup', [
    False,
    True
])
@patch('wazuh.agent.WazuhDBConnection')
@patch('wazuh.agent.remove')
@patch('wazuh.agent.rmtree')
@patch('wazuh.agent.chown')
@patch('wazuh.agent.chmod')
@patch('wazuh.agent.stat')
@patch('wazuh.agent.glob', return_value=['/var/db/global.db'])
@patch('wazuh.agent.path.exists', side_effect=lambda x: not (common.backup_path in x))
@patch('wazuh.database.isfile', return_value=True)
@patch('wazuh.agent.path.isdir', return_value=True)
@patch('wazuh.agent.safe_move')
@patch('wazuh.agent.makedirs')
@patch('wazuh.agent.chmod_r')
@freeze_time('1975-01-01')
def test_remove_manual(chmod_r_mock, makedirs_mock, safe_move_mock, isdir_mock, isfile_mock, exists_mock, glob_mock,
                       stat_mock, chmod_mock, chown_mock, rmtree_mock, remove_mock, wdb_mock, test_data,
                       backup):
    """
    Test the _remove_manual function
    """
    client_keys_text = '\n'.join([f'{str(aid).zfill(3)} {name} {ip} {key}' for aid, name, ip, key in
                                  test_data.global_db.execute(
                                      'select id, name, register_ip, internal_key from agent where id > 0')])

    with patch('wazuh.agent.open', mock_open(read_data=client_keys_text)) as m:
        with patch('sqlite3.connect') as mock_db:
            mock_db.return_value = test_data.global_db
            Agent('001')._remove_manual(backup=backup)

        m.assert_any_call(common.client_keys)
        m.assert_any_call(common.client_keys + '.tmp', 'w')
        stat_mock.assert_called_once_with(common.client_keys)
        chown_mock.assert_called_once_with(common.client_keys + '.tmp', common.ossec_uid, common.ossec_gid)
        remove_mock.assert_any_call(os.path.join(common.ossec_path, 'queue/rids/001'))

        # make sure the mock is called with a string according to a non-backup path
        exists_mock.assert_any_call('/var/ossec/queue/agent-info/agent-1-any')
        safe_move_mock.assert_called_with(common.client_keys + '.tmp', common.client_keys, permissions=0o640)
        if backup:
            backup_path = os.path.join(common.backup_path, f'agents/1975/Jan/01/001-agent-1-any')
            makedirs_mock.assert_called_once_with(backup_path)
            chmod_r_mock.assert_called_once_with(backup_path, 0o750)


@pytest.mark.parametrize('agent_id, expected_exception', [
    ('001', 1746),
    ('100', 1701),
    ('001', 1600),
    ('001', 1748),
    ('001', 1747)
])
@patch('wazuh.agent.WazuhDBConnection')
@patch('wazuh.agent.remove')
@patch('wazuh.agent.rmtree')
@patch('wazuh.agent.chown')
@patch('wazuh.agent.chmod')
@patch('wazuh.agent.stat')
@patch('wazuh.agent.glob')
@patch('wazuh.agent.path.exists', side_effect=lambda x: not (common.backup_path in x))
@patch('wazuh.database.isfile', return_value=True)
@patch('wazuh.agent.path.isdir', return_value=True)
@patch('wazuh.agent.safe_move')
@patch('wazuh.agent.makedirs')
@patch('wazuh.agent.chmod_r')
@freeze_time('1975-01-01')
def test_remove_manual_error(chmod_r_mock, makedirs_mock, safe_move_mock, isdir_mock, isfile_mock, exists_mock, glob_mock,
                             stat_mock, chmod_mock, chown_mock, rmtree_mock, remove_mock, wdb_mock,
                             test_data, agent_id, expected_exception):
    """
    Test the _remove_manual function error cases
    """
    client_keys_text = '\n'.join([f'{str(aid).zfill(3)} {name} {ip} '
                                  f'{key + "" if expected_exception != 1746 else " random"}' for aid, name, ip, key in
                                  test_data.global_db.execute(
                                      'select id, name, register_ip, internal_key from agent where id > 0')])

    glob_mock.return_value = ['/var/db/global.db'] if expected_exception != 1600 else []
    rmtree_mock.side_effect = Exception("Boom!")

    with patch('wazuh.agent.open', mock_open(read_data=client_keys_text)) as m:
        with patch('sqlite3.connect') as mock_db:
            mock_db.return_value = test_data.global_db
            if expected_exception == 1747:
                mock_db.return_value.execute("drop table belongs")
            with pytest.raises(WazuhException, match=f".* {expected_exception} .*"):
                Agent(agent_id)._remove_manual()

    if expected_exception == 1746:
        remove_mock.assert_any_call('/var/ossec/etc/client.keys.tmp')

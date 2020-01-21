#!/usr/bin/env python
# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import re
import sqlite3
import sys
from copy import deepcopy
from functools import wraps
from glob import glob
from unittest.mock import patch, MagicMock
from tempfile import NamedTemporaryFile

import pytest
import requests
from freezegun import freeze_time
from pwd import getpwnam
from grp import getgrnam

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../..'))

with patch('wazuh.common.ossec_uid'):
    with patch('wazuh.common.ossec_gid'):
        sys.modules['api'] = MagicMock()
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators
        from wazuh.tests.util import RBAC_bypasser

        del sys.modules['wazuh.rbac.orm']
        del sys.modules['api']

        wazuh.rbac.decorators.expose_resources = RBAC_bypasser

        from wazuh.agent import get_distinct_agents, get_agents_summary_status, get_agents_summary_os, restart_agents, \
    get_agents, get_agent_by_name, get_agents_in_group, get_agents_keys, delete_agents, add_agent, get_agent_groups, \
    get_group_files
        from wazuh import WazuhError, WazuhException, common, WazuhInternalError
        from wazuh.results import AffectedItemsWazuhResult
        from wazuh.utils import get_hash
# all necessary params

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
test_agent_path = os.path.join(test_data_path, 'agent')
test_shared_path = os.path.join(test_agent_path, 'shared')

# list with Wazuh packages availables with their hash
wpk_versions = [['v3.10.0', '251b1af81d45d291540d85899b124302613f0a4e0'],
                ['v3.9.1', '91b8110b0d39b0d8e1ba10d508503850476c5290'],
                ['v3.9.0', '180e25a1fefafe8d83c763d375cb1a3a387bc08a'],
                ['v3.8.2', '7a49d5604e1034d1327c993412433d124274bc7e'],
                ['v3.8.1', '54c55d50f9d88df937fb2b40a4eeec17cbc6ce24'],
                ['v3.8.0', 'e515d2251af9d4830dfa27902896c8d66c4ded2f'],
                ['v3.7.2', 'e28cfb89469b1b8bfabefe714c09b942ebd7a928'],
                ['v3.7.1', '7ef661a92295a02755812e3e10c87bf49bb52114'],
                ['v3.7.0', 'b1a94c212195899be53564e86b69981d4729154e'],
                ['v3.6.1', 'ed01192281797f64c99d53cff91efe936bc31b17'],
                ['v3.6.0', '83fd0e49c6ab47f59c5d75478a371396082613fe'],
                ['v3.5.0', '5e276bd26d76c3c1eebed5ca57094ee957b3ee40'],
                ['v3.4.0', 'f20e4319b9088d534a4655a9136a608800522d50']]


# Get a fake database
def get_fake_agent_db(sql_file):
    def create_memory_db(*args, **kwargs):
        agent_db = sqlite3.connect(':memory:')
        cur = agent_db.cursor()
        with open(os.path.join(test_data_path, sql_file)) as f:
            cur.executescript(f.read())
        return agent_db

    return create_memory_db


class InitAgent:

    def __init__(self):
        """Sets up necessary test environment for agents:
            * One active agent.
            * One pending agent.
            * One never_connected agent.
            * One disconnected agent.
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


def get_manager_version():
    """
    Get manager version
    """
    manager = Agent(id=0)
    manager.load_info_from_db()

    return manager.version


def check_agent(test_data, agent):
    """
    Checks a single agent is correct
    """
    assert all(map(lambda x: x is not None, agent.values()))
    assert 'status' in agent
    assert 'id' in agent
    if agent['id'] == '000':
        assert agent.keys() == test_data.manager_fields
    elif agent['status'] == 'active' or agent['status'] == 'disconnected':
        assert agent.keys() == test_data.active_fields
    elif agent['status'] == 'pending':
        assert agent.keys() == test_data.pending_fields
    elif agent['status'] == 'never_connected':
        assert agent.keys() == test_data.never_connected_fields
    else:
        raise Exception("Agent status not known: {}".format(agent['status']))


#
# @patch("wazuh.common.database_path_global", new=os.path.join(test_data_path, 'var', 'db', 'global.db'))
# def test_get_agents_overview_default(test_data):
#     """
#     Test to get all agents using default parameters
#     """
#     with patch('sqlite3.connect') as mock_db:
#         mock_db.return_value = test_data.global_db
#
#         agents = Agent.get_agents_overview()
#
#         # check number of agents
#         assert agents['totalItems'] == 6
#         # check the return dictionary has all necessary fields
#
#         for agent in agents['items']:
#             # check no values are returned as None
#             check_agent(test_data, agent)
#
#
# @pytest.mark.parametrize("select, status, older_than, offset", [
#     ({'id', 'dateAdd'}, 'all', None, 0),
#     ({'id', 'ip', 'registerIP'}, 'all', None, 1),
#     ({'id', 'registerIP'}, 'all', None, 1),
#     ({'id', 'ip', 'lastKeepAlive'}, 'active,pending', None, 0),
#     ({'id', 'ip', 'lastKeepAlive'}, 'disconnected', None, 1),
#     ({'id', 'ip', 'lastKeepAlive'}, 'disconnected', '1s', 1),
#     ({'id', 'ip', 'lastKeepAlive'}, 'disconnected', '2h', 0),
#     ({'id', 'ip', 'lastKeepAlive'}, 'all', '15m', 2),
#     ({'id', 'ip', 'lastKeepAlive'}, 'active', '15m', 0),
#     ({'id', 'ip', 'lastKeepAlive'}, 'active,pending', '15m', 1),
#     ({'id', 'ip', 'lastKeepAlive'}, ['active', 'pending'], '15m', 1)
# ])
# @patch("wazuh.common.database_path_global", new=os.path.join(test_data_path, 'var', 'db', 'global.db'))
# def test_get_agents_overview_select(test_data, select, status, older_than, offset):
#     """
#     Test get_agents_overview function with multiple select parameters
#     """
#     with patch('sqlite3.connect') as mock_db:
#         mock_db.return_value = test_data.global_db
#
#         agents = Agent.get_agents_overview(select=select, filters={'status': status, 'older_than': older_than},
#                                            offset=offset)
#         assert all(map(lambda x: x.keys() == select, agents['items']))
#
#
# @pytest.mark.parametrize("query", [
#     "ip=172.17.0.201",
#     "ip=172.17.0.202",
#     "ip=172.17.0.202;registerIP=any",
#     "status=disconnected;lastKeepAlive>34m",
#     "(status=active,status=pending);lastKeepAlive>5m"
# ])
# @patch("wazuh.common.database_path_global", new=os.path.join(test_data_path, 'var', 'db', 'global.db'))
# def test_get_agents_overview_query(test_data, query):
#     """
#     Test filtering by query
#     """
#     with patch('sqlite3.connect') as mock_db:
#         mock_db.return_value = test_data.global_db
#
#         agents = Agent.get_agents_overview(q=query)
#         assert len(agents['items']) == 1
#
#
# @pytest.mark.parametrize("search, totalItems", [
#     ({'value': 'any', 'negation': 0}, 3),
#     ({'value': 'any', 'negation': 1}, 3),
#     ({'value': '202', 'negation': 0}, 1),
#     ({'value': '202', 'negation': 1}, 5),
#     ({'value': 'master', 'negation': 1}, 2)
# ])
# @patch("wazuh.common.database_path_global", new=os.path.join(test_data_path, 'var', 'db', 'global.db'))
# def test_get_agents_overview_search(test_data, search, totalItems):
#     """
#     Test searching by IP and Register IP
#     """
#     with patch('sqlite3.connect') as mock_db:
#         mock_db.return_value = test_data.global_db
#
#         agents = Agent.get_agents_overview(search=search)
#         assert len(agents['items']) == totalItems
#
#
# @pytest.mark.parametrize("status, older_than, totalItems, exception", [
#     ('active', '9m', 1, None),
#     ('all', '1s', 5, None),
#     ('pending,never_connected', '30m', 1, None),
#     (55, '30m', 0, 1729)
# ])
# @patch("wazuh.common.database_path_global", new=os.path.join(test_data_path, 'var', 'db', 'global.db'))
# def test_get_agents_overview_status_olderthan(test_data, status, older_than, totalItems, exception):
#     """
#     Test filtering by status
#     """
#     with patch('sqlite3.connect') as mock_db:
#         mock_db.return_value = test_data.global_db
#         kwargs = {'filters': {'status': status, 'older_than': older_than},
#                   'select': {'fields': ['name', 'id', 'status', 'lastKeepAlive', 'dateAdd']}}
#
#         if exception is None:
#             agents = Agent.get_agents_overview(**kwargs)
#             assert agents['totalItems'] == totalItems
#         else:
#             with pytest.raises(WazuhException, match=f'.* {exception} .*'):
#                 Agent.get_agents_overview(**kwargs)
#
#
# @pytest.mark.parametrize("sort, first_id", [
#     ({'fields': ['dateAdd'], 'order': 'asc'}, '000'),
#     ({'fields': ['dateAdd'], 'order': 'desc'}, '004')
# ])
# @patch('wazuh.common.database_path_global', new=os.path.join(test_data_path, 'var', 'db', 'global.db'))
# def test_get_agents_overview_sort(test_data, sort, first_id):
#     """Test sorting."""
#     with patch('sqlite3.connect') as mock_db:
#         mock_db.return_value = test_data.global_db
#
#         agents = Agent.get_agents_overview(sort=sort, select={'fields': ['dateAdd']})
#         assert agents['items'][0]['id'] == first_id
#
#
# @pytest.mark.parametrize('select', [
#     None,
#     {'fields': ['ip', 'id', 'status']},
# ])
# @pytest.mark.parametrize('a_id, a_ip, a_status', [
#     ('000', '127.0.0.1', 'active'),
#     ('001', '172.17.0.202', 'active'),
#     ('003', 'any', 'never_connected')
# ])
# @patch('wazuh.common.database_path_global', new=os.path.join(test_data_path, 'var', 'db', 'global.db'))
# def test_get_basic_information(test_data, select, a_id, a_ip, a_status):
#     """Test get_basic_information function."""
#     with patch('sqlite3.connect') as mock_db:
#         mock_db.return_value = test_data.global_db
#         agent_info = Agent(a_id).get_basic_information(select=select)
#         if select is not None:
#             assert agent_info.keys() == set(select['fields'])
#
#         assert agent_info['id'] == a_id
#         assert agent_info['ip'] == a_ip
#         assert agent_info['status'] == a_status
#

#
#
# @pytest.mark.parametrize('agent_id, component, configuration, expected_exception', [
#     ('100', 'logcollector', 'internal', 1701),
#     ('005', 'logcollector', 'internal', 1740),
#     ('002', 'logcollector', 'internal', 1735),
#     ('000', None, None, 1307),
#     ('000', 'random', 'random', 1101),
#     ('000', 'analysis', 'internal', 1117),
#     ('000', 'analysis', 'internal', 1118),
#     ('000', 'analysis', 'random', 1116),
#     ('000', 'analysis', 'internal', None)
# ])
# @patch('wazuh.configuration.OssecSocket')
# @patch("wazuh.common.database_path_global", new=os.path.join(test_data_path, 'var', 'db', 'global.db'))
# def test_get_config_error(ossec_socket_mock, test_data, agent_id, component, configuration, expected_exception):
#     """
#     Tests get_config function error cases.
#     """
#     if expected_exception == 1117:
#         ossec_socket_mock.side_effect = Exception('Boom!')
#
#     ossec_socket_mock.return_value.receive.return_value = b'string_without_spaces' if expected_exception == 1118 \
#         else (b'random random' if expected_exception is not None else b'ok {"message":"value"}')
#
#     with patch('sqlite3.connect') as mock_db:
#         mock_db.return_value = test_data.global_db
#         if expected_exception:
#             with pytest.raises(WazuhException, match=f'.* {expected_exception} .*'):
#                 Agent.get_agents_config(agent_id=agent_id, component=component, configuration=configuration)
#         else:
#             res = Agent.get_agents_config(agent_id=agent_id, component=component, configuration=configuration)
#             assert res == {"message": "value"}
#
#
# @pytest.mark.parametrize('backup', [
#     False,
#     True
# ])
# @patch('wazuh.core.core_agent.WazuhDBBackend.connect_to_db')
# @patch('wazuh.core.core_agent.remove')
# @patch('wazuh.core.core_agent.rmtree')
# @patch('wazuh.core.core_agent.chown')
# @patch('wazuh.core.core_agent.chmod')
# @patch('wazuh.core.core_agent.stat')
# @patch('wazuh.core.core_agent.glob', return_value=['/var/db/global.db'])
# @patch("wazuh.common.ossec_path", new=test_data_path)
# @patch('wazuh.core.core_agent.path.exists', side_effect=lambda x: not (common.backup_path in x))
# @patch('wazuh.database.isfile', return_value=True)
# @patch('wazuh.core.core_agent.path.isdir', return_value=True)
# @patch('wazuh.core.core_agent.safe_move')
# @patch('wazuh.core.core_agent.makedirs')
# @patch('wazuh.core.core_agent.chmod_r')
# @freeze_time('1975-01-01')
# @patch("wazuh.common.ossec_uid", return_value=getpwnam("root"))
# @patch("wazuh.common.ossec_gid", return_value=getgrnam("root"))
# @patch("wazuh.common.database_path_global", new=os.path.join(test_data_path, 'var', 'db', 'global.db'))
# def test_remove_manual(grp_mock, pwd_mock, chmod_r_mock, makedirs_mock, safe_move_mock, isdir_mock, isfile_mock,
#                        exists_mock, glob_mock,
#                        stat_mock, chmod_mock, chown_mock, rmtree_mock, remove_mock, wdb_mock, test_data,
#                        backup):
#     """
#     Test the _remove_manual function
#     """
#     client_keys_text = '\n'.join([f'{str(row["id"]).zfill(3)} {row["name"]} {row["register_ip"]} {row["internal_key"]}'
#                                   for row in test_data.global_db.execute(
#             'select id, name, register_ip, internal_key from agent where id > 0')])
#
#     with patch('wazuh.core.core_agent.open', mock_open(read_data=client_keys_text)) as m:
#         with patch('sqlite3.connect') as mock_db:
#             mock_db.return_value = test_data.global_db
#             Agent('001')._remove_manual(backup=backup)
#
#         m.assert_any_call(common.client_keys)
#         m.assert_any_call(common.client_keys + '.tmp', 'w')
#         stat_mock.assert_called_once_with(common.client_keys)
#         chown_mock.assert_called_once_with(common.client_keys + '.tmp', common.ossec_uid(), common.ossec_gid())
#         remove_mock.assert_any_call(os.path.join(common.ossec_path, 'queue/rids/001'))
#
#         # make sure the mock is called with a string according to a non-backup path
#         exists_mock.assert_any_call('{0}/queue/agent-info/agent-1-any'.format(test_data_path))
#         safe_move_mock.assert_called_with(common.client_keys + '.tmp', common.client_keys, permissions=0o640)
#         if backup:
#             backup_path = os.path.join(common.backup_path, f'agents/1975/Jan/01/001-agent-1-any')
#             makedirs_mock.assert_called_once_with(backup_path)
#             chmod_r_mock.assert_called_once_with(backup_path, 0o750)
#
#
# @pytest.mark.parametrize('agent_id, expected_exception', [
#     ('001', 1746),
#     ('100', 1701),
#     ('001', 1600),
#     ('001', 1748),
#     ('001', 1747)
# ])
# @patch('wazuh.core.core_agent.WazuhDBBackend.connect_to_db')
# @patch('wazuh.core.core_agent.remove')
# @patch('wazuh.core.core_agent.rmtree')
# @patch('wazuh.core.core_agent.chown')
# @patch('wazuh.core.core_agent.chmod')
# @patch('wazuh.core.core_agent.stat')
# @patch('wazuh.core.core_agent.glob')
# @patch("wazuh.common.client_keys", new=os.path.join(test_data_path, 'etc', 'client.keys'))
# @patch('wazuh.core.core_agent.path.exists', side_effect=lambda x: not (common.backup_path in x))
# @patch('wazuh.database.isfile', return_value=True)
# @patch('wazuh.core.core_agent.path.isdir', return_value=True)
# @patch('wazuh.core.core_agent.safe_move')
# @patch('wazuh.core.core_agent.makedirs')
# @patch('wazuh.core.core_agent.chmod_r')
# @freeze_time('1975-01-01')
# @patch("wazuh.common.ossec_uid", return_value=getpwnam("root"))
# @patch("wazuh.common.ossec_gid", return_value=getgrnam("root"))
# @patch("wazuh.common.database_path_global", new=os.path.join(test_data_path, 'var', 'db', 'global.db'))
# def test_remove_manual_error(grp_mock, pwd_mock, chmod_r_mock, makedirs_mock, safe_move_mock, isdir_mock, isfile_mock,
#                              exists_mock, glob_mock,
#                              stat_mock, chmod_mock, chown_mock, rmtree_mock, remove_mock, wdb_mock,
#                              test_data, agent_id, expected_exception):
#     """
#     Test the _remove_manual function error cases
#     """
#     client_keys_text = '\n'.join([f'{str(row["id"]).zfill(3)} {row["name"]} {row["register_ip"]} '
#                                   f'{row["internal_key"] + "" if expected_exception != 1746 else " random"}' for row in
#                                   test_data.global_db.execute(
#                                       'select id, name, register_ip, internal_key from agent where id > 0')])
#
#     glob_mock.return_value = ['/var/db/global.db'] if expected_exception != 1600 else []
#     rmtree_mock.side_effect = Exception("Boom!")
#
#     with patch('wazuh.core.core_agent.open', mock_open(read_data=client_keys_text)) as m:
#         with patch('sqlite3.connect') as mock_db:
#             mock_db.return_value = test_data.global_db
#             if expected_exception == 1747:
#                 mock_db.return_value.execute("drop table belongs")
#             with pytest.raises(WazuhException, match=f".* {expected_exception} .*"):
#                 Agent(agent_id)._remove_manual()
#
#     if expected_exception == 1746:
#         remove_mock.assert_any_call('{0}/etc/client.keys.tmp'.format(test_data_path))
#
#
# @pytest.mark.parametrize('agent_id', [
#     ('001'),
#     ('002')
# ])
# @patch('wazuh.core.core_agent.requests')
# @patch("wazuh.common.database_path_global", new=os.path.join(test_data_path, 'var', 'db', 'global.db'))
# def test_get_available_versions(requests_mock, test_data, agent_id):
#     """
#     Test _get_versions method
#     """
#     # regex for checking SHA-1 hash
#     regex_sha1 = re.compile(r'^[0-9a-f]{40}$')
#
#     with patch('sqlite3.connect') as mock_db:
#         mock_db.return_value = test_data.global_db
#         manager_version = get_manager_version()
#         agent = Agent(agent_id)
#         agent.load_info_from_db()
#         # mock request with available versions from server
#         requests_mock.return_value.get.return_value = wpk_versions
#         available_versions = agent._get_versions()
#
#         for version in available_versions:
#             assert WazuhVersion(version[0]) <= WazuhVersion(manager_version)
#             assert re.search(regex_sha1, version[1])
#
#
# @pytest.mark.parametrize('agent_id', [
#     ('001'),
#     ('002')
# ])
# @patch('wazuh.core.core_agent.OssecSocket')
# @patch('wazuh.core.core_agent.Agent._send_wpk_file')
# @patch('socket.socket.sendto', return_value=1)
# @patch("wazuh.common.database_path_global", new=os.path.join(test_data_path, 'var', 'db', 'global.db'))
# def test_upgrade(socket_sendto, _send_wpk_file, ossec_socket_mock, test_data, agent_id):
#     """
#     Test upgrade method
#     """
#     ossec_socket_mock.return_value.receive.return_value = b'ok'
#
#     with patch('sqlite3.connect') as mock_db:
#         mock_db.return_value = test_data.global_db
#         agent = Agent(agent_id)
#         result = agent.upgrade()
#
#         assert result == 'Upgrade procedure started'
#
#
# @patch('wazuh.core.core_agent.OssecSocket')
# @patch('requests.get', side_effect=requests.exceptions.RequestException)
# @patch('wazuh.common.database_path_global', new=os.path.join(test_data_path, 'var', 'db', 'global.db'))
# def test_upgrade_not_access_repo(request_mock, ossec_socket_mock, test_data):
#     """Test upgrade method when repo isn't reachable."""
#     ossec_socket_mock.return_value.receive.return_value = b'ok'
#
#     with patch('sqlite3.connect') as mock_db:
#         mock_db.return_value = test_data.global_db
#         agent = Agent("001")
#         with pytest.raises(WazuhException, match=".* 1713 .*"):
#             agent.upgrade()
#
#
# @pytest.mark.parametrize('agent_id', [
#     ('001'),
#     ('002')
# ])
# @patch('wazuh.core.core_agent.hashlib.sha1')
# @patch('wazuh.core.core_agent.open')
# @patch('wazuh.core.core_agent.requests.get')
# @patch('wazuh.core.core_agent.Agent._get_versions')
# @patch("wazuh.common.database_path_global", new=os.path.join(test_data_path, 'var', 'db', 'global.db'))
# def test_get_wpk_file(versions_mock, get_req_mock, open_mock, sha1_mock, test_data, agent_id):
#     """
#     Test _get_wpk_file method
#     """
#
#     def get_manager_info(available_versions):
#         """
#         Return hash from manager version in available_versions list
#         """
#         for version in available_versions:
#             if WazuhVersion(version[0]) == WazuhVersion(get_manager_version()):
#                 return version[0], version[1]
#         raise Exception  # raise an exception if there is not hash for manager version
#
#     def get_package_version(package_name):
#         """
#         Return package version from package_name
#         """
#         return re.search(r'^wazuh_agent_(v\d+\.\d+\.\d+)\w+\.wpk$', package_name).group(1)
#
#     # mock _get_versions method with a list of available versions
#     versions_mock.return_value = wpk_versions
#
#     with patch('sqlite3.connect') as mock_db:
#         mock_db.return_value = test_data.global_db
#         agent = Agent(agent_id)
#         agent.load_info_from_db()
#         # mock return value of hexdigest function
#         manager_version, hash_manager_version = get_manager_info(wpk_versions)
#         sha1_mock.return_value.hexdigest.return_value = hash_manager_version
#
#         result = agent._get_wpk_file()
#
#         assert get_package_version(result[0]) == manager_version
#         assert result[1] == hash_manager_version
#
#
# @pytest.mark.parametrize('agent_id', [
#     ('001'),
#     ('002')
# ])
# @patch('wazuh.core.core_agent.open')
# @patch('wazuh.core.core_agent.OssecSocket')
# @patch('wazuh.core.core_agent.stat')
# @patch('wazuh.core.core_agent.requests.get')
# @patch('wazuh.core.core_agent.Agent._get_wpk_file')
# @patch("wazuh.common.database_path_global", new=os.path.join(test_data_path, 'var', 'db', 'global.db'))
# def test_send_wpk_file(_get_wpk_mock, get_req_mock, stat_mock, ossec_socket_mock,
#                        open_mock, test_data, agent_id):
#     """
#     Test _send_wpk_file method
#     """
#     with patch('sqlite3.connect') as mock_db:
#         mock_db.return_value = test_data.global_db
#         agent = Agent(agent_id)
#
#         for version in wpk_versions:
#             _get_wpk_mock.return_value = version
#
#             # mock return value of OssecSocket.receive method with a binary string
#             ossec_socket_mock.return_value.receive.return_value = f'ok {version[1]}'.encode()
#             # mock return value of open.read for avoid infinite loop
#             open_mock.return_value.read.return_value = b''
#
#             result = agent._send_wpk_file()
#
#             assert result == ["WPK file sent", version[0]]
#
#
# @patch("wazuh.common.database_path_global", new=os.path.join(test_data_path, 'var', 'db', 'global.db'))
# def test_get_outdated_agents(test_data):
#     """
#     Test get_outdated_agents function
#     """
#     with patch('sqlite3.connect') as mock_db:
#         mock_db.return_value = test_data.global_db
#         result = Agent.get_outdated_agents()
#
#         assert isinstance(result, dict)
#         assert result['totalItems'] == len(result['items'])
#
#         for item in result['items']:
#             assert set(item.keys()) == {'version', 'id', 'name'}
#             assert WazuhVersion(item['version']) < WazuhVersion(get_manager_version())
#
#

#
#
# @patch('wazuh.common.database_path_global', new=os.path.join(test_data_path, 'var', 'db', 'global.db'))
# @patch('wazuh.core.core_agent.OssecQueue')
# @patch('wazuh.core.core_agent.Agent.get_agent_group',
#        return_value={'items': [{'id': '001'}, {'id': '002'}, {'id': '003'}, {'id': '005'}]})
# def test_restart_agents_by_group_ko(mock_get_agent_group, mock_ossec_queue,
#                                     test_data):
#     """Test restart_agents_by_group method when some agents are not restarted."""
#     with patch('sqlite3.connect') as mock_db:
#         mock_db.return_value = test_data.global_db
#         result = Agent.restart_agents_by_group('dmz')
#         # check result fields
#         assert set(result.keys()) == {'failed_ids', 'msg', 'affected_agents'}
#         assert result['msg'] == 'Some agents were not restarted'
#         assert set(result['affected_agents']) == {'001', '002'}
#         assert isinstance(result['failed_ids'], list)
#         for failed_id in result['failed_ids']:
#             assert set(failed_id.keys()) == {'id', 'error'}
#             assert isinstance(failed_id['id'], str)
#             assert set(failed_id['error']) == {'message', 'code'}
#
#
# @patch('wazuh.core.core_agent.Agent.get_all_groups')
# @patch('wazuh.common.database_path_global', new=os.path.join(test_data_path, 'var', 'db', 'global.db'))
# def test_get_full_overview(mock_get_all_groups, test_data):
#     """Test get_full_sumary method."""
#     expected_keys = {'nodes', 'groups', 'agent_os', 'agent_status',
#                      'agent_version', 'last_registered_agent'}
#     with patch('sqlite3.connect') as mock_db:
#         mock_db.return_value = test_data.global_db
#         result = Agent.get_full_overview()
#         # check keys of result
#         assert (set(result.keys()) == expected_keys)
#


full_agent_list = ['000', '001', '002', '003', '004', '005']


@pytest.mark.parametrize('fields, expected_items', [
    (['os.platform'], [{'os': {'platform': 'ubuntu'}, 'count': 4}, {'count': 2}]),
    (['version'], [{'version': 'Wazuh v3.9.0', 'count': 1}, {'version': 'Wazuh v3.8.2', 'count': 2},
                   {'version': 'Wazuh v3.6.2', 'count': 1}, {'count': 2}]),
    (['os.platform', 'os.major'], [{'os': {'major': '18', 'platform': 'ubuntu'}, 'count': 3},
                                   {'os': {'major': '16', 'platform': 'ubuntu'}, 'count': 1}, {'count': 2}])
])
@patch('wazuh.common.database_path_global', new=os.path.join(test_data_path, 'var', 'db', 'global.db'))
def test_agent_get_distinct_agents(test_data, fields, expected_items):
    """Test `get_distinct_agents` function from module agent.

    Parameters
    ----------
    fields : list
    expected_items : list
    """
    with patch('sqlite3.connect', return_value=test_data.global_db):
        distinct = get_distinct_agents(full_agent_list, fields=fields)
        assert distinct.affected_items == expected_items


@patch('wazuh.common.database_path_global', new=os.path.join(test_data_path, 'var', 'db', 'global.db'))
def test_get_agents_summary_status(test_data):
    """Test get_agents_summary function from module agent."""
    with patch('sqlite3.connect', return_value=test_data.global_db):
        summary = get_agents_summary_status(full_agent_list)
        # Asserts are based on what it should get from the fake database
        assert summary['active'] == 3
        assert summary['never_connected'] == 1
        assert summary['pending'] == 1
        assert summary['disconnected'] == 1


@patch('wazuh.common.database_path_global', new=os.path.join(test_data_path, 'var', 'db', 'global.db'))
def test_agent_get_agents_summary_os(test_data):
    """Tests get_os_summary function."""
    with patch('sqlite3.connect', return_value=test_data.global_db):
        summary = get_agents_summary_os(full_agent_list)
        assert summary['items'] == ['ubuntu']


@pytest.mark.parametrize('agent_list, expected_items, expected_fail_code', [
    (['001', '002'], ['001', '002'], None),
    (['000'], [], 1703),
    (['001', '500'], ['001'], 1701)
])
@patch('wazuh.common.database_path_global', new=os.path.join(test_data_path, 'var', 'db', 'global.db'))
@patch('wazuh.agent.get_agents_info', return_value=full_agent_list)
@patch('wazuh.core.core_agent.Agent.restart')
def test_agent_restart_agents(test_data, agents_info_mock, agent_list, expected_items, expected_fail_code):
    """Test `restart_agents` function from module agent.

    Parameters
    ----------
    agent_list
    expected_items
    expected_fail_code
    """
    with patch('sqlite3.connect', return_value=test_data.global_db):
        restart_result = restart_agents(agent_list)
        assert isinstance(restart_result, AffectedItemsWazuhResult)
        assert restart_result.affected_items == expected_items
        if restart_result.failed_items:
            assert next(iter(restart_result.failed_items.keys())).code == expected_fail_code


@pytest.mark.parametrize('agent_list, expected_items', [
    (['001', '002', '003'], ['001', '002', '003']),
    (['001', '400', '002', '500'], ['001', '002'])
])
@patch('wazuh.common.database_path_global', new=os.path.join(test_data_path, 'var', 'db', 'global.db'))
def test_agent_get_agents(test_data, agent_list, expected_items):
    """Test `get_agents` function from module agent.

    Parameters
    ----------
    agent_list
    expected_items
    """
    with patch('sqlite3.connect', return_value=test_data.global_db):
        get_agent_list = get_agents(agent_list=agent_list, select=['id'])
        assert get_agent_list.affected_items
        assert len(get_agent_list.affected_items) == len(expected_items)
        assert (expected_id == agent_id for expected_id, agent_id in zip(expected_items, get_agent_list.affected_items))
        if get_agent_list.failed_items:
            assert (failed_item.message == 'Agent does not exist' for failed_item in get_agent_list.failed_items.keys())


@pytest.mark.parametrize('name, expected_id', [
    ('agent-1', '001'),
    ('nc-agent', '003'),
    ('master', '000'),
    ('invalid-agent', False),
    ('master', 4000),
    ('master', 1000)
])
@patch('wazuh.common.database_path_global', new=os.path.join(test_data_path, 'var', 'db', 'global.db'))
def test_agent_get_agent_by_name(test_data, name, expected_id):
    """Test `get_agent_by_name` function from module agent.

    Parameters
    ----------
    name
    expected_id
    """
    with patch('sqlite3.connect', return_value=test_data.global_db):
        if isinstance(expected_id, str):
            agent_by_name = get_agent_by_name(name=name, select=['id'])
            assert next(iter(agent_by_name.affected_items[0].values())) == expected_id
        elif not expected_id:
            with pytest.raises(WazuhError, match='.* 1754 .*'):
                get_agent_by_name(name=name)
        else:
            with patch('wazuh.agent.get_agents', side_effect=WazuhError(expected_id)):
                with pytest.raises(WazuhError, match=f'.* (1754|{expected_id}) .*'):
                    get_agent_by_name(name=name)


@pytest.mark.parametrize('group, group_exists, expected_agents', [
    ('default', True, ['001', '002', '005']),
    ('not_exists_group', False, None)
])
@patch('wazuh.common.database_path_global', new=os.path.join(test_data_path, 'var', 'db', 'global.db'))
def test_agent_get_agents_in_group(test_data, group, group_exists, expected_agents):
    """Test `get_agents_in_group` from module agent.

    Parameters
    ----------
    group
    group_exists
    expected_agents
    """
    with patch('sqlite3.connect', return_value=test_data.global_db):
        with patch('wazuh.core.core_agent.Agent.group_exists', return_value=group_exists):
            with patch('wazuh.agent.get_agents') as mock_get_agents:
                if group_exists:
                    # Since the decorator is mocked, pass `agent_list` using `call_args` from mock
                    get_agents_in_group(group_id=group, select=['id'])
                    kwargs = mock_get_agents.call_args[1]
                    agents = get_agents(agent_list=full_agent_list, **kwargs)
                    assert agents.affected_items
                    assert len(agents.affected_items) == len(expected_agents)
                    for expected_agent, affected_agent in zip(expected_agents, agents.affected_items):
                        assert expected_agent == next(iter(affected_agent.values()))
                else:
                    # If not `group_exists`, expect an error
                    with pytest.raises(WazuhError, match='.* 1710 .*'):
                        get_agents_in_group(group_id=group)


@pytest.mark.parametrize('agent_list, expected_items', [
    (['001', '002', '003'], ['001', '002', '003']),
    (['001', '400', '002', '500'], ['001', '002'])
])
@patch('wazuh.common.database_path_global', new=os.path.join(test_data_path, 'var', 'db', 'global.db'))
def test_agent_get_agents_keys(test_data, agent_list, expected_items):
    """Test `get_agents_keys` from module agent.

    Parameters
    ----------
    agent_list
    expected_items
    """
    with patch('sqlite3.connect', return_value=test_data.global_db):
        agent_keys = get_agents_keys(agent_list=agent_list)
        assert agent_keys.affected_items
        assert len(agent_keys.affected_items) == len(expected_items)
        for expected_id, agent in zip(expected_items, agent_keys.affected_items):
            assert expected_id == agent['id']
            assert agent['key']
            if agent_keys.failed_items:
                assert (failed_item.message == 'Agent does not exist' for failed_item in agent_keys.failed_items.keys())


@pytest.mark.parametrize('agent_list, remove_return, error_code, expected_items', [
    (['002', '001'], 'Agent deleted successfully.', None, ['001', '002']),
    (['000'], None, 1703, []),
    (['001', '500'], 'Agent deleted successfully.', 1701, ['001']),
    (['001', '002'], WazuhException(1700), 1700, []),
])
@patch('wazuh.common.database_path_global', new=os.path.join(test_data_path, 'var', 'db', 'global.db'))
def test_agent_delete_agents(agent_list, remove_return, error_code, expected_items):
    """Test `delete_agents` function from module agent.

    Parameters
    ----------
    agent_list
    remove_return
    error_code
    expected_items
    """
    with patch('wazuh.agent.Agent.remove', side_effect=remove_return):
        delete_result = delete_agents(agent_list)
        assert delete_result.affected_items == sorted(expected_items)
        if delete_result.failed_items:
            assert next(iter(delete_result.failed_items)).code == error_code
        assert delete_result['older_than'] == "7d"


@patch('wazuh.common.database_path_global', new=os.path.join(test_data_path, 'var', 'db', 'global.db'))
def test_agent_delete_agents_different_status():
    """Test `delete_agents` function from module agent.

    It will force a failed item due to agent not eligible (different status).
    """
    delete_result = delete_agents(['001', '002'], status='active')
    assert delete_result.affected_items == []
    assert delete_result.failed_items
    for failed_item in delete_result.failed_items:
        assert failed_item.code == 1731
        assert 'Agent is not eligible for removal: The agent has a status different to \'active\'' \
               in failed_item.message


@pytest.mark.parametrize('name, agent_id, key', [
    ('agent-1', '001', 'b3650e11eba2f27er4d160c69de533ee7eed601636a85ba2455d53a90927747f'),
    ('a' * 129, '002', 'f304f582f2417a3fddad69d9ae2b4f3b6e6fda788229668af9a6934d454ef44d')
])
@patch('wazuh.common.database_path_global', new=os.path.join(test_data_path, 'var', 'db', 'global.db'))
@patch('wazuh.core.core_agent.fcntl.lockf')
@patch('wazuh.common.client_keys', new=os.path.join(test_agent_path, 'client.keys'))
@patch('wazuh.core.core_agent.chown')
@patch('wazuh.core.core_agent.chmod')
@patch('wazuh.core.core_agent.copyfile')
@patch('wazuh.core.core_agent.common.ossec_uid')
@patch('wazuh.core.core_agent.common.ossec_gid')
@patch('wazuh.core.core_agent.safe_move')
@patch('builtins.open')
def test_agent_add_agent(open_mock, safe_move_mock, common_gid_mock, common_uid_mock, copyfile_mock, chmod_mock,
                         chown_mock, fcntl_mock, test_data, name, agent_id, key):
    """Test `add_agent` from module agent.

    Parameters
    ----------
    name : str
    agent_id : str
    key : str
    """
    try:
        add_result = add_agent(name=name, agent_id=agent_id, key=key)
        assert add_result.dikt['id'] == agent_id
        assert add_result.dikt['key']
    except WazuhError as e:
        assert e.code == 1738


@pytest.mark.parametrize('group_list, expected_result', [
    (['group-1', 'group-2'], ['group-1', 'group-2']),
    (['invalid_group'], [])
])
@patch('wazuh.common.database_path_global', new=os.path.join(test_data_path, 'var', 'db', 'global.db'))
@patch('wazuh.common.client_keys', new=os.path.join(test_agent_path, 'client.keys'))
@patch('wazuh.common.shared_path', new=test_shared_path)
def test_agent_get_agent_groups(test_data, group_list, expected_result):
    with patch('sqlite3.connect', return_value=test_data.global_db):
        group_result = get_agent_groups(group_list)
        assert len(group_result.affected_items) == len(expected_result)
        for item, group_name in zip(group_result.affected_items, group_list):
            assert item['name'] == group_name
            assert item['mergedSum']
            assert item['configSum']


@pytest.mark.parametrize('db_global', [
    'Invalid path',
    os.path.join(test_data_path, 'var', 'db', 'global.db')
])
@patch('wazuh.agent.Connection.execute', side_effect=WazuhException(1000))
def test_agent_get_agent_groups_exceptions(test_data, db_global):
    with patch('wazuh.common.database_path_global', new=db_global):
        try:
            group_result = get_agent_groups(group_list=['invalid group'])
            assert group_result.failed_items
            assert next(iter(group_result.failed_items)).code == 1000
        except WazuhInternalError as e:
            assert e.code == 1600


@pytest.mark.parametrize('group_id', [
    ['group-1'],
    ['invalid-group']
])
@patch('wazuh.common.database_path_global', new=os.path.join(test_data_path, 'var', 'db', 'global.db'))
@patch('wazuh.common.client_keys', new=os.path.join(test_agent_path, 'client.keys'))
@patch('wazuh.common.shared_path', new=test_shared_path)
def test_agent_get_group_files(test_data, group_id):
    with patch('wazuh.common.database_path_global', new=test_data.global_db):
        try:
            file_result = get_group_files(group_list=group_id)
            # Assert 'items' contains agent.conf, merged.mg and ar.conf and 'hash' is not empty
            assert len(file_result.dikt['items']) == 3
            for item, filename in zip(file_result.dikt['items'], ['agent.conf', 'merged.mg', 'ar.conf']):
                assert item['filename'] == filename
                assert item['hash']
        except WazuhError as e:
            assert e.code == 1710
            assert e.message == 'The group does not exist: invalid-group'


@pytest.mark.parametrize('shared_path, group_id, exception, exception_code', [
    (test_shared_path, ['group-empty'], (OSError, IOError), None)
])
def test_agent_get_group_files_exceptions(shared_path, group_id, exception, exception_code):
    with patch('wazuh.common.shared_path', new=shared_path):
        try:
            get_group_files(group_list=group_id)
        except exception as e:
            assert e.code == exception_code

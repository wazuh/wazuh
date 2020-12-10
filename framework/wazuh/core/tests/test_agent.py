#!/usr/bin/env python
# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sqlite3
import sys
from unittest.mock import ANY, patch, mock_open, call

import pytest
from freezegun import freeze_time

with patch('wazuh.core.common.ossec_uid'):
    with patch('wazuh.core.common.ossec_gid'):
        from wazuh.core.agent import *
        from wazuh.core.exception import WazuhException
        from api.util import remove_nones_to_dict
        from wazuh.core.common import reset_context_cache

from pwd import getpwnam
from grp import getgrnam

# all necessary params

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data', 'test_agent')


def get_WazuhDBQuery_params(wdb_class):
    """Get default parameters for the specified WazuhDBQuery class.

    Parameters
    ----------
    wdb_class : str
        Suffix of the WazuhDBQuery class. Example: 'Agents' to get default parameters from `WazuhDBQueryAgents` class.

    Returns
    -------
    parameters_dict
        Dictionary with all the default parameters.
    """
    with patch('wazuh.core.agent.WazuhDBQuery.__init__') as wdbquery_mock:
        getattr(sys.modules[__name__], f'WazuhDBQuery{wdb_class}')()
        return wdbquery_mock.call_args.kwargs


# list with Wazuh packages availables with their hash
wpk_versions = [['v3.10.0', '251b1af81d45d291540d8589b124302613f0a4e0'],
                ['v3.9.0', '180e25a1fefafe8d83c763d375cb1a3a387bc08a'],
                ['v3.8.3', '180e25a1fefafe8d83c763d375cb1a3a387bc08a'],
                ['v3.8.2', '7a49d5604e1034d1327c993412433d124274bc7e'],
                ['v3.8.1', '54c55d50f9d88df937fb2b40a4eeec17cbc6ce24'],
                ['v3.8.0', 'e515d2251af9d4830dfa27902896c8d66c4ded2f'],
                ['v3.7.2', 'e28cfb89469b1b8bfabefe714c09b942ebd7a928'],
                ['v3.7.1', '7ef661a92295a02755812e3e10c87bf49bb52114'],
                ['v3.7.0', 'b1a94c212195899be53564e86b69981d4729154e'],
                ['v3.6.1', 'ed01192281797f64c99d53cff91efe936bc31b17'],
                ['v3.6.0', '83fd0e49c6ab47f59c5d75478a371396082613fe'],
                ['v3.5.0', '5e276bd26d76c3c1eebed5ca57094ee957b3ee40'],
                ['v3.4.0', 'f20e4319b9088d534a4655a9136a608800522d50'],
                ['v3.3.9', '180e25a1fefafe8d83c763d375cb1a3a387bc08a']]


class InitAgent:

    def __init__(self, data_path=test_data_path):
        """
        Sets up necessary test environment for agents:
            * One active agent.
            * One pending agent.
            * One never_connected agent.
            * One disconnected agent.

        :return: None
        """
        self.global_db = sqlite3.connect(':memory:')
        self.global_db.row_factory = sqlite3.Row
        self.cur = self.global_db.cursor()
        with open(os.path.join(data_path, 'schema_global_test.sql')) as f:
            self.cur.executescript(f.read())

        self.never_connected_fields = {'status', 'name', 'ip', 'registerIP', 'node_name', 'dateAdd', 'id'}
        self.pending_fields = self.never_connected_fields | {'manager', 'lastKeepAlive'}
        self.manager_fields = self.pending_fields | {'version', 'os', 'group'}
        self.active_fields = self.manager_fields | {'group', 'mergedSum', 'configSum'}
        self.manager_fields -= {'registerIP'}


test_data = InitAgent()


def send_msg_to_wdb(msg, raw=False):
    query = ' '.join(msg.split(' ')[2:])
    result = test_data.cur.execute(query).fetchall()
    return list(map(remove_nones_to_dict, map(dict, result)))


def get_manager_version():
    """
    Get manager version
    """
    manager = Agent(id=0)
    manager.load_info_from_db()

    return manager.version


def check_agent(test_data, agent):
    """Checks a single agent is correct"""
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


@pytest.mark.parametrize('value', [
    True,
    OSError
])
@patch("wazuh.core.agent.WazuhDBBackend")
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_WazuhDBQueryAgents__init__(socket_mock, send_mock, backend_mock, value):
    """Tests if method __init__ of WazuhDBQueryAgents works properly.

    Parameters
    ----------
    mock_sqli_conn : mock
        Mock of SQLite connection.
    value : boolean
        Boolean to be returned by the method glob.glob().
    """
    socket_mock.side_effect = value
    if value:
        WazuhDBQueryAgents()
        backend_mock.assert_called_once()
    else:
        with pytest.raises(WazuhException, match=".* 2005 .*"):
            WazuhDBQueryAgents()


@patch('socket.socket.connect')
def test_WazuhDBQueryAgents_filter_date(mock_socket_conn):
    """Tests _filter_date of WazuhDBQueryAgents returns expected query"""
    query_agent = WazuhDBQueryAgents()
    query_agent._filter_date({'value': '7d', 'operator': '<', 'field': 'time'}, 'os.name')

    assert ' AND id != 0' in query_agent.query, 'Query returned does not match the expected one'


@pytest.mark.parametrize('field, expected_query', [
    ('status', 'last_keepAlive asc'),
    ('os.version', 'CAST(os_major AS INTEGER) asc, CAST(os_minor AS INTEGER) asc'),
    ('id', 'id asc'),
])
@patch('socket.socket.connect')
def test_WazuhDBQueryAgents_sort_query(mock_socket_conn, field, expected_query):
    """Tests _sort_query of WazuhDBQueryAgents returns expected result

    Parameters
    ----------
    field : str
        One of the available fields.
    expected_query :
        Query expected after using the field value.
    """
    query_agent = WazuhDBQueryAgents(sort={'order': 'asc'})
    result = query_agent._sort_query(field)

    assert expected_query in result, 'Result does not match the expected one'


@patch('socket.socket.connect')
def test_WazuhDBQueryAgents_add_search_to_query(mock_socket_conn):
    """Tests _add_search_to_query of WazuhDBQueryAgents returns expected query"""
    query_agent = WazuhDBQueryAgents(search={'value': 'test', 'negation': True})
    query_agent._add_search_to_query()

    assert 'OR id LIKE :search_id)' in query_agent.query, 'Query returned does not match the expected one'


@patch('socket.socket.connect')
def test_WazuhDBQueryAgents_format_data_into_dictionary(mock_socket_conn):
    """Tests _format_data_into_dictionary of WazuhDBQueryAgents returns expected data"""
    data = [{'id': 0, 'status': 'active', 'group': 'default,group1,group2', 'manager': 'master',
             'dateAdd': 1000000000}]

    query_agent = WazuhDBQueryAgents(offset=0, limit=1, sort=None,
                                     search=None, select={'id', 'status', 'group', 'dateAdd', 'manager'},
                                     default_sort_field=None, query=None, count=5,
                                     get_data=None, min_select_fields='os.version')

    # Mock _data variable with our own data
    query_agent._data = data
    result = query_agent._format_data_into_dictionary()

    # Assert format_fields inside _format_data_into_dictionary is working as expected
    assert result['items'][0]['id'] == '000', 'ID is not as expected'
    assert result['items'][0]['status'] == 'active', 'status is not as expected'
    assert type(result['items'][0]['group']) == list and len(result['items'][0]['group']) == 3, \
        '"group" has different type or length than expected'
    assert type(result['items'][0]['dateAdd']) == datetime, 'Not date type'
    assert result['items'][0]['manager'] == 'master'


@patch('socket.socket.connect')
def test_WazuhDBQueryAgents_parse_legacy_filters(mock_socket_conn):
    """Tests _parse_legacy_filters of WazuhDBQueryAgents returns expected query"""
    query_agent = WazuhDBQueryAgents(filters={'older_than': 'test'})
    query_agent._parse_legacy_filters()

    assert '(lastKeepAlive>test;status!=never_connected,dateAdd>test;status=never_connected)' in query_agent.q, \
        'Query returned does not match the expected one'


@pytest.mark.parametrize('field_name, field_filter, q_filter', [
    ('group', 'field', {'value': '1', 'operator': 'LIKE'}),
    ('group', 'test', {'value': '1', 'operator': 'LIKE'}),
    ('os.name', 'field', {'value': '1', 'operator': 'LIKE', 'field': 'status$0'}),
])
@patch('socket.socket.connect')
def test_WazuhDBQueryAgents_process_filter(mock_socket_conn, field_name, field_filter, q_filter):
    """Tests _process_filter of WazuhDBQueryAgents returns expected query

    Parameters
    ----------
    field_name : str
        One of the available fields.
    field_filter : str
        Defines field filters required by the user.
    q_filter : dict
        Query to filter in database.
    """
    query_agent = WazuhDBQueryAgents()
    query_agent._process_filter(field_name, field_filter, q_filter)

    if field_name == 'group':
        assert f'`group` LIKE :{field_filter}_1 OR `group` LIKE ' \
               f':{field_filter}_2 OR `group` LIKE :{field_filter}_3 OR ' \
               f'`group` = :{field_filter}' in query_agent.query, 'Query returned does not match the expected one'
    else:
        assert 'agentos_name LIKE :field COLLATE NOCASE' in query_agent.query, \
            'Query returned does not match the expected one'


@pytest.mark.parametrize('value', [
    True,
    OSError
])
@patch("wazuh.core.agent.WazuhDBBackend")
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_WazuhDBQueryGroup__init__(socket_mock, send_mock, backend_mock, value):
    """Test if method __init__ of WazuhDBQueryGroup works properly.

    Parameters
    ----------
    mock_sqli_conn : mock
        Mock of SQLite connection.
    value : boolean
        Boolean to be returned by the method glob.glob().
    """
    socket_mock.side_effect = value
    if value:
        WazuhDBQueryGroup()
        backend_mock.assert_called_once()
    else:
        with pytest.raises(WazuhException, match=".* 2005 .*"):
            WazuhDBQueryGroup()


@pytest.mark.parametrize('filters', [
    {'name': 'group-1'},
    {'name': 'group-2'}
])
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_WazuhDBQueryGroup_filters(socket_mock, send_mock, filters):
    """Test if parameter filters of WazuhDBQueryGroup works properly.

        Parameters
        ----------
        filters : dict
            Dict of filters to apply.
        """
    query_group = WazuhDBQueryGroup(filters=filters)
    result = query_group.run()
    assert result['totalItems'] > 0
    for item in result['items']:
        assert (item[key] == value for key, value in filters.items())


@patch('socket.socket.connect')
def test_WazuhDBQueryGroupByAgents__init__(mock_socket_conn):
    """Tests if method __init__ of WazuhDBQueryGroupByAgents works properly."""
    query_group = WazuhDBQueryGroupByAgents(filter_fields=['name', 'os.name'], offset=0, limit=1, sort={'order': 'asc'},
                                            search={'value': 'test', 'negation': True},
                                            select={'os.name'}, query=None, count=5, get_data=None)

    assert query_group.remove_extra_fields, 'Query returned does not match the expected one'


@patch('socket.socket.connect')
def test_WazuhDBQueryGroupByAgents_format_data_into_dictionary(mock_socket_conn):
    """Tests if method _format_data_into_dictionary of WazuhDBQueryGroupByAgents works properly."""
    query_group = WazuhDBQueryGroupByAgents(filter_fields=['name', 'os.name'], offset=0, limit=1, sort={'order': 'asc'},
                                            search={'value': 'test', 'negation': True},
                                            select={'os.name'}, query=None, count=5, get_data=None)

    query_group.filter_fields = {'fields': set(query_group.filter_fields)}
    query_group._data = [{'count': 1, 'name': 'wazuh-master'},
                         {'count': 1, 'name': 'wazuh-agent1'}]

    result = query_group._format_data_into_dictionary()
    assert all(x['os']['name'] == 'unknown' for x in result['items'])


@patch('socket.socket.connect')
def test_WazuhDBQueryGroupByAgents_format_data_into_dictionary_status(mock_socket_conn):
    """Tests if method _format_data_into_dictionary of WazuhDBQueryGroupByAgents works properly."""
    query_group = WazuhDBQueryGroupByAgents(filter_fields=['status', 'os.name'], offset=0, limit=1, sort=None,
                                            search=None, select=None, query=None, count=5, get_data=None)

    query_group.select = {'os.name', 'count', 'status', 'lastKeepAlive', 'version'}
    query_group._data = [
        {'os.name': 'Ubuntu', 'count': 1, 'version': 'Wazuh v4.0.0', 'status': 'disconnected', 'lastKeepAlive': 1593093968},
        {'os.name': 'Ubuntu', 'count': 2, 'version': 'Wazuh v3.13.0', 'status': 'disconnected', 'lastKeepAlive': 1593093968},
        {'os.name': 'Ubuntu', 'count': 1, 'version': 'Wazuh v3.13.0', 'status': 'disconnected', 'lastKeepAlive': 1593093976}]

    result = query_group._format_data_into_dictionary()
    assert result == {'items': [{'os': {'name': 'Ubuntu'}, 'status': 'disconnected', 'count': 4}], 'totalItems': 0}


@patch('socket.socket.connect')
def test_WazuhDBQueryMultigroups__init__(mock_socket_conn):
    """Tests if method __init__ of WazuhDBQueryMultigroups works properly."""
    query_multigroups = WazuhDBQueryMultigroups(group_id='test')

    assert 'group=test' in query_multigroups.q, 'Query returned does not match the expected one'


@pytest.mark.parametrize('group_id', [
    'null',
    'test'
])
@patch('socket.socket.connect')
def test_WazuhDBQueryMultigroups_default_query(mock_socket_conn, group_id):
    """Tests if method _default_query of WazuhDBQueryMultigroups works properly.

    Parameters
    ----------
    group_id : str
        Identifier of the group.
    """
    query_multigroups = WazuhDBQueryMultigroups(group_id=group_id)
    result = query_multigroups._default_query()

    if group_id == 'null':
        assert 'SELECT {0} FROM agent a' in result, 'Query returned does not match the expected one'
    else:
        assert 'SELECT {0} FROM agent a LEFT JOIN belongs b ON a.id = b.id_agent' in result, \
            'Query returned does not match the expected one'


@patch('socket.socket.connect')
def test_WazuhDBQueryMultigroups_default_count_query(mock_socket_conn):
    """Tests if method _default_count_query of WazuhDBQueryMultigroups works properly."""
    query_multigroups = WazuhDBQueryMultigroups(group_id='test')
    result = query_multigroups._default_count_query()

    assert 'COUNT(DISTINCT a.id)' in result, 'Query returned does not match the expected one'


@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_WazuhDBQueryMultigroups_get_total_items(mock_socket_conn, send_mock):
    """Tests if method _get_total_items of WazuhDBQueryMultigroups works properly."""
    query_multigroups = WazuhDBQueryMultigroups(group_id='test')
    query_multigroups._get_total_items()

    assert 'GROUP BY a.id' in query_multigroups.query, 'Query returned does not match the expected one'


@pytest.mark.parametrize('id, ip, name, key', [
    ('1', '127.0.0.1', 'test_agent', 'b3650e11eba2f27er4d160c69de533ee7eed6016fga85ba2455d53a90927747D'),
])
@patch('wazuh.core.agent.Agent._add')
def test_agent__init__(mock_add, id, ip, name, key):
    """Tests if method __init__ of Agent works properly.

    Parameters
    ----------
    id : str
        Identifier of agent. It has 3 digits
    ip : str
        Add an agent (generate id and key automatically)
    name : str
        Add an agent (generate id and key automatically)
    key : str
        Key of the agent.
    """
    agent = Agent(id=id, ip=ip, name=name, key=key)

    assert agent.id == id and agent.ip == ip and agent.name == name and agent.internal_key == key, \
        'Query returned does not match the expected one'


def test_agent__str__():
    """Tests if method __str__ of Agent returns a string type."""
    agent = Agent()

    assert isinstance(str(agent), str)


def test_agent_to_dict():
    """Tests if method to_dict() of Agent returns a dict type."""
    agent = Agent()

    assert isinstance(agent.to_dict(), dict), 'Result is not a dict'


@pytest.mark.parametrize('id, expected_ip, expected_name, expected_codename', [
    ('000', '127.0.0.1', 'master', 'Bionic Beaver'),
    ('001', '172.17.0.202', 'agent-1', 'Bionic Beaver'),
    ('002', '172.17.0.201', 'agent-2', 'Xenial'),
])
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_agent_load_info_from_db(socket_mock, send_mock, id, expected_ip, expected_name, expected_codename):
    """Tests if method load_info_from_db of Agent returns a correct info.

    Parameters
    ----------
    id : str
        Id of the agent to be searched.
    expected_ip : str
        Ip expected on the returned agent.
    expected_name : str
        Name expected on the returned agent.
    expected_codename : str
        OS codename expected on the returned agent.
    """
    agent = Agent(id=id)
    agent.load_info_from_db()
    result = agent.to_dict()

    assert result['id'] == id and result['name'] == expected_name and result['ip'] == expected_ip and \
           result['os']['codename'] == expected_codename


@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_agent_load_info_from_db_ko(socket_mock, send_mock):
    """Tests if method load_info_from_db raises expected exception"""
    with pytest.raises(WazuhResourceNotFound, match='.* 1701 .*'):
        agent = Agent(id=11250)
        agent.load_info_from_db()


@pytest.mark.parametrize('id, select', [
    (0, None),
    (3, None),
    (0, {'id', 'ip', 'version'}),
    (5, {'id', 'ip', 'version'}),
    (0, {'status', 'manager', 'node_name', 'dateAdd', 'lastKeepAlive'}),
    (2, {'status', 'manager', 'node_name', 'dateAdd', 'lastKeepAlive'})
])
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_agent_get_basic_information(socket_mock, send_mock, id, select):
    """Tests if method get_basic_information returns expected data

    Parameters
    ----------
    id : int
        Id of the agent to be searched.
    select : set
        Fields to return.
    """
    agent = Agent(id)
    result = agent.get_basic_information(select)

    assert isinstance(result, dict), 'Result is not a dict'
    if select is not None:
        assert all((x in select for x in result.keys())) and len(result.keys()) == len(select), \
            'Result does not contain expected keys.'


@pytest.mark.parametrize('id, expected_key', [
    (0, 'MCBOb25lIE5vbmUgTm9uZQ=='),
    (1, 'MSBOb25lIE5vbmUgTm9uZQ=='),
    (2, 'MiBOb25lIE5vbmUgTm9uZQ=='),
    (3, 'MyBOb25lIE5vbmUgTm9uZQ=='),
    (4, 'NCBOb25lIE5vbmUgTm9uZQ=='),
    (5, 'NSBOb25lIE5vbmUgTm9uZQ=='),
])
def test_agent_compute_key(id, expected_key):
    """Tests if method compute_key returns expected key for each agent

    Parameters
    ----------
    id : int
        Id of the agent to be searched.
    expected_key :
        Key that should be returned for given ID.
    """

    agent = Agent(id)
    result = agent.compute_key()

    assert result == expected_key, 'Result does not match with expected key'


@pytest.mark.parametrize('id, expected_key', [
    (1, 'MDAxIGFnZW50LTEgYW55IGIzNjUwZTExZWJhMmYyN2VyNGQxNjBjNjlkZTUzM2VlN2VlZDYwMTYzNmE4NWJhMjQ1NWQ1M2E5MDkyNzc0N2Y='),
    (2,
     'MDAyIGFnZW50LTIgMTcyLjE3LjAuMjAxIGIzNjUwZTExZWJhMmYyN2VyNGQxNjBjNjlkZTUzM2VlN2VlZDYwMTZmZ2E4NWJhMjQ1NWQ1M2E5MDkyNzc0N2Y='),
    (3, 'MDAzIG5jLWFnZW50IGFueSBmMzA0ZjU4MmYyNDE3YTNmZGRhZDY5ZDlhZTJiNGYzYjZlNmZkYTc4ODIyOTY2OGFmOWE2OTM0ZDQ1NGVmNDRk'),
    (4,
     'MDA0IHBlbmRpbmctYWdlbnQgYW55IDI4NTViY2Y0OTI3M2M3NTllZjViMTE2ODI5Y2M1ODJmMTUzYzZjMTk5ZGY3Njc2ZTUzZDU5Mzc4NTVmZjU5MDI='),
    (5,
     'MDA1IGFnZW50LTUgMTcyLjE3LjAuMzAwIGIzNjUwZTExZWJhMmYyN2VyNGQxNjBjNjlkZTUzM2VlN2VlZDYwMTYzNmE0MmJhMjQ1NWQ1M2E5MDkyNzc0N2Y='),
])
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_agent_get_key(socket_mock, send_mock, id, expected_key):
    """Tests if method get_key returns expected key for each agent

    Parameters
    ----------
    id : int
        Id of the agent to be searched.
    expected_key :
        Key that should be returned for given ID.
    """
    agent = Agent(id)
    result = agent.get_key()

    assert result == expected_key, 'Result does not match with expected key'


@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_agent_get_key_ko(socket_mock, send_mock):
    """Tests if method get_key raises exception when ID is 0"""
    with pytest.raises(WazuhError, match='.* 1703 .*'):
        agent = Agent(0)
        agent.get_key()


@patch('wazuh.core.agent.OssecQueue')
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_agent_restart(socket_mock, send_mock, mock_queue):
    """Tests if method restart calls other methods with correct params"""
    with patch('wazuh.core.agent.Agent.getconfig', return_value={'active-response': {'disabled': 'no'}}) as \
            mock_config:
        agent = Agent(0)
        agent.restart()

        # Assert methods are called with correct params
        mock_config.assert_called_once_with('com', 'active-response')
        mock_queue.assert_called_once()


@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_agent_restart_ko(socket_mock, send_mock):
    """Tests if method restart raises exception"""
    # Assert exception is raised when status of agent is not 'active'
    with patch('wazuh.core.agent.Agent.getconfig', return_value={'active-response': {'disabled': 'no'}}):
        with pytest.raises(WazuhError, match='.* 1707 .*'):
            agent = Agent(3)
            agent.restart()

    # Assert exception is raised when active-response is disabled
    with patch('wazuh.core.agent.Agent.getconfig', return_value={'active-response': {'disabled': 'yes'}}):
        with pytest.raises(WazuhException, match='.* 1750 .*'):
            agent = Agent(0)
            agent.restart()


@pytest.mark.parametrize('status', [
    'stopped', 'running'
])
@patch('wazuh.core.agent.Agent._remove_authd', return_value='Agent was successfully deleted')
@patch('wazuh.core.agent.Agent._remove_manual', return_value='Agent was successfully deleted')
def test_agent_remove(mock_remove_manual, mock_remove_authd, status):
    """Tests if method remove() works as expected

    Parameters
    ----------
    status : string
        Status to be mocked in ossec-authd.
    """

    with patch('wazuh.core.agent.get_manager_status', return_value={'ossec-authd': status}):
        agent = Agent(0)
        result = agent.remove(use_only_authd=False)
        assert result == 'Agent was successfully deleted', 'Not expected message'

        if status == 'stopped':
            mock_remove_manual.assert_called_once_with(False, False), 'Not expected params'
            mock_remove_authd.assert_not_called(), '_remove_authd should not be called'
        else:
            mock_remove_manual.assert_not_called(), '_remove_manual should not be called'
            mock_remove_authd.assert_called_once_with(False), 'Not expected params'


@patch('wazuh.core.agent.Agent._remove_authd', return_value='Agent was successfully deleted')
@patch('wazuh.core.agent.Agent._remove_manual', return_value='Agent was successfully deleted')
def test_agent_remove_ko(mock_remove_manual, mock_remove_authd):
    """Tests if method remove() raises expected exception"""
    with pytest.raises(WazuhInternalError, match='.* 1726 .*'):
        agent = Agent(0)
        agent.remove(use_only_authd=True)


@patch('wazuh.core.agent.OssecSocketJSON')
def test_agent_remove_authd(mock_ossec_socket):
    """Tests if method remove_authd() works as expected"""
    agent = Agent(0)
    agent._remove_authd(purge=True)
    mock_ossec_socket.return_value.send.assert_called_once_with(
        {"function": "remove", "arguments": {"id": str(0).zfill(3), "purge": True}})
    mock_ossec_socket.return_value.receive.assert_called_once()
    mock_ossec_socket.return_value.close.assert_called_once()


@pytest.mark.parametrize('backup, exists_backup_dir', [
    (False, False),
    (True, False),
    (True, True),
])
@patch('wazuh.core.wdb.WazuhDBConnection.delete_agents_db')
@patch('wazuh.core.agent.remove')
@patch('wazuh.core.agent.rmtree')
@patch('wazuh.core.agent.chown')
@patch('wazuh.core.agent.chmod')
@patch('wazuh.core.agent.stat')
@patch("wazuh.core.common.ossec_path", new=test_data_path)
@patch('wazuh.core.agent.path.exists')
@patch('wazuh.core.database.isfile', return_value=True)
@patch('wazuh.core.agent.path.isdir', return_value=False)
@patch('wazuh.core.agent.safe_move')
@patch('wazuh.core.agent.makedirs')
@patch('wazuh.core.agent.chmod_r')
@freeze_time('1975-01-01')
@patch("wazuh.core.common.ossec_uid", return_value=getpwnam("root"))
@patch("wazuh.core.common.ossec_gid", return_value=getgrnam("root"))
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('wazuh.core.wdb.WazuhDBConnection.run_wdb_command')
@patch('socket.socket.connect')
def test_agent_remove_manual(socket_mock, run_wdb_mock, send_mock, grp_mock, pwd_mock, chmod_r_mock, makedirs_mock,
                             safe_move_mock, isdir_mock, isfile_mock, exists_mock, stat_mock, chmod_mock,
                             chown_mock, rmtree_mock, remove_mock, mock_delete_agents, backup, exists_backup_dir):
    """Test the _remove_manual function

    Parameters
    ----------
    backup : bool
        Create backup before removing the agent.
    """
    client_keys_text = '\n'.join([f'{str(row["id"]).zfill(3)} {row["name"]} {row["register_ip"]} {row["internal_key"]}'
                                  for row in test_data.global_db.execute(
            'select id, name, register_ip, internal_key from agent where id > 0')])

    with patch('wazuh.core.agent.open', mock_open(read_data=client_keys_text)) as m:
        if exists_backup_dir:
            exists_mock.side_effect = [True, True, True] + [False] * 10
        else:
            exists_mock.side_effect = lambda x: not (common.backup_path in x)
        Agent('001')._remove_manual(backup=backup)

        m.assert_any_call(common.client_keys)
        m.assert_any_call(common.client_keys + '.tmp', 'w')
        stat_mock.assert_called_once_with(common.client_keys)
        chown_mock.assert_called_once_with(common.client_keys + '.tmp', common.ossec_uid(), common.ossec_gid())
        mock_delete_agents.assert_called_once_with(['001'])
        run_wdb_mock.assert_called_once_with('global sql DELETE FROM belongs WHERE id_agent = 001')
        remove_mock.assert_any_call(os.path.join(common.ossec_path, 'queue/rids/001'))

        # make sure the mock is called with a string according to a non-backup path
        exists_mock.assert_any_call('{0}/queue/agent-info/agent-1-any'.format(test_data_path))
        safe_move_mock.assert_called_with(common.client_keys + '.tmp', common.client_keys, permissions=0o640)
        if backup:
            if exists_backup_dir:
                backup_path = os.path.join(common.backup_path, f'agents/1975/Jan/01/001-agent-1-any-002')
            else:
                backup_path = os.path.join(common.backup_path, f'agents/1975/Jan/01/001-agent-1-any')
            makedirs_mock.assert_called_once_with(backup_path)
            chmod_r_mock.assert_called_once_with(backup_path, 0o750)


@pytest.mark.parametrize("authd_status", [
    'running',
    'stopped'
])
@pytest.mark.parametrize("ip, id, key, force", [
    ('192.168.0.0', None, None, -1),
    ('192.168.0.0/28', '002', None, -1),
    ('any', '002', 'WMPlw93l2PnwQMN', -1),
    ('any', '003', 'WMPlw93l2PnwQMN', 1),
])
@patch('wazuh.core.agent.Agent._add_manual')
@patch('wazuh.core.agent.Agent._add_authd')
def test_agent_add(mock_add_authd, mock_add_manual, authd_status, ip, id, key, force):
    """Test method _add() call other functions with correct params.

    Parameters
    ----------
    authd_status : str
        Status to be returned when calling get_manager_status().
    ip : str
        IP of the new agent. It can be an IP, IP/NET or ANY.
    id : str
        ID of the new agent.
    key : str
        Key of the new agent.
    force : int
        Remove old agents with same IP if disconnected since <force> seconds.
    """
    agent = Agent(1, use_only_authd=False)

    with patch('wazuh.core.agent.get_manager_status', return_value={'ossec-authd': authd_status}):
        agent._add('test_name', ip, id=id, key=key, force=force)

    if authd_status == 'running':
        mock_add_authd.assert_called_once_with('test_name', ip, id, key, force)
    else:
        mock_add_manual.assert_called_once_with('test_name', ip, id, key, force)


@patch('wazuh.core.agent.get_manager_status', return_value={'ossec-authd': 'stopped'})
def test_agent_add_ko(mock_maganer_status):
    """Test if _add() method raises expected exception."""
    agent = Agent(1)

    with pytest.raises(WazuhError, match='.* 1706 .*'):
        agent._add('test_name', 'http://jaosdf', use_only_authd=True)

    with pytest.raises(WazuhError, match='.* 1706 .*'):
        agent._add('test_name', '1111', use_only_authd=True)

    with pytest.raises(WazuhInternalError, match='.* 1726 .*'):
        agent._add('test_name', '192.168.0.0', use_only_authd=True)


@pytest.mark.parametrize("name, ip, id, key", [
    ('test_agent', '172.19.0.100', None, None),
    ('test_agent', '172.19.0.100', '002', 'MDAyIHdpbmRvd3MtYWdlbnQyIGFueSAzNDA2MjgyMjEwYmUwOWVlMWViNDAyZTYyODZmNWQ2O'
                                          'TE5MjBkODNjNTVjZDE5N2YyMzk3NzA0YWRhNjg1YzQz')
])
@patch('wazuh.core.agent.OssecSocketJSON')
def test_agent_add_authd(mock_ossec_socket, name, ip, id, key):
    """Tests if method _add_authd() works as expected

    Parameters
    ----------
    name : str
        Name of the new agent.
    ip : str
         IP of the new agent. It can be an IP, IP/NET or ANY.
    id : str
        ID of the new agent.
    key : str
         Key of the new agent.
    """
    agent = Agent(id)
    agent._add_authd(name, ip, id, key)

    mock_ossec_socket.return_value.receive.assert_called_once()
    mock_ossec_socket.return_value.close.assert_called_once()
    if id and key:
        mock_ossec_socket.return_value.send.assert_called_once_with(
            {"function": "add", "arguments": {"name": name, "ip": ip, "id": id, "key": key, "force": -1}})
    else:
        mock_ossec_socket.return_value.send.assert_called_once_with(
            {"function": "add", "arguments": {"name": name, "ip": ip, "force": -1}})


@pytest.mark.parametrize("mocked_exception, expected_exception", [
    (None, None),
    (WazuhError(9008, cmd_error=True), ".* 1705 .*"),
    (WazuhError(9007, cmd_error=True), ".* 1706 .*"),
    (WazuhError(9012, cmd_error=True), ".* 1708 .*"),
    (WazuhError(9000, cmd_error=True), ".* None")
])
@patch('wazuh.core.agent.OssecSocketJSON')
def test_agent_add_authd_ko(mock_ossec_socket, mocked_exception, expected_exception):
    """Tests if method _add_authd() raises expected exception"""
    agent = Agent('001')

    if not mocked_exception:
        with pytest.raises(WazuhError, match=".* 1709 .*"):
            agent._add_authd('test_add', '192.168.0.1', '2', 'adsiojew')
    else:
        mock_ossec_socket.return_value.receive.side_effect = mocked_exception
        with pytest.raises(WazuhError, match=expected_exception):
            agent._add_authd('test_add', '192.168.0.1')


@pytest.mark.parametrize("ip, id, key, force", [
    ('192.168.0.0', '002', None, -1),
    ('192.168.0.0/28', '002', None, -1),
    ('any', '002', 'WMPlw93l2PnwQMN', -1),
    ('any', '003', 'WMPlw93l2PnwQMN', 1),
])
@patch('wazuh.core.agent.safe_move')
@patch('wazuh.core.agent.copyfile')
@patch('wazuh.core.common.ossec_uid')
@patch('wazuh.core.common.ossec_gid')
@patch('wazuh.core.agent.chown')
@patch('wazuh.core.agent.chmod')
@patch('wazuh.core.agent.stat')
@patch('wazuh.core.agent.fcntl.lockf')
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_agent_add_manual(socket_mock, mock_send, mock_lockf, mock_stat, mock_chmod, mock_chown, mock_ossec_gid,
                          mosck_ossec_uid, mock_copyfile, mock_safe_move, ip, id, key, force):
    """Tests if method _add_manual() works as expected"""
    key = 'MDAyIHdpbmRvd3MtYWdlbnQyIGFueSAzNDA2MjgyMjEwYmUwOWVlMWViNDAyZTYyODZmNWQ2OTE5' \
          'MjBkODNjNTVjZDE5N2YyMzk3NzA0YWRhNjg1YzQz'
    client_keys_text = f'001 windows-agent any {key}\n \n002 #name '

    with patch('wazuh.core.agent.open', mock_open(read_data=client_keys_text)) as m:
        agent = Agent(1)

        agent._add_manual('test_agent', ip=ip, id=id, key=key, force=force)

        assert agent.id == id, 'ID should has been updated.'
        calls = [call('global sql select count(*) from agent where (id = 0)'),
                 call('global sql select name from agent where (id = 0) limit 1 offset 0')]

        mock_send.assert_has_calls(calls)
        mock_chown.assert_called_once_with('{0}.tmp'.format(common.client_keys), ANY, ANY)
        mock_chmod.assert_called_once_with('{0}.tmp'.format(common.client_keys), ANY)
        mock_copyfile.assert_called_once_with(common.client_keys, '{0}.tmp'.format(common.client_keys))
        mock_safe_move.assert_called_once_with('{0}.tmp'.format(common.client_keys), common.client_keys,
                                               permissions=ANY)


@patch('wazuh.core.agent.copyfile')
@patch('wazuh.core.common.ossec_uid')
@patch('wazuh.core.common.ossec_gid')
@patch('wazuh.core.agent.chown')
@patch('wazuh.core.agent.chmod')
@patch('wazuh.core.agent.stat')
@patch('wazuh.core.agent.fcntl.lockf')
def test_agent_add_manual_ko(mock_lockf, mock_stat, mock_chmod, mock_chown, mock_ossec_gid, mosck_ossec_uid,
                             mock_copyfile):
    """Tests if method _add_manual() raises expected exceptions"""
    key = 'MDAyIHdpbmRvd3MtYWdlbnQyIGFueSAzNDA2MjgyMjEwYmUwOWVlMWViNDAyZTYyODZmNWQ2OTE5' \
          'MjBkODNjNTVjZDE5N2YyMzk3NzA0YWRhNjg1YzQz'
    client_keys_text = f'001 windows-agent 192.168.0.1 {key}\n#\n'

    with pytest.raises(WazuhError, match=".* 1709 .*"):
        agent = Agent(1)
        agent._add_manual('test_agent', '172.19.0.100', key='j3921n19')

    # Adding agent with the name of the manager
    with patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb):
        with patch('socket.socket.connect'):
            with patch('wazuh.core.agent.open', mock_open(read_data=client_keys_text)):
                with pytest.raises(WazuhError, match=".* 1705 .*"):
                    agent = Agent(1)
                    agent._add_manual('master', '172.19.0.100')

                with patch('wazuh.core.agent.fcntl.lockf'):
                    # ID already exists
                    with pytest.raises(WazuhError, match=".* 1708 .*"):
                        agent = Agent(1)
                        agent._add_manual('test_agent', '172.19.0.100', id='001')

                    # Name already exists
                    with pytest.raises(WazuhError, match=".* 1705 .*"):
                        agent = Agent(1)
                        agent._add_manual('windows-agent', '172.19.0.100')

                    # IP already assigned
                    with pytest.raises(WazuhError, match=".* 1706 .*"):
                        agent = Agent(1)
                        agent._add_manual('test_agent', '192.168.0.1')

                    with pytest.raises(WazuhError, match=".* 1725 .*"):
                        agent._add_manual('test_agent', '172.19.0.100')

                    with patch('wazuh.core.agent.Agent.remove') as mock_remove:
                        # IP already exists and force
                        with pytest.raises(WazuhError, match=".* 1725 .*"):
                            agent = Agent(1)
                            agent._add_manual('test_agent', '192.168.0.1', force=0)
                        mock_remove.assert_called_once_with(backup=True)

                    with patch('wazuh.core.agent.Agent.check_if_delete_agent', return_value=False):
                        # IP already exists and force
                        with pytest.raises(WazuhError, match=".* 1706 .*"):
                            agent = Agent(1)
                            agent._add_manual('test_agent', '192.168.0.1', force=1)

                        # Name already exists and force
                        with pytest.raises(WazuhError, match=".* 1705 .*"):
                            agent = Agent(1)
                            agent._add_manual('windows-agent', '172.19.0.100', force=1)


@patch('wazuh.core.agent.path.exists', return_value=True)
@patch('wazuh.core.common.shared_path', new=os.path.join(test_data_path, 'etc', 'shared'))
@patch('wazuh.core.common.backup_path', new=os.path.join(test_data_path, 'backup'))
@patch('wazuh.core.agent.safe_move')
@patch('wazuh.core.agent.time', return_value=0)
@patch('wazuh.core.agent.Agent._remove_manual', return_value='Agent was successfully deleted')
def test_agent_delete_single_group(mock_remove_manual, mock_time, mock_safe_move, mock_exists):
    """Tests if method delete_single_group() works as expected"""

    agent = Agent(0)
    result = agent.delete_single_group('001')

    assert isinstance(result, dict), 'Result is not a dict'
    assert result['message'] == "Group '001' deleted.", 'Not expected message'
    mock_safe_move.assert_called_once_with(os.path.join(common.shared_path, '001'),
                                           os.path.join(common.backup_path, 'groups', '001_0'),
                                           permissions=0o660), 'Safe_move not called with expected params'


@pytest.mark.parametrize("agent_id, expected_result", [
    (0, 'Ubuntu'),
    (7, 'Windows'),
])
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_agent_get_agent_os_name(socket_mock, send_mock, agent_id, expected_result):
    """Tests if method get_agent_os_name() returns expected value

    Parameters
    ----------
    agent_id : int
        ID of the agent to return the attribute from.
    expected_result : str
        Expected value to be obtained.
    """
    agent = Agent(agent_id)
    result = agent.get_agent_os_name()
    assert result == expected_result


@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_agent_get_agent_os_name_ko(socket_mock, send_mock):
    """Tests if method get_agent_os_name() returns expected value when there is no attribute in the DB"""
    agent = Agent(4)
    assert 'null' == agent.get_agent_os_name()


@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_agent_get_agents_overview_default(socket_mock, send_mock):
    """Test to get all agents using default parameters"""

    agents = Agent.get_agents_overview()

    # check number of agents
    assert agents['totalItems'] == 9
    # check the return dictionary has all necessary fields

    for agent in agents['items']:
        # check no values are returned as None
        check_agent(test_data, agent)


@pytest.mark.parametrize("select, status, older_than, offset", [
    ({'id', 'dateAdd'}, 'all', None, 0),
    ({'id', 'ip', 'registerIP'}, 'all', None, 1),
    ({'id', 'registerIP'}, 'all', None, 1),
    ({'id', 'ip', 'lastKeepAlive'}, 'active', None, 0),
    ({'id', 'ip', 'lastKeepAlive'}, 'disconnected', None, 1),
    ({'id', 'ip', 'lastKeepAlive'}, 'disconnected', '1s', 1),
    ({'id', 'ip', 'lastKeepAlive'}, 'disconnected', '2h', 0),
    ({'id', 'ip', 'lastKeepAlive'}, 'all', '15m', 2),
    ({'id', 'ip', 'lastKeepAlive'}, 'active', '15m', 0),
    ({'id', 'ip', 'lastKeepAlive'}, 'pending', '15m', 1),
    ({'id', 'ip', 'lastKeepAlive'}, ['active', 'pending'], '15m', 1)
])
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_agent_get_agents_overview_select(socket_mock, send_mock, select, status, older_than, offset):
    """Test get_agents_overview function with multiple select parameters

    Parameters
    ----------
    select : set
        Select fields to return.
    status : str
        Filter agents with this status.
    older_than : str
        Filter agents with this value.
    offset : int
        First item to return.
    """
    agents = Agent.get_agents_overview(select=select, filters={'status': status, 'older_than': older_than},
                                       offset=offset)
    assert all(map(lambda x: x.keys() == select, agents['items']))


@pytest.mark.parametrize("search, totalItems", [
    ({'value': 'any', 'negation': 0}, 3),
    ({'value': 'any', 'negation': 1}, 6),
    ({'value': '202', 'negation': 0}, 1),
    ({'value': '202', 'negation': 1}, 8),
    ({'value': 'master', 'negation': 1}, 2)
])
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_agent_get_agents_overview_search(socket_mock, send_mock, search, totalItems):
    """Test searching by IP and Register IP

    Parameters
    ----------
    search : dict
        Select fields to return.
    totalItems : int
        Expected number of items to be returned.
    """
    agents = Agent.get_agents_overview(search=search)
    assert len(agents['items']) == totalItems


@pytest.mark.parametrize("query, totalItems", [
    ("ip=172.17.0.201", 1),
    ("ip=172.17.0.202", 1),
    ("ip=172.17.0.202;registerIP=any", 1),
    ("status=disconnected;lastKeepAlive>34m", 1),
    ("(status=active,status=pending);lastKeepAlive>5m", 4)
])
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_agent_get_agents_overview_query(socket_mock, send_mock, query, totalItems):
    """

    Parameters
    ----------
    query : str
        Defines query to filter in DB.
    totalItems : int
        Expected number of items to be returned.
    """
    agents = Agent.get_agents_overview(q=query)
    assert len(agents['items']) == totalItems


@pytest.mark.parametrize("status, older_than, totalItems", [
    ('active', '9m', 4),
    ('all', '1s', 8),
    ('never_connected', '30m', 1)
])
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_agent_get_agents_overview_status_olderthan(socket_mock, send_mock, status, older_than, totalItems):
    """Test filtering by status

    Parameters
    ----------
    status : str
        Filter agents with this status.
    older_than : str
        Filter agents with this value.
    totalItems : int
        Expected number of items to be returned.
    """
    kwargs = {'filters': {'status': status, 'older_than': older_than},
              'select': {'name', 'id', 'status', 'lastKeepAlive', 'dateAdd'}}

    agents = Agent.get_agents_overview(**kwargs)
    assert agents['totalItems'] == totalItems


@pytest.mark.parametrize("sort, first_id", [
    ({'fields': ['dateAdd'], 'order': 'asc'}, '000'),
    ({'fields': ['dateAdd'], 'order': 'desc'}, '004')
])
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_agent_get_agents_overview_sort(socket_mock, send_mock, sort, first_id):
    """Test sorting.

    Parameters
    ----------
    sort : dict
        Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
    first_id : str
        First expected ID.
    """
    agents = Agent.get_agents_overview(sort=sort, select={'dateAdd'})
    assert agents['items'][0]['id'] == first_id


@pytest.mark.parametrize("agent_id, group_id, force, replace, replace_list", [
    ('002', 'test_group', False, False, None),
    ('002', 'test_group', True, False, None),
    ('002', 'test_group', False, True, ['default']),
])
@patch('wazuh.core.common.groups_path', new=test_data_path)
@patch('wazuh.core.common.shared_path', new=test_data_path)
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_agent_add_group_to_agent(socket_mock, send_mock, agent_id, group_id, force, replace, replace_list):
    """Test if add_group_to_agent() works as expected when adding an existing group to agent

    Parameters
    ----------
    agent_id : str
        Id of the agent to be searched.
    group_id : str
        Name of the group to be added.
    force : bool
        Do not check if agent exists.
    replace : bool
        Whether to append new group to current agent's group or replace it.
    replace_list : list
        List of Group names that can be replaced.
    """
    try:
        # Create the file 'group_id'
        with open(os.path.join(test_data_path, group_id), 'w+'):
            pass
        # Create the file 'agent_id'
        with open(os.path.join(test_data_path, agent_id), 'w+') as f:
            f.write('default')

        with patch('sqlite3.connect') as mock_db:
            mock_db.return_value = test_data.global_db

            # Run the method with different options
            result = Agent.add_group_to_agent(group_id, agent_id, force, replace, replace_list)
            assert result == f'Agent {agent_id} assigned to {group_id}', 'Result is not the expected one'

            with open(os.path.join(test_data_path, agent_id), 'r') as f:
                agent_groups = f.readline().split(',')
                assert group_id in agent_groups, f'{group_id} should be in file {agent_id} but it is not'
                if replace:
                    assert 'default' not in agent_groups, '"default" group should not be within agent groups'
                else:
                    assert 'default' in agent_groups, '"default" group should be within agent groups'

    finally:
        # Remove created files in the test
        os.remove(os.path.join(test_data_path, group_id))
        os.remove(os.path.join(test_data_path, agent_id))


@patch('wazuh.core.common.groups_path', new=os.path.join(test_data_path, 'etc', 'shared'))
@patch('wazuh.core.common.shared_path', new=os.path.join(test_data_path, 'etc', 'shared'))
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_agent_add_group_to_agent_ko(socket_mock, send_mock):
    """Test if add_group_to_agent() raises expected exceptions"""
    # Master cannot be added to a conf group
    with pytest.raises(WazuhError, match='.* 1703 .*'):
        Agent.add_group_to_agent('test_group', '000')

    # Group does not exists
    with pytest.raises(WazuhResourceNotFound, match='.* 1710 .*'):
        Agent.add_group_to_agent('test_group', '002')

    with patch('os.path.exists', return_value=True):
        # Agent status is never_connected
        with pytest.raises(WazuhError, match='.* 1753 .*'):
            Agent.add_group_to_agent('test_group', '003')

        # Agent file does not exists
        with pytest.raises(WazuhInternalError, match='.* 1005 .*'):
            Agent.add_group_to_agent('test_group', '002')

        with patch('builtins.open', mock_open(read_data='default')):
            # Group cannot be replaced because it is not in replace_list (not enough permissions in rbac)
            with pytest.raises(WazuhError, match='.* 1752 .*'):
                Agent.add_group_to_agent('test_group', '002', replace=True, replace_list=['other'])

            # The group already belongs to the agent
            with pytest.raises(WazuhError, match='.* 1751 .*'):
                Agent.add_group_to_agent('default', '002')

            with patch('wazuh.core.common.max_groups_per_multigroup', new=0):
                # Multigroup limit exceeded.
                with pytest.raises(WazuhError, match='.* 1737 .*'):
                    Agent.add_group_to_agent('test_group', '002')


@pytest.mark.parametrize("agent_id, seconds, expected_result", [
    ('002', 10, True),
    ('002', 700, False)
])
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_agent_check_if_delete_agent(socket_mock, send_mock, agent_id, seconds, expected_result):
    """Test if check_if_delete_agent() returns True when time from last connection is greater than <seconds>

    Parameters
    ----------
    agent_id : str
        Id of the agent to be searched.
    seconds : int
        Number of seconds.
    expected_result : bool
        Result that check_if_delete_agent() should return with given params.
    """
    result = Agent.check_if_delete_agent(agent_id, seconds)
    assert result == expected_result, f'Result is {result} but should be {expected_result}'


@patch("wazuh.core.agent.Agent.get_basic_information")
def test_agent_check_if_delete_agent_ko(mock_agent):
    """Test if check_if_delete_agent() returns True when lastKeepAlive == 0 or not instance of datetime"""
    mock_agent.return_value = {'lastKeepAlive': 0}
    result = Agent.check_if_delete_agent(0, 700)
    assert result, f'Result is {result} but should be True'

    mock_agent.return_value = {'lastKeepAlive': '2000-01-01 00:00:00'}
    result = Agent.check_if_delete_agent(0, 700)
    assert result, f'Result is {result} but should be True'


@pytest.mark.parametrize("group_exists", [
    True,
    False,
])
def test_agent_group_exists(group_exists):
    """Test if group_exists() returns True when time from last connection is greater than <seconds>

    Parameters
    ----------
    group_exists : bool
        Expected result
    """
    with patch('os.path.exists', return_value=group_exists):
        result = Agent.group_exists('default')
        assert result == group_exists, f'Group exists should return {group_exists}'


def test_agent_group_exists_ko():
    """Test if group_exists() raises exception when the name isn't valid"""
    with pytest.raises(WazuhError, match='.* 1722 .*'):
        Agent.group_exists('default**')


@pytest.mark.parametrize("group_exists", [
    True,
    False,
])
@patch('builtins.open', mock_open(read_data='default'))
def test_agent_get_agents_group_file(group_exists):
    """Test if get_agents_group_file() returns the group of the agent.

    Parameters
    ----------
    group_exists : bool
        If group should be returned.
    """
    with patch('os.path.exists', return_value=group_exists):
        result = Agent.get_agents_group_file('002')
        if group_exists:
            assert result == 'default', 'Group "default" should be returned.'
        else:
            assert result == '', 'No group should be returned.'


@patch('builtins.open')
@patch('wazuh.core.common.ossec_uid')
@patch('wazuh.core.common.ossec_gid')
@patch('wazuh.core.agent.chown')
@patch('wazuh.core.agent.chmod')
def test_agent_set_agent_group_file(mock_chmod, mock_chown, mock_gid, mock_uid, mock_open):
    """Test if set_agent_group_file() set the group_id in the agent"""
    Agent.set_agent_group_file('002', 'test_group')

    # Assert methods are called with expected params
    mock_open.assert_called_once_with(os.path.join(common.groups_path, '002'), 'w')
    mock_chown.assert_called_once()
    mock_chmod.assert_called_once_with(os.path.join(common.groups_path, '002'), 0o660)


def test_agent_set_agent_group_file_ko():
    """Test if set_agent_group_file() raises expected exception"""
    with pytest.raises(WazuhInternalError, match='.* 1005 .*'):
        Agent.set_agent_group_file('002', 'test_group')


@pytest.mark.parametrize('groups, expected_result', [
    ('default0,default1,default2,default3', True),
    ('default0,default1', False),
    ('', False)
])
@patch('wazuh.core.common.max_groups_per_multigroup', new=3)
def test_agent_check_multigroup_limit(groups, expected_result):
    """Test if check_multigroup_limit() returns True when limit of groups is reached

    Parameters
    ----------
    groups : str
        Groups to which the agent belongs.
    expected_result : bool
        Expected result.
    """
    with patch('wazuh.core.agent.Agent.get_agents_group_file', return_value=groups):
        result = Agent.check_multigroup_limit('002')
        assert result == expected_result, f'check_multigroup_limit returns {result} but should return {expected_result}'


@pytest.mark.parametrize('agent_id, group_id, force, previous_groups, set_default', [
    ('002', 'test_group', False, 'default,test_group,another_test', False),
    ('002', 'test_group', True, 'default,test_group,another_test', False),
    ('002', 'test_group', False, 'test_group', True),
    ('002', 'test_group', False, 'test_group,another_test', False)
])
@patch('wazuh.core.common.groups_path', new=test_data_path)
@patch('wazuh.core.common.shared_path', new=test_data_path)
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_agent_unset_single_group_agent(socket_mock, send_mock, agent_id, group_id, force, previous_groups,
                                        set_default):
    """Test if unset_single_group_agent() returns expected message and removes group from agent

    Parameters
    ----------
    agent_id : str
        Id of the agent.
    group_id : str
        Name of the group.
    force : bool
        Do not check if agent or group exists.
    previous_groups : str
        Groups to which the agent belongs.
    set_default : bool
        The agent belongs to 'default' group.
    """
    try:
        # Create the file 'group_id'
        with open(os.path.join(test_data_path, group_id), 'w+'):
            pass
        # Create the file 'agent_id'
        with open(os.path.join(test_data_path, agent_id), 'w+') as f:
            f.write(previous_groups)

        with patch('sqlite3.connect') as mock_db:
            mock_db.return_value = test_data.global_db

            result = Agent.unset_single_group_agent(agent_id, group_id, force)
            # Assert message is as expected
            assert result == f"Agent '{agent_id}' removed from '{group_id}'." + \
                   (" Agent reassigned to group default." if set_default else ""), 'Result message not as expected.'

            # Check that the agent groups file has been updated.
            with open(os.path.join(test_data_path, agent_id), 'r') as f:
                agent_groups = f.readline().split(',')
                if set_default:
                    assert 'default' in agent_groups
                else:
                    assert group_id not in agent_groups, f'{group_id} should not be in file {agent_id}'

    finally:
        # Remove created files in the test
        os.remove(os.path.join(test_data_path, group_id))
        os.remove(os.path.join(test_data_path, agent_id))


@patch('wazuh.core.common.groups_path', new=os.path.join(test_data_path, 'etc', 'shared'))
@patch('wazuh.core.common.shared_path', new=os.path.join(test_data_path, 'etc', 'shared'))
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_agent_unset_single_group_agent_ko(socket_mock, send_mock):
    """Test if unset_single_group_agent() raises expected exceptions"""
    # Master cannot be added to a conf group
    with pytest.raises(WazuhError, match='.* 1703 .*'):
        Agent.unset_single_group_agent('000', 'test_group')

    # Group does not exists
    with pytest.raises(WazuhResourceNotFound, match='.* 1710 .*'):
        Agent.unset_single_group_agent('002', 'test_group')

    with patch('os.path.exists', return_value=True):
        with patch('wazuh.core.agent.Agent.get_agents_group_file', return_value='new_group,new_group2'):
            # Group_id is not within group_list
            with pytest.raises(WazuhError, match='.* 1734 .*'):
                Agent.unset_single_group_agent('002', 'test_group')

        with patch('wazuh.core.agent.Agent.get_agents_group_file', return_value='default'):
            # Agent file does not exists
            with pytest.raises(WazuhError, match='.* 1745 .*'):
                Agent.unset_single_group_agent('002', 'default')

@patch('wazuh.core.configuration.OssecSocket')
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_agent_getconfig(socket_mock, send_mock, mock_ossec_socket):
    """Test getconfig method returns expected message."""
    agent = Agent('001')
    mock_ossec_socket.return_value.receive.return_value = b'ok {"test": "conf"}'
    result = agent.getconfig('com', 'active-response')
    assert result == {"test": "conf"}, 'Result message is not as expected.'


@patch('wazuh.core.configuration.OssecSocket')
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_agent_getconfig_ko(socket_mock, send_mock, mock_ossec_socket):
    """Test getconfig method raises expected exceptions."""
    # Agent version is null
    agent = Agent('004')
    with pytest.raises(WazuhInternalError, match=".* 1015 .*"):
        agent.getconfig('com', 'active-response')

    # Agent Wazuh version is lower than v3.7.0
    agent = Agent('002')
    with pytest.raises(WazuhInternalError, match=".* 1735 .*"):
        agent.getconfig('com', 'active-response')


@pytest.mark.parametrize('last_keep_alive, pending, expected_status', [
    (10, False, 'active'),
    (1900, False, 'disconnected'),
    (10, True, 'pending'),
])
def test_calculate_status(last_keep_alive, pending, expected_status):
    """Test calculate_status returns expected status according to last_keep_alive.

    Parameters
    ----------
    last_keep_alive : int
        Seconds since last connection.
    pending : bool
        Return pending if status is not disconnected.
    expected_status : str
        Expected status to be returned.
    """
    result = calculate_status(int(time()) - last_keep_alive, pending)
    assert result == expected_status, 'Result message is not as expected.'


@patch('wazuh.core.agent.OssecQueue')
def test_send_restart_command(mock_ossec_queue):
    """Test that restart_command calls send_msg_to_agent with correct params"""
    send_restart_command('001')
    mock_ossec_queue.return_value.send_msg_to_agent.assert_called_once_with(ANY, '001')


def test_get_agents_info():
    """Test that get_agents_info() returns expected agent IDs"""
    with open(os.path.join(test_data_path, 'client.keys')) as f:
        client_keys = ''.join(f.readlines())

    expected_result = {'000', '001', '002', '003', '004', '005', '006', '007', '008', '009', '010'}

    with patch('wazuh.core.agent.open', mock_open(read_data=client_keys)) as m:
        result = get_agents_info()
        assert result == expected_result


def test_get_groups():
    """Test that get_groups() returns expected agent groups"""
    expected_result = {'group-1', 'group-2'}
    shared = os.path.join(test_data_path, 'shared')

    with patch('wazuh.core.common.shared_path', new=shared):
        try:
            for group in list(expected_result):
                os.makedirs(os.path.join(shared, group))
            open(os.path.join(shared, 'non-dir-file'), 'a').close()

            result = get_groups()
            assert result == expected_result
        finally:
            rmtree(shared)


@pytest.mark.parametrize('group, expected_agents', [
    ('group1', {'000'}),
    ('group2', {'001'}),
    ('*', {'000', '001', '002', '005'})
])
def test_expand_group(group, expected_agents):
    """Test that expand_group() returns expected agent IDs

    Parameters
    ----------
    group : str
        Name of the group to be expanded
    expected_agents : set
        Expected agent IDs for the selected group
    """
    # Clear and set get_agents_info cache
    reset_context_cache()
    test_get_agents_info()

    id_groups = {'000': 'group1', '001': 'group2', '002': 'group3', '004': '', '005': 'group3,group4', '006': ''}
    agent_groups = os.path.join(test_data_path, 'agent-groups')

    with patch('wazuh.core.common.groups_path', new=agent_groups):
        try:
            os.makedirs(agent_groups)
            for id_, groups in id_groups.items():
                with open(os.path.join(agent_groups, id_), 'w+') as f:
                    f.write(groups)

            result = expand_group(group)
            assert result == expected_agents
        except Exception as e:
            pytest.fail(f'Exception raised: {e}')
        finally:
            rmtree(agent_groups)

@pytest.mark.parametrize('agent_id, expected_exception', [
    ('001', 1746),
    ('006', 1701),
    ('001', 1747),
    ('001', 1748),
])
@patch('wazuh.core.wdb.WazuhDBConnection.delete_agents_db')
@patch('wazuh.core.agent.remove')
@patch('wazuh.core.agent.rmtree')
@patch('wazuh.core.agent.chown')
@patch('wazuh.core.agent.chmod')
@patch('wazuh.core.agent.stat')
@patch("wazuh.core.common.client_keys", new=os.path.join(test_data_path, 'etc', 'client.keys'))
@patch('wazuh.core.agent.path.isdir', return_value=True)
@patch('wazuh.core.agent.makedirs')
@patch('wazuh.core.agent.chmod_r')
@freeze_time('1975-01-01')
@patch("wazuh.core.common.ossec_uid", return_value=getpwnam("root"))
@patch("wazuh.core.common.ossec_gid", return_value=getgrnam("root"))
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_agent_remove_manual_ko(socket_mock, send_mock, grp_mock, pwd_mock, chmod_r_mock, makedirs_mock, isdir_mock,
                                stat_mock, chmod_mock, chown_mock, rmtree_mock, remove_mock, delete_mock, agent_id,
                                expected_exception):
    """Test the _remove_manual function error cases.

    Parameters
    ----------
    agent_id : str
        Id of the agent to be searched.
    expected_exception : int
        Error code that is expected.
    """

    def check_exception(client_keys):
        with patch('wazuh.core.agent.open', mock_open(read_data=client_keys)) as m:
            with pytest.raises(WazuhException, match=f".* {expected_exception} .*"):
                Agent(agent_id)._remove_manual()

    client_keys_text = '\n'.join([f'{str(row["id"]).zfill(3) if expected_exception != 1701 else "100"} '
                                  f'{row["name"]} '
                                  f'{row["register_ip"]} '
                                  f'{row["internal_key"] + "" if expected_exception != 1746 else " random"}' for row
                                  in
                                  test_data.global_db.execute(
                                      'select id, name, register_ip, internal_key from agent where id > 0')])

    rmtree_mock.side_effect = Exception("Boom!")

    if expected_exception == 1747:
        check_exception(client_keys_text)
    else:
        with patch('wazuh.core.wdb.WazuhDBConnection.run_wdb_command'):
            check_exception(client_keys_text)

    if expected_exception == 1746:
        remove_mock.assert_any_call('{0}/etc/client.keys.tmp'.format(test_data_path))


@pytest.mark.parametrize('system_resources, permitted_resources, filters, expected_result', [
    ({'001', '002', '003', '004'}, ['001', '002', '005', '006'], None,
     {'filters': {'rbac_ids': ['004', '003']}, 'rbac_negate': True}),
    ({'001'}, ['002', '005', '006'], None,
     {'filters': {'rbac_ids': ['001']}, 'rbac_negate': True}),
    ({'group1', 'group3', 'group4'}, ['group1', 'group2', 'group5', 'group6'], None,
     {'filters': {'rbac_ids': ['group3', 'group4']}, 'rbac_negate': True}),
    ({'group1', 'group2', 'group3', 'group4', 'group5', 'group6'}, ['group1'], {'testing': 'first'},
     {'filters': {'rbac_ids': {'group1'}, 'testing': 'first'}, 'rbac_negate': False})
])
def test_get_rbac_filters(system_resources, permitted_resources, filters, expected_result):
    """Check that the function get_rbac_filters calculates correctly the list of allowed or denied

    Parameters
    ----------
    system_resources : str
        Id of the agent to be searched.
    permitted_resources : int
        Error code that is expected.
    """
    result = get_rbac_filters(system_resources=system_resources,
                              permitted_resources=permitted_resources, filters=filters)
    result['filters']['rbac_ids'] = set(result['filters']['rbac_ids'])
    expected_result['filters']['rbac_ids'] = set(expected_result['filters']['rbac_ids'])
    assert result == expected_result

#!/usr/bin/env python
# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sqlite3
import sys
from copy import copy
from unittest.mock import AsyncMock, patch

import pytest
from shutil import rmtree

with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
        from wazuh.core.agent import *
        from wazuh.core.exception import WazuhException, WazuhIndexerError
        from server_management_api.util import remove_nones_to_dict
        from wazuh.core.common import reset_context_cache
        from wazuh.core.indexer.agent import Agent as IndexerAgent
        from wazuh.core.utils import get_group_file_path

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

    def __init__(self, data_path=test_data_path, db_name='schema_global_test.sql'):
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
        with open(os.path.join(data_path, db_name)) as f:
            self.cur.executescript(f.read())

        self.never_connected_fields = {'status', 'name', 'ip', 'registerIP', 'node_name', 'dateAdd', 'id',
                                       'group_config_status', 'status_code'}
        self.pending_fields = self.never_connected_fields | {'manager', 'lastKeepAlive'}
        self.manager_fields = self.pending_fields | {'version', 'os', 'group'}
        self.active_fields = self.manager_fields | {'group', 'mergedSum', 'configSum'}
        self.disconnected_fields = self.active_fields | {'disconnection_time'}
        self.manager_fields -= {'registerIP'}


test_data = InitAgent()


def send_msg_to_wdb(msg, raw=False):
    query = ' '.join(msg.split(' ')[2:])
    result = list(map(remove_nones_to_dict, map(dict, test_data.cur.execute(query).fetchall())))
    return ['ok', dumps(result)] if raw else result



def check_agent(test_data, agent):
    """Checks a single agent is correct"""
    assert all(map(lambda x: x is not None, agent.values()))
    assert 'status' in agent
    assert 'id' in agent
    if agent['status'] == 'active':
        assert agent.keys() == test_data.active_fields
    elif agent['status'] == 'disconnected':
        assert agent.keys() == test_data.disconnected_fields
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
    ('os.version', 'CAST(os_major AS INTEGER) asc, CAST(os_minor AS INTEGER) asc'),
    ('status', 'status asc'),
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


@pytest.mark.parametrize('data', [
    [{'id': 0, 'status': 'active', 'group': 'default,group1,group2', 'manager': 'master', 'dateAdd': 1000000000,
      'disconnection_time': 0}],
    [{'id': 3, 'status': 'disconnected', 'group': 'default', 'manager': 'worker1', 'dateAdd': 1000000000,
      'disconnection_time': 19345809}]
])
@patch('socket.socket.connect')
def test_WazuhDBQueryAgents_format_data_into_dictionary(mock_socket_conn, data):
    """Tests _format_data_into_dictionary of WazuhDBQueryAgents returns expected data"""
    query_agent = WazuhDBQueryAgents(offset=0, limit=1, sort=None,
                                     search=None, select={'id', 'status', 'group', 'dateAdd', 'manager',
                                                          'disconnection_time'},
                                     default_sort_field=None, query=None, count=5,
                                     get_data=None, min_select_fields={'os.version'})

    # Mock _data variable with our own data
    d = copy(data[0])
    query_agent._data = data
    result = query_agent._format_data_into_dictionary()

    # Assert format_fields inside _format_data_into_dictionary is working as expected
    res = result['items'][0]

    assert res["id"] == str(d["id"]).zfill(3), "ID is not as expected"
    assert res["status"] == d["status"], "status is not as expected"
    assert isinstance(res["group"], list) and len(res["group"]) == len(d["group"].split(",")), \
        "'group' has different type or length than expected"
    assert isinstance(res["dateAdd"], datetime), "Not date type"
    assert res["manager"] == d["manager"]
    assert "disconnection_time" not in res if d["disconnection_time"] == 0 \
        else isinstance(res["disconnection_time"], datetime)


@patch('socket.socket.connect')
def test_WazuhDBQueryAgents_parse_legacy_filters(mock_socket_conn):
    """Tests _parse_legacy_filters of WazuhDBQueryAgents returns expected query"""
    query_agent = WazuhDBQueryAgents(filters={'older_than': 'test'})
    query_agent._parse_legacy_filters()

    assert '(lastKeepAlive>test;status!=never_connected,dateAdd>test;status=never_connected)' in query_agent.q, \
        'Query returned does not match the expected one'


@pytest.mark.parametrize('field_name, field_filter, q_filter', [
    ('group', 'field', {'value': '1', 'operator': '='}),
    ('group', 'test', {'value': '1', 'operator': '!='}),
    ('group', 'test', {'value': '1', 'operator': 'LIKE'}),
    ('group', 'test', {'value': '1', 'operator': '<'}),
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
    equal_regex = r"\(',' || [\w`]+ || ','\) LIKE :\w+"
    not_equal_regex = f"NOT {equal_regex}"
    like_regex = r"[\w`]+ LIKE :\w+"

    query_agent = WazuhDBQueryAgents()
    try:
        query_agent._process_filter(field_name, field_filter, q_filter)
    except WazuhError as e:
        assert e.code == 1409 and q_filter['operator'] not in {'=', '!=', 'LIKE'}
        return

    if field_name == 'group':
        if q_filter['operator'] == '=':
            assert re.search(equal_regex, query_agent.query)
        elif q_filter['operator'] == '!=':
            assert re.search(not_equal_regex, query_agent.query)
        elif q_filter['operator'] == 'LIKE':
            assert re.search(like_regex, query_agent.query)
        else:
            pytest.fail('Unexpected operator')
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
    assert all(x['os']['name'] == 'N/A' for x in result['items'])


@pytest.mark.parametrize('filter_fields, expected_response', [
    (['os.codename'], [{'os': {'codename': 'Bionic Beaver'}, 'count': 2}, {'os': {'codename': 'Xenial'}, 'count': 1},
                       {'os': {'codename': 'N/A'}, 'count': 2}, {'os': {'codename': 'XP'}, 'count': 3}]),
    (['node_name'], [{'count': 6, 'node_name': 'node01'}, {'count': 2, 'node_name': 'unknown'}]),
    (['status', 'os.version'], [{'os': {'version': '18.04.1 LTS'}, 'count': 1, 'status': 'active'},
                                {'os': {'version': '16.04.1 LTS'}, 'count': 1, 'status': 'active'},
                                {'os': {'version': 'N/A'}, 'count': 1, 'status': 'never_connected'},
                                {'os': {'version': 'N/A'}, 'count': 1, 'status': 'pending'},
                                {'os': {'version': '18.04.1 LTS'}, 'count': 1, 'status': 'disconnected'},
                                {'os': {'version': '5.2'}, 'count': 2, 'status': 'active'},
                                {'os': {'version': '7.2'}, 'count': 1, 'status': 'active'}])
])
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_WazuhDBQueryGroupByAgents(mock_socket_conn, send_mock, filter_fields, expected_response):
    """Tests if WazuhDBQueryGroupByAgents works properly."""
    query_group = WazuhDBQueryGroupByAgents(filter_fields=filter_fields, offset=0, limit=None, sort=None,
                                            search=None, select=None, query=None, count=5, get_data=True)
    result = query_group.run()
    assert result['items'] == expected_response


@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_WazuhDBQueryGroup__add_sort_to_query(mock_socket_conn, send_mock):
    """Tests if _add_sort_to_query method of WazuhDBQueryGroup works properly"""
    query_group = WazuhDBQueryGroup()
    query_group._add_sort_to_query()

    assert 'count' in query_group.fields and query_group.fields['count'] == 'count(id_group)'


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
    (3, None),
    (5, {'id', 'ip', 'version'}),
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


@patch('wazuh.core.agent.WazuhQueue.send_msg_to_agent')
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_agent_reconnect(socket_mock, send_mock, mock_send_msg):
    """Test if method reconnect calls send_msg method with correct params."""
    agent_id = '001'
    agent = Agent(agent_id)
    agent.reconnect(WazuhQueue(common.AR_SOCKET))

    # Assert send_msg method is called with correct params
    mock_send_msg.assert_called_with(WazuhQueue.HC_FORCE_RECONNECT, agent_id)


@patch('wazuh.core.agent.WazuhQueue')
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_agent_reconnect_ko(socket_mock, send_mock, mock_queue):
    """Test if method reconnect raises exception."""
    # Assert exception is raised when status of agent is not 'active'
    with pytest.raises(WazuhError, match='.* 1707 .*'):
        agent = Agent('003')
        agent.reconnect(mock_queue)


@patch('wazuh.core.agent.Agent._remove_authd', return_value='Agent was successfully deleted')
def test_agent_remove(mock_remove_authd):
    """Tests if method remove() works as expected."""

    with patch('wazuh.core.agent.get_manager_status', return_value={'wazuh-authd': 'running'}):
        agent = Agent('001')
        result = agent.remove()
        assert result == 'Agent was successfully deleted', 'Not expected message'

        mock_remove_authd.assert_called_once_with(False), 'Not expected params'


@patch('wazuh.core.agent.Agent._remove_authd', return_value='Agent was successfully deleted')
def test_agent_remove_ko(mock_remove_authd):
    """Tests if method remove() raises expected exception"""
    with pytest.raises(WazuhError, match='.* 1726 .*'):
        agent = Agent('001')
        agent.remove()


@patch('wazuh.core.agent.WazuhSocketJSON')
def test_agent_remove_authd(mock_wazuh_socket):
    """Tests if method remove_authd() works as expected"""
    agent = Agent('001')
    agent._remove_authd(purge=True)
    mock_wazuh_socket.return_value.send.assert_called_once_with(
        {"function": "remove", "arguments": {"id": str(1).zfill(3), "purge": True}})
    mock_wazuh_socket.return_value.receive.assert_called_once()
    mock_wazuh_socket.return_value.close.assert_called_once()


@pytest.mark.parametrize("authd_status", [
    'running',
    'stopped'
])
@pytest.mark.parametrize("ip, id, key, force", [
    ('192.168.0.0', None, None, {"enabled": False}),
    ('192.168.0.0/28', '002', None, {"enabled": False}),
    ('any', '002', 'WMPlw93l2PnwQMN', {"enabled": False}),
    ('any', '003', 'WMPlw93l2PnwQMN', {"enabled": True}),
])
@patch('wazuh.core.agent.Agent._add_authd')
def test_agent_add(mock_add_authd, authd_status, ip, id, key, force):
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
    force : dict
        Remove old agents with same name or IP if conditions are met.
    """
    agent = Agent('001')

    with patch('wazuh.core.agent.get_manager_status', return_value={'wazuh-authd': 'running'}):
        agent._add('test_name', ip, id=id, key=key, force=force)

    mock_add_authd.assert_called_once_with('test_name', ip, id, key, force)


@patch('wazuh.core.agent.get_manager_status', return_value={'wazuh-authd': 'stopped'})
def test_agent_add_ko(mock_maganer_status):
    """Test if _add() method raises expected exception."""
    agent = Agent('001')

    with pytest.raises(WazuhError, match='.* 1706 .*'):
        agent._add('test_name', 'http://jaosdf')

    with pytest.raises(WazuhError, match='.* 1706 .*'):
        agent._add('test_name', '1111')

    with pytest.raises(WazuhError, match='.* 1726 .*'):
        agent._add('test_name', '192.168.0.0')


@pytest.mark.parametrize("name, ip, id, key, force", [
    ('test_agent', '172.19.0.100', None, None, None),
    ('test_agent', 'any', '001', None, None),
    ('test_agent', 'any', None, 'MDAyIHdpbmRvd3MtYWdlbnQyIGFueSAzNDA2MjgyMjEwYmUwOWVlMWViNDAyZTYyODZmNWQ2OTE5MjBkODN'
                                'jNTVjZDE5N2YyMzk3NzA0YWRhNjg1YzQz', None),
    ('test_agent', '172.19.0.100', '002', 'MDAyIHdpbmRvd3MtYWdlbnQyIGFueSAzNDA2MjgyMjEwYmUwOWVlMWViNDAyZTYyODZmNWQ2O'
                                          'TE5MjBkODNjNTVjZDE5N2YyMzk3NzA0YWRhNjg1YzQz',
     {"enabled": True, "disconnected_time": {"enabled": True, "value": "1h"}})
])
@patch('wazuh.core.agent.WazuhSocketJSON')
def test_agent_add_authd(mock_wazuh_socket, name, ip, id, key, force):
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
    force : dict
        Force parameters.
    """
    agent = Agent(id)
    agent._add_authd(name, ip, id, key, force)

    mock_wazuh_socket.return_value.receive.assert_called_once()
    mock_wazuh_socket.return_value.close.assert_called_once()
    socket_msg = {"function": "add", "arguments": {"name": name, "ip": ip}}
    if id:
        socket_msg["arguments"].update({"id": id})
    if key:
        socket_msg["arguments"].update({"key": key})
    if force:
        socket_msg["arguments"].update({"force": {"key_mismatch": True, **force}})

    mock_wazuh_socket.return_value.send.assert_called_once_with(socket_msg)


@pytest.mark.parametrize("mocked_exception, expected_exception", [
    (None, None),
    (WazuhError(9008, cmd_error=True), ".* 1705 .*"),
    (WazuhError(9007, cmd_error=True), ".* 1706 .*"),
    (WazuhError(9012, cmd_error=True), ".* 1708 .*"),
    (WazuhError(9000, cmd_error=True), ".* None")
])
@patch('wazuh.core.agent.WazuhSocketJSON')
def test_agent_add_authd_ko(mock_wazuh_socket, mocked_exception, expected_exception):
    """Tests if method _add_authd() raises expected exception"""
    agent = Agent('001')

    if not mocked_exception:
        with pytest.raises(WazuhError, match=".* 1709 .*"):
            agent._add_authd('test_add', '192.168.0.1', '2', 'adsiojew')
    else:
        mock_wazuh_socket.return_value.receive.side_effect = mocked_exception
        with pytest.raises(WazuhError, match=expected_exception):
            agent._add_authd('test_add', '192.168.0.1')


# TODO: Review use case. The manager name will not be stored in an internal DB nor will be related to agents.

# @patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
# @patch('socket.socket.connect')
# def test_get_manager_name(mock_connect, mock_send):
#     get_manager_name()
#     calls = [call('global sql select count(*) from agent where (id = 0)'),
#              call('global sql select name from agent where (id = 0) limit 1 offset 0', raw=True)]
#
#     mock_send.assert_has_calls(calls)


@pytest.mark.asyncio
@patch('wazuh.core.agent.remove')
@patch('wazuh.core.agent.path.exists', return_value=True)
@patch('wazuh.core.common.WAZUH_GROUPS', new=os.path.join(test_data_path, 'etc', 'groups'))
@patch('wazuh.core.indexer.Indexer._get_opensearch_client')
@patch('wazuh.core.indexer.Indexer.connect')
@patch('wazuh.core.indexer.Indexer.close')
@patch('wazuh.core.indexer.agent.AgentsIndex.delete_group')
async def test_agent_delete_single_group(delete_group_mock, get_os_client_mock, connect_mock, close_mock, mock_exists,
                                         mock_remove):
    """Tests if method delete_single_group() works as expected"""

    agent = Agent('001')
    group = 'test_group'

    result = await agent.delete_single_group(group)
    assert isinstance(result, dict), 'Result is not a dict'
    assert result['message'] == f"Group '{group}' deleted.", 'Not expected message'
    mock_remove.assert_called_once_with(get_group_file_path(group))


@pytest.mark.parametrize("agent_id, expected_result", [
    (1, 'Ubuntu'),
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
    agent = Agent('004')
    assert 'null' == agent.get_agent_os_name()


@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_agent_get_agents_overview_default(socket_mock, send_mock):
    """Test to get all agents using default parameters"""

    agents = Agent.get_agents_overview()

    # check number of agents
    assert agents['totalItems'] == 8
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
    ({'value': 'any', 'negation': 1}, 5),
    ({'value': 'Windows', 'negation': 0}, 3),
    ({'value': 'Windows', 'negation': 1}, 5),
    ({'value': 'master', 'negation': 1}, 2),
    ({'value': '停', 'negation': 0}, 0)
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
    ({'fields': ['dateAdd'], 'order': 'asc'}, '005'),
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


@pytest.mark.asyncio
@patch('wazuh.core.indexer.create_indexer')
async def test_agent_get_agent_groups(create_indexer_mock):
    """Test if get_agent_groups() asks for agent's groups correctly."""
    agent_id = '0191c895-3037-7ed6-a8e3-def51ec2bca9'
    groups = ['default', 'group1']

    create_indexer_mock.return_value.agents.get.return_value = IndexerAgent(groups=','.join(groups))
    agent_groups = await Agent.get_agent_groups(agent_id)

    assert agent_groups == groups


@pytest.mark.asyncio
@pytest.mark.parametrize('remove, override, expected_mode', [
    (False, False, 'append'),
    (True, False, 'remove'),
    (True, True, 'remove'),
    (False, True, 'override')
])
@patch('wazuh.core.indexer.Indexer._get_opensearch_client')
@patch('wazuh.core.indexer.Indexer.connect')
@patch('wazuh.core.indexer.Indexer.close')
@patch('wazuh.core.indexer.agent.AgentsIndex.remove_agents_from_group')
@patch('wazuh.core.indexer.agent.AgentsIndex.add_agents_to_group')
async def test_agent_set_agent_group_relationship(add_agents_to_group_mock, remove_agents_from_group_mock,
                                                  close_mock, connect_mock, get_opensearch_client_mock, remove,
                                                  override, expected_mode):
    """Test if set_agent_group_relationship() uses the correct command to create/remove the relationship between
    an agent and a group.

    Parameters
    ----------
    remove: bool
        Whether to remove the relationship or not.
    override: bool
        Whether to override the previous groups or not.
    expected_mode: str
        Expected mode to send to wdb to change the relationship between an agent and a group.
    """
    agent_id = '001'
    group_id = 'group1' if remove else 'group2'
    groups = ['default', 'group1']

    # Default relationship -> add an agent to a group
    with patch('wazuh.core.indexer.agent.AgentsIndex.get', return_value=IndexerAgent(groups=','.join(groups))):
        await Agent.set_agent_group_relationship(agent_id, group_id, remove, override)

    if remove:
        remove_agents_from_group_mock.assert_called_with(group_name=group_id, agent_ids=[agent_id])
    else:
        add_agents_to_group_mock.assert_called_with(group_name=group_id, agent_ids=[agent_id], override=override)


@pytest.mark.asyncio
@patch('wazuh.core.indexer.Indexer._get_opensearch_client', side_effect=WazuhIndexerError(2200))
async def test_agent_set_agent_group_relationship_ko(get_client_mock):
    """Test if set_agent_group_relationship() raises expected exception."""
    with pytest.raises(WazuhInternalError, match='.* 2200 .*'):
        await Agent.set_agent_group_relationship('002', 'test_group')


@patch('wazuh.core.wazuh_socket.WazuhSocket')
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_agent_get_config(socket_mock, send_mock, mock_wazuh_socket):
    """Test getconfig method returns expected message."""
    agent = Agent('001')
    mock_wazuh_socket.return_value.receive.return_value = b'ok {"test": "conf"}'
    result = agent.get_config('com', 'active-response', 'Wazuh v4.0.0')
    assert result == {"test": "conf"}, 'Result message is not as expected.'


@patch('wazuh.core.wazuh_socket.WazuhSocket')
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_agent_get_config_ko(socket_mock, send_mock, mock_wazuh_socket):
    """Test getconfig method raises expected exceptions."""
    # Invalid component
    agent = Agent('003')
    with pytest.raises(WazuhError, match=".* 1101 .*"):
        agent.get_config('invalid_component', 'active-response', 'Wazuh v4.0.0')

    # Component or config is none
    agent = Agent('003')
    with pytest.raises(WazuhError, match=".* 1307 .*"):
        agent.get_config('com', None, 'Wazuh v4.0.0')
        agent.get_config(None, 'active-response', 'Wazuh v4.0.0')

    # Agent Wazuh version is lower than ACTIVE_CONFIG_VERSION
    agent = Agent('002')
    with pytest.raises(WazuhInternalError, match=".* 1735 .*"):
        agent.get_config('com', 'active-response', 'Wazuh v3.6.0')


@patch('wazuh.core.indexer.create_indexer')
async def test_get_agents_info(create_indexer_mock):
    """Test that get_agents_info() returns expected agent IDs"""
    reset_context_cache()

    agents = []
    for i in range(1, 11):
        agents.append(IndexerAgent(id=str(i).zfill(3)))

    expected_result = {'001', '002', '003', '004', '005', '006', '007', '008', '009', '010'}
    agents_search_mock = AsyncMock(return_value=agents)
    create_indexer_mock.return_value.agents.search = agents_search_mock

    result = await get_agents_info()
    assert result == expected_result


def test_get_groups():
    """Test that get_groups() returns expected agent groups"""
    expected_result = {'group-1', 'group-2'}
    groups = os.path.join(test_data_path, 'groups')

    with patch('wazuh.core.common.WAZUH_GROUPS', new=groups):
        try:
            os.makedirs(groups)
            for group in list(expected_result):
                with open(os.path.join(groups, f'{group}.yml'), 'w') as f:
                    f.write('')

            result = get_groups()
            assert result == expected_result
        finally:
            rmtree(groups)


@pytest.mark.parametrize('group, group_agents, expected_agents', [
    ('default', [IndexerAgent(id='001'), IndexerAgent(id='002')], {'001', '002'}),
    ('test_group', [IndexerAgent(id='005')], {'005'}),
    ('*', [], {'001', '002', '003', '004', '005'}),
])
@patch('wazuh.core.indexer.create_indexer')
async def test_expand_group(create_indexer_mock, group, group_agents, expected_agents):
    """Test that expand_group() returns expected agent IDs.

    Parameters
    ----------
    group : str
        Name of the group to be expanded.
    group_agents: list
        Mock return values for the `AgentsIndex.get_group_agents` method.
    expected_agents : set
        Expected agent IDs for the selected group.
    """
    # Clear get_agents_info cache
    reset_context_cache()

    agents = []
    for i in range(1, 6):
        agents.append(IndexerAgent(id=str(i).zfill(3)))

    agents_search_mock = AsyncMock(return_value=agents)
    create_indexer_mock.return_value.agents.search = agents_search_mock

    if group == '*':
        assert await expand_group(group) == await get_agents_info()

    agents_in_group_mock = AsyncMock(return_value=group_agents)
    create_indexer_mock.return_value.agents.get_group_agents = agents_in_group_mock

    assert await expand_group(group) == expected_agents


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

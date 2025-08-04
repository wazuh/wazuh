#!/usr/bin/env python
# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import shutil
import sys
import pytest

from grp import getgrnam
from json import dumps
from pwd import getpwnam
from unittest.mock import AsyncMock, MagicMock, patch, call
from typing import Any

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../..'))

with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators
        from wazuh.tests.util import RBAC_bypasser

        del sys.modules['wazuh.rbac.orm']
        wazuh.rbac.decorators.expose_resources = RBAC_bypasser

        from wazuh.agent import add_agent, assign_agents_to_group, create_group, delete_agents, delete_groups, \
            get_agent_conf, get_agent_config, get_agent_groups, get_agents, get_agents_in_group, get_agents_keys, \
            get_agents_summary, get_agents_summary_os, get_agents_summary_status, get_agents_sync_group, \
            get_distinct_agents, get_file_conf, get_full_overview, get_group_files, get_outdated_agents, \
            get_upgrade_result, remove_agent_from_group, remove_agent_from_groups, remove_agents_from_group, \
            restart_agents, upgrade_agents, upload_group_file, restart_agents_by_node, reconnect_agents, \
            check_uninstall_permission, ERROR_CODES_UPGRADE_SOCKET_BAD_REQUEST, ERROR_CODES_UPGRADE_SOCKET
        from wazuh.core.agent import Agent
        from wazuh import WazuhError, WazuhException, WazuhInternalError
        from wazuh.core.results import WazuhResult, AffectedItemsWazuhResult
        from wazuh.core.tests.test_agent import InitAgent
        from api.util import remove_nones_to_dict
        from wazuh.core.exception import WazuhResourceNotFound
        from wazuh.core.wdb_http import AgentsSummary

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
test_agent_path = os.path.join(test_data_path, 'agent')
test_shared_path = os.path.join(test_agent_path, 'shared')
test_multigroup_path = os.path.join(test_agent_path, 'multigroups')
test_global_bd_path = os.path.join(test_data_path, 'global.db')

test_data = InitAgent(data_path=test_data_path)
full_agent_list = ['000', '001', '002', '003', '004', '005', '006', '007', '008', '009']
short_agent_list = ['000', '001', '002', '003', '004', '005']

def send_msg_to_wdb_http_post_restartinfo(endpoint: str, data: Any, empty_response: bool = False):
    ids = ",".join(map(str, data["ids"]))
    negate = "NOT" if data['negate'] else ""
    query = f"SELECT id, version, connection_status as status FROM agent WHERE id {negate} IN ({ids});"
    result = [ dict(row) for row in test_data.cur.execute(query).fetchall() ]
    return {"items": result} if result else {}

def send_msg_to_wdb(msg, raw=False):
    query = ' '.join(msg.split(' ')[2:])
    result = list(map(remove_nones_to_dict, map(dict, test_data.cur.execute(query).fetchall())))
    return ['ok', dumps(result)] if raw else result


@pytest.mark.parametrize('fields, expected_items', [
    (
            ['os.platform'],
            [{'os': {'platform': 'ubuntu'}, 'count': 4}, {'os': {'platform': 'N/A'}, 'count': 2}]
    ),
    (
            ['version'],
            [{'version': 'Wazuh v3.9.0', 'count': 1}, {'version': 'Wazuh v3.8.2', 'count': 2},
             {'version': 'Wazuh v3.6.2', 'count': 1}, {'version': 'N/A', 'count': 2}]
    ),
    (
            ['os.platform', 'os.major'],
            [{'count': 1, 'os': {'major': '20', 'platform': 'ubuntu'}},
             {'count': 1, 'os': {'major': '18', 'platform': 'ubuntu'}},
             {'count': 2, 'os': {'major': '16', 'platform': 'ubuntu'}},
             {'count': 2, 'os': {'major': 'N/A', 'platform': 'N/A'}}]
    ),
    (
            ['node_name'],
            [{'node_name': 'unknown', 'count': 2}, {'node_name': 'node01', 'count': 4}]
    ),
    (
            ['os.name', 'os.platform', 'os.version'],
            [{'count': 1, 'os': {'name': 'Ubuntu', 'platform': 'ubuntu', 'version': '20.04.1 LTS'}},
             {'count': 1, 'os': {'name': 'Ubuntu', 'platform': 'ubuntu', 'version': '18.08.1 LTS'}},
             {'count': 1, 'os': {'name': 'Ubuntu', 'platform': 'ubuntu', 'version': '16.06.1 LTS'}},
             {'count': 1, 'os': {'name': 'Ubuntu', 'platform': 'ubuntu', 'version': '16.04.1 LTS'}},
             {'count': 2, 'os': {'name': 'N/A', 'platform': 'N/A', 'version': 'N/A'}}]
    ),
])
@patch('wazuh.core.common.CLIENT_KEYS', new=os.path.join(test_agent_path, 'client.keys'))
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_agent_get_distinct_agents(socket_mock, send_mock, fields, expected_items):
    """Test `get_distinct_agents` function from agent module.

    Parameters
    ----------
    fields : list
        List of fields to check their values.
    expected_items : list
        List of expected values for the provided fields.
    """
    distinct = get_distinct_agents(short_agent_list, fields=fields, sort={'fields': fields, 'order': 'desc'})
    assert isinstance(distinct, AffectedItemsWazuhResult), 'The returned object is not an "AffectedItemsWazuhResult".'
    assert distinct.affected_items == expected_items, f'"Affected_items" does not match. Should be "{expected_items}".'


@pytest.mark.parametrize('fields, order, expected_items', [
    (['os.version', 'os.name'], 'asc',
     [
         {'id': '003'},
         {'id': '004'},
         {'id': '009', 'os': {'name': 'Windows', 'version': '10.0.0 XP'}},
         {'id': '002', 'os': {'name': 'Ubuntu', 'version': '16.04.1 LTS'}},
         {'id': '001', 'os': {'name': 'Ubuntu', 'version': '16.06.1 LTS'}},
         {'id': '007', 'os': {'name': 'Ubuntu', 'version': '18.04.1 LTS'}},
         {'id': '008', 'os': {'name': 'Xubuntu', 'version': '18.04.1 LTS'}},
         {'id': '005', 'os': {'name': 'Ubuntu', 'version': '18.08.1 LTS'}},
         {'id': '000', 'os': {'name': 'Ubuntu', 'version': '20.04.1 LTS'}},
         {'id': '006', 'os': {'name': 'Xubuntu', 'version': '21.04.1 LTS'}}
     ]
     ),
    (['os.name', 'os.version'], 'asc',
     [
         {'id': '003'},
         {'id': '004'},
         {'id': '002', 'os': {'name': 'Ubuntu', 'version': '16.04.1 LTS'}},
         {'id': '001', 'os': {'name': 'Ubuntu', 'version': '16.06.1 LTS'}},
         {'id': '007', 'os': {'name': 'Ubuntu', 'version': '18.04.1 LTS'}},
         {'id': '005', 'os': {'name': 'Ubuntu', 'version': '18.08.1 LTS'}},
         {'id': '000', 'os': {'name': 'Ubuntu', 'version': '20.04.1 LTS'}},
         {'id': '009', 'os': {'name': 'Windows', 'version': '10.0.0 XP'}},
         {'id': '008', 'os': {'name': 'Xubuntu', 'version': '18.04.1 LTS'}},
         {'id': '006', 'os': {'name': 'Xubuntu', 'version': '21.04.1 LTS'}}
     ]
     ),
    (['os.platform', 'os.minor', 'os.major'], 'desc',
     [
         {'id': '006', 'os': {'major': '21', 'minor': '04', 'platform': 'xubuntu'}},
         {'id': '008', 'os': {'major': '18', 'minor': '04', 'platform': 'xubuntu'}},
         {'id': '009', 'os': {'major': '10', 'minor': '00', 'platform': 'windows'}},
         {'id': '005', 'os': {'major': '18', 'minor': '08', 'platform': 'ubuntu'}},
         {'id': '001', 'os': {'major': '16', 'minor': '06', 'platform': 'ubuntu'}},
         {'id': '000', 'os': {'major': '20', 'minor': '04', 'platform': 'ubuntu'}},
         {'id': '007', 'os': {'major': '18', 'minor': '04', 'platform': 'ubuntu'}},
         {'id': '002', 'os': {'major': '16', 'minor': '04', 'platform': 'ubuntu'}},
         {'id': '003'},
         {'id': '004'}
     ]
     ),
])
@patch('wazuh.core.common.CLIENT_KEYS', new=os.path.join(test_agent_path, 'client.keys'))
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_agent_sort_order(socket_mock, send_mock, fields, order, expected_items):
    """Test `sort` parameter of GET /agents endpoint with multiples and/or nested fields."""
    sorted_agents = get_agents(agent_list=full_agent_list, select=fields, sort={'fields': fields, 'order': order})
    assert isinstance(sorted_agents, AffectedItemsWazuhResult), 'The returned object is not an ' \
                                                                '"AffectedItemsWazuhResult". '
    assert sorted_agents.affected_items == expected_items, f'"Affected_items" does not match. Should be ' \
                                                           f'"{expected_items}". '


@patch('wazuh.core.wdb_http.WazuhDBHTTPClient')
async def test_get_agents_summary(wdb_http_client_mock: AsyncMock):
    """Test if get_agent_groups() asks for agent's groups correctly."""
    agent_ids = []
    summary = AgentsSummary(agents_by_status={'active': 10, 'disconnected': 2})
    wdb_http_client_mock.return_value.close = AsyncMock()
    get_agents_summary_mock = AsyncMock(return_value=summary)
    wdb_http_client_mock.return_value.get_agents_summary = get_agents_summary_mock

    agents_summary = await get_agents_summary(agent_ids)
    assert agents_summary['data'] == summary.to_dict()

    get_agents_summary_mock.assert_called_once_with(agent_ids)


@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_agent_get_agents_summary_status(socket_mock, send_mock):
    """Test `get_agents_summary` function from agent module."""
    summary = get_agents_summary_status(short_agent_list)
    assert isinstance(summary, WazuhResult), 'The returned object is not an "WazuhResult" instance.'
    # Asserts are based on what it should get from the fake database
    expected_results = {
        'connection': {'active': 2, 'disconnected': 1, 'never_connected': 1, 'pending': 1, 'total': 5},
        'configuration': {'synced': 2, 'not_synced': 3, 'total': 5}
    }
    summary_data = summary['data']

    assert summary_data == expected_results


@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_agent_get_agents_summary_os(connect_mock, send_mock):
    """Tests `get_os_summary function`."""
    summary = get_agents_summary_os(short_agent_list)
    assert isinstance(summary, AffectedItemsWazuhResult), 'The returned object is not an "WazuhResult" instance.'
    assert summary.affected_items == ['ubuntu'], f"Expected ['ubuntu'] OS but received '{summary['items']} instead."


@pytest.mark.parametrize('agent_list, expected_items, error_code', [
    (['001', '002'], ['001', '002'], None),
    (['000'], [], 1703),
    (['001', '500'], ['001'], 1701)
])
@patch('wazuh.core.agent.Agent.reconnect')
@patch('wazuh.agent.get_agents_info', return_value=short_agent_list)
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_agent_reconnect_agents(socket_mock, send_mock, agents_info_mock, reconnect_mock, agent_list, expected_items,
                                error_code):
    """Test `reconnect_agents` function from agent module.

    Parameters
    ----------
    agent_list : List of str
        List of agent ID's.
    expected_items : List of str
        List of expected agent ID's returned by 'reconnect_agents'.
    error_code : int
        The expected error code.
    """
    result = reconnect_agents(agent_list)
    assert isinstance(result, AffectedItemsWazuhResult), 'The returned object is not an "AffectedItemsWazuhResult".'
    assert result.affected_items == expected_items, f'"Affected_items" does not match. Should be "{expected_items}".'
    if result.failed_items:
        code = next(iter(result.failed_items.keys())).code
        assert code == error_code, f'"{error_code}" code was expected but "{code}" was received.'


@pytest.mark.parametrize('agent_list, expected_items, error_code', [
    (['001', '002'], ['001', '002'], None),
    (['000'], [], 1703),
    (['001', '500'], ['001'], 1701)
])
@patch('wazuh.agent.send_restart_command')
@patch('wazuh.agent.get_agents_info', return_value=set(short_agent_list))
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_agent_restart_agents(socket_mock, send_mock, agents_info_mock, send_restart_mock, agent_list,
                              expected_items, error_code):
    """Test `restart_agents` function from agent module.

    Parameters
    ----------
    agent_list : List of str
        List of agent ID's.
    expected_items : List of str
        List of expected agent ID's returned by 'restart_agents'.
    error_code : int
        The expected error code.
    """
    result = restart_agents(agent_list)
    assert isinstance(result, AffectedItemsWazuhResult), 'The returned object is not an "AffectedItemsWazuhResult".'
    assert result.affected_items == expected_items, f'"Affected_items" does not match. Should be "{expected_items}".'
    if result.failed_items:
        code = next(iter(result.failed_items.keys())).code
        assert code == error_code, f'"{error_code}" code was expected but "{code}" was received.'


@pytest.mark.parametrize('agent_list, expected_items, error_code', [
    (['000', '001', '002'], ['001', '002'], 1703),
    (['001', '500'], ['001'], 1701)
])
@patch('wazuh.agent.send_restart_command')
@patch('wazuh.agent.get_agents_info', return_value=set(short_agent_list))
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_agent_restart_agents_by_node(socket_mock, send_mock, agents_info_mock, send_restart_mock, agent_list,
                                      expected_items, error_code):
    """Test `restart_agents_by_node` function from agent module.

    Parameters
    ----------
    agent_list : List of str
        List of agent ID's.
    expected_items : List of str
        List of expected agent ID's returned by 'restart_agents'.
    error_code : int
        The expected error code.
    """
    result = restart_agents_by_node(agent_list)
    assert isinstance(result, AffectedItemsWazuhResult), 'The returned object is not an "AffectedItemsWazuhResult".'
    assert result.affected_items == expected_items, f'"Affected_items" does not match. Should be "{expected_items}".'
    if result.failed_items:
        code = next(iter(result.failed_items.keys())).code
        assert code == error_code, f'"{error_code}" code was expected but "{code}" was received.'


@pytest.mark.parametrize('agent_list, expected_items', [
    (['001', '002', '003'], ['001', '002', '003']),
    (['001', '400', '002', '500'], ['001', '002'])
])
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_agent_get_agents(socket_mock, send_mock, agent_list, expected_items):
    """Test `get_agents` function from agent module.

    Parameters
    ----------
    agent_list : List of str
        List of agent ID's.
    expected_items : List of str
        List of expected agent ID's returned by 'get_agents'.
    """
    result = get_agents(agent_list=agent_list, select=['id'])
    assert isinstance(result, AffectedItemsWazuhResult), 'The returned object is not an "AffectedItemsWazuhResult".'
    assert result.affected_items
    assert len(result.affected_items) == len(expected_items)
    assert (expected_id == agent_id for expected_id, agent_id in zip(expected_items, result.affected_items))
    if result.failed_items:
        assert (failed_item.message == 'Agent does not exist' for failed_item in result.failed_items.keys())


@pytest.mark.parametrize('group, group_exists, expected_agents', [
    ('default', True, ['001', '002', '005']),
    ('not_exists_group', False, None)
])
@patch('wazuh.agent.get_agents')
@patch('wazuh.agent.get_groups')
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_agent_get_agents_in_group(socket_mock, send_mock, mock_get_groups, mock_get_agents, group, group_exists,
                                   expected_agents):
    """Test `get_agents_in_group` from agent module.

    Parameters
    ----------
    group : str
        Name of the group to which the agent belongs.
    group_exists : bool
        Value to be returned by the mocked function 'group_exists'.
    expected_agents : List of str
        List of agent ID's that belongs to a given group.
    """
    mock_get_groups.return_value = ['default']
    if group_exists:
        # Since the decorator is mocked, pass `group_list` using `call_args` from mock
        get_agents_in_group(group_list=[group], select=['id'])
        kwargs = mock_get_agents.call_args[1]
        agents = get_agents(agent_list=short_agent_list, **kwargs)
        assert agents.affected_items
        assert len(agents.affected_items) == len(expected_agents)
        for expected_agent, affected_agent in zip(expected_agents, agents.affected_items):
            assert expected_agent == next(iter(affected_agent.values()))
    else:
        # If not `group_exists`, expect an error
        with pytest.raises(WazuhResourceNotFound, match='.* 1710 .*'):
            get_agents_in_group(group_list=[group])


@pytest.mark.parametrize('group, q, expected_q', [
    ('default', '(name~wazuh,status~active)', 'group=default;((name~wazuh,status~active))'),
    ('default', 'name~wazuh,status~active', 'group=default;(name~wazuh,status~active)')
])
@patch('wazuh.agent.get_agents')
@patch('wazuh.agent.get_groups')
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_agent_get_agents_in_group_q_formats(socket_mock, send_mock, mock_get_groups, mock_get_agents, group,
                                             q, expected_q):
    """Test the formatting of the `q` parameter in `get_agents_in_group` from agent module.

    Parameters
    ----------
    group : str
        Name of the group to which the agent belongs.
    q : str
        Value of the q parameter.
    expected_q : str
        Value of the expected q parameter used in the `get_agents` call.
    """
    mock_get_groups.return_value = ['default']
    # Since the decorator is mocked, pass `group_list` using `call_args` from mock
    get_agents_in_group(group_list=[group], q=q)
    kwargs = mock_get_agents.call_args.kwargs

    assert kwargs['q'] == expected_q


@pytest.mark.parametrize('agent_list, expected_items', [
    (['001', '002', '003'], ['001', '002', '003']),
    (['001', '400', '002', '500'], ['001', '002'])
])
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_agent_get_agents_keys(socket_mock, send_mock, agent_list, expected_items):
    """Test `get_agents_keys` from agent module.

    Parameters
    ----------
    agent_list : List of str
        List of agent ID's.
    expected_items : List of str
        List of expected agent ID's returned by 'get_agents_keys'.
    """
    agent_keys = get_agents_keys(agent_list=agent_list)
    assert agent_keys.affected_items
    assert len(agent_keys.affected_items) == len(expected_items)
    for expected_id, agent in zip(expected_items, agent_keys.affected_items):
        assert expected_id == agent['id']
        assert agent['key']
        if agent_keys.failed_items:
            assert (failed_item.message == 'Agent does not exist' for failed_item in agent_keys.failed_items.keys())


@pytest.mark.parametrize('agent_list, filters, q, error_code, expected_items', [
    (full_agent_list[1:], {'status': 'all', 'older_than': '1s'}, None, None, full_agent_list[1:]),
    (full_agent_list[1:], {'status': 'all', 'older_than': '1s', 'group': 'group-0'}, None, 1731, ['001', '002']),
    (full_agent_list[1:], {'status': 'all', 'older_than': '1s', 'group': 'group-1'}, None, 1731, ['006', '008']),
    (full_agent_list[1:], {'status': 'all', 'older_than': '1s', 'group': 'group-2'}, None, 1731, ['007', '008']),
    (full_agent_list[1:], {'status': 'all', 'older_than': '1s', 'registerIP': 'any'}, None, 1731,
     ['001', '003', '004', '006', '007', '008', '009']),
    (full_agent_list[1:], {'status': 'all', 'older_than': '1s', 'ip': '172.17.0.202'}, None, 1731, ['001']),
    (full_agent_list[1:], {'status': 'all', 'older_than': '1s', 'name': 'agent-6'}, None, 1731, ['006']),
    (full_agent_list[1:], {'status': 'all', 'older_than': '1s', 'node_name': 'random'}, None, 1731, []),
    (full_agent_list[1:], {'status': 'all', 'older_than': '1s', 'version': 'Wazuh v3.6.2'}, None, 1731, ['002']),
    (full_agent_list[1:], {'status': 'all', 'older_than': '1s', 'manager': 'master'}, None, 1731,
     ['001', '002', '005', '006', '007', '008', '009']),
    (full_agent_list[1:], {'status': 'all', 'older_than': '1s', 'os.name': 'ubuntu'}, None, 1731,
     ['001', '002', '005', '007']),
    (full_agent_list[1:], {'status': 'all', 'older_than': '1s', 'os.version': '16.04.1 LTS'}, None, 1731, ['002']),
    (full_agent_list[1:], {'status': 'all', 'older_than': '1s', 'os.platform': 'centos'}, None, 1731, []),
    (full_agent_list[1:], {'status': 'all', 'older_than': '1s', 'node_name': 'random'}, None, 1731, []),
    (
            full_agent_list[1:], {'status': 'all', 'older_than': '1s'}, 'manager=master;registerIP!=any', 1731,
            ['002', '005']),
    (['000'], {'status': 'all', 'older_than': '1s'}, None, 1703, []),
    (['001', '500'], {'status': 'all', 'older_than': '1s'}, None, 1701, ['001']),
    (['001', '002'], {'status': 'all', 'older_than': '1s'}, None, WazuhError(1726), None),
])
@patch('wazuh.agent.Agent.remove')
@patch('wazuh.core.common.CLIENT_KEYS', new=os.path.join(test_agent_path, 'client.keys'))
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_agent_delete_agents(socket_mock, send_mock, mock_remove, agent_list, filters, q, error_code, expected_items):
    """Test `delete_agents` function from agent module.

    Parameters
    ----------
    agent_list : List of str
        List of agent ID's.
    filters : dict
        Defines required field filters. Format: {"field1":"value1", "field2":["value2","value3"]}
    q : str
        Defines query to filter in DB.
    error_code : int
        The expected error code.
    expected_items : List of str
        List of expected agent ID's returned by
    """
    if not isinstance(error_code, WazuhException):
        result = delete_agents(agent_list, filters=filters, q=q)
        assert result.affected_items == sorted(expected_items), \
            f'"Affected_items" does not match. Should be "{result.affected_items}".'
        if result.failed_items:
            assert next(iter(result.failed_items)).code == error_code
    else:
        with pytest.raises(error_code.__class__, match=f'.* {error_code.code} .*'):
            mock_remove.side_effect = error_code
            delete_agents(agent_list, filters=filters, q=q)


@pytest.mark.parametrize('name, agent_id, key, force', [
    ('agent-1', '011', 'b3650e11eba2f27er4d160c69de533ee7eed601636a85ba2455d53a90927747f', None),
    ('agent-1', '012', 'b3650e11eba2f27er4d160c69de533ee7eed601636a85ba2455d53a90927747f', {'enabled': True}),
    ('a' * 129, '002', 'f304f582f2417a3fddad69d9ae2b4f3b6e6fda788229668af9a6934d454ef44d', None)
])
@patch('wazuh.core.agent.WazuhSocketJSON')
@patch('wazuh.core.agent.get_manager_status', return_value={'wazuh-authd': 'running'})
def test_agent_add_agent(manager_status_mock, socket_mock, name, agent_id, key, force):
    """Test `add_agent` from agent module.

    Parameters
    ----------
    name : str
        Name of the agent.
    agent_id : str
        ID of the agent whose name is the specified one.
    key : str
        The agent key.
    force : dict
        Force parameters.
    """
    try:
        socket_mock.return_value.receive.return_value = {"id": agent_id, "key": key}
        add_result = add_agent(name=name, agent_id=agent_id, key=key, force=force)

        assert add_result.dikt['data']['id'] == agent_id
        assert add_result.dikt['data']['key']
    except WazuhError as e:
        assert e.code == 1738, 'The exception was raised as expected but "error_code" does not match.'


@pytest.mark.parametrize('group_list, q, expected_result', [
    (['group-1', 'group-2'], None, ['group-1', 'group-2']),
    (['invalid_group'], None, []),
    (['group-1', 'group-2'], 'name~1', ['group-1']),
    (['group-1', 'group-2', 'group-3'], 'mergedSum=a336982f3c020cd558a16113f752fd5b', ['group-1', 'group-2']),
    ([], '', []) # An empty group_list should return nothing
])
@patch('wazuh.core.common.CLIENT_KEYS', new=os.path.join(test_agent_path, 'client.keys'))
@patch('wazuh.core.common.SHARED_PATH', new=test_shared_path)
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_agent_get_agent_groups(socket_mock, send_mock, group_list, q, expected_result):
    """Test `get_agent_groups` from agent module.

    This will check if the provided groups exists.

    Parameters
    ----------
    group_list : List of str
        List of groups to check if they exists.
    expected_result : List of str
        List of expected groups to be returned by 'get_agent_groups'.
    """
    group_result = get_agent_groups(group_list, q=q)
    assert len(group_result.affected_items) == len(expected_result)
    for item, group_name in zip(group_result.affected_items, group_list):
        assert item['name'] == group_name
        assert item['mergedSum']
        assert item['configSum']


@pytest.mark.parametrize('db_global, system_groups, error_code', [
    (test_global_bd_path, 'invalid_group', 1710)
])
@patch('wazuh.agent.get_groups')
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_agent_get_agent_groups_exceptions(socket_mock, send_mock, mock_get_groups, db_global, system_groups,
                                           error_code):
    """Test `get_agent_groups` function from agent module raises the expected exceptions if an invalid 'global.db' path
    or group is specified.

    """
    mock_get_groups.return_value = {'valid-group'}
    with patch('wazuh.core.common.DATABASE_PATH_GLOBAL', new=db_global):
        try:
            group_result = get_agent_groups(group_list=[system_groups])
            assert group_result.failed_items
            assert next(iter(group_result.failed_items)).code == error_code
        except WazuhException as e:
            assert e.code == error_code, 'The exception was raised as expected but "error_code" does not match.'


@pytest.mark.parametrize('group_list', [
    ['group-1'],
    ['invalid-group']
])
@patch('wazuh.core.common.DATABASE_PATH_GLOBAL', new=test_global_bd_path)
@patch('wazuh.core.common.CLIENT_KEYS', new=os.path.join(test_agent_path, 'client.keys'))
@patch('wazuh.core.common.SHARED_PATH', new=test_shared_path)
def test_agent_get_group_files(group_list):
    """Test `get_group_files` from agent module.

    Parameters
    ----------
    group_list : List of str
        List of groups to get their files.
    """
    result = get_group_files(group_list=group_list)
    # Assert 'items' contains agent.conf, merged.mg and ar.conf and 'hash' is not empty
    if result.total_failed_items != 0:
        assert list(result.failed_items.keys())[0].code == 1710
    else:
        assert result.total_affected_items == 3
        assert set(item['filename'] for item in result.affected_items).difference(
            set(['agent.conf', 'merged.mg', 'ar.conf'])) == set()
        for item in result.affected_items:
            assert item['hash']


@pytest.mark.parametrize('shared_path, group_list, group_exists, side_effect, expected_exception', [
    (test_shared_path, ['none'], False, None, WazuhResourceNotFound(1710)),
    ('invalid-path', ['default'], True, None, WazuhError(1006)),
    (test_shared_path, ['default'], True, WazuhError(1405), WazuhError(1405)),
    (test_shared_path, ['default'], True, WazuhException(1400), WazuhInternalError(1727))
])
@patch('wazuh.agent.process_array')
@patch('wazuh.core.agent.Agent.group_exists')
def test_agent_get_group_files_exceptions(mock_group_exists, mock_process_array, shared_path, group_list, group_exists,
                                          side_effect, expected_exception):
    """Test `get_group_files` function from agent module raises the expected exceptions if an invalid 'global.db' path
    is specified.

    Parameters
    ----------
    group_list : List of str
        List of groups to get their files.
    group_exists : bool
        Value to be returned by the mocked function `group_exists`.
    side_effect : Exception
        Exception type to be raised by the mocked `process_array` function.
    expected_exception : Exception
        Exception expected to be raised by `get_group_files` with the given parameters.
    """
    with patch('wazuh.core.common.SHARED_PATH', new=shared_path):
        mock_group_exists.return_value = group_exists
        mock_process_array.side_effect = side_effect
        try:
            result = get_group_files(group_list=group_list)
            assert list(result.failed_items.keys())[0] == expected_exception
        except (WazuhError, WazuhInternalError) as e:
            assert e.code == expected_exception.code, 'The exception raised is not the one expected.'


@pytest.mark.parametrize('group_id', [
    'non-existent-group',
    'invalid-group'
])
@patch('wazuh.core.common.SHARED_PATH', new=test_shared_path)
@patch('wazuh.core.common.wazuh_gid', return_value=getgrnam('root'))
@patch('wazuh.core.common.wazuh_uid', return_value=getpwnam('root'))
@patch('wazuh.agent.chown_r')
def test_create_group(chown_mock, uid_mock, gid_mock, group_id):
    """Test `create_group` function from agent module.

    When a group is created a folder with the same name is created in `common.SHARED_PATH`.

    Parameters
    ----------
    group_id : str
        Name of the group to be created.
    """
    expected_msg = f"Group '{group_id}' created."
    path_to_group = os.path.join(test_shared_path, group_id)
    try:
        result = create_group(group_id)
        assert isinstance(result, WazuhResult), 'The returned object is not an "WazuhResult" instance.'
        assert len(result.dikt) == 1, \
            f'Result dikt length is "{len(result.dikt)}" instead of "1". Result dikt content is: {result.dikt}'
        assert result.dikt['message'] == expected_msg, \
            f'The "result.dikt[\'message\']" received is not the expected.\n' \
            f'Expected: "{expected_msg}"\n' \
            f'Received: "{result.dikt["message"]}"'
        assert os.path.exists(path_to_group), \
            f'The path "{path_to_group}" does not exists and should be created by "create_group" function.'
    finally:
        # Remove the new folder to avoid affecting other tests
        shutil.rmtree(path_to_group, ignore_errors=True)


@pytest.mark.parametrize('group_id, exception, exception_code', [
    ('default', WazuhError, 1711),
    ('group-1', WazuhError, 1711),
    ('invalid!', WazuhError, 1722),
    ('delete-me', WazuhInternalError, 1005),
    ('ar.conf', WazuhError, 1713),
    ('agent-template.conf', WazuhError, 1713)
])
@patch('wazuh.core.common.SHARED_PATH', new=test_shared_path)
def test_create_group_exceptions(group_id, exception, exception_code):
    """Test `create_group` function from agent module raises the expected exceptions if an invalid `group_id` is
    specified.

    Parameters
    ----------
    group_id : str
        The invalid group id to use.
    exception : Exception
        The expected exception to be raised by `create_group`.
    exception_code : int
        Expected error code for the Wazuh Exception object raised by `get_group_files` with the given parameters.
    """
    try:
        create_group(group_id)
    except exception as e:
        assert e.code == exception_code
    finally:
        # Remove the new group file to avoid affecting the next tests
        shutil.rmtree(os.path.join(test_shared_path, 'delete-me'), ignore_errors=True)


@pytest.mark.parametrize('group_list', [
    ['group-1'],
    ['group-1', 'group-2']
])
@patch('wazuh.agent.get_groups')
@patch('wazuh.agent.Agent.delete_single_group')
def test_agent_delete_groups(mock_delete, mock_get_groups, group_list):
    """Test `delete_groups` function from agent module.

    Parameters
    ----------
    group_list : List of str
        List of groups to be deleted.
    """

    def groups():
        return set(group_list)

    mock_get_groups.side_effect = groups
    result = delete_groups(group_list)
    # Check typing
    assert isinstance(result, AffectedItemsWazuhResult), 'The returned object is not an "AffectedItemsWazuhResult".'
    assert isinstance(result.affected_items, list)
    # Check affected items
    assert result.total_affected_items == len(result.affected_items)
    assert result.affected_items == group_list

    mock_delete.assert_has_calls([call(group) for group in group_list])

    # Check failed items
    assert result.total_failed_items == 0


@pytest.mark.parametrize('group_list, expected_errors', [
    (['none-1'], [WazuhResourceNotFound(1710)]),
    (['default'], [WazuhError(1712)]),
    (['none-1', 'none-2'], [WazuhResourceNotFound(1710)]),
    (['default', 'none-1'], [WazuhError(1712), WazuhResourceNotFound(1710)]),
])
@patch('wazuh.agent.get_groups')
def test_agent_delete_groups_other_exceptions(mock_get_groups, group_list, expected_errors):
    """Test `delete_groups` function from agent module returns the expected exceptions when using invalid group lists.

    Parameters
    ----------
    group_list : List of str
        List of groups to be deleted.
    expected_errors : list of WazuhError
        List of expected WazuhError to be raised by delete_groups if a group is not valid. An exception will be returned
        for each invalid group.
    """
    mock_get_groups.side_effect = {'default'}
    result = delete_groups(group_list)
    assert isinstance(result, AffectedItemsWazuhResult), 'The returned object is not an "AffectedItemsWazuhResult".'
    assert isinstance(result.failed_items, dict)
    # Check failed items
    assert result.total_failed_items == len(group_list)
    assert len(result.failed_items.keys()) == len(expected_errors)
    assert set(result.failed_items.keys()).difference(set(expected_errors)) == set()


@pytest.mark.parametrize('group_list, agent_list, num_failed', [
    (['group-1'], ['001'], 0),
    (['group-1'], ['001', '002', '003', '100'], 1)
])
@patch('wazuh.agent.Agent.add_group_to_agent')
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('wazuh.core.agent.Agent.group_exists', return_value=True)
@patch('socket.socket.connect')
async def test_assign_agents_to_group(socket_mock, group_exists_mock, send_mock, add_group_mock, group_list, agent_list,
                                num_failed):
    """Test `assign_agents_to_group` function from agent module. Does not check its raised exceptions.

    Parameters
    ----------
    group_list : List of str
        List of group to apply to the agents
    agent_list : List of str
        List of agent ID's.
    num_failed : int
        Number of expected failed_items
    """
    result = await assign_agents_to_group(group_list, agent_list)
    # Check typing
    assert isinstance(result, AffectedItemsWazuhResult), 'The returned object is not an "AffectedItemsWazuhResult".'
    assert isinstance(result.affected_items, list)
    # Check affected items
    assert result.total_affected_items == len(result.affected_items)
    assert set(result.affected_items).difference(set(agent_list)) == set()
    # Check if the number of affected items matches the number of times `add_group_to_agent` was called
    # `agent_list` must only have those agent IDs without exceptions at this level
    assert len(result.affected_items) == add_group_mock.call_count
    # Check failed items
    assert result.total_failed_items == num_failed


@pytest.mark.parametrize('group_list, agent_list, expected_error, catch_exception', [
    (['none-1'], ['001'], WazuhResourceNotFound(1710), True),
    (['group-1'], ['100'], WazuhResourceNotFound(1701), False),
    (['default'], ['000'], WazuhError(1703), False)
])
@patch('wazuh.agent.Agent.group_exists')
@patch('wazuh.agent.Agent.add_group_to_agent')
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
async def test_agent_assign_agents_to_group_exceptions(socket_mock, send_mock, mock_add_group, mock_group_exists, group_list,
                                                 agent_list, expected_error, catch_exception):
    """Test `assign_agents_to_group` function from agent module raises the expected exceptions when using invalid groups.

    Parameters
    ----------
    group_list : List of str
        List of group to apply to the agents
    agent_list : List of str
        List of agent ID's.
    expected_error : WazuhError
        Expected exception to be raised by `assign_agents_to_group` function using the specified parameters.
    catch_exception : bool
        True if the exception will be raised by the function and must be caught. False if the function must return an
        `AffectedItemsWazuhResult` containing the exceptions in its 'failed_items'.
    """

    def group_exists(group_id):
        return group_id != 'none-1'

    def add_group_to_agent(group_id, agent_id, replace=False, replace_list=None):
        return f"Agent {agent_id} assigned to {group_id}"

    mock_group_exists.side_effect = group_exists
    mock_add_group.side_effect = add_group_to_agent
    try:
        result = await assign_agents_to_group(group_list, agent_list)
        assert not catch_exception
        assert isinstance(result, AffectedItemsWazuhResult), 'The returned object is not an "AffectedItemsWazuhResult".'
        assert isinstance(result.failed_items, dict)
        # Check failed items
        assert result.total_failed_items == len(group_list)
        assert result.total_failed_items == len(result.failed_items)
        assert set(result.failed_items.keys()).difference({expected_error}) == set()
    except WazuhException as ex:
        assert catch_exception
        assert ex == expected_error


@pytest.mark.parametrize('group_id, agent_id', [
    ('default', '001'),
    ('group-1', '005')
])
@patch('wazuh.core.common.DATABASE_PATH_GLOBAL', new=test_global_bd_path)
@patch('wazuh.core.agent.Agent.unset_single_group_agent')
@patch('wazuh.agent.get_groups')
@patch('wazuh.agent.get_agents_info')
async def test_agent_remove_agent_from_group(mock_get_agents, mock_get_groups, mock_unset, group_id, agent_id):
    """Test `remove_agent_from_group` function from agent module. Does not check its raised exceptions.

    Parameters
    ----------
    group_id : str
        Name of the group from where the agent will be removed.
    agent_id : str
        ID of the agent to be removed from the group.
    """
    expected_msg = f"Agent '{agent_id}' removed from '{group_id}'"
    mock_get_agents.return_value = short_agent_list
    mock_unset.return_value = expected_msg
    mock_get_groups.return_value = {group_id}

    result = await remove_agent_from_group(group_list=[group_id], agent_list=[agent_id])
    mock_unset.assert_called_once_with(agent_id=agent_id, group_id=group_id, force=True)
    assert isinstance(result, WazuhResult), 'The returned object is not an "WazuhResult" instance.'
    assert result.dikt['message'] == expected_msg


@pytest.mark.parametrize('group_id, agent_id, expected_error', [
    ('any-group', '100', WazuhResourceNotFound(1701)),
    ('any-group', '000', WazuhError(1703)),
    ('group-1', '005', WazuhResourceNotFound(1710)),
])
@patch('wazuh.agent.get_agents_info', return_value=short_agent_list)
@patch('wazuh.agent.get_groups', side_effect={'default'})
async def test_agent_remove_agent_from_group_exceptions(group_mock, agents_info_mock, group_id, agent_id, expected_error):
    """Test `remove_agent_from_group` function from agent module raises the expected exceptions if an invalid 'agent_id'
    or 'group_id' are specified.

    Parameters
    ----------
    group_id : str
        The invalid group id to use.
    agent_id : str
        the invalid agent id to use.
    expected_error : WazuhError
        The WazuhError object expected to be raised by remove_agent_from_group with the given parameters.
    """
    try:
        await remove_agent_from_group(group_list=[group_id], agent_list=[agent_id])
        pytest.fail('An exception should be raised for the given configuration.')
    except (WazuhError, WazuhResourceNotFound) as error:
        assert error == expected_error


@pytest.mark.parametrize('group_list, agent_list', [
    (['group-1'], ['001'])
])
@patch('wazuh.core.agent.Agent.unset_single_group_agent')
@patch('wazuh.agent.get_agents_info', return_value=short_agent_list)
@patch('wazuh.agent.get_groups', return_value={'group-1'})
async def test_agent_remove_agent_from_groups(mock_get_groups, mock_get_agents, mock_unset, group_list, agent_list):
    """Test `remove_agent_from_groups` function from agent module.

    Parameters
    ----------
    group_list : List of str
        List of group names from where the agents will be removed.
    agent_list : List of str
        List of agent ID's.
    """
    expected_msg = f"Agent '{group_list[0]}' removed from '{group_list[0]}'"
    mock_unset.return_value = expected_msg
    result = await remove_agent_from_groups(agent_list=agent_list, group_list=group_list)
    # Check typing
    assert isinstance(result, AffectedItemsWazuhResult), 'The returned object is not an "AffectedItemsWazuhResult".'
    assert isinstance(result.affected_items, list)
    # Check affected items
    assert result.total_affected_items == len(result.affected_items)
    assert set(result.affected_items).difference(set(group_list)) == set(), f'received: {result.affected_items}'
    # Check failed items
    assert result.total_failed_items == 0


@pytest.mark.parametrize('group_list, agent_list, expected_error, catch_exception', [
    (['any-group'], ['100'], WazuhResourceNotFound(1701), True),
    (['any-group'], ['000'], WazuhError(1703), True),
    (['any-group'], ['005'], WazuhResourceNotFound(1710), False),
])
@patch('wazuh.core.agent.Agent.unset_single_group_agent')
@patch('wazuh.agent.get_agents_info', return_value=short_agent_list)
@patch('wazuh.agent.get_groups', return_value={'group-1'})
async def test_agent_remove_agent_from_groups_exceptions(mock_get_groups, mock_get_agents, mock_unset, group_list, agent_list,
                                                   expected_error, catch_exception):
    """Test `remove_agent_from_groups` function from agent module raises the expected errors when using invalid group
    or agent lists.

    Parameters
    ----------
    group_list : List of str
        List of group names from where the agents will be removed.
    agent_list : List of str
        List of agent ID's.
    expected_error : WazuhError
        The expected error to be raised or returned by the function.
    catch_exception : bool
        True if the exception will be raised by the function and must be caught. False if the function must return an
        `AffectedItemsWazuhResult` containing the exceptions in its 'failed_items'.
    """
    expected_msg = f"Agent '{group_list[0]}' removed from '{group_list[0]}'"
    mock_unset.return_value = expected_msg
    try:
        result = await remove_agent_from_groups(group_list=group_list, agent_list=agent_list)
        assert not catch_exception, \
            'An "WazuhError" exception was expected but was not raised.'
        # Check Typing
        assert isinstance(result, AffectedItemsWazuhResult), 'The returned object is not an "AffectedItemsWazuhResult".'
        assert isinstance(result.failed_items, dict), \
            f'"failed_items" should be a dict object but was "{type(result.failed_items)}" instead.'
        # Check Failed Items
        assert result.total_failed_items == len(group_list), \
            f'The number of "failed_items" is "{result.total_failed_items}" but was expected to be ' \
            f'"{len(group_list)}".'
        assert result.total_failed_items == len(result.failed_items), \
            '"total_failed_items" length does not match with "failed_items".'
        assert set(result.failed_items.keys()).difference({expected_error}) == set(), \
            f'The "failed_items" received does not match.\n' \
            f' - The "failed_items" received is: "{set(result.failed_items.keys())}"\n' \
            f' - The "failed_items" expected was "{ {expected_error} }"\n' \
            f' - The difference between them is "{set(result.failed_items.keys()).difference({expected_error})}"\n'
    except (WazuhError, WazuhResourceNotFound) as error:
        assert catch_exception, \
            'No exception should be raised at this point. An AffectedItemsWazuhResult object with at least one ' \
            'failed item was expected instead.'
        assert error == expected_error


@pytest.mark.parametrize('group_list, agent_list', [
    (['group-1'], ['001'])
])
@patch('wazuh.core.agent.Agent.unset_single_group_agent')
@patch('wazuh.agent.get_agents_info', return_value=short_agent_list)
@patch('wazuh.agent.get_groups', return_value={'group-1'})
async def test_agent_remove_agents_from_group(mock_get_groups, mock_get_agents, mock_unset, group_list, agent_list):
    """Test `remove_agents_from_group` function from agent module.

    Parameters
    ----------
    group_list : List of str
        List of group names from where the agents will be removed. The list must contain only one group name.
    agent_list : List of str
        List of agent ID's.
    """
    expected_msg = f"Agent '{group_list[0]}' removed from '{group_list[0]}'"
    mock_unset.return_value = expected_msg
    result = await remove_agents_from_group(agent_list=agent_list, group_list=group_list)
    # Check typing
    assert isinstance(result, AffectedItemsWazuhResult), 'The returned object is not an "AffectedItemsWazuhResult".'
    assert isinstance(result.affected_items, list)
    # Check affected items
    assert result.total_affected_items == len(result.affected_items)
    assert set(result.affected_items).difference(set(agent_list)) == set(), f'received: {result.affected_items}'
    # Check failed items
    assert result.total_failed_items == 0


@pytest.mark.parametrize('group_list, agent_list, expected_error, catch_exception', [
    (['non-group'], ['000'], WazuhResourceNotFound(1710), True),
    (['group-1'], ['000'], WazuhError(1703), False),
    (['group-1'], ['100'], WazuhResourceNotFound(1701), False),
])
@patch('wazuh.agent.get_agents_info', return_value=short_agent_list)
@patch('wazuh.agent.get_groups', return_value={'group-1'})
async def test_agent_remove_agents_from_group_exceptions(group_mock, agents_info_mock, group_list, agent_list,
                                                   expected_error, catch_exception):
    """Test `remove_agents_from_group` function from agent module raises the expected exceptions when using invalid
    parameters.

    Parameters
    ----------
    group_list : List of str
        List of group names from where the agents will be removed.
    agent_list : List of str
        List of agent ID's.
    expected_error : WazuhError
        The expected error to be raised or returned by the function.
    catch_exception : bool
        True if the exception will be raised by the function and must be caught. False if the function must return an
        `AffectedItemsWazuhResult` containing the exceptions in its 'failed_items'.
    """
    try:
        result = await remove_agents_from_group(group_list=group_list, agent_list=agent_list)
        # Ensure no exception was expected
        assert not catch_exception
        assert isinstance(result, AffectedItemsWazuhResult), 'The returned object is not an "AffectedItemsWazuhResult".'
        assert isinstance(result.failed_items, dict)
        # Check failed items
        assert result.total_failed_items == len(group_list)
        assert result.total_failed_items == len(result.failed_items)
        assert set(result.failed_items.keys()).difference({expected_error}) == set()
    except (WazuhError, WazuhResourceNotFound) as error:
        assert catch_exception
        assert error == expected_error


@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_agent_get_outdated_agents(socket_mock, send_mock):
    """Test get_oudated_agents function from agent module.

    Parameters
    ----------
    outdated_agents : List of str
        List of agent ID's we expect to be outdated.
    """
    outdated_agents = ['001', '002', '005']
    result = get_outdated_agents(agent_list=short_agent_list)
    # Check typing
    assert isinstance(result, AffectedItemsWazuhResult)
    assert isinstance(result.affected_items, list)
    # Check affected items
    assert result.total_affected_items == len(outdated_agents)
    for item in result.affected_items:
        assert item['id'] in outdated_agents
    # Check failed items
    assert result.total_failed_items == 0


@pytest.mark.parametrize('agent_set, expected_errors_and_items, result_from_socket, filters, raise_error', [
    (
            {'000', '001', '002', '003', '004', '999'},
            {'1703': {'000'}, '1701': {'999'}, '1822': {'002'}, '1707': {'003', '004'}},
            {'error': 0,
             'data': [{'error': 0, 'message': 'Success', 'agent': 1, 'task_id': 1},
                      {'error': 12,
                       'message': 'Current agent version is greater or equal',
                       'agent': 2}
                      ],
             'message': 'Success'},
            None,
            False
    ),
    (
            {'000', '001', '002'},
            {'1703': {'000'}, '1731': {'001', '002'}},
            {},
            {'os.version': 'unknown_version'},
            False
    ),
    (
            {'001', '006'},
            {'1731': {'001'}},
            {'error': 0,
             'data': [{'error': 0, 'message': 'Success', 'agent': 6, 'task_id': 1}],
             'message': 'Success'},
            {'group': 'group-1'},
            False
    ),
    (
            {'001'},
            {'1824': '001'},
            {'error': 1,
             'data': [{'error': 14,
                       'message': 'The repository is not reachable',
                       'agent': 1}
                      ],
             'message': 'Error'},
            None,
            True
    ),
    (
            {'001'},
            {'1828': '001'},
            {'error': 1,
             'data': [{'error': 18,
                       'message': 'Error from socket indicating WazuhInternalError',
                       'agent': 1}
                      ],
             'message': 'Error'},
            None,
            True
    )
])
@patch('wazuh.agent.get_agents_info', return_value=set(full_agent_list))
@patch('wazuh.core.common.CLIENT_KEYS', new=os.path.join(test_agent_path, 'client.keys'))
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_agent_upgrade_agents(mock_socket, mock_wdb, mock_client_keys, agent_set, expected_errors_and_items,
                              result_from_socket, filters, raise_error):
    """Test `upgrade_agents` function from agent module.

    Parameters
    ----------
    agent_set : set
        Set of agent ID's to be updated.
    expected_errors_and_items : dict
        Dictionary containing expected errors and agent IDs.
    result_from_socket : dict
        Dictionary containing the result sent by the socket.
    filters : dict
        Defines required field filters. Format: {"field1":"value1", "field2":["value2","value3"]}
    raise_error : bool
        Boolean variable used to indicate that the
    """
    with patch('wazuh.core.agent.core_upgrade_agents') as core_upgrade_agents_mock:
        core_upgrade_agents_mock.return_value = result_from_socket

        if raise_error:
            # Upgrade expecting a Wazuh Exception
            for error in expected_errors_and_items.keys():
                if int(error) in ERROR_CODES_UPGRADE_SOCKET_BAD_REQUEST:
                    with pytest.raises(WazuhError, match=f".* {error} .*"):
                        upgrade_agents(agent_list=list(agent_set), filters=filters)
                elif int(error) not in (ERROR_CODES_UPGRADE_SOCKET + [1701, 1703, 1707, 1731]):
                    with pytest.raises(WazuhInternalError, match=f".* {error} .*"):
                        upgrade_agents(agent_list=list(agent_set), filters=filters)
        else:
            # Upgrade with no Exception
            result = upgrade_agents(agent_list=list(agent_set), filters=filters)

            assert isinstance(result, AffectedItemsWazuhResult)

            # Check affected items
            affected_items = set([af_item['agent'] for af_item in result.affected_items])
            values_failed_items = list(expected_errors_and_items.values())
            agents_with_errors = set()
            for value in values_failed_items:
                str_value = list(value)[0]
                if ',' in str_value:
                    agent = str_value.split(', ')
                    agents_with_errors.update(agent)
                    values_failed_items.remove(value)
            [agents_with_errors.update(s) for s in values_failed_items]
            assert affected_items == agent_set - agents_with_errors

            # Check failed items
            error_codes_in_failed_items = [error.code for error in result.failed_items.keys()]
            failed_items = list(result.failed_items.values())
            errors_and_items = {}
            for i, error in enumerate(error_codes_in_failed_items):
                errors_and_items[str(error)] = failed_items[i]
            assert expected_errors_and_items == errors_and_items


@pytest.mark.parametrize('agent_set, expected_errors_and_items, result_from_socket, filters, raise_error', [
    (
            {'000', '001', '002', '003', '006', '999'},
            {'1703': {'000'}, '1701': {'999'}, '1707': {'003'}, '1813': {'006'}},
            {'error': 0,
             'data': [
                 {'error': 0, 'message': 'Success', 'agent': 1, 'task_id': 1,
                  'module': 'upgrade_module', 'command': 'upgrade',
                  'status': 'upgraded', 'create_time': '2020/09/23 10:39:53',
                  'update_time': '2020/09/23 10:54:53'},
                 {'error': 0, 'message': 'Success', 'agent': 2, 'task_id': 2,
                  'module': 'upgrade_module', 'command': 'upgrade',
                  'status': 'Legacy upgrade: ...',
                  'create_time': '2020/09/23 11:24:27',
                  'update_time': '2020/09/23 11:24:47'},
                 {'error': 3, 'message': 'No task in DB', 'agent': 6}],
             'message': 'Success'},
            None,
            False
    ),
    (
            {'000', '001', '002'},
            {'1703': {'000'}, '1731': {'001', '002'}},
            {},
            {'os.version': 'unknown_version'},
            False
    ),
    (
            {'001', '006'},
            {'1731': {'001'}},
            {'error': 0,
             'data': [{'error': 0, 'message': 'Success', 'agent': 6, 'task_id': 1,
                       'module': 'upgrade_module', 'command': 'upgrade',
                       'status': 'upgraded', 'create_time': '2020/09/23 10:39:53',
                       'update_time': '2020/09/23 10:54:53'}, ],
             'message': 'Success'},
            {'group': 'group-1'},
            False
    ),
    (
            {'001'},
            {'1828': '001'},
            {'error': 1,
             'data': [{'error': 18,
                       'message': 'Error from socket indicating WazuhInternalError',
                       'agent': 1}
                      ],
             'message': 'Error'},
            None,
            True
    )
])
@patch('wazuh.agent.get_agents_info', return_value=set(full_agent_list))
@patch('wazuh.core.common.CLIENT_KEYS', new=os.path.join(test_agent_path, 'client.keys'))
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_agent_get_upgrade_result(mock_socket, mock_wdb, mock_client_keys, agent_set, expected_errors_and_items,
                                  result_from_socket, filters, raise_error):
    """Test `upgrade_agents` function from agent module.

    Parameters
    ----------
    agent_set : set
        Set of agent ID's to be updated.
    expected_errors_and_items : dict
        Dictionary containing expected errors and agent IDs.
    result_from_socket : dict
        Dictionary containing the result sent by the socket.
    filters : dict
        Defines required field filters. Format: {"field1":"value1", "field2":["value2","value3"]}
    raise_error : bool
        Boolean variable used to indicate that the
    """
    with patch('wazuh.core.agent.core_upgrade_agents') as core_upgrade_agents_mock:
        core_upgrade_agents_mock.return_value = result_from_socket

        if raise_error:
            # Get upgrade result expecting a Wazuh Exception
            for error in expected_errors_and_items.keys():
                with pytest.raises(WazuhInternalError, match=f".* {error} .*"):
                    get_upgrade_result(agent_list=list(agent_set))
        else:
            # Get upgrade result with no Exception
            result = get_upgrade_result(agent_list=list(agent_set), filters=filters)

            assert isinstance(result, AffectedItemsWazuhResult)

            # Check affected items
            affected_items = set([af_item['agent'] for af_item in result.affected_items])
            values_failed_items = list(expected_errors_and_items.values())
            agents_with_errors = set()
            for value in values_failed_items:
                str_value = list(value)[0]
                if ',' in str_value:
                    agent = str_value.split(', ')
                    agents_with_errors.update(agent)
                    values_failed_items.remove(value)
            [agents_with_errors.update(s) for s in values_failed_items]
            assert affected_items == agent_set - agents_with_errors

            # Check failed items
            error_codes_in_failed_items = [error.code for error in result.failed_items.keys()]
            failed_items = list(result.failed_items.values())
            errors_and_items = {}
            for i, error in enumerate(error_codes_in_failed_items):
                errors_and_items[str(error)] = failed_items[i]
            assert expected_errors_and_items == errors_and_items


@pytest.mark.parametrize('agent_list, component, configuration', [
    (['001'], 'logcollector', 'internal')
])
@patch('wazuh.core.wazuh_socket.WazuhSocket')
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
@patch('os.path.exists')
def test_agent_get_agent_config(mock_exists, socket_mock, send_mock, wazuh_socket_mock, agent_list, component, configuration):
    """Test `get_agent_config` function from agent module.

    Parameters
    ----------
    agent_list : List of str
        List of agent ID's.
    component : str
        Name of the component.
    configuration : str
        Name of the configuration file.
    """
    wazuh_socket_mock.return_value.receive.return_value = b'ok {"test": "conf"}'

    result = get_agent_config(agent_list=agent_list, component=component, config=configuration)
    assert isinstance(result, WazuhResult), 'The returned object is not an "WazuhResult" instance.'
    assert result.dikt['data'] == {"test": "conf"}, 'Result message is not as expected.'


@pytest.mark.parametrize('agent_list', [
    ['005']
])
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_agent_get_agent_config_exceptions(socket_mock, send_mock, agent_list):
    """Test `get_agent_config` function from agent module raises the expected exceptions when using invalid parameters.

    Parameters
    ----------
    agent_list : List of str
        List of agent ID's.
    """
    try:
        get_agent_config(agent_list=agent_list)
        pytest.fail('An exception should be raised.')
    except WazuhError as error:
        assert error == WazuhError(1740)


@pytest.mark.parametrize('agent_list', [
    full_agent_list[1:]
])
@patch('wazuh.core.common.SHARED_PATH', new=test_shared_path)
@patch('wazuh.core.common.MULTI_GROUPS_PATH', new=test_multigroup_path)
@patch('wazuh.agent.get_agents_info', return_value=full_agent_list)
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_agent_get_agents_sync_group(socket_mock, send_mock, get_agent_mock, agent_list):
    """Test `get_agents_sync_group` function from agent module.

    Parameters
    ----------
    agent_list : List of str
        List of agent ID's.
    """
    result = get_agents_sync_group(agent_list=agent_list)
    assert isinstance(result, AffectedItemsWazuhResult), 'The returned object is not an "AffectedItemsWazuhResult".'
    # Check affected items
    assert result.total_affected_items == len(agent_list)
    assert len([item for item in result.affected_items if 'synced' in item]) == len(agent_list)


@pytest.mark.parametrize('agent_list, expected_error', [
    (['000'], WazuhError(1703)),
    (['100'], WazuhResourceNotFound(1701))
])
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_agent_get_agents_sync_group_exceptions(socket_mock, send_mock, agent_list, expected_error):
    """Test `get_agents_sync_group` function from agent module returns the expected exceptions when using invalid
    parameters.

    Parameters
    ----------
    agent_list : List of str
        List of agent ID's.
    expected_error : WazuhError
        Expected WazuhError to be returned (not raised) by the function.
    """
    result = get_agents_sync_group(agent_list=agent_list)
    assert isinstance(result, AffectedItemsWazuhResult), 'The returned object is not an "AffectedItemsWazuhResult".'
    # Check failed items
    assert result.total_failed_items == len(agent_list)
    assert isinstance(result.failed_items, dict)
    assert result.failed_items == {expected_error: {agent_list[0]}}


@pytest.mark.parametrize('filename, group_list', [
    ('agent.conf', ['default'])
])
@patch('wazuh.core.common.DATABASE_PATH_GLOBAL', new=test_global_bd_path)
@patch('wazuh.core.common.SHARED_PATH', new=test_shared_path)
def test_agent_get_file_conf(filename, group_list):
    """Test `get_file_conf` from agent module.

    Parameters
    ----------
    filename : str
        Name of the agent.
    group_list : List of str
        List of group names.
    """
    result = get_file_conf(filename=filename, group_list=group_list)
    assert isinstance(result, WazuhResult), 'The returned object is not an "WazuhResult" instance.'
    assert 'data' in result.dikt
    assert isinstance(result.dikt['data'], dict)
    assert 'total_affected_items' in result.dikt['data']
    assert result.dikt['data']['total_affected_items'] == 1


@pytest.mark.parametrize('group_list', [
    ['default']
])
@patch('wazuh.core.common.DATABASE_PATH_GLOBAL', new=test_global_bd_path)
@patch('wazuh.core.common.SHARED_PATH', new=test_shared_path)
def test_agent_get_agent_conf(group_list):
    """Test `get_agent_agent_conf` function from agent module.

    Parameters
    ----------
    group_list : List of str
        List of group names.
    """
    result = get_agent_conf(group_list=group_list)
    assert isinstance(result, WazuhResult), 'The returned object is not an "WazuhResult" instance.'
    assert 'total_affected_items' in result.dikt['data']
    assert result.dikt['data']['total_affected_items'] == 1


@pytest.mark.parametrize('group_list', [
    ['default']
])
@patch('wazuh.core.common.SHARED_PATH', new=test_shared_path)
@patch('wazuh.core.configuration.upload_group_configuration')
def test_agent_upload_group_file(mock_upload, group_list):
    """Test `upload_group_file` function from agent module.

    Parameters
    ----------
    group_list : List of str
        List of group names.
    """
    expected_msg = 'Agent configuration was successfully updated'
    mock_upload.return_value = expected_msg
    result = upload_group_file(group_list=group_list, file_data="sample")
    assert isinstance(result, WazuhResult), 'The returned object is not an "WazuhResult" instance.'
    assert 'message' in result.dikt
    assert result.dikt['message'] == expected_msg


@pytest.mark.parametrize('agent_list, group_list, index_error, last_agent', [
    (['000', '001'], ['group-2'], False, '001'),
    (['001'], ['group-2'], False, '001'),
    (['001', '002'], ['group-2', 'group-1'], False, '002'),
    (['001', '002', '003'], ['group-2', 'group-1'], False, '002'),
    (full_agent_list, ['group-1'], False, '004'),
    (full_agent_list, ['group-1'], True, None)
])
@patch('wazuh.core.common.SHARED_PATH', new=test_shared_path)
@patch('wazuh.agent.get_distinct_agents')
@patch('wazuh.agent.get_agent_groups')
@patch('wazuh.agent.get_agents_summary_status')
@patch('wazuh.agent.get_agents')
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_agent_get_full_overview(socket_mock, send_mock, get_mock, summary_mock, group_mock, distinct_mock, agent_list,
                                 group_list, index_error, last_agent):
    """Test `get_full_overview` function from agent module.

    Parameters
    ----------
    agent_list : List of str
        List of agent ID's.
    group_list : List of str
        List of group names.
    index_error : bool
        True if an `index_error` exception must be raised, False otherwise.
    last_agent : str
        ID of the last registered agent.
    """
    expected_fields = ['nodes', 'groups', 'agent_os', 'agent_status', 'agent_version', 'last_registered_agent']

    def mocked_get_distinct_agents(fields, q):
        return get_distinct_agents(agent_list=agent_list, fields=fields, q=q)

    def mocked_get_agent_groups():
        return get_agent_groups(group_list=group_list)

    def mocked_get_agents_summary_status():
        return get_agents_summary_status(agent_list=agent_list)

    def mocked_get_agents(limit, sort, q):
        if index_error:
            raise IndexError()
        else:
            return get_agents(agent_list=agent_list, limit=limit, sort=sort, q=q)

    distinct_mock.side_effect = mocked_get_distinct_agents
    group_mock.side_effect = mocked_get_agent_groups
    summary_mock.side_effect = mocked_get_agents_summary_status
    get_mock.side_effect = mocked_get_agents
    result = get_full_overview()
    assert isinstance(result, WazuhResult), 'The returned object is not an "WazuhResult" instance.'
    assert set(result.dikt['data'].keys()) == set(expected_fields)
    if index_error:
        assert len(result.dikt['data']['last_registered_agent']) == 0
    else:
        assert result.dikt['data']['last_registered_agent'][0]['id'] == last_agent


@pytest.fixture(scope='module')
def insert_agents_db(n_agents=100000):
    """Insert n_agents in the global.db test database.

    All the tests using this fixture should be run in the last place, since
    agent's database is modified.

    Parameters
    ----------
    n_agents : int
        Total number of agents that must be inside the db after running this function.
    """
    last_inserted_id = next(map(list, test_data.cur.execute("select max(id) from agent")), 0)[0]
    for agent_id in range(last_inserted_id + 1, n_agents):
        msg = f"INSERT INTO agent (id, name, ip, date_add) VALUES ({agent_id}, 'test_{agent_id}', 'any', 1621925385)"
        test_data.cur.execute(msg)


@pytest.mark.parametrize('agent_list, params, expected_ids', [
    (range(500), {}, range(500)),
    (range(1000), {}, range(500)),
    (range(1000, 2000), {}, range(1000, 1500)),
    (range(100000), {'limit': 1000}, range(1000)),
    (range(100000), {'offset': 50000}, range(50000, 50500)),
    (range(1000), {'limit': 100, 'offset': 500}, range(500, 600)),
    (range(100000), {'limit': 1000, 'offset': 80000}, range(80000, 81000)),
])
@patch('wazuh.agent.get_agents_info', return_value=['test', 'test2'])
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
def test_get_agents_big_env(mock_conn, mock_send, mock_get_agents, insert_agents_db, agent_list, params, expected_ids):
    """Check that the expected number of items is returned when limit is greater than 500.

    Parameters
    ----------
    agent_list : list
        Agents to retrieve.
    params : dict
        Parameters to be passed to get_agents function.
    expected_ids
        IDs that should be returned.
    """

    def agent_ids_format(ids_list):
        return [str(agent_id).zfill(3) for agent_id in ids_list]

    with patch('wazuh.agent.get_agents_info', return_value=set(agent_ids_format(range(100000)))):
        result = get_agents(agent_list=agent_ids_format(agent_list), **params).render()
        expected_ids = agent_ids_format(expected_ids)
        for item in result['data']['affected_items']:
            assert item['id'] in expected_ids, f'Received ID {item["id"]} is not within expected IDs.'


@pytest.mark.parametrize('agent_groups, agent_id, group_id', [
    (['dmz'], '005', 'dmz'),
    (['dmz', 'webserver'], '005', 'dmz'),
    (['dmz', 'webserver', 'database'], '005', 'dmz')
])
@patch('wazuh.core.agent.Agent.get_agent_groups', new_callable=AsyncMock)
@patch('wazuh.core.agent.Agent.set_agent_group_relationship')
async def test_unset_single_group_agent(set_agent_group_patch, get_groups_patch, agent_groups,
                                   agent_id, group_id):
    """Test successfully unsetting a group from an agent.

    Parameters
    ----------
    agent_groups: list
        List of groups an agent belongs to.
    agent_id: str
        Agent ID.
    group_id: str
        Group ID.
    """
    get_groups_patch.return_value = agent_groups

    ret_msg = await Agent.unset_single_group_agent(agent_id, group_id, force=True)

    # Response message is different depending on the remaining group. If the only group is removed, 'default'
    # will be reassigned through wdb and the message will reflect it
    reassigned_msg = " Agent reassigned to group default." \
        if len(agent_groups) == 1 and agent_groups[0] == group_id else ''

    assert ret_msg == f"Agent '{agent_id}' removed from '{group_id}'.{reassigned_msg}"


@pytest.mark.parametrize('agent_id, group_id, force, expected_exc', [
    ('000', 'whatever', False, 1703),
    ('001', 'whatever', False, 1710),
    ('001', 'not_exists', True, 1734),
    ('001', 'default', True, 1745),
])
@patch('wazuh.core.agent.Agent.get_agent_groups', new_callable=AsyncMock)
@patch('wazuh.core.agent.Agent.group_exists', return_value=False)
@patch('wazuh.core.agent.Agent.get_basic_information')
async def test_unset_single_group_agent_ko(agent_basic_mock, group_exists_mock, get_groups_mock, agent_id, group_id,
                                      force, expected_exc):
    """Test `remove_single_group_agent` method exceptions.

    Parameters
    ----------
    agent_id: str
        Agent ID.
    group_id: str
        Group ID.
    force: bool
        Whether to force the agent-group relationship or not.
    expected_exc: int
        Expected WazuhException code error.
    """
    get_groups_mock.return_value = ['default']
    with pytest.raises(WazuhException, match=f".* {expected_exc} .*"):
        await Agent.unset_single_group_agent(agent_id, group_id, force=force)


def test_check_uninstall_permission():
    """Check that agent_check_uninstall_permission returns the expected msg"""

    result = check_uninstall_permission()
    expected = WazuhResult({'message': 'User has permission to uninstall agents'})

    assert result == expected

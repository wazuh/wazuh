#!/usr/bin/env python
# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys
from grp import getgrnam
from json import dumps
from pwd import getpwnam
from unittest.mock import AsyncMock, MagicMock, call, patch

import pytest

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../..'))

with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
        with patch('wazuh.core.utils.load_wazuh_xml'):
            sys.modules['wazuh.rbac.orm'] = MagicMock()
            import wazuh.rbac.decorators
            from wazuh.tests.util import RBAC_bypasser

            del sys.modules['wazuh.rbac.orm']
            wazuh.rbac.decorators.expose_resources = RBAC_bypasser

        from wazuh import WazuhError, WazuhException, WazuhInternalError
        from wazuh.agent import (
            ERROR_CODES_UPGRADE_SOCKET,
            ERROR_CODES_UPGRADE_SOCKET_BAD_REQUEST,
            add_agent,
            build_agents_query,
            create_group,
            delete_agents,
            delete_groups,
            get_group_conf,
            get_agent_config,
            get_agent_groups,
            get_agents,
            get_agents_in_group,
            get_agents_keys,
            get_agents_summary_os,
            get_agents_summary_status,
            get_distinct_agents,
            get_full_overview,
            get_outdated_agents,
            get_upgrade_result,
            reconnect_agents,
            remove_agent_from_groups,
            remove_agents_from_group,
            restart_agents,
            restart_agents_by_node,
            upgrade_agents,
            update_group_file,
        )
        from wazuh.core.agent import Agent
        from wazuh.core.exception import WazuhResourceNotFound
        from wazuh.core.indexer.base import IndexerKey
        from wazuh.core.indexer.models.agent import Agent as IndexerAgent
        from wazuh.core.indexer.models.commands import CreateCommandResponse, ResponseResult
        from wazuh.core.results import AffectedItemsWazuhResult, WazuhResult
        from wazuh.core.tests.test_agent import InitAgent

        from api.util import remove_nones_to_dict

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
test_agent_path = os.path.join(test_data_path, 'agent')
test_shared_path = os.path.join(test_agent_path, 'shared')
test_global_bd_path = os.path.join(test_data_path, 'global.db')

test_data = InitAgent(data_path=test_data_path)
full_agent_list = ['001', '002', '003', '004', '005', '006', '007', '008', '009']
short_agent_list = ['001', '002', '003', '004', '005']


def send_msg_to_wdb(msg, raw=False):
    query = ' '.join(msg.split(' ')[2:])
    result = list(map(remove_nones_to_dict, map(dict, test_data.cur.execute(query).fetchall())))
    return ['ok', dumps(result)] if raw else result


@pytest.mark.parametrize('fields, expected_items', [
    (
            ['os.platform'],
            [{'os': {'platform': 'ubuntu'}, 'count': 3}, {'os': {'platform': 'N/A'}, 'count': 2}]
    ),
    (
            ['version'],
            [{'version': 'Wazuh v3.8.2', 'count': 2},
             {'version': 'Wazuh v3.6.2', 'count': 1}, {'version': 'N/A', 'count': 2}]
    ),
    (
            ['os.platform', 'os.major'],
            [{'count': 1, 'os': {'major': '18', 'platform': 'ubuntu'}},
             {'count': 2, 'os': {'major': '16', 'platform': 'ubuntu'}},
             {'count': 2, 'os': {'major': 'N/A', 'platform': 'N/A'}}]
    ),
    (
            ['node_name'],
            [{'node_name': 'unknown', 'count': 2}, {'node_name': 'node01', 'count': 3   }]
    ),
    (
            ['os.name', 'os.platform', 'os.version'],
            [{'count': 1, 'os': {'name': 'Ubuntu', 'platform': 'ubuntu', 'version': '18.08.1 LTS'}},
             {'count': 1, 'os': {'name': 'Ubuntu', 'platform': 'ubuntu', 'version': '16.06.1 LTS'}},
             {'count': 1, 'os': {'name': 'Ubuntu', 'platform': 'ubuntu', 'version': '16.04.1 LTS'}},
             {'count': 2, 'os': {'name': 'N/A', 'platform': 'N/A', 'version': 'N/A'}}]
    ),
])
@patch('wazuh.core.common.CLIENT_KEYS', new=os.path.join(test_agent_path, 'client.keys'))
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
@pytest.mark.skip('Remove tested function or update it to use the indexer.')
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


@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
@pytest.mark.skip('Remove tested function or update it to use the indexer.')
def test_agent_get_agents_summary_status(socket_mock, send_mock):
    """Test `get_agents_summary` function from agent module."""
    summary = get_agents_summary_status(short_agent_list)
    assert isinstance(summary, WazuhResult), 'The returned object is not an "WazuhResult" instance.'
    # Asserts are based on what it should get from the fake database
    expected_results = {'connection': {'active': 2, 'disconnected': 1, 'never_connected': 1, 'pending': 1, 'total': 5},
                        'configuration': {'synced': 2, 'not_synced': 3, 'total': 5}}
    summary_data = summary['data']

    # For the following test cases, if summary_data has unexpected keys, a KeyError will be raised

    # Check the data dictionary follows the expected keys schema
    assert all(summary_data[key].keys() == expected_results[key].keys() for key in expected_results.keys()), \
        'The result obtained has unexpected keys'
    # Check that the agents count for connection and configuration statuses are the expected ones
    assert all(all(summary_data[key][status] == expected_results[key][status] for status in
                   summary_data[key].keys()) for key in expected_results.keys()), \
        'The agents connection or configuration status counts are not the expected ones'


@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
@pytest.mark.skip('Remove tested function or update it to use the indexer.')
def test_agent_get_agents_summary_os(connect_mock, send_mock):
    """Tests `get_os_summary function`."""
    summary = get_agents_summary_os(short_agent_list)
    assert isinstance(summary, AffectedItemsWazuhResult), 'The returned object is not an "WazuhResult" instance.'
    assert summary.affected_items == ['ubuntu'], f"Expected ['ubuntu'] OS but received '{summary['items']} instead."


@pytest.mark.parametrize('agent_list, expected_items, error_code', [
    (['001', '002'], ['001', '002'], None),
    (['001', '500'], ['001'], 1701)
])
@patch('wazuh.core.agent.Agent.reconnect')
@patch('wazuh.agent.get_agents_info', return_value=short_agent_list)
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
@pytest.mark.skip('Remove tested function or update it to use the indexer.')
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


@pytest.mark.parametrize('agent_list, expected_items, fail', [
    (
        ['01928c6a-3069-7056-80d0-eb397a8fec78', '01928c6a-3069-736d-a641-647352e4fd0d'],
        ['01928c6a-3069-7056-80d0-eb397a8fec78', '01928c6a-3069-736d-a641-647352e4fd0d'],
        False
    ),
    (
        [],
        [
            '01928c6a-3069-7056-80d0-eb397a8fec78',
            '01928c6a-3069-736d-a641-647352e4fd0d',
            '01928c6a-3069-719c-a32c-44671da04717'
        ],
        False
    ),
    (
        ['01928c6a-3069-7056-80d0-eb397a8fec78', '01928c6a-3069-736d-a641-647352e4fd0d'],
        ['01928c6a-3069-7056-80d0-eb397a8fec78', '01928c6a-3069-736d-a641-647352e4fd0d'],
        True
    ),
])
@patch('wazuh.core.indexer.create_indexer')
async def test_agent_restart_agents(create_indexer_mock, agent_list, expected_items, fail):
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
    all_agent_ids = [
        '01928c6a-3069-7056-80d0-eb397a8fec78',
        '01928c6a-3069-736d-a641-647352e4fd0d',
        '01928c6a-3069-719c-a32c-44671da04717'
    ]
    agents_search_mock = AsyncMock(return_value=[Agent(id=agent_id) for agent_id in all_agent_ids])
    create_indexer_mock.return_value.agents.search = agents_search_mock

    document_id = 'pBjePGfvgm'
    create_response = CreateCommandResponse(
        index='.commands',
        document_id=document_id,
        result=ResponseResult.INTERNAL_ERROR if fail else ResponseResult.CREATED,
    )

    commands_create_mock = AsyncMock(return_value=create_response)
    create_indexer_mock.return_value.commands_manager.create = commands_create_mock

    result = await restart_agents(agent_list)
    assert isinstance(result, AffectedItemsWazuhResult)
    assert result.total_affected_items == len(expected_items)
    if fail:
        error = str(list(result.failed_items.keys())[0])
        assert error == 'Error 1762 - Error sending command to the commands manager: ' \
            f'{ResponseResult.INTERNAL_ERROR.value}'
        failed_ids = list(result.failed_items.values())[0]
        assert failed_ids == set(expected_items)
    else:
        assert result.affected_items == expected_items


@pytest.mark.parametrize('agent_list, expected_items, error_code', [])
@pytest.mark.skip('We sould review whether to keep this endpoint or not.')
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


@pytest.mark.parametrize(
        'agent_list,expected_items',
        [
            (['019008da'], ['019008da']),
            (['019008da'], []),
            (['019008da', '019008db'], ['019008da']),
            ([], ['019008da']),
            ([], []),
        ]
)
@pytest.mark.parametrize(
    'filters,params', [
        ({}, {'select': 'id', 'limit': 20}),
        ({'older_than': '1d', 'name': 'test'}, {'select': 'id', 'limit': 20}),
        ({'older_than': '1d', 'name': 'test'}, {}),
    ]
)
@patch('wazuh.agent.build_agents_query')
@patch('wazuh.core.indexer.create_indexer')
async def test_agent_get_agents(
    create_indexer_mock, build_agents_query_mock, agent_list, expected_items, filters, params
):
    """Test `get_agents` function from agent module.

    Parameters
    ----------
    agent_list : List of str
        List of agent ID's.
    expected_items : List of str
        List of expected agent ID's returned by 'get_agents'.
    """
    agents_search_mock = AsyncMock(return_value=expected_items)
    create_indexer_mock.return_value.agents.search = agents_search_mock

    result = await get_agents(agent_list, filters=filters, **params)

    build_agents_query_mock.assert_called_once_with(agent_list, filters)
    assert isinstance(result, AffectedItemsWazuhResult), 'The returned object is not an "AffectedItemsWazuhResult".'
    assert len(result.affected_items) == len(expected_items)
    assert (expected_id == agent_id for expected_id, agent_id in zip(expected_items, result.affected_items))


@pytest.mark.asyncio
@pytest.mark.parametrize('group, group_exists, expected_agents', [
    ('default', True, ['0191c7fa-26d5-705f-bc3c-f54810d30d79']),
    ('not_exists_group', False, None)
])
@patch('wazuh.agent.get_groups')
@patch('wazuh.core.indexer.create_indexer')
async def test_agent_get_agents_in_group(create_indexer_mock, mock_get_groups, group, group_exists, expected_agents):
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
    get_group_agents_mock = AsyncMock(return_value=[{'id': '0191c7fa-26d5-705f-bc3c-f54810d30d79'}])
    create_indexer_mock.return_value.agents.get_group_agents = get_group_agents_mock

    if group_exists:
        result = await get_agents_in_group(group_list=[group], select=['id'])
        get_group_agents_mock.assert_called_with(group)
        assert result.affected_items
        assert len(result.affected_items) == len(expected_agents)
        for expected_agent, affected_agent in zip(expected_agents, result.affected_items):
            assert expected_agent == next(iter(affected_agent.values()))
    else:
        # If not `group_exists`, expect an error
        with pytest.raises(WazuhResourceNotFound, match='.* 1710 .*'):
            await get_agents_in_group(group_list=[group])


@pytest.mark.parametrize('agent_list, expected_items', [
    (['001', '002', '003'], ['001', '002', '003']),
    (['001', '400', '002', '500'], ['001', '002'])
])
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
@pytest.mark.skip('Remove tested function or update it to use the indexer.')
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


@pytest.mark.parametrize(
        'agent_list,available_agents,expected_items',
        [
            (['019008da'], ['019008da'], ['019008da']),
            (['019008da'], [], []),
            (['019008da', '019008db'], ['019008da'], ['019008da']),
            ([], ['019008da'], ['019008da']),
            ([], [], []),
        ]
)
@patch('wazuh.core.indexer.create_indexer')
async def test_agent_delete_agents(
    create_indexer_mock, agent_list, available_agents, expected_items
):
    """Test `delete_agents` function from agent module.

    Parameters
    ----------
    agent_list : List of str
        List of agent ID's.
    expected_items : List of str
        List of expected agent ID's returned by
    """
    filters = {}
    agents_search_mock = AsyncMock(return_value=[Agent(id=agent_id) for agent_id in available_agents])
    agents_delete_mock = AsyncMock(return_value=expected_items)

    create_indexer_mock.return_value.agents.search = agents_search_mock
    create_indexer_mock.return_value.agents.delete = agents_delete_mock

    result = await delete_agents(agent_list, filters)

    if agent_list == available_agents:
        agents_delete_mock.assert_called_once_with(agent_list)
    else:
        agents_delete_mock.assert_called_once_with(available_agents)

    agents_search_mock.assert_called_once_with(query=build_agents_query(agent_list, filters))

    assert result.affected_items == expected_items

    if len(agent_list) > 1:
        assert list(result.failed_items.values())[0] == set(agent_list[1:])


@pytest.mark.parametrize('id,name,key,groups,type,version', [
    (
        '019008da-1575-7375-b54f-ef43e393517ef',
        'test',
        '95fffd306c752289d426e66013881538',
        ['group1'],
        'endpoint',
        '5.0.0'
    ),
])
@patch('wazuh.core.indexer.create_indexer')
async def test_agent_add_agent(
    create_indexer_mock,
    name,
    id,
    key,
    groups,
    type,
    version,
):
    """Test `add_agent` from agent module. """
    new_agent = IndexerAgent(
        id=id,
        name=name,
        raw_key=key,
        type=type,
        version=version,
        groups=','.join(groups),
    )
    agents_create_mock = AsyncMock(return_value=new_agent)
    create_indexer_mock.return_value.agents.create = agents_create_mock
    create_response = CreateCommandResponse(index='.commands', document_id='pwrD5Ddf', result=ResponseResult.CREATED)
    commands_create_mock = AsyncMock(return_value=create_response)
    create_indexer_mock.return_value.commands_manager.create = commands_create_mock

    result = await add_agent(
        name=name,
        id=id,
        key=key,
        type=type,
        version=version,
        groups=groups,
        
    )

    assert result.dikt['data'].id == new_agent.id
    assert result.dikt['data'].name == new_agent.name
    assert result.dikt['data'].key == new_agent.key
    assert result.dikt['data'].type == new_agent.type
    assert result.dikt['data'].version == new_agent.version
    assert result.dikt['data'].groups == new_agent.groups


@pytest.mark.parametrize(
    'id,name,key,type,version', [
        ('019008da-1575-7375-b54f-ef43e393517ef', 'test', '95fffd306c752289d426e66013881538', 'endpoint', '5.0.0'),
    ]
)
@patch('wazuh.core.indexer.create_indexer')
async def test_agent_add_agent_ko(create_indexer_mock, name, id, key, type, version):
    """Test `add_agent` from agent module.

    Parameters
    ----------
    id : str
        ID of the agent.
    name : str
        Name of the agent.
    key : str
        The agent key.
    """
    with pytest.raises(WazuhError, match='.* 1738 .*'):
        await add_agent(name=name*128, id=id, key=key, type=type, version=version)



@pytest.mark.parametrize('group_list, q, expected_result', [
    (['group-1', 'group-2'], None, ['group-1', 'group-2']),
    (['invalid_group'], None, []),
    (['group-1', 'group-2'], 'name~1', ['group-1']),
    (['group-1', 'group-2', 'group-3'], None, ['group-1', 'group-2']),
    ([], '', []) # An empty group_list should return nothing
])
@patch('wazuh.core.common.WAZUH_SHARED', new=test_shared_path)
async def test_agent_get_agent_groups(group_list, q, expected_result):
    """Test `get_agent_groups` from agent module.

    This will check if the provided groups exists.

    Parameters
    ----------
    group_list : List of str
        List of groups to check if they exists.
    expected_result : List of str
        List of expected groups to be returned by 'get_agent_groups'.
    """
    group_result = await get_agent_groups(group_list, q=q)
    assert len(group_result.affected_items) == len(expected_result)
    for item, group_name in zip(group_result.affected_items, group_list):
        assert item['name'] == group_name
        assert item['configSum']


@pytest.mark.parametrize('system_groups, error_code', [('invalid_group', 1710)])
@patch('wazuh.agent.get_groups')
async def test_agent_get_agent_groups_exceptions(mock_get_groups, system_groups, error_code):
    """Test that the `get_agent_groups` function raises the expected exceptions if an invalid group is specified."""
    mock_get_groups.return_value = {'valid-group'}
    try:
        group_result = await get_agent_groups(group_list=[system_groups])
        assert group_result.failed_items
        assert next(iter(group_result.failed_items)).code == error_code
    except WazuhException as e:
        assert e.code == error_code, 'The exception was raised as expected but "error_code" does not match.'


@pytest.mark.parametrize('group_id', [
    'non-existent-group',
    'invalid-group'
])
@patch('wazuh.core.common.WAZUH_SHARED', new=test_shared_path)
@patch('wazuh.core.common.wazuh_gid', return_value=getgrnam('root'))
@patch('wazuh.core.common.wazuh_uid', return_value=getpwnam('root'))
@patch('wazuh.agent.chown')
async def test_create_group(chown_mock, uid_mock, gid_mock, group_id):
    """Test `create_group` function from agent module.

    When a group is created a folder with the same name is created in `common.WAZUH_SHARED`.

    Parameters
    ----------
    group_id : str
        Name of the group to be created.
    """
    expected_msg = f"Group '{group_id}' created."
    path_to_group = os.path.join(test_shared_path, f'{group_id}.conf')
    try:
        result = await create_group(group_id)
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
        # Remove the new file to avoid affecting other tests
        if os.path.exists(path_to_group):
            os.remove(path_to_group)


@pytest.mark.parametrize('group_id, exception, exception_code', [
    ('default', WazuhError, 1711),
    ('group-1.conf', WazuhError, 1722),
    ('invalid!', WazuhError, 1722),
    ('delete-me', WazuhInternalError, 1005),
    ('agent-template', WazuhError, 1713)
])
@patch('wazuh.core.common.WAZUH_SHARED', new=test_shared_path)
async def test_create_group_exceptions(group_id, exception, exception_code):
    """Test `create_group` function from agent module raises the expected exceptions if an invalid `group_id` is
    specified.

    Parameters
    ----------
    group_id : str
        The invalid group id to use.
    exception : Exception
        The expected exception to be raised by `create_group`.
    exception_code : int
        Expected error code for the Wazuh Exception object raised by `create_group` with the given parameters.
    """
    try:
        await create_group(group_id)
    except exception as e:
        assert e.code == exception_code
    finally:
        # Remove the new group file to avoid affecting the next tests
        path = os.path.join(test_shared_path, f'{group_id}.conf')
        if os.path.exists(path) and group_id != 'agent-template':
            os.remove(path)


@pytest.mark.asyncio
@pytest.mark.parametrize('group_list', [
    ['group-1'],
    ['group-1', 'group-2']
])
@patch('wazuh.agent.get_groups')
@patch('wazuh.agent.Agent.delete_single_group')
@patch('wazuh.core.indexer.create_indexer')
async def test_agent_delete_groups(create_indexer_mock, mock_delete, mock_get_groups, group_list):
    """Test `delete_groups` function from agent module.

    Parameters
    ----------
    group_list : List of str
        List of groups to be deleted.
    """

    def groups():
        return set(group_list)

    mock_get_groups.side_effect = groups
    result = await delete_groups(group_list)
    # Check typing
    assert isinstance(result, AffectedItemsWazuhResult), 'The returned object is not an "AffectedItemsWazuhResult".'
    assert isinstance(result.affected_items, list)
    # Check affected items
    assert result.total_affected_items == len(result.affected_items)
    assert result.affected_items == group_list

    mock_delete.assert_has_calls([call(group) for group in group_list])

    # Check failed items
    assert result.total_failed_items == 0


@pytest.mark.asyncio
@pytest.mark.parametrize('group_list, expected_errors', [
    (['none-1'], [WazuhResourceNotFound(1710)]),
    (['default'], [WazuhError(1712)]),
    (['none-1', 'none-2'], [WazuhResourceNotFound(1710)]),
    (['default', 'none-1'], [WazuhError(1712), WazuhResourceNotFound(1710)]),
])
@patch('wazuh.agent.get_groups')
async def test_agent_delete_groups_other_exceptions(mock_get_groups, group_list, expected_errors):
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
    result = await delete_groups(group_list)
    assert isinstance(result, AffectedItemsWazuhResult), 'The returned object is not an "AffectedItemsWazuhResult".'
    assert isinstance(result.failed_items, dict)
    # Check failed items
    assert result.total_failed_items == len(group_list)
    assert len(result.failed_items.keys()) == len(expected_errors)
    assert set(result.failed_items.keys()).difference(set(expected_errors)) == set()


@pytest.mark.asyncio
@pytest.mark.parametrize('group_list, agent_list', [
    (['group-1'], ['0191c87f-a892-78b1-8452-8180e261075c'])
])
@patch('wazuh.core.agent.Agent.get')
@patch('wazuh.core.agent.Agent.unset_single_group_agent')
@patch('wazuh.agent.get_groups', return_value={'group-1'})
@patch('wazuh.core.indexer.create_indexer')
async def test_agent_remove_agent_from_groups(create_indexer_mock, mock_get_groups, mock_get_agent, mock_unset,
                                              group_list, agent_list):
    """Test `remove_agent_from_groups` function from agent module.

    Parameters
    ----------
    group_list : List of str
        List of group names from where the agents will be removed.
    agent_list : List of str
        List of agent ID's.
    """
    create_response = CreateCommandResponse(index='.commands', document_id='pwrD5Ddf', result=ResponseResult.CREATED)
    commands_create_mock = AsyncMock(return_value=create_response)
    create_indexer_mock.return_value.commands_manager.create = commands_create_mock

    result = await remove_agent_from_groups(agent_list=agent_list, group_list=group_list)
    # Check typing
    assert isinstance(result, AffectedItemsWazuhResult)
    assert isinstance(result.affected_items, list)
    # Check affected items
    assert result.total_affected_items == len(result.affected_items)
    assert set(result.affected_items).difference(set(group_list)) == set(), f'received: {result.affected_items}'
    # Check failed items
    assert result.total_failed_items == 0


@pytest.mark.asyncio
@pytest.mark.parametrize('group_list, agent_list, expected_error, catch_exception', [
    (['any-group'], ['0191c87f-a892-78b1-8452-8180e261075c'], WazuhResourceNotFound(1701), True),
    (['any-group'], ['0191c87f-a892-77a3-a988-b73fc8164c32'], WazuhResourceNotFound(1710), False),
])
@patch('wazuh.core.agent.Agent.unset_single_group_agent')
@patch('wazuh.core.agent.Agent.get', return_value='0191c87f-a892-78b1-8452-8180e261075c')
@patch('wazuh.agent.get_groups', return_value={'group-1'})
@patch('wazuh.core.indexer.create_indexer')
async def test_agent_remove_agent_from_groups_exceptions(create_indexer_mock, mock_get_groups, mock_get_agent,
                                                         mock_unset, group_list, agent_list, expected_error,
                                                         catch_exception):
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
    create_response = CreateCommandResponse(index='.commands', document_id='pwrD5Ddf', result=ResponseResult.CREATED)
    commands_create_mock = AsyncMock(return_value=create_response)
    create_indexer_mock.return_value.commands_manager.create = commands_create_mock

    try:
        with patch('wazuh.core.agent.Agent.get',
            return_value='0191c87f-a892-78b1-8452-8180e261075c',
            side_effect=expected_error if catch_exception else None
        ):
            result = await remove_agent_from_groups(group_list=group_list, agent_list=agent_list)

        assert not catch_exception, \
            'An "WazuhError" exception was expected but was not raised.'
        # Check Typing
        assert isinstance(result, AffectedItemsWazuhResult)
        assert isinstance(result.failed_items, dict)
        # Check Failed Items
        assert result.total_failed_items == len(group_list)
        assert result.total_failed_items == len(result.failed_items)
        assert set(result.failed_items.keys()).difference({expected_error}) == set()
    except (WazuhError, WazuhResourceNotFound) as error:
        assert catch_exception, \
            'No exception should be raised at this point. An AffectedItemsWazuhResult object with at least one ' \
            'failed item was expected instead.'
        assert error == expected_error


@pytest.mark.asyncio
@pytest.mark.parametrize('group_list, agent_list', [
    (['group-1'], ['0191c7fa-26d5-705f-bc3c-f54810d30d79'])
])
@patch('wazuh.core.agent.Agent.unset_single_group_agent')
@patch('wazuh.core.indexer.create_indexer')
@patch('wazuh.agent.get_groups', return_value={'group-1'})
async def test_agent_remove_agents_from_group(mock_get_groups, create_indexer_mock, mock_unset, group_list, agent_list):
    """Test `remove_agents_from_group` function from agent module.

    Parameters
    ----------
    group_list : List of str
        List of group names from where the agents will be removed. The list must contain only one group name.
    agent_list : List of str
        List of agent ID's.
    """
    search_mock = AsyncMock(return_value=[IndexerAgent(id='0191c7fa-26d5-705f-bc3c-f54810d30d79')])
    create_indexer_mock.return_value.agents.search = search_mock

    create_response = CreateCommandResponse(index='.commands', document_id='pwrD5Ddf', result=ResponseResult.CREATED)
    commands_create_mock = AsyncMock(return_value=create_response)
    create_indexer_mock.return_value.commands_manager.create = commands_create_mock

    result = await remove_agents_from_group(agent_list=agent_list, group_list=group_list)
    # Check typing
    assert isinstance(result, AffectedItemsWazuhResult)
    assert isinstance(result.affected_items, list)
    # Check affected items
    assert result.total_affected_items == len(result.affected_items)
    assert set(result.affected_items).difference(set(agent_list)) == set()
    # Check failed items
    assert result.total_failed_items == 0


@pytest.mark.asyncio
@pytest.mark.parametrize('group_list, agent_list, expected_error, catch_exception', [
    (['group-1'], ['0191c7fa-26d5-705f-bc3c-f54810d30d79'], WazuhResourceNotFound(1701), False),
])
@patch('wazuh.core.indexer.create_indexer')
@patch('wazuh.agent.get_groups', return_value={'group-1'})
async def test_agent_remove_agents_from_group_exceptions(group_mock, create_indexer_mock, group_list, agent_list,
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
@pytest.mark.skip('Remove tested function or update it to use the indexer.')
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
            {'001', '002', '003', '004', '999'},
            {'1701': {'999'}, '1822': {'002'}, '1707': {'003', '004'}},
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
            {'001', '002'},
            {'1731': {'001', '002'}},
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
@pytest.mark.skip('Remove tested function or update it to use the indexer.')
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
                elif int(error) not in (ERROR_CODES_UPGRADE_SOCKET + [1701, 1707, 1731]):
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
            {'001', '002', '003', '006', '999'},
            {'1701': {'999'}, '1707': {'003'}, '1813': {'006'}},
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
            {'001', '002'},
            {'1731': {'001', '002'}},
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
@pytest.mark.skip('Remove tested function or update it to use the indexer.')
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


@pytest.mark.parametrize('group_list', [
    ['group-1']
])
@patch('wazuh.core.common.WAZUH_SHARED', new=test_shared_path)
async def test_agent_get_group_conf(group_list):
    """Test `get_group_conf` function from agent module.

    Parameters
    ----------
    group_list : List of str
        List of group names.
    """
    result = await get_group_conf(group_list=group_list)
    assert isinstance(result, WazuhResult), 'The returned object is not an "WazuhResult" instance.'
    assert 'total_affected_items' in result.dikt['data']
    assert result.dikt['data']['total_affected_items'] == 1


@pytest.mark.parametrize('group_list', [
    ['update']
])
@patch('wazuh.core.common.WAZUH_SHARED', new=test_shared_path)
@patch('wazuh.core.configuration.update_group_configuration')
async def test_agent_upload_group_file(mock_update, group_list):
    """Test `upload_group_file` function from agent module.

    Parameters
    ----------
    group_list : List of str
        List of group names.
    """
    expected_msg = 'Agent configuration was successfully updated'
    mock_update.return_value = expected_msg
    result = await update_group_file(group_list=group_list, file_data="sample")
    assert isinstance(result, WazuhResult), 'The returned object is not an "WazuhResult" instance.'
    assert 'message' in result.dikt
    assert result.dikt['message'] == expected_msg


@pytest.mark.parametrize('agent_list, group_list, index_error, last_agent', [
    (['001'], ['group-2'], False, '001'),
    (['001', '002'], ['group-2', 'group-1'], False, '002'),
    (['001', '002', '003'], ['group-2', 'group-1'], False, '002'),
    (full_agent_list, ['group-1'], False, '004'),
    (full_agent_list, ['group-1'], True, None)
])
@patch('wazuh.core.common.WAZUH_SHARED', new=test_shared_path)
@patch('wazuh.agent.get_distinct_agents')
@patch('wazuh.agent.get_agent_groups')
@patch('wazuh.agent.get_agents_summary_status')
@patch('wazuh.agent.get_agents')
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
@pytest.mark.skip('Define if we will keep this function')
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

    def mocked_get_distinct_agents(fields):
        return get_distinct_agents(agent_list=agent_list, fields=fields)

    def mocked_get_agent_groups():
        return get_agent_groups(group_list=group_list)

    def mocked_get_agents_summary_status():
        return get_agents_summary_status(agent_list=agent_list)

    def mocked_get_agents(limit, sort):
        if index_error:
            raise IndexError()
        else:
            return get_agents(agent_list=agent_list, limit=limit, sort=sort)

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
    (range(1, 500), {}, range(1, 500)),
    (range(1, 1000), {}, range(1, 501)),
    (range(1000, 2000), {}, range(1000, 1500)),
    (range(1, 100000), {'limit': 1000}, range(1, 1001)),
    (range(1, 100000), {'offset': 50000}, range(50000, 50501)),
    (range(1, 1000), {'limit': 100, 'offset': 500}, range(500, 601)),
    (range(1, 100000), {'limit': 1000, 'offset': 80000}, range(80000, 81001)),
])
@patch('wazuh.agent.get_agents_info', return_value=['test', 'test2'])
@patch('wazuh.core.wdb.WazuhDBConnection._send', side_effect=send_msg_to_wdb)
@patch('socket.socket.connect')
@pytest.mark.skip('Define if we will keep this function')
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

    with patch('wazuh.agent.get_agents_info', return_value=set(agent_ids_format(range(1, 100000)))):
        result = get_agents(agent_list=agent_ids_format(agent_list), **params).render()
        expected_ids = agent_ids_format(expected_ids)
        for item in result['data']['affected_items']:
            assert item['id'] in expected_ids, f'Received ID {item["id"]} is not within expected IDs {expected_ids}.'


@pytest.mark.asyncio
@pytest.mark.parametrize('agent_groups, agent_id, group_id', [
    (['dmz'], '005', 'dmz'),
    (['dmz', 'webserver'], '005', 'dmz'),
    (['dmz', 'webserver', 'database'], '005', 'dmz')
])
@patch('wazuh.core.agent.Agent.get_agent_groups', new_callable=AsyncMock)
@patch('wazuh.core.agent.Agent.set_agent_group_relationship', new_callable=AsyncMock)
@patch('wazuh.core.agent.Agent.set_agent_group_file')
@patch('wazuh.core.agent.Agent')
async def test_unset_single_group_agent(agent_patch, set_agent_group_patch, set_relationship_mock, get_groups_patch,
                                        agent_groups, agent_id, group_id):
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

    assert ret_msg == f"Agent '{agent_id}' removed from '{group_id}'."


@pytest.mark.asyncio
@pytest.mark.parametrize('agent_id, group_id, force, expected_exc', [
    ('0191c87f-a892-77b4-b53f-d5a3ad313665', 'whatever', False, 1710),
    ('0191c87f-a892-77b4-b53f-d5a3ad313665', 'not_exists', True, 1734),
    ('0191c87f-a892-77b4-b53f-d5a3ad313665', 'default', True, 1745),
])
@patch('wazuh.core.agent.Agent.get_agent_groups', return_value=['default'])
@patch('wazuh.core.agent.Agent.group_exists', return_value=False)
@patch('wazuh.core.indexer.create_indexer')
async def test_unset_single_group_agent_ko(create_indexer_mock, group_exists_mock, get_groups_mock, agent_id, group_id,
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
    with pytest.raises(WazuhException, match=f".* {expected_exc} .*"):
        await Agent.unset_single_group_agent(agent_id, group_id, force=force)

@pytest.mark.parametrize(
    'agent_list,filters,expected_filters',
    [
        (
            ['019008da-1575-7375-b54f-ef43e393517ef'],
            {'last_login': '1d', 'name': 'test'},
            [
                {IndexerKey.TERMS: {IndexerKey._ID: ['019008da-1575-7375-b54f-ef43e393517ef']}},
                {IndexerKey.RANGE: {'last_login': {IndexerKey.LTE: 'now-1d'}}},
                {IndexerKey.TERM: {'name': 'test'}}
            ]
        ),
        (
            ['019008da-1575-7375-b54f-ef43e393517ef'],
            {'name': None, 'last_login': None, 'host.ip': '127.0.0.1'},
            [
                {IndexerKey.TERMS: {IndexerKey._ID: ['019008da-1575-7375-b54f-ef43e393517ef']}},
                {IndexerKey.TERM: {'host.ip': '127.0.0.1'}}
            ]
        ),
        (
            [],
            {'is_connected': True, 'host.os.full': 'Ubuntu 24.04'},
            [
                {IndexerKey.TERM: {'is_connected': True}},
                {IndexerKey.TERM: {'host.os.full': 'Ubuntu 24.04'}}
            ]
        )
    ]
)
def test_build_agents_query(agent_list, filters, expected_filters):
    """Test `build_agents_query` function from agent module works as expected.

    Parameters
    ----------
    agent_list : list
        Agents id.
    filters : dict
        Filters to parse.
    expected_filters : dict
        Expected query.
    """
    query = build_agents_query(agent_list, filters)

    assert IndexerKey.QUERY in query
    assert IndexerKey.BOOL in query[IndexerKey.QUERY]
    assert query[IndexerKey.QUERY][IndexerKey.BOOL][IndexerKey.FILTER] == expected_filters

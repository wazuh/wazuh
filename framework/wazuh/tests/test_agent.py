#!/usr/bin/env python
# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sys
from grp import getgrnam
from pwd import getpwnam
from unittest.mock import AsyncMock, call, patch

import pytest
from wazuh.core.config.client import CentralizedConfig
from wazuh.core.config.models.base import ValidateFilePathMixin
from wazuh.tests.util import get_default_configuration

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../..'))

with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
        with patch.object(ValidateFilePathMixin, '_validate_file_path', return_value=None):
            default_config = get_default_configuration()
            CentralizedConfig._config = default_config

            import wazuh.rbac.decorators
            from wazuh.tests.util import RBAC_bypasser

            wazuh.rbac.decorators.expose_resources = RBAC_bypasser

        from wazuh import WazuhError, WazuhException, WazuhInternalError
        from wazuh.agent import (
            add_agent,
            build_agents_query,
            create_group,
            delete_agents,
            delete_groups,
            get_agent_groups,
            get_agents,
            get_agents_in_group,
            get_group_conf,
            reconnect_agents,
            remove_agents_from_group,
            restart_agents,
            update_group_file,
        )
        from wazuh.core.exception import WazuhResourceNotFound
        from wazuh.core.indexer.base import IndexerKey
        from wazuh.core.indexer.commands import CommandsManager
        from wazuh.core.indexer.models.agent import Agent as IndexerAgent
        from wazuh.core.indexer.models.commands import CreateCommandResponse, ResponseResult
        from wazuh.core.results import AffectedItemsWazuhResult, WazuhResult
        from wazuh.core.utils import GROUP_FILE_EXT

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
test_agent_path = os.path.join(test_data_path, 'agent')
test_groups_path = os.path.join(test_agent_path, 'groups')
test_global_bd_path = os.path.join(test_data_path, 'global.db')

full_agent_list = ['001', '002', '003', '004', '005', '006', '007', '008', '009']
short_agent_list = ['001', '002', '003', '004', '005']


@pytest.mark.parametrize(
    'agent_list, expected_items, error_code', [(['001', '002'], ['001', '002'], None), (['001', '500'], ['001'], 1701)]
)
@patch('wazuh.core.agent.Agent.reconnect')
@patch('wazuh.agent.get_agents_info', return_value=short_agent_list)
@patch('socket.socket.connect')
@pytest.mark.skip('Remove tested function or update it to use the indexer.')
def test_agent_reconnect_agents(
    socket_mock, send_mock, agents_info_mock, reconnect_mock, agent_list, expected_items, error_code
):
    """Test `reconnect_agents` function from agent module."""
    result = reconnect_agents(agent_list)
    assert isinstance(result, AffectedItemsWazuhResult), 'The returned object is not an "AffectedItemsWazuhResult".'
    assert result.affected_items == expected_items, f'"Affected_items" does not match. Should be "{expected_items}".'
    if result.failed_items:
        code = next(iter(result.failed_items.keys())).code
        assert code == error_code, f'"{error_code}" code was expected but "{code}" was received.'


@pytest.mark.parametrize(
    'agent_list, expected_items, fail',
    [
        (
            ['01928c6a-3069-7056-80d0-eb397a8fec78', '01928c6a-3069-736d-a641-647352e4fd0d'],
            ['01928c6a-3069-7056-80d0-eb397a8fec78', '01928c6a-3069-736d-a641-647352e4fd0d'],
            False,
        ),
        (
            [],
            [
                '01928c6a-3069-7056-80d0-eb397a8fec78',
                '01928c6a-3069-736d-a641-647352e4fd0d',
                '01928c6a-3069-719c-a32c-44671da04717',
            ],
            False,
        ),
        (
            ['01928c6a-3069-7056-80d0-eb397a8fec78', '01928c6a-3069-736d-a641-647352e4fd0d'],
            ['01928c6a-3069-7056-80d0-eb397a8fec78', '01928c6a-3069-736d-a641-647352e4fd0d'],
            True,
        ),
    ],
)
@patch('wazuh.core.indexer.create_indexer')
async def test_agent_restart_agents(create_indexer_mock, agent_list, expected_items, fail):
    """Test `restart_agents` function from agent module."""
    all_agent_ids = [
        '01928c6a-3069-7056-80d0-eb397a8fec78',
        '01928c6a-3069-736d-a641-647352e4fd0d',
        '01928c6a-3069-719c-a32c-44671da04717',
    ]
    agents_search_mock = AsyncMock(return_value=[IndexerAgent(id=agent_id) for agent_id in all_agent_ids])
    create_indexer_mock.return_value.agents.search = agents_search_mock

    create_response = CreateCommandResponse(
        index=CommandsManager.INDEX,
        document_ids=['pBjePGfvgm'],
        result=ResponseResult.INTERNAL_ERROR if fail else ResponseResult.CREATED,
    )

    commands_create_mock = AsyncMock(return_value=create_response)
    create_indexer_mock.return_value.commands_manager.create = commands_create_mock

    result = await restart_agents(agent_list)
    assert isinstance(result, AffectedItemsWazuhResult)
    assert result.total_affected_items == len(expected_items)
    if fail:
        error = str(list(result.failed_items.keys())[0])
        assert (
            error == 'Error 1762 - Error sending command to the commands manager: '
            f'{ResponseResult.INTERNAL_ERROR.value}'
        )
        failed_ids = list(result.failed_items.values())[0]
        assert failed_ids == set(expected_items)
    else:
        assert result.affected_items == expected_items


@pytest.mark.parametrize(
    'agent_list,expected_items',
    [
        (['019008da'], ['019008da']),
        (['019008da'], []),
        (['019008da', '019008db'], ['019008da']),
        ([], ['019008da']),
        ([], []),
    ],
)
@pytest.mark.parametrize(
    'filters,params',
    [
        ({}, {'select': 'id', 'limit': 20}),
        ({'older_than': '1d', 'name': 'test'}, {'select': 'id', 'limit': 20}),
        ({'older_than': '1d', 'name': 'test'}, {}),
    ],
)
@patch('wazuh.agent.build_agents_query')
@patch('wazuh.core.indexer.create_indexer')
async def test_agent_get_agents(
    create_indexer_mock, build_agents_query_mock, agent_list, expected_items, filters, params
):
    """Test `get_agents` function from agent module."""
    agents_search_mock = AsyncMock(return_value=expected_items)
    create_indexer_mock.return_value.agents.search = agents_search_mock

    result = await get_agents(agent_list, filters=filters, **params)

    build_agents_query_mock.assert_called_once_with(agent_list, filters)
    assert isinstance(result, AffectedItemsWazuhResult), 'The returned object is not an "AffectedItemsWazuhResult".'
    assert len(result.affected_items) == len(expected_items)
    assert (expected_id == agent_id for expected_id, agent_id in zip(expected_items, result.affected_items))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'group, group_exists, expected_agents',
    [('default', True, ['0191c7fa-26d5-705f-bc3c-f54810d30d79']), ('not_exists_group', False, None)],
)
@patch('wazuh.agent.get_groups')
@patch('wazuh.core.indexer.create_indexer')
async def test_agent_get_agents_in_group(create_indexer_mock, mock_get_groups, group, group_exists, expected_agents):
    """Test `get_agents_in_group` from agent module."""
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


@pytest.mark.parametrize(
    'agent_list,available_agents,expected_items',
    [
        (['019008da'], ['019008da'], ['019008da']),
        (['019008da'], [], []),
        (['019008da', '019008db'], ['019008da'], ['019008da']),
        ([], ['019008da'], ['019008da']),
        ([], [], []),
    ],
)
@patch('wazuh.core.indexer.create_indexer')
async def test_agent_delete_agents(create_indexer_mock, agent_list, available_agents, expected_items):
    """Test `delete_agents` function from agent module."""
    filters = {}
    agents_search_mock = AsyncMock(return_value=[IndexerAgent(id=agent_id) for agent_id in available_agents])
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


@pytest.mark.parametrize(
    'id,name,key,type,version',
    [
        ('019008da-1575-7375-b54f-ef43e393517ef', 'test', '95fffd306c752289d426e66013881538', 'endpoint', '5.0.0'),
    ],
)
@patch('wazuh.core.indexer.create_indexer')
@patch('wazuh.core.agent.group_exists', return_value=True)
async def test_agent_add_agent(
    mock_group_exists,
    create_indexer_mock,
    id,
    name,
    key,
    type,
    version,
):
    """Test `add_agent` from agent module."""
    new_agent = IndexerAgent(
        id=id,
        name=name,
        raw_key=key,
        type=type,
        version=version,
    )
    agents_create_mock = AsyncMock(return_value=new_agent)
    create_indexer_mock.return_value.agents.create = agents_create_mock

    result = await add_agent(
        name=name,
        id=id,
        key=key,
        type=type,
        version=version,
    )

    assert result.dikt['data'].id == new_agent.id
    assert result.dikt['data'].name == new_agent.name
    assert result.dikt['data'].key == new_agent.key
    assert result.dikt['data'].type == new_agent.type
    assert result.dikt['data'].version == new_agent.version


@pytest.mark.parametrize(
    'id,name,key,type,version',
    [
        ('019008da-1575-7375-b54f-ef43e393517ef', 'test', '95fffd306c752289d426e66013881538', 'endpoint', '5.0.0'),
    ],
)
@patch('wazuh.core.indexer.create_indexer')
@patch('wazuh.core.agent.group_exists', return_value=True)
async def test_agent_add_agent_ko(mock_group_exists, create_indexer_mock, name, id, key, type, version):
    """Test `add_agent` from agent module."""
    with pytest.raises(WazuhError, match='.* 1738 .*'):
        await add_agent(name=name * 128, id=id, key=key, type=type, version=version)


@pytest.mark.parametrize(
    'group_list, q, expected_result',
    [
        (['group-1', 'group-2'], None, ['group-1', 'group-2']),
        (['invalid_group'], None, []),
        (['group-1', 'group-2'], 'name~1', ['group-1']),
        (['group-1', 'group-2', 'group-3'], None, ['group-1', 'group-2']),
        ([], '', []),  # An empty group_list should return nothing
    ],
)
@patch('wazuh.core.common.WAZUH_GROUPS', new=test_groups_path)
async def test_agent_get_agent_groups(group_list, q, expected_result):
    """Test `get_agent_groups` from agent module."""
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


@pytest.mark.parametrize('group_id', ['non-existent-group', 'invalid-group'])
@patch('wazuh.core.common.WAZUH_GROUPS', new=test_groups_path)
@patch('wazuh.core.common.wazuh_gid', return_value=getgrnam('root'))
@patch('wazuh.core.common.wazuh_uid', return_value=getpwnam('root'))
@patch('wazuh.agent.chown')
async def test_create_group(chown_mock, uid_mock, gid_mock, group_id):
    """Test `create_group` function from agent module."""
    expected_msg = f"Group '{group_id}' created."
    path_to_group = os.path.join(test_groups_path, f'{group_id}{GROUP_FILE_EXT}')
    try:
        result = await create_group(group_id)
        assert isinstance(result, WazuhResult), 'The returned object is not an "WazuhResult" instance.'
        assert len(result.dikt) == 1, (
            f'Result dikt length is "{len(result.dikt)}" instead of "1". Result dikt content is: {result.dikt}'
        )
        assert result.dikt['message'] == expected_msg, (
            f'The "result.dikt[\'message\']" received is not the expected.\n'
            f'Expected: "{expected_msg}"\n'
            f'Received: "{result.dikt["message"]}"'
        )
        assert os.path.exists(path_to_group), (
            f'The path "{path_to_group}" does not exists and should be created by "create_group" function.'
        )
    finally:
        # Remove the new file to avoid affecting other tests
        if os.path.exists(path_to_group):
            os.remove(path_to_group)


@pytest.mark.parametrize(
    'group_id, exception, exception_code',
    [
        ('default', WazuhError, 1711),
        (f'group-1{GROUP_FILE_EXT}', WazuhError, 1722),
        ('invalid!', WazuhError, 1722),
        ('delete-me', WazuhInternalError, 1005),
        ('agent-template', WazuhError, 1713),
    ],
)
@patch('wazuh.core.common.WAZUH_GROUPS', new=test_groups_path)
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
        path = os.path.join(test_groups_path, f'{group_id}{GROUP_FILE_EXT}')
        if os.path.exists(path) and group_id != 'agent-template':
            os.remove(path)


@pytest.mark.asyncio
@pytest.mark.parametrize('group_list', [['group-1'], ['group-1', 'group-2']])
@patch('wazuh.agent.get_groups')
@patch('wazuh.agent.delete_single_group')
@patch('wazuh.core.indexer.create_indexer')
async def test_agent_delete_groups(create_indexer_mock, mock_delete, mock_get_groups, group_list):
    """Test `delete_groups` function from agent module."""

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
@pytest.mark.parametrize(
    'group_list, expected_errors',
    [
        (['none-1'], [WazuhResourceNotFound(1710)]),
        (['default'], [WazuhError(1712)]),
        (['none-1', 'none-2'], [WazuhResourceNotFound(1710)]),
        (['default', 'none-1'], [WazuhError(1712), WazuhResourceNotFound(1710)]),
    ],
)
@patch('wazuh.agent.get_groups')
async def test_agent_delete_groups_other_exceptions(mock_get_groups, group_list, expected_errors):
    """Test `delete_groups` function from agent module returns the expected exceptions when using invalid group
    lists.
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
@pytest.mark.parametrize('group_list, agent_list', [(['group-1'], ['0191c7fa-26d5-705f-bc3c-f54810d30d79'])])
@patch('wazuh.core.indexer.create_indexer')
@patch('wazuh.agent.get_groups', return_value={'group-1'})
async def test_agent_remove_agents_from_group(mock_get_groups, create_indexer_mock, group_list, agent_list):
    """Test `remove_agents_from_group` function from agent module."""
    search_mock = AsyncMock(return_value=[IndexerAgent(id='0191c7fa-26d5-705f-bc3c-f54810d30d79')])
    create_indexer_mock.return_value.agents.search = search_mock

    create_response = CreateCommandResponse(
        index=CommandsManager.INDEX, document_ids=['pwrD5Ddf'], result=ResponseResult.CREATED
    )
    commands_create_mock = AsyncMock(return_value=create_response)
    create_indexer_mock.return_value.commands_manager.create = commands_create_mock

    result = await remove_agents_from_group(agent_list=agent_list, group_list=group_list)
    # Check typing
    assert isinstance(result, AffectedItemsWazuhResult)
    assert isinstance(result.affected_items, list)
    # Check affected items
    assert result.total_affected_items == len(result.affected_items)
    assert set(result.affected_items).difference(set(agent_list)) == set()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'group_list, agent_list, expected_error, catch_exception',
    [
        (['group-1'], ['0191c7fa-26d5-705f-bc3c-f54810d30d79'], WazuhResourceNotFound(1701), False),
    ],
)
@patch('wazuh.core.indexer.create_indexer')
@patch('wazuh.agent.get_groups', return_value={'group-1'})
async def test_agent_remove_agents_from_group_exceptions(
    group_mock, create_indexer_mock, group_list, agent_list, expected_error, catch_exception
):
    """Test `remove_agents_from_group` function from agent module raises the expected exceptions when using invalid
    parameters.
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


@pytest.mark.parametrize('group_list', [['group-1']])
@patch('wazuh.core.common.WAZUH_GROUPS', new=test_groups_path)
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


@pytest.mark.parametrize('group_list', [['update']])
@patch('wazuh.core.common.WAZUH_GROUPS', new=test_groups_path)
@patch('wazuh.core.configuration.update_group_configuration')
async def test_agent_update_group_file(mock_update, group_list):
    """Test `update_group_file` function from agent module."""
    expected_msg = 'Agent configuration was successfully updated'
    mock_update.return_value = expected_msg
    result = await update_group_file(group_list=group_list, file_data='sample')
    assert isinstance(result, WazuhResult), 'The returned object is not an "WazuhResult" instance.'
    assert 'message' in result.dikt
    assert result.dikt['message'] == expected_msg


@pytest.mark.parametrize(
    'agent_list,filters,expected_filters',
    [
        (
            ['019008da-1575-7375-b54f-ef43e393517ef'],
            {'last_login': '1d', 'name': 'test'},
            [
                {IndexerKey.TERMS: {IndexerKey._ID: ['019008da-1575-7375-b54f-ef43e393517ef']}},
                {IndexerKey.RANGE: {'last_login': {IndexerKey.LTE: 'now-1d'}}},
                {IndexerKey.TERM: {'name': 'test'}},
            ],
        ),
        (
            ['019008da-1575-7375-b54f-ef43e393517ef'],
            {'name': None, 'last_login': None, 'host.ip': '127.0.0.1'},
            [
                {IndexerKey.TERMS: {IndexerKey._ID: ['019008da-1575-7375-b54f-ef43e393517ef']}},
                {IndexerKey.TERM: {'host.ip': '127.0.0.1'}},
            ],
        ),
        (
            [],
            {'is_connected': True, 'host.os.full': 'Ubuntu 24.04'},
            [{IndexerKey.TERM: {'is_connected': True}}, {IndexerKey.TERM: {'host.os.full': 'Ubuntu 24.04'}}],
        ),
    ],
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

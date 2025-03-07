#!/usr/bin/env python
# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
from shutil import rmtree
from unittest.mock import AsyncMock, patch

import pytest
from wazuh.core.cluster.tests.conftest import get_default_configuration
from wazuh.core.config.client import CentralizedConfig

with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
        default_config = get_default_configuration()
        CentralizedConfig._config = default_config

        from wazuh.core.agent import (
            delete_single_group,
            expand_group,
            get_agents_info,
            get_group_file_path,
            get_groups,
            get_rbac_filters,
            group_exists,
        )
        from wazuh.core.common import reset_context_cache
        from wazuh.core.exception import WazuhError
        from wazuh.core.indexer.agent import Agent as IndexerAgent

# all necessary params

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data', 'test_agent')


@pytest.mark.asyncio
@patch('wazuh.core.agent.remove')
@patch('wazuh.core.agent.path.exists', return_value=True)
@patch('wazuh.core.common.WAZUH_GROUPS', new=os.path.join(test_data_path, 'etc', 'groups'))
@patch('wazuh.core.indexer.Indexer._get_opensearch_client')
@patch('wazuh.core.indexer.Indexer.connect')
@patch('wazuh.core.indexer.Indexer.close')
@patch('wazuh.core.indexer.agent.AgentsIndex.delete_group')
async def test_agent_delete_single_group(
    delete_group_mock, get_os_client_mock, connect_mock, close_mock, mock_exists, mock_remove
):
    """Validate that the method `delete_single_group` works as expected."""
    group = 'test_group'

    result = await delete_single_group(group)
    assert isinstance(result, dict), 'Result is not a dict'
    assert result['message'] == f"Group '{group}' deleted.", 'Not expected message'
    mock_remove.assert_called_once_with(get_group_file_path(group))


@pytest.mark.parametrize(
    'group_exists',
    [
        True,
        False,
    ],
)
def test_agent_group_exists(group_exists):
    """Test if group_exists() returns True when time from last connection is greater than <seconds>.

    Parameters
    ----------
    group_exists : bool
        Expected result
    """
    with patch('os.path.exists', return_value=group_exists):
        result = group_exists('default')
        assert result == group_exists, f'Group exists should return {group_exists}'


def test_agent_group_exists_ko():
    """Test if group_exists() raises exception when the name isn't valid."""
    with pytest.raises(WazuhError, match='.* 1722 .*'):
        group_exists('default**')


@patch('wazuh.core.indexer.create_indexer')
async def test_get_agents_info(create_indexer_mock):
    """Test that get_agents_info() returns expected agent IDs."""
    with patch.object(CentralizedConfig, 'load', return_value=None):
        CentralizedConfig._config = default_config
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
    """Test that get_groups() returns expected agent groups."""
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


@pytest.mark.parametrize(
    'group, group_agents, expected_agents',
    [
        ('default', [IndexerAgent(id='001'), IndexerAgent(id='002')], {'001', '002'}),
        ('test_group', [IndexerAgent(id='005')], {'005'}),
        ('*', [], {'001', '002', '003', '004', '005'}),
    ],
)
@patch('wazuh.core.indexer.create_indexer')
async def test_expand_group(create_indexer_mock, group, group_agents, expected_agents):
    """Test that expand_group() returns expected agent IDs."""
    # Clear get_agents_info cache
    with patch.object(CentralizedConfig, 'load', return_value=None):
        CentralizedConfig._config = default_config
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


@pytest.mark.parametrize(
    'system_resources, permitted_resources, filters, expected_result',
    [
        (
            {'001', '002', '003', '004'},
            ['001', '002', '005', '006'],
            None,
            {'filters': {'rbac_ids': ['004', '003']}, 'rbac_negate': True},
        ),
        ({'001'}, ['002', '005', '006'], None, {'filters': {'rbac_ids': ['001']}, 'rbac_negate': True}),
        (
            {'group1', 'group3', 'group4'},
            ['group1', 'group2', 'group5', 'group6'],
            None,
            {'filters': {'rbac_ids': ['group3', 'group4']}, 'rbac_negate': True},
        ),
        (
            {'group1', 'group2', 'group3', 'group4', 'group5', 'group6'},
            ['group1'],
            {'testing': 'first'},
            {'filters': {'rbac_ids': {'group1'}, 'testing': 'first'}, 'rbac_negate': False},
        ),
    ],
)
def test_get_rbac_filters(system_resources, permitted_resources, filters, expected_result):
    """Check that the function get_rbac_filters calculates correctly the list of allowed or denied."""
    result = get_rbac_filters(
        system_resources=system_resources, permitted_resources=permitted_resources, filters=filters
    )
    result['filters']['rbac_ids'] = set(result['filters']['rbac_ids'])
    expected_result['filters']['rbac_ids'] = set(expected_result['filters']['rbac_ids'])
    assert result == expected_result

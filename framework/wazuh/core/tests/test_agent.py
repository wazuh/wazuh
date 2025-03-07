#!/usr/bin/env python
# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import sqlite3
from shutil import rmtree
from unittest.mock import AsyncMock, patch

import pytest
from wazuh.core.config.client import CentralizedConfig

with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
        from server_management_api.util import remove_nones_to_dict
        from wazuh.core.agent import *
        from wazuh.core.common import reset_context_cache
        from wazuh.core.indexer.agent import Agent as IndexerAgent

# all necessary params

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data', 'test_agent')


# list with Wazuh packages availables with their hash
wpk_versions = [
    ['v3.10.0', '251b1af81d45d291540d8589b124302613f0a4e0'],
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
    ['v3.3.9', '180e25a1fefafe8d83c763d375cb1a3a387bc08a'],
]


class InitAgent:
    """Class to set up the necessary test environment for agents."""

    def __init__(self, data_path=test_data_path, db_name='schema_global_test.sql'):
        """Sets up necessary test environment for agents:
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

        self.never_connected_fields = {
            'status',
            'name',
            'ip',
            'registerIP',
            'node_name',
            'dateAdd',
            'id',
            'group_config_status',
            'status_code',
        }
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
    """Checks a single agent is correct."""
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
        raise Exception('Agent status not known: {}'.format(agent['status']))


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
    """Check that the function get_rbac_filters calculates correctly the list of allowed or denied.

    Parameters
    ----------
    system_resources : str
        Id of the agent to be searched.
    permitted_resources : int
        Error code that is expected.
    """
    result = get_rbac_filters(
        system_resources=system_resources, permitted_resources=permitted_resources, filters=filters
    )
    result['filters']['rbac_ids'] = set(result['filters']['rbac_ids'])
    expected_result['filters']['rbac_ids'] = set(expected_result['filters']['rbac_ids'])
    assert result == expected_result

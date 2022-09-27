# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from unittest.mock import patch

import pytest

with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
        from wazuh.core.agent import Agent
        from wazuh.core.exception import WazuhException


class AgentMock:
    def __init__(self, agent_id, agent_groups):
        self.id = agent_id
        self.group = agent_groups.split(',')

    @staticmethod
    def get_basic_information(self):
        return True


@pytest.mark.parametrize('agent_groups, agent_id, group_id', [
    (['dmz'], '005', 'dmz'),
    (['dmz', 'webserver'], '005', 'dmz'),
    (['dmz', 'webserver', 'database'], '005', 'dmz')
])
@patch('wazuh.core.agent.Agent.get_agent_groups')
@patch('wazuh.core.agent.Agent.set_agent_group_file')
@patch('wazuh.core.agent.Agent')
def test_remove_single_group_agent(agent_patch, set_agent_group_patch, get_groups_patch, agent_groups,
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

    ret_msg = Agent.unset_single_group_agent(agent_id, group_id, force=True)

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
@patch('wazuh.core.agent.Agent.get_agent_groups', return_value=['default'])
@patch('wazuh.core.agent.Agent.group_exists', return_value=False)
@patch('wazuh.core.agent.Agent.get_basic_information')
def test_remove_single_group_agent_ko(agent_basic_mock, group_exists_mock, get_groups_mock, agent_id, group_id,
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
        Agent.unset_single_group_agent(agent_id, group_id, force=force)

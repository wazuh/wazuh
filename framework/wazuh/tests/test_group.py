# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from unittest.mock import patch
import pytest

from wazuh.agent import Agent
from wazuh.exception import WazuhException


class AgentMock:
    def __init__(self, agent_id, agent_groups):
        self.id = agent_id
        self.group = agent_groups.split(',')

    def get_basic_information(self):
        return True


@pytest.mark.parametrize('agent_groups, agent_id, group_id, expected_new_group', [
    ('dmz', '005', 'dmz', 'default'),
    ('dmz,webserver', '005', 'dmz', 'webserver'),
    ('dmz,webserver,database', '005', 'dmz', 'webserver,database'),
    ('dmz,default', '005', 'default', 'dmz')
])
@patch('wazuh.agent.Agent.get_agents_group_file')
@patch('wazuh.agent.Agent.create_multi_group')
@patch('wazuh.agent.Agent.unset_all_groups_agent')
@patch('wazuh.agent.Agent')
def test_sucessfully_remove_single_group_agent(agent_patch, unset_groups_patch, create_multigroup_patch,
                                               get_groups_patch, agent_groups, agent_id, group_id, expected_new_group):
    """
    Tests sucessfully unsseting a group from an agent. Test cases:
        * The agent only belongs to one group. It must be assigned to the default one.
        * The agent belongs to two groups, it must be assigned to the remaining group.
        * The agent belongs to three groups, the group to remove must be removed from the multigroup.
    """
    get_groups_patch.return_value = agent_groups
    agent_patch.return_value = AgentMock(agent_id, agent_groups)

    with patch('wazuh.agent.Agent.multi_group_exists', return_value=False):
        ret_msg = Agent.unset_single_group_agent(agent_id, group_id, False)

    assert ret_msg == (f"Agent {agent_id} set to group default." if expected_new_group == 'default' else
                       f"Group '{group_id}' unset for agent '{agent_id}'.")

    if ',' in expected_new_group:
        create_multigroup_patch.assert_called_with(expected_new_group)

    unset_groups_patch.assert_called_with(agent_id, True, expected_new_group)


@pytest.mark.parametrize('agent_groups, agent_id, group_id, expected_exception', [
    ('', '005', 'dmz', 1734),
    ('dmz', '005', 'default', 1734),
    ('default', '005', 'default', 1745),
    ('dmz', '005', 'webserver,database', 1734)
])
@patch('wazuh.agent.Agent.get_agents_group_file')
@patch('wazuh.agent.Agent')
def test_failed_remove_single_group_agent(agent_patch, get_groups_patch, agent_groups, agent_id, group_id,
                                          expected_exception):
    with pytest.raises(WazuhException, match=f'.* {expected_exception} .*'):
        get_groups_patch.return_value = agent_groups
        agent_patch.return_value = AgentMock(agent_id, agent_groups)

        Agent.unset_single_group_agent(agent_id, group_id, False)

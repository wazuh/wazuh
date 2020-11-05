# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from unittest.mock import patch
import pytest

with patch('wazuh.core.common.ossec_uid'):
    with patch('wazuh.core.common.ossec_gid'):
        from wazuh.core.agent import Agent
        from wazuh.core.exception import WazuhException


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
@patch('wazuh.core.agent.Agent.get_agents_group_file')
@patch('wazuh.core.agent.Agent.set_agent_group_file')
@patch('wazuh.core.agent.Agent')
def test_sucessfully_remove_single_group_agent(agent_patch, set_agent_group_patch, get_groups_patch, agent_groups,
                                               agent_id, group_id, expected_new_group):
    """Test sucessfully unsseting a group from an agent. Test cases:
        * The agent only belongs to one group. It must be assigned to the default one.
        * The agent belongs to two groups, it must be assigned to the remaining group.
        * The agent belongs to three groups, the group to remove must be removed from the multigroup.
    """
    get_groups_patch.return_value = agent_groups
    agent_patch.return_value = AgentMock(agent_id, agent_groups)

    with patch('wazuh.core.agent.Agent.multi_group_exists', return_value=False):
        ret_msg = Agent.unset_single_group_agent(agent_id, group_id, force=False)

    reassigned_text = " Agent reassigned to group default." if expected_new_group == 'default' else ""
    assert ret_msg == f"Agent '{agent_id}' removed from '{group_id}'.{reassigned_text}"
    set_agent_group_patch.assert_called_with(agent_id, expected_new_group)


@pytest.mark.parametrize('agent_groups, agent_id, group_id, expected_exception', [
    ('', '005', 'dmz', 1734),
    ('dmz', '005', 'default', 1734),
    ('default', '005', 'default', 1745),
    ('dmz', '005', 'webserver,database', 1734)
])
@patch('wazuh.core.agent.Agent.get_agents_group_file')
@patch('wazuh.core.agent.Agent')
def test_failed_remove_single_group_agent(agent_patch, get_groups_patch, agent_groups, agent_id, group_id,
                                          expected_exception):
    with pytest.raises(WazuhException, match=f'.* {expected_exception} .*'):
        get_groups_patch.return_value = agent_groups
        agent_patch.return_value = AgentMock(agent_id, agent_groups)

        Agent.unset_single_group_agent(agent_id, group_id, force=False)

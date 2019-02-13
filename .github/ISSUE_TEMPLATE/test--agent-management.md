---
name: 'Test: Agent management'
about: Test suite for agent management.
title: ''
labels: ''
assignees: ''

---

# Agent management test

| Version | Revision | Branch |
| --- | --- | --- |
| x.y.z | rev | branch |

## *agent.conf*

- [ ] Check if the "verify-agent-conf" tool verifies the agent.conf including all the modules. (1)
- [ ] Set a configuration for a non-existent agent, OS, or profile. Try to send it to agents. (1)
- [ ] Send by the agent.conf an unrecognizable module for the agent.
- [ ] Agents (Linux/Windows) receive the agent.conf, applying the configuration and restarting the agent automatically. (1)
- [ ] Agents ignore agent.conf when it is specified in the internal options. (1)

(1) https://documentation.wazuh.com/3.x/user-manual/reference/centralized-configuration.html

## Labels

- [ ] Set nested labels for an agent in the "agent.conf". (2)
- [ ] Show hidden labels with the internal option of analysisd. (2)
- [ ] Use labels in the "localfile" section for a monitored log file in JSON. (3) 

(2) https://documentation.wazuh.com/3.x/user-manual/capabilities/labels.html
(3) https://documentation.wazuh.com/3.x/user-manual/reference/ossec-conf/localfile.html#label

## Groups / Multiple groups

- [ ] For all the checks, test the consistency between the API and `agent_groups` results.
- [ ] Create a group, add agents and send them a centralized configuration. (4)
- [ ] Remove a group, remove agents from a group, and check that they are assigned to the default group. (5)
- [ ] Assign several groups to an agent. Check that the agent receives the merged configuration. (6)
- [ ] Remove an agent from a group. It should belongs to the rest of the groups assigned.
- [ ] Check the synchronization of shared files between groups and agents.
- [ ] Remove a group existing in several multigroups, check if is correctly removed and agents affected.
- [ ] Force a replacement of groups for an agent and check that it changed correctly.
- [ ] Try to assign an agent to an invalid group. Registered and in the registration process with `agent-auth`.
- [ ] Check if an agent is reassigned to its group(s) after registering it with another name or ID. Enable the internal option `remoted.guess_agent_group` to enable it.

(4) https://documentation.wazuh.com/3.x/user-manual/agents/grouping-agents.html
(5) https://documentation.wazuh.com/3.x/user-manual/reference/tools/agent_groups.html#examples
(6) https://documentation.wazuh.com/current/user-manual/agents/grouping-agents.html#multiple-groups

## Leaky bucket

- [ ] Change the buffer parameters (eps and queue size) to trigger alerts of flooding. (6)
- [ ] Change the threshold levels of the buffer and check that alerts are triggered when they have to. (6)
- [ ] Set a less minimum of eps than it is specified in the parameter "agent.min_eps". (7)
- [ ] Test the agent modules anti-flooding. You can write in a monitored log by logcollector with an infinite loop to do this. (8)

(6) https://documentation.wazuh.com/3.x/user-manual/capabilities/antiflooding.html#how-it-works-leaky-bucket
(7) https://documentation.wazuh.com/3.x/user-manual/reference/internal-options.html#agent
(8) https://documentation.wazuh.com/3.x/user-manual/capabilities/antiflooding.html#anti-flooding-in-agent-modules

## *agent_control*

- [ ] Check that "agent_control" shows agent status in real-time (after 30 minutes). (9)
- [ ] Check that the information provided by the API about agents is consistent with the "agent_control" tool. (10)

(9) https://documentation.wazuh.com/3.x/user-manual/reference/tools/agent_control.html
(10) https://documentation.wazuh.com/3.x/user-manual/api/reference.html#get-all-agents

 - [ ] Enable debug mode in the internal options file. (11)

(11) https://documentation.wazuh.com/3.x/user-manual/reference/internal-options.html?highlight=debug%20mode

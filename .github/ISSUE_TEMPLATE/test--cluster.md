---
name: 'Test: Cluster'
about: Test suite for cluster.
title: ''
labels: ''
assignees: ''

---

# Cluster test

| Version | Revision | Branch |
| --- | --- | --- |
| x.y.z | rev | branch |

## Installation

- [ ] Installation by default: Run `/var/ossec/bin/wazuh-clusterd -f`
- [ ] Installation by default: Run `python3 /var/ossec/bin/wazuh-clusterd -f`
- [ ] Installation by default - centos6: Run `/var/ossec/bin/wazuh-clusterd -f`

## Configuration

- [ ] Python 2:
    - [ ] Configure cluster: No key.
    - [ ] Configure cluster: Wrong key.
    - [ ] Configure cluster: Wrong node type.
    - [ ] Configure cluster: Wrong master node IP.
- [ ] Python 3:
    - [ ] Configure cluster: No key.
    - [ ] Configure cluster: Wrong key.
    - [ ] Configure cluster: Wrong node type.
    - [ ] Configure cluster: Wrong master node IP.

## Cluster

- [ ] Python 2:
    - [ ] Start the master before/after the clients.
    - [ ] Change path to opt in master and var in clients.
    - [ ] Synchronization process when one of the clients is down.
    - [ ] Stop master and start it after some time.
    - [ ] Disconnect worker node internet connection and check it disconnects after 2 minutes. Check the master node removes that node. Connect the node to the internet again and check it reconnects to the master node without restarting (https://github.com/wazuh/wazuh/pull/1482).
    - [ ] Disconnect worker and reconnect it again to the internet in less than 2 minutes. Check it keeps working as usual (https://github.com/wazuh/wazuh/pull/1482).
    - [ ] File level tests: Run automatic tests and review KO files.
- [ ] Python 3:
    - [ ] Start the master before/after the clients.
    - [ ] Change path to opt in master and var in clients.
    - [ ] Synchronization process when one of the clients is down.
    - [ ] Stop master and start it after some time.
    - [ ] Disconnect worker node internet connection and check it disconnects after 2 minutes. Check the master node removes that node. Connect the node to the internet again and check it reconnects to the master node without restarting (https://github.com/wazuh/wazuh/pull/1482).
    - [ ] Disconnect worker and reconnect it again to the internet in less than 2 minutes. Check it keeps working as usual (https://github.com/wazuh/wazuh/pull/1482).
    - [ ] File level tests: Run automatic tests and review KO files.

## Cluster control
- [ ] Master
    - [ ] Python 2:
        - [ ] check `cluster_control -l`
        - [ ] check `cluster_control -a`
        - [ ] check `cluster_control -i`
    - [ ] Python 3:
        - [ ] check `cluster_control -l`
        - [ ] check `cluster_control -a`
        - [ ] check `cluster_control -i`
- [ ] Worker
    - [ ] Python 2:
        - [ ] check `cluster_control -l`
        - [ ] check `cluster_control -a`
        - [ ] check `cluster_control -i`
    - [ ] Python 3:
        - [ ] check `cluster_control -l`
        - [ ] check `cluster_control -a`
        - [ ] check `cluster_control -i`

## Agents

- [ ] Python 2:
    - [ ] Register an agent in master and point it to a client.
    The *client.keys* must be propagated and the agent must be reporting. Then, if the agents are listed in the master, it must be Active.
    - [ ] `cluster-control -a` must show the agents information and the manager.
    - [ ] Connect the previous agent to a different client and review logs/alerts. It must be transparent for the user.
    - [ ] Remove an agent in master. It must be removed in all the clients.
- [ ] Python 3:
    - [ ] Register an agent in master and point it to a client.
    The *client.keys* must be propagated and the agent must be reporting. Then, if the agents are listed in the master, it must be Active.
    - [ ] `cluster-control -a` must show the agents information and the manager.
    - [ ] Connect the previous agent to a different client and review logs/alerts. It must be transparent for the user.
    - [ ] Remove an agent in master. It must be removed in all the clients.

## Groups

- [ ] Python 2:
    - [ ] Create a new group.
    - [ ] Create a file in a group.
    - [ ] Modify a file in a group.
    - [ ] Remove a file in a group.
    - [ ] Remove group.
    - [ ] Re-create a removed group.
    - [ ] Assign agent to a group.
    - [ ] Unassign agent group.
    - [ ] Assign a group in a client using md5. Then, check if it is propagated to the master.
- [ ] Python 3:
    - [ ] Create a new group.
    - [ ] Create a file in a group.
    - [ ] Modify a file in a group.
    - [ ] Remove a file in a group.
    - [ ] Remove group.
    - [ ] Re-create a removed group.
    - [ ] Assign agent to a group.
    - [ ] Unassign agent group.
    - [ ] Assign a group in a client using md5. Then, check if it is propagated to the master.

## Ruleset

- [ ] Python 2:
    - [ ] Modify a file in the rules/decoders/lists directory.
    - [ ] Add a file in the rules/decoders/lists directory.
    - [ ] Remove a file in the rules/decoders/lists directory.
- [ ] Python 3:
    - [ ] Modify a file in the rules/decoders/lists directory.
    - [ ] Add a file in the rules/decoders/lists directory.
    - [ ] Remove a file in the rules/decoders/lists directory.

## Performance

- [ ] Python 2:
    - [ ] 1 master, 10 clients, 100k agent-info and agent-groups.
- [ ] Python 3:
    - [ ] 1 master, 10 clients, 100k agent-info and agent-groups.

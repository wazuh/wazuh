---
name: 'Test: Cluster'
about: Test suite for cluster.

---

# Cluster test

| Version | Revision | Branch |
| --- | --- | --- |
| x.y.z | rev | branch |

## Installation

- [ ] Installation by default: Run `/var/ossec/bin/wazuh-clusterd -f`
- [ ] Installation by default - centos6: Run `/var/ossec/bin/wazuh-clusterd -f`
- [ ] Installation by default: Run `/var/ossec/bin/cluster-control -n`

## Configuration

- [ ] Configure cluster: No key.
- [ ] Configure cluster: Wrong key.
- [ ] Configure cluster: Wrong node type.
- [ ] Configure cluster: Wrong master node IP.

## Cluster

- [ ] Start the master before/after the clients.
- [ ] Change path to opt in master and var in clients.
- [ ] Synchronization process when one of the clients is down.
- [ ] Stop master and start it after some time.
- [ ] File level tests: Run automatic tests and review KO files.
- [ ] check `cluster_control -n`
- [ ] check `cluster_control -a`
- [ ] check `cluster_control -i`

## Agents

- [ ] Register an agent in master and point it to a client.
The *client.keys* must be propagated and the agent must be reporting. Then, if the agents are listed in the master, it must be Active.
- [ ] `cluster-control -a` must show the agents information and the manager.
- [ ] Connect the previous agent to a different client and review logs/alerts. It must be transparent for the user.
- [ ] Remove an agent in master. It must be removed in all the clients.

## Groups

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

- [ ] Modify a file in the rules/decoders/lists directory.
- [ ] Add a file in the rules/decoders/lists directory.
- [ ] Remove a file in the rules/decoders/lists directory.

## Performance

- [ ] 1 master, 10 clients, 100k agent-info and agent-groups.

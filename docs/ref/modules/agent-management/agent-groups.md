# Agent Groups

## Introduction

Agent groups allow administrators to organize Wazuh agents into logical collections for targeted configuration and policy management. Each group has its own shared directory on the Wazuh manager where centralized configuration files and shared resources are stored.

All agents belong to the `default` group by default. Agents can be assigned to one or more groups, enabling flexible policy management across the deployment.

## How it works

1. The administrator creates a group on the Wazuh manager.
2. Agents are assigned to the group via the Wazuh API or command-line tools.
3. The manager maintains a shared directory for each group containing the group's `agent.conf` and any shared files.
4. When agents connect, they receive the merged configuration from all their assigned groups.

## Group directory structure

Each group has a dedicated directory under the manager's shared configuration path:

```
/var/wazuh-manager/etc/shared/
├── default/
│   └── agent.conf
├── web-servers/
│   └── agent.conf
├── database-servers/
│   └── agent.conf
└── dmz/
    └── agent.conf
```

## Managing groups with the Wazuh API

### Create a group

```
PUT /groups?group_id=<GROUP_NAME>
```

Example using `curl`:

```bash
TOKEN=$(curl -u <USER>:<PASSWORD> -k -X POST "https://<MANAGER_IP>:55000/security/user/authenticate" | jq -r '.data.token')

curl -k -X PUT "https://<MANAGER_IP>:55000/groups?group_id=web-servers" \
  -H "Authorization: Bearer $TOKEN"
```

### List groups

```
GET /groups
```

### Assign an agent to a group

```
PUT /agents/<AGENT_ID>/group/<GROUP_NAME>
```

### Remove an agent from a group

```
DELETE /agents/<AGENT_ID>/group/<GROUP_NAME>
```

### Delete a group

```
DELETE /groups?groups_list=<GROUP_NAME>
```

## Managing groups with command-line tools

### List agent groups

```bash
/var/wazuh-manager/bin/agent_groups -l
```

### Create a group

```bash
/var/wazuh-manager/bin/agent_groups -a -g <GROUP_NAME>
```

### Assign an agent to a group

```bash
/var/wazuh-manager/bin/agent_groups -a -i <AGENT_ID> -g <GROUP_NAME>
```

### Remove an agent from a group

```bash
/var/wazuh-manager/bin/agent_groups -r -i <AGENT_ID> -g <GROUP_NAME>
```

## Multi-group agents

Agents can belong to multiple groups simultaneously. When an agent is in multiple groups, the configurations from all groups are merged.

### Configuration merge order

When an agent belongs to multiple groups, the configurations are merged in alphabetical order by group name. If a conflict occurs (the same setting defined in multiple groups), the value from the group that appears first alphabetically takes precedence.

### Example

An agent assigned to groups `database-servers` and `web-servers`:

1. The `default` group configuration is applied first.
2. The `database-servers` group configuration is merged.
3. The `web-servers` group configuration is merged.

## Shared files

In addition to `agent.conf`, the group shared directory can contain other files that are distributed to agents in the group:

- CIS benchmark files for SCA
- Rootcheck policy files
- Any other files needed by the agent

These files are placed in the group's shared directory and are automatically distributed to agents in the group.

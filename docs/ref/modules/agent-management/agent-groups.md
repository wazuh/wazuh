# Agent Groups

## Introduction

Agent groups organize Wazuh agents into collections that share a centralized configuration. Each group
is a directory on the manager holding the group's `agent.conf` and any other file to distribute to its
agents.

An agent enrolled without a group is placed in the `default` group. An agent can belong to several
groups at once, up to 128.

## How it works

1. The administrator creates a group (API or `agent_groups`), which creates
   `/var/wazuh-manager/etc/shared/<GROUP_NAME>/` with a copy of `etc/shared/agent-template.conf` as its
   `agent.conf`.
2. Agents are assigned to the group; the assignment is stored by `wazuh-manager-db`.
3. `wazuh-manager-remoted` builds a `merged.mg` file from every file of each group (and of each
   combination of groups an agent has, under `var/multigroups/`).
4. Agents fetch their `merged.mg` on their next configuration poll and apply it as their
   `agent.conf` — see [Centralized Configuration](centralized-configuration.md).

## Group directory structure

```text
/var/wazuh-manager/etc/shared/
├── agent-template.conf      ← copied into every new group
├── default/
│   └── agent.conf
├── web-servers/
│   └── agent.conf
└── database-servers/
    └── agent.conf
```

A group name may contain `a-z`, `A-Z`, `0-9`, `_`, `-` and `.`, up to 128 characters through the API;
`.`, `..` and `all` are refused, and so is `default`, which always exists and cannot be deleted.

## Managing groups with the Wazuh API

| Task | Request | RBAC action |
|------|---------|-------------|
| Create a group | `POST /groups` with body `{"group_id": "<GROUP_NAME>"}` | `group:create` |
| List groups | `GET /groups` | `group:read` |
| List a group's agents | `GET /groups/<GROUP_NAME>/agents` | `group:read`, `agent:read` |
| List a group's files | `GET /groups/<GROUP_NAME>/files` | `group:read` |
| Read a group's `agent.conf` | `GET /groups/<GROUP_NAME>/configuration` | `group:read` |
| Replace a group's `agent.conf` | `PUT /groups/<GROUP_NAME>/configuration` with an `application/xml` body | `group:update_config` |
| Assign an agent to a group | `PUT /agents/<AGENT_ID>/group/<GROUP_NAME>` (`force_single_group=true` removes it from its other groups) | `agent:modify_group`, `group:modify_assignments` |
| Assign several agents | `PUT /agents/group?group_id=<GROUP_NAME>&agents_list=<ID>,<ID>` | `agent:modify_group`, `group:modify_assignments` |
| Remove an agent from a group | `DELETE /agents/<AGENT_ID>/group/<GROUP_NAME>` | `agent:modify_group`, `group:modify_assignments` |
| Remove an agent from several groups | `DELETE /agents/<AGENT_ID>/group?groups_list=<GROUP>,<GROUP>` | `agent:modify_group`, `group:modify_assignments` |
| List agents without a group | `GET /agents/no_group` | `agent:read` |
| Delete groups | `DELETE /groups?groups_list=<GROUP_NAME>` (`all` for every group but `default`) | `group:delete` |
| Restart / reload a group's agents | `PUT /agents/group/<GROUP_NAME>/restart`, `.../reload` | `agent:restart`, `agent:reload` |

Example using `curl`:

```bash
TOKEN=$(curl -u <USER>:<PASSWORD> -k -X POST "https://<MANAGER_IP>:55000/security/user/authenticate" | jq -r '.data.token')

curl -k -X POST "https://<MANAGER_IP>:55000/groups" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"group_id": "web-servers"}'

curl -k -X PUT "https://<MANAGER_IP>:55000/agents/001/group/web-servers" \
  -H "Authorization: Bearer $TOKEN"
```

Errors you may meet: `1710` the group does not exist, `1711` it already exists, `1712` `default`
cannot be deleted, `1713` the name is reserved, `1722` invalid name, `1734` the agent is not in that
group, `1737` the agent already has 128 groups, `1745` the agent's only group is `default`, `1751` the
agent already belongs to the group.

Removing an agent from its last group other than `default` puts it back in `default`.

## Managing groups with `agent_groups`

`/var/wazuh-manager/bin/agent_groups` (source `framework/scripts/agent_groups.py`) does the same
through the framework, forwarded to the master node in a cluster. Every change asks for confirmation
unless `-q` is given.

| Command | Does |
|---------|------|
| `agent_groups` or `agent_groups -l` | List every group with its agent count, and the number of agents without a group |
| `agent_groups -l -g <GROUP_NAME>` | List the agents in a group |
| `agent_groups -c -g <GROUP_NAME>` | List the group's files with their MD5 hashes |
| `agent_groups -a -g <GROUP_NAME> [-q]` | Create a group |
| `agent_groups -a -i <AGENT_ID> -g <GROUP_NAME> [-q] [-f]` | Add the group to the agent; with `-f`, replace the agent's other groups with it |
| `agent_groups -s -i <AGENT_ID>` | Show the groups of an agent |
| `agent_groups -r -i <AGENT_ID> -g <GROUP_NAME> [-q]` | Remove the agent from the group |
| `agent_groups -r -i <AGENT_ID> [-q]` | Remove the agent from all its groups; an agent left with none is reassigned to `default` (and an agent only in `default` stays there) |
| `agent_groups -r -g <GROUP_NAME> [-q]` | Delete the group |
| `agent_groups -u` | Print the usage text |

| Flag | Long form |
|------|-----------|
| `-l` | `--list` |
| `-c` | `--list-files` |
| `-a` | `--add` |
| `-f` | `--force` (with `-a -i`: force a single group) |
| `-s` | `--show-group` |
| `-r` | `--remove` |
| `-i` | `--agent-id` |
| `-g` | `--group-id` |
| `-q` | `--quiet` (no confirmation) |
| `-d` | `--debug` (re-raise errors with a traceback) |
| `-u` | `--usage` |

Only one of `-l`, `-c`, `-a`, `-s`, `-r` may be given. Errors are printed as `Error <code>: <message>`.

## Verifying assignments

```bash
/var/wazuh-manager/bin/agent_groups -s -i 001
# The agent 'web-01' with ID '001' belongs to groups: default, web-servers.
```

or `GET /groups/<GROUP_NAME>/agents` through the API.

## Multi-group agents

When an agent belongs to several groups, the files of all of them are merged into one `merged.mg`
for that combination of groups, stored under `/var/wazuh-manager/var/multigroups/`.

### Configuration merge order

When an agent belongs to multiple groups, the configurations are merged in the order the groups were assigned to the agent, not by group name. Each group's `agent.conf` is appended to the merged `agent.conf` in that order, and the agent reads it top to bottom. If a conflict occurs (the same setting defined in multiple groups), the value from the group assigned last takes precedence. Other shared files with the same name in several groups are overwritten the same way, so the copy from the group assigned last is the one distributed.

### Example

An agent in the `default` group that is then assigned to `web-servers` and, after that, to `database-servers`:

1. The `default` group configuration is applied first.
2. The `web-servers` group configuration is merged.
3. The `database-servers` group configuration is merged.

If `web-servers` and `database-servers` set the same option, the `database-servers` value applies.

## Shared files

Every file placed in a group's directory, not only `agent.conf`, is included in the group's
`merged.mg` and written into the agent's shared directory (`/var/ossec/etc/shared/` on Linux agents).
`merged.mg` itself is generated and must not be edited: `wazuh-manager-remoted` rewrites it.

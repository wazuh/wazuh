# API Reference

This document covers the key API endpoints with practical examples, the Wazuh Query Language (WQL), error handling, and input validation.

> All paths are validated against `api/api/spec/spec.yaml` (OpenAPI 3.0).  
> For the complete endpoint specification, refer to the [official Wazuh API Reference](https://documentation.wazuh.com/current/user-manual/api/reference.html).

---

## Common Query Parameters

Most `GET` endpoints accept these standard parameters:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `pretty` | boolean | `false` | Human-readable output |
| `wait_for_complete` | boolean | `false` | Disable timeout response |
| `offset` | int | `0` | First element to return |
| `limit` | int | `500` | Max elements to return (max: 100,000) |
| `search` | string | — | Free-text search (prefix `-` for complementary) |
| `sort` | string | — | Sort by fields (`+` asc, `-` desc, dot notation for nested) |
| `select` | string | — | Fields to return (comma-separated) |
| `q` | string | — | WQL query filter |
| `distinct` | boolean | `false` | Return distinct values |

---

## Authentication

### Obtain JWT token

```bash
curl -u <USER>:<PASSWORD> -k -X POST "https://localhost:55000/security/user/authenticate"
```

```json
{
  "data": {
    "token": "<YOUR_JWT_TOKEN>"
  },
  "error": 0
}
```

All subsequent requests must include the token:

```bash
curl -k -X <METHOD> "https://localhost:55000/<ENDPOINT>" \
  -H "Authorization: Bearer <YOUR_JWT_TOKEN>"
```

### Update token expiration

```bash
curl -k -X PUT "https://localhost:55000/security/config" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"auth_token_exp_timeout": 1800}'
```

> **Note:** Changing security config revokes all existing tokens.

---

## Key Endpoints & Examples

### API Info

**`GET /`** — Returns API version, hostname, and timestamp.

```bash
curl -k -X GET "https://localhost:55000/?pretty=true" \
  -H "Authorization: Bearer $TOKEN"
```

```json
{
  "data": {
    "title": "Wazuh API REST",
    "api_version": "5.0.0",
    "revision": "alpha0",
    "license_name": "GPL 2.0",
    "hostname": "wazuh-manager",
    "timestamp": "2026-02-20T12:00:00Z"
  },
  "error": 0
}
```

---

### Agents

#### List agents

**`GET /agents`** — Return all agents with optional filters.

```bash
# List active agents, limit 5
curl -k -X GET "https://localhost:55000/agents?status=active&limit=5&pretty=true" \
  -H "Authorization: Bearer $TOKEN"

# Filter with WQL: active Ubuntu agents
curl -k -X GET "https://localhost:55000/agents?q=status%3Dactive%3Bos.name~%3Dubuntu&pretty=true" \
  -H "Authorization: Bearer $TOKEN"

# Select specific fields
curl -k -X GET "https://localhost:55000/agents?select=id,name,status,ip&sort=-id&pretty=true" \
  -H "Authorization: Bearer $TOKEN"
```

Key filters: `status`, `os.platform`, `os.name`, `os.version`, `manager`, `version`, `group`, `node_name`, `name`, `ip`, `older_than`.

#### Add agent

**`POST /agents`** — Create a new agent. Returns the agent ID and registration key.

```bash
curl -k -X POST "https://localhost:55000/agents?pretty=true" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "web-server-01", "ip": "10.0.10.11"}'
```

```json
{
  "data": {
    "id": "009",
    "key": "MDA5IHdlYi1zZXJ2ZXItMDEgMTAuMC4xMC4xMSA..."
  },
  "error": 0
}
```

#### Restart agent

**`PUT /agents/{agent_id}/restart`** — Restart a specific agent.

```bash
curl -k -X PUT "https://localhost:55000/agents/002/restart?pretty=true" \
  -H "Authorization: Bearer $TOKEN"
```

#### Delete agents

**`DELETE /agents`** — Delete agents by ID or criteria. Requires `agents_list` and `status`.

```bash
# Delete disconnected agents older than 30 days
curl -k -X DELETE "https://localhost:55000/agents?agents_list=all&status=disconnected&older_than=30d&pretty=true" \
  -H "Authorization: Bearer $TOKEN"

# Delete specific agent permanently
curl -k -X DELETE "https://localhost:55000/agents?agents_list=009&status=all&purge=true&pretty=true" \
  -H "Authorization: Bearer $TOKEN"
```

#### Agent overview

**`GET /overview/agents`** — Full summary: status counts, OS distribution, versions, groups, and last registered agent.

```bash
curl -k -X GET "https://localhost:55000/overview/agents?pretty=true" \
  -H "Authorization: Bearer $TOKEN"
```

---

### Groups

#### List groups

**`GET /groups`** — List all agent groups with agent count and checksums.

```bash
curl -k -X GET "https://localhost:55000/groups?pretty=true" \
  -H "Authorization: Bearer $TOKEN"
```

#### Create group

**`POST /groups`** — Create a new agent group.

```bash
curl -k -X POST "https://localhost:55000/groups?pretty=true" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"group_id": "web-servers"}'
```

#### Assign agent to group

**`PUT /agents/{agent_id}/group/{group_id}`** — Add an agent to a group.

```bash
curl -k -X PUT "https://localhost:55000/agents/002/group/web-servers?pretty=true" \
  -H "Authorization: Bearer $TOKEN"
```

---

### Cluster

#### Cluster status

**`GET /cluster/status`** — Check if the cluster is enabled and running.

```bash
curl -k -X GET "https://localhost:55000/cluster/status?pretty=true" \
  -H "Authorization: Bearer $TOKEN"
```

#### List nodes

**`GET /cluster/nodes`** — List all cluster nodes with type, version, and IP.

```bash
# All nodes
curl -k -X GET "https://localhost:55000/cluster/nodes?pretty=true" \
  -H "Authorization: Bearer $TOKEN"

# Only worker nodes
curl -k -X GET "https://localhost:55000/cluster/nodes?type=worker&pretty=true" \
  -H "Authorization: Bearer $TOKEN"
```

#### Restart cluster

**`PUT /cluster/restart`** — Restart all cluster nodes.

```bash
curl -k -X PUT "https://localhost:55000/cluster/restart?pretty=true" \
  -H "Authorization: Bearer $TOKEN"
```

---

### Active Response

**`PUT /active-response`** — Execute an active response command on agents.

```bash
curl -k -X PUT "https://localhost:55000/active-response?agents_list=001,002&pretty=true" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"command": "!firewall-drop", "arguments": ["-srcip", "10.0.0.50"]}'
```

---

### Events

**`POST /events`** — Ingest events into analysisd. Limited to **30 req/min** and **100 events/request**.

```bash
curl -k -X POST "https://localhost:55000/events?pretty=true" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"events": ["Failed login from 192.168.1.50", "{\"action\": \"block\", \"srcip\": \"10.0.0.99\"}"]}'
```

---

### Security

#### List users

**`GET /security/users`** — List all security users with their roles.

```bash
curl -k -X GET "https://localhost:55000/security/users?pretty=true" \
  -H "Authorization: Bearer $TOKEN"
```

#### Revoke tokens

**`PUT /security/user/revoke`** — Revoke all active JWT tokens.

```bash
curl -k -X PUT "https://localhost:55000/security/user/revoke?pretty=true" \
  -H "Authorization: Bearer $TOKEN"
```

---

### Syscheck & Rootcheck

**`PUT /syscheck`** — Run a syscheck (FIM) scan on agents.

```bash
curl -k -X PUT "https://localhost:55000/syscheck?agents_list=001,002&pretty=true" \
  -H "Authorization: Bearer $TOKEN"
```

**`PUT /rootcheck`** — Run a rootcheck scan on agents.

```bash
curl -k -X PUT "https://localhost:55000/rootcheck?agents_list=001&pretty=true" \
  -H "Authorization: Bearer $TOKEN"
```

---

### MITRE ATT&CK

**`GET /mitre/techniques`** — Query MITRE techniques with full details (tactics, mitigations, software, groups, references).

```bash
# Search for specific technique
curl -k -X GET "https://localhost:55000/mitre/techniques?search=phishing&limit=3&pretty=true" \
  -H "Authorization: Bearer $TOKEN"

# Get by technique ID
curl -k -X GET "https://localhost:55000/mitre/techniques?technique_ids=T1566&pretty=true" \
  -H "Authorization: Bearer $TOKEN"
```

Other MITRE endpoints: `/mitre/tactics`, `/mitre/groups`, `/mitre/software`, `/mitre/mitigations`, `/mitre/references`, `/mitre/metadata`.

---

### Tasks

**`GET /tasks/status`** — Check the status of async tasks (upgrades, etc.).

```bash
curl -k -X GET "https://localhost:55000/tasks/status?pretty=true" \
  -H "Authorization: Bearer $TOKEN"
```

---

## Full Endpoint Index

<details>
<summary>Click to expand all endpoints</summary>

### API Info
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | API info |

### Agents
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/agents` | List agents |
| POST | `/agents` | Create agent |
| DELETE | `/agents` | Delete agents |
| POST | `/agents/insert` | Insert agent with key |
| POST | `/agents/insert/quick` | Quick insertion |
| PUT | `/agents/{agent_id}/restart` | Restart agent |
| GET | `/agents/{agent_id}/key` | Get agent key |
| DELETE | `/agents/{agent_id}/group` | Remove from all groups |
| PUT | `/agents/{agent_id}/group/{group_id}` | Assign to group |
| DELETE | `/agents/{agent_id}/group/{group_id}` | Remove from group |
| GET | `/agents/{agent_id}/group/is_sync` | Sync status |
| GET | `/agents/{agent_id}/config/{component}/{configuration}` | Active config |
| GET | `/agents/{agent_id}/daemons/stats` | Daemon stats |
| GET | `/agents/{agent_id}/stats/{component}` | Component stats |
| PUT | `/agents/restart` | Restart all |
| PUT | `/agents/reconnect` | Force reconnect |
| PUT | `/agents/group` | Bulk assign to group |
| DELETE | `/agents/group` | Bulk remove from group |
| PUT | `/agents/group/{group_id}/restart` | Restart group |
| PUT | `/agents/node/{node_id}/restart` | Restart by node |
| GET | `/agents/no_group` | Without group |
| GET | `/agents/outdated` | Outdated agents |
| PUT | `/agents/upgrade` | Upgrade agents |
| PUT | `/agents/upgrade_custom` | Custom upgrade |
| GET | `/agents/upgrade_result` | Upgrade result |
| GET | `/agents/uninstall` | Uninstall agents |
| GET | `/agents/stats/distinct` | Distinct fields |
| GET | `/agents/summary` | Summary |
| GET | `/agents/summary/os` | OS summary |
| GET | `/agents/summary/status` | Status summary |

### Groups
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/groups` | List groups |
| POST | `/groups` | Create group |
| DELETE | `/groups` | Delete groups |
| GET | `/groups/{group_id}/agents` | Group agents |
| GET | `/groups/{group_id}/configuration` | Group config |
| PUT | `/groups/{group_id}/configuration` | Update group config |
| GET | `/groups/{group_id}/files` | Group files |
| GET | `/groups/{group_id}/files/{file_name}` | File content |

### Cluster
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/cluster/status` | Cluster status |
| GET | `/cluster/nodes` | List nodes |
| GET | `/cluster/healthcheck` | Healthcheck |
| GET | `/cluster/local/info` | Local node info |
| GET | `/cluster/local/config` | Local node config |
| GET | `/cluster/api/config` | API config |
| PUT | `/cluster/restart` | Restart cluster |
| GET | `/cluster/configuration/validation` | Validate config |
| GET | `/cluster/version/check` | Version check |
| GET | `/cluster/{node_id}/status` | Node status |
| GET | `/cluster/{node_id}/info` | Node info |
| GET | `/cluster/{node_id}/configuration` | Node config |
| PUT | `/cluster/{node_id}/configuration` | Update node config |
| GET | `/cluster/{node_id}/configuration/{component}/{configuration}` | Active config |
| GET | `/cluster/{node_id}/daemons/stats` | Daemon stats |
| GET | `/cluster/{node_id}/stats` | Node stats |
| GET | `/cluster/{node_id}/stats/hourly` | Hourly stats |
| GET | `/cluster/{node_id}/stats/weekly` | Weekly stats |
| GET | `/cluster/{node_id}/stats/analysisd` | Analysisd stats |
| GET | `/cluster/{node_id}/stats/remoted` | Remoted stats |
| GET | `/cluster/{node_id}/logs` | Node logs |
| GET | `/cluster/{node_id}/logs/summary` | Log summary |

### Security
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/security/user/authenticate` | Login (get JWT) |
| POST | `/security/user/authenticate/run_as` | Login with auth context |
| PUT | `/security/user/revoke` | Revoke tokens |
| GET | `/security/users` | List users |
| POST | `/security/users` | Create user |
| DELETE | `/security/users` | Delete users |
| PUT | `/security/users/{user_id}` | Update user |
| PUT | `/security/users/{user_id}/run_as` | Set run_as |
| POST | `/security/users/{user_id}/roles` | Assign roles |
| DELETE | `/security/users/{user_id}/roles` | Remove roles |
| GET | `/security/users/me` | Current user |
| GET | `/security/users/me/policies` | My policies |
| GET | `/security/roles` | List roles |
| POST | `/security/roles` | Create role |
| DELETE | `/security/roles` | Delete roles |
| PUT | `/security/roles/{role_id}` | Update role |
| POST | `/security/roles/{role_id}/policies` | Assign policies |
| DELETE | `/security/roles/{role_id}/policies` | Remove policies |
| POST | `/security/roles/{role_id}/rules` | Assign rules |
| DELETE | `/security/roles/{role_id}/rules` | Remove rules |
| GET | `/security/policies` | List policies |
| POST | `/security/policies` | Create policy |
| DELETE | `/security/policies` | Delete policies |
| PUT | `/security/policies/{policy_id}` | Update policy |
| GET | `/security/rules` | List rules |
| POST | `/security/rules` | Create rule |
| DELETE | `/security/rules` | Delete rules |
| PUT | `/security/rules/{rule_id}` | Update rule |
| GET | `/security/actions` | RBAC actions |
| GET | `/security/resources` | RBAC resources |
| GET | `/security/config` | Security config |
| PUT | `/security/config` | Update config |
| DELETE | `/security/config` | Reset config |

### Syscheck, Rootcheck & Active Response
| Method | Endpoint | Description |
|--------|----------|-------------|
| PUT | `/syscheck` | Run syscheck scan |
| PUT | `/rootcheck` | Run rootcheck scan |
| PUT | `/active-response` | Run AR command |

### MITRE
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/mitre/techniques` | Techniques |
| GET | `/mitre/tactics` | Tactics |
| GET | `/mitre/groups` | Groups |
| GET | `/mitre/software` | Software |
| GET | `/mitre/mitigations` | Mitigations |
| GET | `/mitre/references` | References |
| GET | `/mitre/metadata` | Metadata |

### Events, Overview & Tasks
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/events` | Ingest events |
| GET | `/overview/agents` | Agent overview |
| GET | `/tasks/status` | Task status |

</details>

---

## Wazuh Query Language (WQL)

WQL allows server-side filtering of large datasets, reducing payload size and avoiding client-side filtering.

### Syntax

```
field operator value[;connector field operator value]
```

### Operators

| Operator | Meaning |
|----------|---------|
| `=` | Equals |
| `!=` | Not equals |
| `>` | Greater than |
| `<` | Less than |
| `>=` | Greater than or equal |
| `<=` | Less than or equal |
| `~=` | Contains (like) |

### Connectors

| Connector | Meaning |
|-----------|---------|
| `;` | AND |
| `,` | OR |

### Examples

```bash
# Active agents
curl -k -X GET "https://localhost:55000/agents?q=status%3Dactive" \
  -H "Authorization: Bearer $TOKEN"

# Active agents on Ubuntu
curl -k -X GET "https://localhost:55000/agents?q=status%3Dactive%3Bos.name~%3Dubuntu" \
  -H "Authorization: Bearer $TOKEN"

# Agents with version not equal to 5.0.0
curl -k -X GET "https://localhost:55000/agents?q=version!%3Dwazuh%205.0.0" \
  -H "Authorization: Bearer $TOKEN"
```

---

## Error Handling

Errors follow a structured JSON response format.

### HTTP Status Codes

| HTTP Code | Meaning           | Notes                    |
|-----------|-------------------|--------------------------|
| 400       | Bad Request       | Invalid parameters       |
| 401       | Unauthorized      | Invalid or expired token |
| 403       | Forbidden         | RBAC denied              |
| 404       | Not Found         | Invalid endpoint         |
| 405       | Method Not Allowed | Invalid HTTP method     |
| 413       | Payload Too Large | Request body too large   |
| 429       | Too Many Requests | Rate limit exceeded      |
| 500       | Internal Error    | Check manager logs       |

### Exception Hierarchy

All exceptions inherit from `WazuhException` (defined in `core/exception.py`), with a numeric error code catalog:

| Range | Category | Examples |
|-------|----------|----------|
| 900–999 | API-level errors | Child process terminated, executor failure, endpoint restricted to master |
| 999–1099 | Core Wazuh errors | Incompatible Python, internal error, command errors, socket issues |
| 1100–1199 | Configuration errors | Invalid section/field/type, XML syntax, missing config |
| 1200–1299 | Agent errors | Agent not found, duplicate, version mismatch |
| 1700–1799 | RBAC errors | Permission denied, invalid role/policy |
| 2000+ | Module-specific errors | Syscheck, rootcheck, active response, cluster |

Error responses include a `dapi_errors` field in cluster deployments.

---

## Input Validation

The API layer (`api/validator.py`) validates all inputs with pre-compiled regex patterns before they reach the framework:

| Pattern | Description |
|---------|-------------|
| Hashes | MD5 (32), SHA1 (40), SHA224 (56), SHA256 (64), SHA384 (96), SHA512 (128) |
| Groups | Group name validation (excludes `.`, `..`, `all`) |
| Base64 | Standard base64 encoded strings |
| Dates | Date and datetime format validation |
| WQL | Query syntax (`field operator value;connector`) |
| XML | Validated via `lxml` and `defusedxml` |
| Special chars | Separate patterns for names vs. paths |

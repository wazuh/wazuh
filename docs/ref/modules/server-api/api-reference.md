# API Reference

This document covers the key API endpoints with practical examples, the `q` query filter syntax, error handling, and input validation.

> All paths are validated against `api/api/spec/spec.yaml` (OpenAPI 3.0), which is the complete
> endpoint specification: parameters, bodies, responses and the RBAC actions of each operation
> (`x-rbac-actions`). The actions themselves are listed in [RBAC](../rbac/README.md#actions-reference).

---

## Common Query Parameters

Most `GET` endpoints that return a list accept these standard parameters (`pretty` and `wait_for_complete` are accepted by almost every endpoint):

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `pretty` | boolean | `false` | Human-readable output |
| `wait_for_complete` | boolean | `false` | Disable the request timeout (`intervals.request_timeout`) |
| `offset` | int | `0` | First element to return (max: 2,147,483,647) |
| `limit` | int | `500` | Max elements to return (1 to 100,000) |
| `search` | string | — | Free-text search (prefix `-` for complementary) |
| `sort` | string | — | Sort by fields (comma-separated, dot notation for nested); one leading `+` (asc, default) or `-` (desc) applies to the whole list, e.g. `-name,id` |
| `select` | string | — | Fields to return (comma-separated) |
| `q` | string | — | Query filter (see [Query filter syntax](#query-filter-syntax)) |
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

The token expires after `auth_token_exp_timeout` seconds (900 by default). `DELETE /security/user/authenticate` logs out, invalidating every token of the current user; called with a `run_as` token it invalidates only the tokens granted for the same authorization context, since the account that logged in is shared by every end user it logs in.

### Update token expiration

`auth_token_exp_timeout` takes an integer of at least `30` through this endpoint.

```bash
curl -k -X PUT "https://localhost:55000/security/config" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"auth_token_exp_timeout": 1800}'
```

> **Note:** Changing (`PUT`) or resetting (`DELETE`) the security configuration revokes all existing tokens.

---

## Key Endpoints & Examples

### API Info

**`GET /`** — Returns the API title, version, revision, license, hostname, and timestamp. It needs a token but no RBAC action.

```bash
curl -k -X GET "https://localhost:55000/?pretty=true" \
  -H "Authorization: Bearer $TOKEN"
```

```json
{
  "data": {
    "title": "Wazuh API REST",
    "api_version": "5.0.0",
    "revision": "rc2",
    "license_name": "GPL 2.0",
    "license_url": "https://github.com/wazuh/wazuh/blob/v5.0.0-rc2/LICENSE",
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

# Filter with q: active agents whose OS name contains "Ubuntu"
curl -k -X GET "https://localhost:55000/agents?q=status%3Dactive%3Bos.name~Ubuntu&pretty=true" \
  -H "Authorization: Bearer $TOKEN"

# Select specific fields
curl -k -X GET "https://localhost:55000/agents?select=id,name,status,ip&sort=-id&pretty=true" \
  -H "Authorization: Bearer $TOKEN"
```

Key filters: `agents_list`, `status`, `older_than`, `os.type`, `os.platform`, `os.version`, `os.major`, `os.minor`, `os.arch`, `os.name`, `version`, `group`, `name`, `ip`, `registerIP` (an exact match against the stored text; IPv4, IPv6 and CIDR values such as `10.0.0.0/24` are accepted, so an agent registered for a range is found by that range; an IPv6 value matches in any spelling, compact or expanded, since it is rewritten to the expanded form the manager stores, for example `fd00:e2e::/64` to `FD00:0E2E:0000:0000:0000:0000:0000:0000/64`). A mask is **not** rewritten: registration stores a single address without its mask and a network as `<address>/<prefix length>`, so `10.250.0.1/32` or `10.250.6.0/255.255.255.0` finds nothing — give `10.250.0.1` and `10.250.6.0/24`.

`version` is rewritten to the form a 4.x agent's version is stored in: `4.14.3`, `v4.14.3` and `wazuh 4.14.3` all become `wazuh v4.14.3`, which matches a 4.x agent's stored `Wazuh v4.14.3`. A 5.x agent's version is stored as `v5.0.0`, without the `Wazuh` prefix, so the `version` filter **never matches a 5.x agent**; `q` is not rewritten, so `q=version~5.0.0` (contains) finds the agents of that version in either stored form. Responses show both generations as `vX.Y.Z`. `group` matches a group name exactly, case included: `Web` and `web` are two groups. Inside `q` an IPv6 value is not rewritten and must be given in the stored, expanded form.

#### Add agent

**`POST /agents`** — Create a new agent (`name` required; `ip` defaults to the one detected). Returns the agent ID and registration key.

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

**`PUT /agents/{agent_id}/restart`** — Restart a specific agent. Requires agent v5.0.0+: an older agent fails with error `1761`.

```bash
curl -k -X PUT "https://localhost:55000/agents/002/restart?pretty=true" \
  -H "Authorization: Bearer $TOKEN"
```

#### Reload agent

**`PUT /agents/{agent_id}/reload`** — Reload configuration on a specific agent without a full restart. Requires agent v5.0.0+.

```bash
curl -k -X PUT "https://localhost:55000/agents/002/reload?pretty=true" \
  -H "Authorization: Bearer $TOKEN"
```

#### Reload agents

**`PUT /agents/reload`** — Reload configuration on all agents or a specified list. Requires agent v5.0.0+.

```bash
# Reload all agents
curl -k -X PUT "https://localhost:55000/agents/reload?pretty=true" \
  -H "Authorization: Bearer $TOKEN"

# Reload specific agents
curl -k -X PUT "https://localhost:55000/agents/reload?agents_list=001,002&pretty=true" \
  -H "Authorization: Bearer $TOKEN"
```

#### Reload agents in group

**`PUT /agents/group/{group_id}/reload`** — Reload configuration on all agents belonging to a group. Requires agent v5.0.0+.

```bash
curl -k -X PUT "https://localhost:55000/agents/group/web-servers/reload?pretty=true" \
  -H "Authorization: Bearer $TOKEN"
```

#### Delete agents

**`DELETE /agents`** — Delete agents by ID or criteria. Requires `agents_list` and `status`. `older_than` defaults to `7d`, so only agents whose last keep alive (register date for `never_connected` ones) is older than 7 days are deleted unless another value is given; `older_than=0s` selects every agent.

Deleting an agent also removes its documents from the Wazuh Indexer (inventory state, reported
configuration and statistics), which is why its data disappears from the dashboard. That cleanup is
not part of this call: `wazuh-manager-authd` records a durable `agent_delete_indexer` task that the
task manager runs no earlier than `authd.purge_delay` (120 seconds by default) after the removal, and
retries until the indexer accepts it — see the
[Inventory Sync Server FAQ](../inventory-sync-server/README.md#faq-operations) for how to check it.

```bash
# Delete disconnected agents older than 30 days
curl -k -X DELETE "https://localhost:55000/agents?agents_list=all&status=disconnected&older_than=30d&pretty=true" \
  -H "Authorization: Bearer $TOKEN"

# Delete a specific agent permanently, whatever its last keep alive
curl -k -X DELETE "https://localhost:55000/agents?agents_list=009&status=all&older_than=0s&purge=true&pretty=true" \
  -H "Authorization: Bearer $TOKEN"
```

#### Agent overview

**`GET /overview/agents`** — Full summary: status counts, OS distribution, versions, groups, and last registered agent.

```bash
curl -k -X GET "https://localhost:55000/overview/agents?pretty=true" \
  -H "Authorization: Bearer $TOKEN"
```

#### Trigger vulnerability scan

**`PUT /agents/scan/vulnerability`** — Request an on-demand Vulnerability Detection scan for all agents or a specified list. All agents are selected by default if `agents_list` is not specified.

```bash
# Scan all agents
curl -k -X PUT "https://localhost:55000/agents/scan/vulnerability?pretty=true" \
  -H "Authorization: Bearer $TOKEN"

# Scan specific agents
curl -k -X PUT "https://localhost:55000/agents/scan/vulnerability?agents_list=001,003&pretty=true" \
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
curl -k -X PUT "https://localhost:55000/security/user/revoke" \
  -H "Authorization: Bearer $TOKEN"
```

---

### MITRE ATT&CK

The bundled dataset is MITRE ATT&CK Enterprise **v19.2** (STIX 2.0 bundle from github.com/mitre/cti), loaded into `var/db/mitre.db` at installation time.
`GET /mitre/metadata` does not report that release: its `mitre_version` is the bundle's STIX
`spec_version` (`2.0`), and `db_version` the version of the database layout.

**`GET /mitre/techniques`** — Query MITRE techniques with full details (tactics, mitigations, software, groups, references).

```bash
# Search for specific technique
curl -k -X GET "https://localhost:55000/mitre/techniques?search=phishing&limit=3&pretty=true" \
  -H "Authorization: Bearer $TOKEN"

# Get by ATT&CK ID (T1566); `technique_ids` takes the STIX IDs (attack-pattern--…) instead
curl -k -X GET "https://localhost:55000/mitre/techniques?q=external_id%3DT1566&pretty=true" \
  -H "Authorization: Bearer $TOKEN"
```

Other MITRE endpoints: `/mitre/tactics`, `/mitre/groups`, `/mitre/software`, `/mitre/mitigations`, `/mitre/references`, `/mitre/metadata`.

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
| POST | `/agents/enrollment-tokens` | Mint an enrollment token (the `token` is returned once) |
| GET | `/agents/enrollment-tokens` | List enrollment tokens (never their credential) |
| DELETE | `/agents/enrollment-tokens/{token_id}` | Revoke an enrollment token |
| DELETE | `/agents/enrollment-tokens` | Purge enrollment tokens: `status=dead` (default) removes the ones that can no longer enrol anybody, `status=all` empties the store |
| PUT | `/agents/{agent_id}/restart` | Restart agent (v5.0.0+) |
| PUT | `/agents/{agent_id}/reload` | Reload agent config (v5.0.0+) |
| GET | `/agents/{agent_id}/key` | Get agent key. Requires `agent:read_secrets` over that agent, not `agent:read`; serving the key is logged as `secret_read` |
| DELETE | `/agents/{agent_id}/group` | Remove from all groups |
| PUT | `/agents/{agent_id}/group/{group_id}` | Assign to group |
| DELETE | `/agents/{agent_id}/group/{group_id}` | Remove from group |
| PUT | `/agents/restart` | Restart all (v5.0.0+) |
| PUT | `/agents/reload` | Reload all agents config (v5.0.0+) |
| PUT | `/agents/group` | Bulk assign to group |
| DELETE | `/agents/group` | Bulk remove from group |
| PUT | `/agents/group/{group_id}/restart` | Restart group (v5.0.0+) |
| PUT | `/agents/group/{group_id}/reload` | Reload group config (v5.0.0+) |
| GET | `/agents/no_group` | Without group |
| GET | `/agents/outdated` | Agents older than the manager (versions compared as versions, `5.0.0` equals `v5.0.0`; only major, minor and patch count, as in the upgrade check, so `v5.0.0-rc1` is not outdated against a `v5.0.0` manager) |
| PUT | `/agents/upgrade` | Upgrade agents |
| PUT | `/agents/upgrade_custom` | Custom upgrade |
| PUT | `/agents/scan/vulnerability` | Request on-demand vulnerability scan |
| GET | `/agents/uninstall` | Check whether the calling user holds `agent:uninstall` (resource `*:*:*`); it takes no agent list |
| GET | `/agents/stats/distinct` | Distinct fields: one row per combination of the `fields` values, with the `count` of agents that have it; `total_affected_items` counts the rows |
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
| GET | `/groups/{group_id}/configuration` | Group config, as JSON: one entry per set of `<agent_config>` filters, with those `filters` and the `config` of every block that has them. Sections are keyed by tag (a wodle by its `name`); `syscheck`, `rootcheck`, `sca`, `syscollector` and `client` sections are merged into one object, any other section is a list with one object per occurrence, including sections the manager does not know |
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
| GET | `/cluster/local/config` | Local node config. The cluster key comes back masked unless the caller holds `cluster:read_secrets` over this node |
| GET | `/cluster/api/config` | API config |
| PUT | `/cluster/restart` | Restart cluster |
| PUT | `/cluster/reload` | Restart manager daemons on all nodes, or a given list, keeping active agent connections |
| GET | `/cluster/configuration/validation` | Validate config |
| GET | `/cluster/{node_id}/status` | Node status |
| GET | `/cluster/{node_id}/info` | Node info |
| GET | `/cluster/{node_id}/configuration` | Node config. Sensitive values are masked unless the caller holds `cluster:read_secrets` over that node |
| PUT | `/cluster/{node_id}/configuration` | Update node config. A cluster key sent back masked keeps the current one; changing it, or changing the indexer section, requires `cluster:read_secrets` over that node (`1132` otherwise) |
| GET | `/cluster/{node_id}/configuration/{component}/{configuration}` | Active config. `auth/auth` carries the enrollment password, masked unless the caller holds `cluster:read_secrets` over that node; serving it in clear is logged as `secret_read` in that node's `cluster.log` |
| GET | `/cluster/{node_id}/daemons/stats` | Daemon stats |
| GET | `/cluster/{node_id}/daemons/remoted/tls` | TLS certificate validity of remoted's listener and its CA bundle (dates, `x509-sha256` identities, which CA signs the leaf). `available: false` with a `reason` when remoted on that node cannot answer |
| GET | `/cluster/{node_id}/logs` | Node logs |
| GET | `/cluster/{node_id}/logs/summary` | Log summary |

### Security
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/security/user/authenticate` | Login (get JWT) |
| DELETE | `/security/user/authenticate` | Logout (invalidate all of the current user's tokens, or of the current authorization context with a `run_as` token) |
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

### Overview
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/overview/agents` | Agent overview |

</details>

---

## Query filter syntax

The `q` parameter allows server-side filtering of large datasets, reducing payload size and avoiding client-side filtering.

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
| `~` | Contains (SQL `LIKE`) |

Any other operator (`>=`, `<=`, `~=`) is rejected: with error `1409` (*Invalid query operator*) on the
collections whose `q` is turned into a `wazuh-manager-db` query (agents), and with error `1407` (*Query does
not match expected format*) on the collections the framework filters in memory (groups, MITRE, users,
roles, policies, enrollment tokens and cluster nodes, for example).
Clauses can be grouped with parentheses: `(status=active,status=pending);os.platform=ubuntu`.

### Connectors

| Connector | Meaning |
|-----------|---------|
| `;` | AND |
| `,` | OR |

### Value types on in-memory collections

Endpoints whose records are filtered in memory rather than in SQL — `/agents/enrollment-tokens`
among them — accept `=`, `!=`, `<`, `>` and `~` only, and read the literal as the type of the field
it is compared against. With `=`, `!=`, `<` and `>`, a date field takes `YYYY-MM-DD`,
`YYYY-MM-DDTHH:MM:SSZ`, `YYYY-MM-DD HH:MM:SS` or `YYYY-MM-DDTHH:MM:SS.ffffffZ`
(`q=created>2026-01-01`), all read as UTC, or a timestamp with a numeric UTC offset —
`YYYY-MM-DDTHH:MM:SS±HH:MM`, optionally with `.ffffff` fractional seconds, a space instead of the
`T`, or the offset written `±HHMM` — converted to UTC before it is compared, so a timestamp read back
from a response body (`2026-01-01T00:00:00+00:00`) can be passed back as-is with every operator.
Encode a `+` in the offset as `%2B` in the URL; left bare, it is decoded as a space and the literal is
no longer a date but plain text, which a date field cannot be ordered against (`<`/`>` answer 400,
`=` matches nothing, `!=` matches every record). A date's stored value keeps second-level precision, so `=`/`!=` need the
full timestamp to match a specific record (`q=created=2026-01-01T00:00:00Z`); a bare `YYYY-MM-DD`
parses as exact midnight UTC and matches only a record created at that instant. Bound a whole day
with `<`/`>` instead.

With `=` and `!=`, a boolean field takes `true`, `false`, `1` or `0` (`q=revoked=true`; any other
literal is rejected with a 400). A date-shaped literal against a boolean field is read as a date
rather than an unrecognized literal, so it takes a different path than that 400 and falls through
to Python's own cross-type comparison: `=` matches nothing and `!=` matches everything. A literal
whose type the field cannot address is a property of the record, not of the query -- the same
clause evaluates normally against a differently-typed record -- so it excludes only its own record,
and `q` is reported invalid with a 400 once, after the whole collection, only when no record could
evaluate the clause at all. A field that no record has is not an error here: `q=nosuchfield=x` answers
`200` with no items, where the agents collection, filtered in SQL, refuses it with error `1408`
(*Field does not exist*, listing the available fields). The `search` parameter is case-insensitive and matches the
rendered value, so `search=true` also finds records
whose boolean field is set. `~` is case-sensitive on a boolean field, unlike `=`/`!=`/`search`: it
matches the exact rendered value (`q=revoked~True`, `q=revoked~False`), not `true`/`false`.

### Examples

```bash
# Active agents
curl -k -X GET "https://localhost:55000/agents?q=status%3Dactive" \
  -H "Authorization: Bearer $TOKEN"

# Active agents whose OS name contains "Ubuntu"
curl -k -X GET "https://localhost:55000/agents?q=status%3Dactive%3Bos.name~Ubuntu" \
  -H "Authorization: Bearer $TOKEN"

# Agents whose OS platform is set and is not Windows (`!=` never matches a NULL field, so agents that have
# never connected, which have no OS yet, are left out)
curl -k -X GET "https://localhost:55000/agents?q=os.platform!%3Dwindows" \
  -H "Authorization: Bearer $TOKEN"
```

---

## Error Handling

Errors follow a structured JSON response format.

### HTTP Status Codes

| HTTP Code | Meaning           | Notes                    |
|-----------|-------------------|--------------------------|
| 400       | Bad Request       | Invalid parameters       |
| 401       | Unauthorized      | Invalid credentials, or an invalid or expired token |
| 403       | Forbidden         | RBAC denied, or the client IP is blocked after too many failed logins (`6000`) |
| 404       | Not Found         | Invalid endpoint, or the named resource does not exist: a group (`1710`), a file in a group (`1006`), a cluster node (`1730`), an enrollment token (`1767`) |
| 405       | Method Not Allowed | Invalid HTTP method     |
| 413       | Payload Too Large | Request body too large. The body carries `"error": 413` (the HTTP status, not an error code) |
| 415       | Unsupported Media Type | A `Content-Type` the operation does not accept, or a body sent with no `Content-Type` at all (`6002`), on every operation that takes a body, the `run_as` login included |
| 417       | Expectation Failed | An `Expect` header other than `100-continue` |
| 429       | Too Many Requests | Rate limit exceeded (`6001` authenticated, `6005` unauthenticated), or too many logins already waiting for their password check (`6006`) |
| 500       | Internal Error    | Check manager logs       |

### Exception Hierarchy

All exceptions inherit from `WazuhException` (defined in `core/exception.py`), with a numeric error code catalog:

| Range | Category | Examples |
|-------|----------|----------|
| 900–901 | API process pool errors | Child process terminated, executor failure |
| 999–1099 | Core Wazuh errors | Incompatible Python, internal error, command errors, socket issues |
| 1100–1199 | Configuration errors | Invalid section/field/type, validation, protected options (`1127`, `1129`, `1132`) |
| 1300–1399 | Statistics errors | Invalid parameters |
| 1400–1499 | Query and pagination errors | Invalid offset/limit/sort, invalid `q` query filter or operator, invalid time frame |
| 1700–1799 | Agent errors | Agent not found, duplicate, version mismatch |
| 1900–1999 | Manager errors | Control socket, configuration validation, request body |
| 2000–2099 | Internal service errors | wazuh-db, engine, modulesd and remoted admin sockets |
| 2200–2299 | Indexer errors | Connection, credentials |
| 3000–3999 | Cluster errors | Cluster configuration, distributed API requests, worker not connected |
| 4000–4500 | RBAC errors | Permission denied, invalid role/policy/resources |
| 5000–5999 | User management errors | User not found, insecure password, invalid `allow_run_as` |
| 6000–6999 | Security errors | Blocked IP, request rate limit reached, login queue full, `run_as` not enabled for the user |
| 8000–8999 | Vulnerability scan errors | Scanner or feed not ready, scan queue full |

Error responses include a `dapi_errors` field in cluster deployments.

Agents are the exception to the 404 rule. Every endpoint that names agents, the single-agent paths
included (`GET /agents/{agent_id}/key`, `PUT /agents/{agent_id}/group/{group_id}`,
`PUT /agents/{agent_id}/restart`), answers `200` with the unknown agent as a failed item (`1701`), the
same shape a list of agents gets, where some may exist and others not. A missing group or cluster node
named in the same request is still a `404`, except in the node lists of `GET /cluster/nodes`,
`GET /cluster/healthcheck` and `GET /cluster/configuration/validation` (`nodes_list`): there an unknown
node is a failed item (`1730`, *Node does not exist*) of a `200` answer, next to the nodes that exist.

While one of the core daemons (`wazuh-manager-modulesd`, `wazuh-manager-analysisd`, `wazuh-manager-db`,
`wazuh-manager-remoted`) is stopped, failed or restarting, requests are refused with `500` and error
`1017`, naming the node and the daemons. Logging in and out, the status and health endpoints
(`GET /cluster/status`, `GET /cluster/healthcheck`, `GET /cluster/{node_id}/status`) and
`PUT /cluster/restart` and `PUT /cluster/reload` keep working, so a node can be inspected and restarted
remotely. They work without `wazuh-manager-modulesd` too: when its control socket (`control.sock`) does not
exist or refuses the connection, the node runs `bin/wazuh-manager-service-control restart|reload` itself
(the helper modulesd would run) and logs a `WARNING` naming the socket error. The node waits up to 5
seconds for the helper to accept, then up to 4 more for the configuration and credentials check it runs
before handing the action to systemd. A refusal in either is a failed item `1904` (*The manager
service-control helper refused the restart request*, with its exit code and reason, such as `the manager
configuration or credentials check failed; the manager was not restarted`), and the manager keeps running; a
helper that cannot be run is `1903`. A failure the node no longer waits for (a longer check, or `systemctl`
itself) is logged as an `ERROR` in `api.log` (`cluster.log` on a worker): `The manager restart run by
wazuh-manager-service-control failed (exit code 1): …`. While modulesd runs, the request goes through its
control socket instead, which answers as soon as the helper accepts. See
[the control module](../control/README.md#manager-restart-and-reload).

These codes are the framework's catalog (`framework/wazuh/core/exception.py`). The API process has a
separate, startup-only catalog (`api/api/api_exception.py`) whose codes overlap numerically: `2000`
invalid `api.yaml`, `2003` TLS certificate errors, `2004` configuration file not loadable, `2010`
address already in use, `2011` logger setup error, `2012` `rbac.db` absent or failing its integrity check. They stop
`wazuh-manager-apid` from starting and are printed as *Error when trying to start the Wazuh API* (or
logged in `api.log` once the logger is set up); they are never returned to a client.

---

## Input Validation

The API layer (`api/validator.py`) validates all inputs with pre-compiled regex patterns before they reach the framework:

| Pattern | Description |
|---------|-------------|
| Hashes | MD5 (32), SHA1 (40), SHA224 (56), SHA256 (64), SHA384 (96), SHA512 (128) |
| Groups | Group name validation (excludes `.`, `..`, `all`) |
| Base64 | Standard base64 encoded strings |
| Dates | Date and datetime format validation |
| `q` filter | Query syntax (`field operator value;connector`) |
| XML | Parsed with `defusedxml` |
| Special chars | Separate patterns for names vs. paths |

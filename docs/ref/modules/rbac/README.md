# RBAC

Wazuh RBAC (Role-Based Access Control) decides what each user of the [Server API](../server-api/README.md)
may do. Every API operation declares the RBAC actions it needs (`x-rbac-actions` in
`api/api/spec/spec.yaml`), and the framework checks them, against the resources the request touches,
before any logic runs.

The RBAC data lives in `/var/wazuh-manager/api/configuration/security/rbac.db` on the master node,
seeded from `framework/wazuh/rbac/default/*.yaml`, and is managed through the `/security` endpoints.

---

## Model

| Object | What it is |
|--------|------------|
| User | An API account. Authenticates with `POST /security/user/authenticate` |
| Role | A named set of policies, linked to users directly or through rules |
| Policy | A list of `actions`, a list of `resources` and an `effect` (`allow` or `deny`) |
| Rule | A condition on an authorization context. A user with `allow_run_as` that logs in with `POST /security/user/authenticate/run_as` receives the roles of every rule its context matches — this is how the Wazuh dashboard maps its logged-in user to Wazuh roles (a "role mapping") |

`rbac_mode` in the [security configuration](../server-api/configuration.md#rbac_mode) sets what an
action no policy mentions gets: `white` (the default) denies it, `black` allows it. A user's policies
are applied in order (its roles, then each role's policies, by the `position` they were linked at), and
a later policy overrides an earlier one on the same resource: a `deny` applied after an `allow` removes
that resource.

### Resources

A policy resource is `<type>:<field>:<value>`, with `*` as a wildcard value (`agent:id:*`,
`agent:group:web`, `node:id:master-node`). Actions that act on no existing resource use `*:*:*`.

| Resource | References |
|----------|------------|
| `*:*` | Resourceless actions (creating something, reading global state) |
| `agent:id` | Agents by ID (`agent:id:001`) |
| `agent:group` | Agents by group name (`agent:group:web`) |
| `group:id` | Agent groups by name (`group:id:default`) |
| `node:id` | Cluster nodes by name (`node:id:worker1`) |
| `policy:id`, `role:id`, `rule:id`, `user:id` | Security resources by ID (`role:id:1`) |

`GET /security/actions` and `GET /security/resources` return this catalog from the running API.

---

## Actions reference

The 34 actions of `x-rbac-catalog` in `api/api/spec/spec.yaml`, with the endpoints that require them.

### Agents and enrollment tokens

| Action | Resources | Endpoints |
|--------|-----------|-----------|
| `agent:create` | `*:*` | `POST /agents`, `POST /agents/insert`, `POST /agents/insert/quick` |
| `agent:read` | `agent:id`, `agent:group` | `GET /agents`, `/agents/no_group`, `/agents/outdated`, `/agents/stats/distinct`, `/agents/summary`, `/agents/summary/os`, `/agents/summary/status`, `/groups/{group_id}/agents`, `/overview/agents` |
| `agent:read_secrets` | `agent:id`, `agent:group` | `GET /agents/{agent_id}/key` |
| `agent:delete` | `agent:id`, `agent:group` | `DELETE /agents` |
| `agent:modify_group` | `agent:id`, `agent:group` | `PUT`/`DELETE /agents/{agent_id}/group/{group_id}`, `DELETE /agents/{agent_id}/group`, `PUT`/`DELETE /agents/group` |
| `agent:restart` | `agent:id`, `agent:group` | `PUT /agents/{agent_id}/restart`, `/agents/restart`, `/agents/group/{group_id}/restart` (agents v5.0.0+) |
| `agent:reload` | `agent:id`, `agent:group` | `PUT /agents/{agent_id}/reload`, `/agents/reload`, `/agents/group/{group_id}/reload` (agents v5.0.0+) |
| `agent:upgrade` | `agent:id`, `agent:group` | `PUT /agents/upgrade`, `/agents/upgrade_custom` |
| `agent:scan_vulnerability` | `agent:id`, `agent:group` | `PUT /agents/scan/vulnerability` |
| `agent:uninstall` | `*:*` | `GET /agents/uninstall` |
| `enrollment_token:create` | `*:*` | `POST /agents/enrollment-tokens` |
| `enrollment_token:read` | `*:*` | `GET /agents/enrollment-tokens` |
| `enrollment_token:delete` | `*:*` | `DELETE /agents/enrollment-tokens`, `DELETE /agents/enrollment-tokens/{token_id}` |

### Groups

| Action | Resources | Endpoints |
|--------|-----------|-----------|
| `group:create` | `*:*` | `POST /groups` |
| `group:read` | `group:id` | `GET /groups`, `/groups/{group_id}/agents`, `/groups/{group_id}/configuration`, `/groups/{group_id}/files`, `/groups/{group_id}/files/{file_name}`, `/overview/agents` |
| `group:update_config` | `group:id` | `PUT /groups/{group_id}/configuration` |
| `group:delete` | `group:id` | `DELETE /groups` |
| `group:modify_assignments` | `group:id` | The same five group-assignment endpoints as `agent:modify_group` |

Changing an agent's group needs **both** `agent:modify_group` over the agent and
`group:modify_assignments` over the group.

### Cluster

| Action | Resources | Endpoints |
|--------|-----------|-----------|
| `cluster:status` | `*:*` | `GET /cluster/status` |
| `cluster:read` | `node:id` | `GET /cluster/nodes`, `/cluster/healthcheck`, `/cluster/local/info`, `/cluster/local/config`, `/cluster/configuration/validation`, `/cluster/{node_id}/status`, `/cluster/{node_id}/info`, `/cluster/{node_id}/configuration`, `/cluster/{node_id}/configuration/{component}/{configuration}`, `/cluster/{node_id}/daemons/stats`, `/cluster/{node_id}/daemons/remoted/tls`, `/cluster/{node_id}/logs`, `/cluster/{node_id}/logs/summary`; `PUT /cluster/restart`, `/cluster/reload` |
| `cluster:read_secrets` | `node:id` | Unmasks the enrollment password and cluster key in `GET /cluster/local/config`, `/cluster/{node_id}/configuration` and `/cluster/{node_id}/configuration/{component}/{configuration}`; needed to change the cluster key with `PUT /cluster/{node_id}/configuration` |
| `cluster:update_config` | `node:id` | `PUT /cluster/{node_id}/configuration` |
| `cluster:read_api_config` | `*:*` | `GET /cluster/api/config` |
| `cluster:restart` | `node:id` | `PUT /cluster/restart`, `/cluster/reload` |

See [Sensitive configuration values](../server-api/authentication.md#sensitive-configuration-values)
for how `cluster:read_secrets` is checked.

### Security

| Action | Resources | Endpoints |
|--------|-----------|-----------|
| `security:create` | `*:*` | `POST /security/roles`, `/security/policies`, `/security/rules` |
| `security:create_user` | `*:*` | `POST /security/users` |
| `security:read` | `policy:id`, `role:id`, `rule:id`, `user:id` | `GET /security/users`, `/security/roles`, `/security/policies`, `/security/rules` |
| `security:update` | `policy:id`, `role:id`, `rule:id`, `user:id` | `PUT /security/users/{user_id}`, `/security/roles/{role_id}`, `/security/policies/{policy_id}`, `/security/rules/{rule_id}`; `POST /security/users/{user_id}/roles`, `/security/roles/{role_id}/policies`, `/security/roles/{role_id}/rules` |
| `security:delete` | `policy:id`, `role:id`, `rule:id`, `user:id` | `DELETE /security/users`, `/security/roles`, `/security/policies`, `/security/rules`, `/security/users/{user_id}/roles`, `/security/roles/{role_id}/policies`, `/security/roles/{role_id}/rules` |
| `security:edit_run_as` | `*:*` | `PUT /security/users/{user_id}/run_as` |
| `security:read_config` | `*:*` | `GET /security/config` |
| `security:update_config` | `*:*` | `PUT`/`DELETE /security/config` |
| `security:revoke` | `*:*` | `PUT /security/user/revoke` |

Enabling `allow_run_as`, and resetting another user's password, also need `security:update` over the
roles that user can reach: see [Default Users](../server-api/authentication.md#default-users).

### MITRE

| Action | Resources | Endpoints |
|--------|-----------|-----------|
| `mitre:read` | `*:*` | `GET /mitre/techniques`, `/mitre/tactics`, `/mitre/groups`, `/mitre/software`, `/mitre/mitigations`, `/mitre/references`, `/mitre/metadata` |

### Endpoints without an action

`GET /`, the login and logout endpoints (`POST`/`DELETE /security/user/authenticate`,
`POST /security/user/authenticate/run_as`), `GET /security/users/me`,
`GET /security/users/me/policies`, `GET /security/actions` and `GET /security/resources` need a valid
token (or, for the logins, valid credentials) but no RBAC action.

### Notes on specific actions

`agent:read_secrets` gates `GET /agents/{agent_id}/key`, which returns the agent's pre-shared key.
`agent:read` does not grant key export: it covers agent information (id, name, group, last keep alive,
OS, status) and nothing else. The action is scopable per agent and per group like `agent:read`, and
it sits in the `secrets_read` policy alongside `cluster:read_secrets`, so the only built-in role that
holds it is `administrator`. `agents_admin` and `wazuh_indexer_admin`, which manage agents through
`agents_all`, do not export their keys; neither do `readonly` and `agents_readonly`. That division
holds in `rbac_mode: white`, the shipped mode; under `black` mode every action no policy explicitly
denies is allowed, so `agent:read_secrets` is granted there by default, as is any newly added action.
Provisioning is unaffected either way: `agent:create` stays in `agents_all` and `POST /agents` still
answers with the key of the agent it just created, so what needs `administrator` is re-reading the
key of an agent that already exists. Every key served is recorded as a `secret_read` audit line
naming the caller and the agents, never a key.

`agent:restart` and `agent:reload` are dispatched as task manager tasks that the agent fetches; an
agent older than v5.0.0 is refused with error `1761`.

---

## Default roles and policies

Seeded into a new `rbac.db` from `framework/wazuh/rbac/default/`. An existing database is not
re-seeded with new defaults unless `CURRENT_ORM_VERSION` in `framework/wazuh/rbac/orm.py` changes
(see [Default Users](../server-api/authentication.md#default-users)).

| Role | Policies | Rules |
|------|----------|-------|
| `administrator` | `agents_all`, `security_all`, `cluster_all`, `mitre_read`, `secrets_read` | `wui_elastic_admin`, `wui_opensearch_admin` |
| `readonly` | `agents_read`, `cluster_read`, `mitre_read` | `wazuh_indexer_readonly`, `wazuh_indexer_demo` |
| `wazuh_indexer_admin` | `agents_all`, `security_read`, `cluster_all`, `mitre_read` | `wazuh_indexer_admin` |
| `users_admin` | `users_all` | — |
| `agents_readonly` | `agents_read` | — |
| `agents_admin` | `agents_all` | — |
| `cluster_readonly` | `cluster_read` | — |
| `cluster_admin` | `cluster_all` | — |

| Policy | Allows |
|--------|--------|
| `agents_all` | `agent:create`, `group:create`, `agent:uninstall`, `enrollment_token:create`/`read`/`delete` on `*:*:*`; `agent:read`, `delete`, `modify_group`, `restart`, `reload`, `upgrade`, `scan_vulnerability` on every agent; `group:read`, `delete`, `update_config`, `modify_assignments` on every group |
| `agents_read` | `enrollment_token:read`; `agent:read` on every agent; `group:read` on every group |
| `security_all` | `security:create`, `create_user`, `read_config`, `update_config`, `revoke`, `edit_run_as`; `security:read`, `update`, `delete` on every role, policy, user and rule |
| `security_read` | `security:read_config`; `security:read` on every role, policy, user and rule |
| `users_all` | `security:create_user`, `revoke`, `edit_run_as`; `security:read`, `update`, `delete` on every user |
| `users_modify_run_as` | `security:edit_run_as` (linked to no default role) |
| `cluster_all` | `cluster:status`, `update_config`, `restart` on `*:*:*`; `cluster:read_api_config`, `read`, `restart`, `update_config` on every node |
| `cluster_read` | `cluster:status`, `read`, `read_api_config` on `*:*:*`; `cluster:read_api_config`, `read` on every node |
| `secrets_read` | `cluster:read_secrets` on every node; `agent:read_secrets` on every agent (`agent:id:*`) |
| `mitre_read` | `mitre:read` |

The default users `wazuh` and `wazuh-wui` both hold `administrator`; see
[Default Users](../server-api/authentication.md#default-users).

### Default rules

| Rule | Matches the authorization context |
|------|-----------------------------------|
| `wui_elastic_admin` | `username` is `elastic` |
| `wui_opensearch_admin` | `user_name` is `admin` |
| `wazuh_indexer_admin` | `user_name` is `wazuh-admin` |
| `wazuh_indexer_readonly` | `user_name` is `wazuh-readonly` |
| `wazuh_indexer_demo` | `user_name` is `wazuh-demo` |

These reserved rules are evaluated only for the `wazuh-wui` user (ID 2); rules created through the API
apply to any user with `allow_run_as`.

---

## Mapping dashboard users to Wazuh roles

The Wazuh dashboard authenticates to the API as `wazuh-wui` with `run_as` enabled
(`wazuh_core.hosts.<host>.run_as: true` in the dashboard's `opensearch_dashboards.yml`), sending the
logged-in indexer user as the authorization context. A **role mapping** created in the dashboard
(**Server management** > **Security** > **Roles mapping**) is a rule linked to a Wazuh role: every
dashboard user it matches receives that role.

### Give a user administrator permissions

1. Create the internal user in the indexer security plugin (dashboard: **Indexer management** >
   **Security** > **Internal users**).
2. Create a role mapping with the role `administrator` and that internal user.
3. Log in again in the dashboard as that user.

### Give a user read-only permissions

1. Create the internal user in the indexer security plugin, with an indexer role that grants read access.
2. Create a role mapping with the role `readonly` and that internal user.

### Use case: read and manage a group of agents

Agents `001` and `003` belong to group `Team_A`. To let a user see only them:

1. Create a policy that allows `agent:read` over `agent:group:Team_A`:

    ```bash
    curl -k -X POST "https://localhost:55000/security/policies" \
      -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
      -d '{"name": "team_a_read", "policy": {"actions": ["agent:read"], "resources": ["agent:group:Team_A"], "effect": "allow"}}'
    ```

2. Create a role (`POST /security/roles`) and link the policy to it
   (`POST /security/roles/{role_id}/policies?policy_ids=<id>`).
3. Create a role mapping from the user to that role, as above.

In `rbac_mode: white` the user then lists only the agents of `Team_A`. To restrict what the same user
sees in the indexer, give its indexer role document-level security on the group field of the indices
it reads.

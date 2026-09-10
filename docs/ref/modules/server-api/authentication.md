# Authentication & Security

All access to the Wazuh Server API is protected by JWT authentication and RBAC authorization. Additional protections include rate limiting, brute-force prevention, and security headers.

---

## JWT Authentication

- All endpoints require a JWT token (except `/security/user/authenticate`)
- Tokens are short-lived (default: **900 seconds**)
- Tokens must be included in every request: `Authorization: Bearer <JWT_TOKEN>`
- Tokens are signed using **Elliptic Curve (EC) keys** generated at startup
- Authentication logic uses `PyJWT` for token encoding/decoding
- Credentials are validated against the RBAC ORM database
- Authentication **must run on the master node** in cluster deployments

### Authentication Flow

```mermaid
sequenceDiagram
    participant C as Client
    participant API as Server API
    participant Auth as authentication.py
    participant RBAC as RBAC ORM

    C->>API: POST /security/user/authenticate
    API->>Auth: Validate credentials
    Auth->>RBAC: Check user in database
    RBAC-->>Auth: User record
    Auth-->>API: Generate JWT (EC-signed)
    API-->>C: 200 + JWT token

    C->>API: GET /agents (Authorization: Bearer <token>)
    API->>Auth: Verify JWT signature
    Auth-->>API: Token valid + user context
    API->>API: Proceed with RBAC check
```

---

## Default Users

A fresh installation seeds `rbac.db` from `rbac/default/*.yaml` with exactly two users, both linked to the `administrator` role:

| ID | User | `allow_run_as` | Used by |
|----|------|----------------|---------|
| 1 | `wazuh` | No | Operators and scripts calling the API directly |
| 2 | `wazuh-wui` | Yes | The Wazuh dashboard |

Only `wazuh-wui` can authenticate with an authorization context, because resolving one into roles is the dashboard's mechanism for mapping the indexer user who logged in onto a Wazuh role (see the rules in `rbac/default/rules.yaml`). `wazuh` has no use for it, so the flag is off: `POST /security/user/authenticate/run_as` as `wazuh` answers `403` with error `6004`. Either flag can be changed with `PUT /security/users/{user_id}/run_as`.

The flag on its own does not grant the shipped mappings, which is easy to miss. `RBAChecker.get_user_roles` evaluates a rule holding a reserved ID — the five in `rules.yaml` get IDs `1..5`, while rules created through the API start at `100` — only when the caller is user ID 2. Enabling `allow_run_as` on any other account therefore lets it resolve **custom rules only**, and a context that matches one grants that role whatever the account's own role links say.

Both users are created with **the password shipped in `rbac/default/users.yaml`**, which is the username itself. They are reserved IDs (`<= MAX_ID_RESERVED`), so only another reserved user can change their password — `update_user` needs a `current_user` naming who is asking, which the API takes from the token's `sub`.

The `administrator` role these two users carry is also the only one that receives `secrets_read`,
the policy behind `cluster:read_secrets`. An `rbac.db` seeded **before** that policy existed does not
gain it — the defaults are only re-inserted when the ORM version changes — so on such an installation
even `wazuh` sees the enrollment password and the cluster key masked until the database is recreated
or the policy is added by hand.

`wazuh-manager-apid` logs a warning on every start for each of these users whose password is still the shipped one. It does not refuse to serve: the defaults are documented, and some deployments configure the credentials only after the first start.

Change them with `bin/rbac_control change-password`, which prompts for each password when run without options (an empty answer leaves that one unchanged) and can also be driven from a file so that installers and password tools can use it:

```bash
# One user, password read from the first line of a file (use '-' for the standard input)
bin/rbac_control change-password --user wazuh-wui --password-file /root/wui.pass

# Every default user in a single execution
echo '{"wazuh": "...", "wazuh-wui": "..."}' | bin/rbac_control change-password --passwords-file -
```

Passwords are never accepted as a command-line argument, so they do not reach the process list. The command exits non-zero if any requested change was not applied. A new password must satisfy the policy enforced by `framework/wazuh/security.py`: 12 to 64 characters, with a lowercase letter, an uppercase letter, a digit and a symbol. Changing `wazuh-wui`'s password requires updating the dashboard configuration to match.

### What a password change does and does not do

The policy above is enforced by `security.update_user` and `security.create_user`: a password outside 12-64 characters fails with error `5009`, one missing a character class with `5007`. A caller that is not itself a reserved user gets `5011`, however privileged its role, and these users cannot be deleted at all (`5004`).

Once a change goes through:

- It is written to the **master** node's `rbac.db`. `check_user` and `update_user` are `local_master` requests, so a worker forwards every authentication and needs no action while it stays a worker. Each node still keeps its own `rbac.db`, seeded with the default users, and the cluster does not synchronize it (`cluster.json` shares `etc/`, `etc/shared/` and `var/multigroups/` only) — so a worker promoted to master starts serving the shipped defaults again. Repeat the change on any node that may take that role.
- **No daemon restart** is required. The next `POST /security/user/authenticate` already uses the new password.
- Every token held by the modified user is **revoked immediately** (`update_user` calls `invalid_users_tokens`), so a script that changes its own user's password must authenticate again before its next call. Tokens of other users are untouched; `PUT /security/user/revoke` revokes all of them at once.
- A client left with the old password — typically a dashboard whose stored copy was not updated — is counted against `max_login_attempts` (50) and its IP is then blocked for `block_time` (300 seconds), answering `403`. The block is lifted when that time elapses, not when the password is corrected.
- No manager component authenticates with `wazuh` or `wazuh-wui`, so the keystore and the manager configuration files are unaffected. The only copy outside the manager is the dashboard's `wazuh_core.hosts.<host>.password`, which is why changing `wazuh-wui` — and only that user — needs the dashboard updated and restarted.

The step-by-step procedure, including the dashboard side and the container variants, is in [Installation](../../getting-started/installation.md#change-the-default-api-passwords).

---

## RBAC Enforcement

RBAC is enforced **before** any core logic is executed.

- Permissions are evaluated per endpoint
- Framework functions are decorated with `expose_resources` from `rbac/decorators.py`
- RBAC policies can allow or deny access even with valid tokens
- Two RBAC modes: **white** (deny by default) and **black** (allow by default)
- A `403 Forbidden` usually indicates RBAC blocking, not auth failure
- Current user, RBAC mode, and cluster context are stored in `contextvars` for request-scoped access

### Sensitive configuration values

`GET /cluster/local/config` and the two node-configuration endpoints answer with the enrollment
password (`authd.pass`) and the cluster key in them. Those two values come back masked as `*****`
unless the caller holds **`cluster:read_secrets`**, an action of its own: being allowed to change the
configuration does not entitle anyone to read the secrets inside it. It is granted by the default
policy `secrets_read`, which only the `administrator` role carries.

The action is checked **against the node that answers**, with the same matcher every other permission
goes through: a policy that grants it over `node:id:master-node` does not uncover a worker's values,
a later `deny` over the node being served wins, and in `rbac_mode: black` the values come back in
clear unless a policy denies them, as everything else does in that mode. The default policy grants
it over `node:id:*`, so an `administrator` sees them on every node.

Every disclosure is recorded as a `secret_read` line naming the user and the fields, never the value.
It lands in `logs/api.log` for `GET /cluster/local/config`, which the API process serves, and in
`logs/cluster.log` for the two node-configuration endpoints, which run inside the answering node's
`wazuh-manager-clusterd`. If the masking itself fails, the request fails: a response nobody could
mask is not served.

### RBAC Components

| File | Role |
|------|------|
| `rbac/decorators.py` | `expose_resources` decorator that enforces action/resource permissions |
| `rbac/orm.py` | ORM models for roles, policies, and user-role mappings |
| `rbac/preprocessor.py` | Resource preprocessing before permission checks |
| `rbac/default/*.yaml` | Built-in default RBAC data, loaded via `insert_default_resources` in `rbac/orm.py` |
| `rbac/auth_context.py` | Authentication context handling |

---

## Rate Limiting & Brute-Force Protection

- The API tracks failed login attempts per IP address
- After exceeding a configurable threshold, the IP is added to a blocked set
- Blocked IPs receive `429 Too Many Requests` or immediate rejection
- Rate limiting state is managed in-memory within `middlewares.py` and `error_handler.py`

---

## Security Headers

The API sets the following security headers on all responses:

| Header | Value | Purpose |
|--------|-------|---------|
| `Content-Security-Policy` | `none` | Restricts resource loading |
| `X-Frame-Options` | `DENY` | Prevents clickjacking |
| `Server` | `Wazuh` | Masks underlying server technology |

These are applied via the `secure` Python library in `middlewares.py`.

---

## Best Practices

- Handle token expiration gracefully — re-authenticate before the token expires
- Treat `403` as RBAC errors, not authentication failures
- Never embed credentials in scripts — use environment variables or secret managers
- In cluster deployments, ensure authentication calls reach the master node
- Use the `rbac_mode` setting appropriate for your security posture (`white` for strict environments)

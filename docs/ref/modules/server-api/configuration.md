# Server API Configuration Reference

Complete configuration reference for the Server API (`wazuh-manager-apid`).

The Server API is configured through YAML files, not through `wazuh-manager.conf`.

- **Module:** Manager-only; `wazuh-manager-apid` runs on the master node only
- **Configuration format:** YAML
- **Security:** JWT authentication, RBAC authorization, TLS

For module overview and architecture, see [Server API Module](README.md).

---

## Configuration files

| Path | Contents | Owner:group mode |
|------|----------|------------------|
| `/var/wazuh-manager/api/configuration/api.yaml` | API settings ([options](#api-options)). Installed as a template with every option commented out | root:wazuh-manager 0660 |
| `/var/wazuh-manager/api/configuration/security/security.yaml` | [Security settings](#security-configuration). Not installed: written by `PUT /security/config` | directory root:wazuh-manager 0770 |
| `/var/wazuh-manager/api/configuration/security/rbac.db` | RBAC database (users, roles, policies, rules) | wazuh-manager:wazuh-manager 0640 |

**XML Section:** None. **Internal Options:** None.

Both YAML files are merged over built-in defaults (`api/api/configuration.py`) and validated against a
JSON schema (`api/api/validator.py`) when `wazuh-manager-apid` starts: an unknown option or a value of
the wrong type stops it with error `2000`. Every string value is lowercased except `https.key`,
`https.cert` and `https.ca`, and the strings `yes`/`no` are read as booleans. A change to `api.yaml`
takes effect when `wazuh-manager-apid` restarts (for example with
`/var/wazuh-manager/bin/wazuh-manager-control restart`).

Validate a file without starting the API:

```bash
/var/wazuh-manager/bin/wazuh-manager-apid -t -c /var/wazuh-manager/api/configuration/api.yaml
```

It prints nothing and exits `0` when the file is valid, and prints `Configuration not valid. ERROR: ...`
and exits `1` otherwise. Without `-c`, `-t` validates only the built-in defaults.

### `wazuh-manager-apid` options

`wazuh-manager-control start` runs `wazuh-manager-apid` without arguments. The options are for manual
runs and debugging:

| Option | Effect |
|--------|--------|
| `-f` | Run in the foreground, logging to the console as well as to the log files |
| `-r` | Run as root: do not drop privileges to `wazuh-manager` (otherwise governed by [`drop_privileges`](#drop_privileges)) |
| `-c <file>` | Use this API configuration file (merged over the built-in defaults) instead of `api.yaml` |
| `-t` | Validate the configuration file given with `-c` and exit |
| `-V` | Print the version and exit |
| `-d` | Accepted, but has no effect: the log level is [`logs.level`](#logs) |

---

## API options

### host

Addresses the API listens on.

- **Default value:** `['0.0.0.0', '::']`
- **Allowed values:** List of IP addresses or host names. One socket is bound per address each entry
  resolves to (see [Startup and socket binding](architecture.md#startup-and-socket-binding)).

### port

- **Default value:** `55000`
- **Allowed values:** Number

### drop_privileges

Run the API as the `wazuh-manager` user after it has read its configuration and certificates.

- **Default value:** `true`
- **Allowed values:** `true`, `false`. Ignored when `wazuh-manager-apid` is started with `-r`.

### max_upload_size

Maximum size, in bytes, of a request body the API accepts.

- **Default value:** `10485760` (10 MB)
- **Allowed values:** Non-negative integer; `0` disables this limit
- **Note:** A request whose body exceeds this value is refused with `413 Payload Too Large` and a
  detail naming the limit, whatever its content type and whether or not it sends an
  `Expect: 100-continue` header. The refusal is also recorded in `api.log` at `WARNING` level with
  the endpoint and the limit that rejected it.
- **Note:** This is the general limit only. `POST /security/user/authenticate/run_as` is additionally
  bounded by [`auth_context_max_payload_size`](#auth_context_max_payload_size), a limit that setting
  `max_upload_size` to `0` does **not** lift: that endpoint still answers `413` for a body every other
  endpoint would accept.

### auth_context_max_payload_size

Maximum size, in bytes, of the authorization context body accepted by `POST
/security/user/authenticate/run_as`.

- **Default value:** `65536` (64 KB)
- **Allowed values:** Integer from `1024` to `1048576`
- **Note:** A body above this value is refused with `413 Payload Too Large` before the credentials are
  checked, even when `max_upload_size` is `0`. `max_upload_size`, when set, still bounds the same body,
  so the effective limit is the lower of the two.
- **Note:** Raise it when AD/LDAP/SSO logins with large group memberships are refused with `413`. The
  API buffers up to this many bytes of each `run_as` request before authenticating it.

### authentication_pool_size

Number of worker processes dedicated to authentication requests.

- **Default value:** `2`
- **Allowed values:** Integer from `1` to `50`
- **Note:** Increase for high-concurrency environments with many simultaneous login attempts

### intervals

#### request_timeout

Maximum time in seconds for API request processing.

- **Default value:** `10`
- **Allowed values:** Non-negative number (seconds, decimals allowed)
- **Note:** A request that exceeds it is answered with a timeout error, unless it is sent with
  `wait_for_complete=true`

### https

TLS settings of the listener. File names are resolved under `/var/wazuh-manager/etc/certs/` and may
contain only letters, digits, `_`, `-` and `.`.

| Option | Default | Description |
|--------|---------|-------------|
| `enabled` | `true` | Serve HTTPS. With `false` the API serves plain HTTP |
| `key` | `apid-key.pem` | Private key |
| `cert` | `apid.pem` | Certificate |
| `use_ca` | `false` | Require a client certificate signed by `ca` |
| `ca` | `root-ca.pem` | CA used to verify client certificates when `use_ca` is `true` |
| `ssl_ciphers` | `""` | OpenSSL cipher list; empty keeps the default |

The installer does not issue `apid.pem`. When `enabled` is `true` and the key or certificate is
missing, `wazuh-manager-apid` generates, at startup, a 2048-bit RSA key and a self-signed certificate
valid for one year (subject `CN=wazuh.com`, SAN `localhost`), and logs *HTTPS is enabled but cannot
find the private key and/or certificate. Attempting to generate them*. Replace them with a certificate
your clients trust and restart the API. A key that does not match the certificate stops the API with
error `2003`.

### logs

| Option | Default | Description |
|--------|---------|-------------|
| `level` | `info` | `debug2`, `debug`, `info`, `warning`, `error` or `critical` |
| `format` | `plain` | `plain` (`logs/api.log`), `json` (`logs/api.json`), or both: `plain,json` / `json,plain` |
| `max_size.enabled` | `false` | Rotate by size instead of at midnight |
| `max_size.size` | `1M` | `<number>K` or `<number>M`, at least `1M` (error `2011` otherwise) |

### cors

Cross-origin resource sharing, applied with Starlette's `CORSMiddleware`.

| Option | Default | Description |
|--------|---------|-------------|
| `enabled` | `false` | Enable CORS |
| `source_route` | `"*"` | Allowed origins |
| `expose_headers` | `"*"` | Headers exposed to the browser (string or list) |
| `allow_headers` | `"*"` | Headers allowed in requests (string or list) |
| `allow_credentials` | `false` | Allow credentials |

### access

| Option | Default | Description |
|--------|---------|-------------|
| `max_login_attempts` | `50` | Failed logins from one IP before it is blocked (`403`, error `6000`) |
| `block_time` | `300` | Seconds an IP stays blocked, counted from its last login attempt |
| `max_request_per_minute` | `300` | Authenticated requests per minute per client address (`429`, error `6001`); `0` disables it |
| `max_unauthenticated_request_per_minute` | `10` | Unauthenticated or failed-authentication requests per minute per client address (`429`, error `6005`); `0` disables it |

See [Request rate limiting](#request-rate-limiting) and
[Rate Limiting & Brute-Force Protection](authentication.md#rate-limiting--brute-force-protection).

### upload_configuration

Options of `wazuh-manager.conf` that `PUT /cluster/{node_id}/configuration` may change.

| Option | Default | Description |
|--------|---------|-------------|
| `indexer.allow` | `true` | With `false`, a new configuration that changes the `indexer` section is refused with error `1127` |
| `agents.allow_higher_versions.allow` | `true` | With `false`, a change to `auth.agents.allow_higher_versions` or `remote.agents.allow_higher_versions` is refused with error `1129` |

The cluster key is protected by RBAC rather than by this block: see
[Sensitive configuration values](authentication.md#sensitive-configuration-values).

The schema also accepts `upload_configuration.remote_commands` (`localfile`, `wodle_command`) and
`upload_configuration.limits.eps`, and a top-level `cache` block (`enabled`, `time`). Nothing reads
them: they are accepted for compatibility and have no effect.

---

## Security configuration

Stored in `api/configuration/security/security.yaml`, and read and changed through
`GET`, `PUT` and `DELETE /security/config` (`security:read_config`, `security:update_config`).
`DELETE` restores the defaults. Changing or resetting it revokes every issued token.

### auth_token_exp_timeout

JWT token expiration time in seconds.

- **Default value:** `900` (15 minutes)
- **Allowed values:** Integer; at least `30` through `PUT /security/config`
- **Note:** Shorter timeouts increase security but require more frequent re-authentication

### rbac_mode

Role-Based Access Control enforcement mode.

- **Default value:** `white`
- **Allowed values:**
  - `white` - Deny by default (recommended)
  - `black` - Allow by default
- **Note:** White-list mode provides better security by requiring explicit permission grants

---

## Configuration Examples

### Default API Configuration

The values the API uses when `api.yaml` sets nothing:

```yaml
host: ["0.0.0.0", "::"]
port: 55000
drop_privileges: true
max_upload_size: 10485760  # 10 MB
auth_context_max_payload_size: 65536  # 64 KB
authentication_pool_size: 2
intervals:
  request_timeout: 10
https:
  enabled: true
  key: apid-key.pem
  cert: apid.pem
  use_ca: false
  ca: root-ca.pem
  ssl_ciphers: ""
logs:
  level: info
  format: plain
  max_size:
    enabled: false
    size: 1M
cors:
  enabled: false
  source_route: "*"
  expose_headers: "*"
  allow_headers: "*"
  allow_credentials: false
access:
  max_login_attempts: 50
  block_time: 300
  max_request_per_minute: 300
  max_unauthenticated_request_per_minute: 10
upload_configuration:
  agents:
    allow_higher_versions:
      allow: true
  indexer:
    allow: true
```

### Secure Production Configuration

Stricter access limits, client certificates, and no configuration changes to the indexer section
through the API:

```yaml
access:
  max_login_attempts: 3
  block_time: 900  # 15 minutes
  max_request_per_minute: 100
  max_unauthenticated_request_per_minute: 10
upload_configuration:
  indexer:
    allow: false
logs:
  level: warning
https:
  enabled: true
  key: apid-key.pem    # file names only, resolved under etc/certs/
  cert: apid.pem
  use_ca: true
  ca: root-ca.pem
```

### Development Configuration

Relaxed settings for development and testing:

```yaml
drop_privileges: false
max_upload_size: 52428800  # 50 MB
auth_context_max_payload_size: 262144  # Room for large AD/LDAP group lists
authentication_pool_size: 4
intervals:
  request_timeout: 30  # Longer for debugging
cors:
  enabled: true
  source_route: "*"
  expose_headers: "*"
  allow_headers: "*"
  allow_credentials: true
access:
  max_login_attempts: 10
  block_time: 60
  max_request_per_minute: 1000
logs:
  level: debug
```

### Custom JWT Configuration

```bash
curl -k -X PUT "https://localhost:55000/security/config" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"auth_token_exp_timeout": 1800, "rbac_mode": "white"}'
```

---

## Framework Configuration

The framework reads, validates and writes the manager configuration file,
`/var/wazuh-manager/etc/wazuh-manager.conf`, by running `bin/wazuh-manager-conf`
(`framework/wazuh/core/manager_conf.py`), so the API applies exactly the validation the daemons do.
It is served and changed through `/cluster/{node_id}/configuration`. Agent group configuration
(`etc/shared/<group>/agent.conf`) is parsed with `defusedxml`. See the
[Manager Configuration Reference](../../configuration/manager/README.md) for the options.

---

## Performance Considerations

### Request Rate Limiting

Control API load using `max_request_per_minute`:

**Small deployments (<10 users):**
```yaml
access:
  max_request_per_minute: 300
```

**Medium deployments (10-50 users):**
```yaml
access:
  max_request_per_minute: 600
```

**Large deployments (50+ users):**
```yaml
access:
  max_request_per_minute: 1000
```

Requests are keyed per client address, so `max_request_per_minute` is enforced independently
for each address rather than as a single counter shared by every caller. Unauthenticated and
failed-authentication requests draw from a separate, much smaller allowance controlled by
`max_unauthenticated_request_per_minute` (default `10`), so they can't exhaust the budget an
authenticated caller shares the same address with. Setting `max_unauthenticated_request_per_minute`
to `0` disables only this sub-limit. Unlike `max_request_per_minute`, this value does not scale
with deployment size in the table above — it bounds abuse/probing traffic rather than legitimate
demand, so it stays at `10` regardless of deployment size. A request to a path or method the API
does not expose is always billed to this smaller allowance, regardless of any credential it
carries, since it never reaches the authentication step in the first place. An authenticated
caller already over its `max_request_per_minute` ceiling is rejected before authentication runs,
not after, so exceeding the ceiling does not itself cost the authentication step.

### Database Query Limits

Use pagination for large result sets:

- Default limit: 500 results (`DATABASE_LIMIT` in `framework/wazuh/core/common.py`)
- Maximum limit: 100,000 results (`MAXIMUM_DATABASE_LIMIT`)
- Use `offset` and `limit` parameters in API calls

---

## Monitoring

### Check API Status

Verify the API is running and responsive (every endpoint but the login ones needs a token):

```bash
TOKEN=$(curl -s -k -u wazuh:<PASSWORD> -X POST "https://localhost:55000/security/user/authenticate?raw=true")
curl -k -X GET "https://localhost:55000/" -H "Authorization: Bearer $TOKEN"
```

`/var/wazuh-manager/bin/wazuh-manager-control status` reports `wazuh-manager-apid is running...` on
the master; see [Startup and socket binding](architecture.md#startup-and-socket-binding) for the case
where it runs but is not yet listening.

### View API Logs

Monitor API activity and errors:

```bash
# Plain-text log (requests, errors and startup messages), when logs.format includes plain
tail -f /var/wazuh-manager/logs/api.log

# Same events as JSON, one object per line, when logs.format includes json
tail -f /var/wazuh-manager/logs/api.json
```

### Authentication Monitoring

Track failed logins (access log lines of the login endpoints answered `401`):

```bash
grep -E '"POST /security/user/authenticate(/run_as)?" .*: 401$' /var/wazuh-manager/logs/api.log
```

### Performance Metrics

Check API response times and request rates:

```bash
# Requests logged so far
grep -cE '"(GET|POST|PUT|DELETE) ' /var/wazuh-manager/logs/api.log

# Slow requests (>1s)
grep -E 'done in [1-9][0-9]*\.[0-9]{3}s:' /var/wazuh-manager/logs/api.log
```

---

## Troubleshooting

### API Won't Start

**Validate the configuration:**
```bash
/var/wazuh-manager/bin/wazuh-manager-apid -t -c /var/wazuh-manager/api/configuration/api.yaml
```

**Check the startup errors** (bind failures, certificates, logger, `rbac.db` integrity):
```bash
grep -E 'ERROR|CRITICAL' /var/wazuh-manager/logs/api.log | tail
```

**Verify permissions:**
```bash
ls -l /var/wazuh-manager/api/configuration/api.yaml
# Should be owned by root:wazuh-manager with mode 0660
```

### Authentication Failures

**Check token expiration and RBAC mode:**
```bash
curl -k -H "Authorization: Bearer $TOKEN" "https://localhost:55000/security/config"
```

**Verify user exists:**
```bash
# List API users (needs a token with security:read)
curl -k -H "Authorization: Bearer $TOKEN" "https://localhost:55000/security/users"
```

A `403` with error `6000` on a login means the client IP is blocked; it is lifted `block_time`
seconds after its last attempt.

### High Load

**Reduce concurrent requests:**
```yaml
access:
  max_request_per_minute: 100
  max_unauthenticated_request_per_minute: 10
```

### CORS Issues

**Enable CORS for development:**
```yaml
cors:
  enabled: true
  source_route: "*"
  expose_headers: "*"
  allow_headers: "*"
  allow_credentials: true
```

**Note:** Restrict CORS in production to specific origins.

**Restrict CORS to specific origins:**
```yaml
cors:
  enabled: true
  source_route:
    - "https://dashboard.example.com"
    - "https://admin.example.com"
  expose_headers: "*"
  allow_headers: ["Authorization", "Content-Type"]
```

`source_route`, `expose_headers` and `allow_headers` take a list or a string; a string is split on
commas (`"https://a.example, https://b.example"`). An origin is allowed only when it equals one of the
entries, scheme and port included. A CORS preflight is answered for the methods the API serves:
`GET`, `POST`, `PUT` and `DELETE`.

---

## See Also

- [Server API Module](README.md) - Module overview and architecture
- [API Reference](api-reference.md) - API endpoint documentation
- [RBAC](../rbac/README.md) - Role-based access control
- [Manager Configuration Reference](../../configuration/manager/README.md) - All manager configuration options

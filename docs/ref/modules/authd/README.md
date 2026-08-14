# Authd (Enrollment Service)

`wazuh-manager-authd` handles agent enrollment. It listens for agent registration requests over TLS, validates credentials, generates cryptographic keys, and writes the resulting entries to the agent keystore.

Source: `src/os_auth/`

For configuration options see [Authd Configuration](configuration.md).

## How it works

1. Agent connects to port 1515 over TLS.
2. If `use_password` is enabled (the default for new installations), the agent must send the enrollment password (`OSSEC PASS: <password>`). The password is auto-generated on the manager at first start and must be copied to each agent before enrollment; see [use_password configuration](configuration.md#use_password).
3. If mutual TLS is configured (`ssl_agent_ca`), the agent's certificate is verified.
4. The agent sends an enrollment request:
   ```
   OSSEC A:'<agent_name>' V:'<version>' G:'<groups>' IP:'<ip>' K:'<key_hash>'
   ```
   Only `A:'<agent_name>'` is mandatory; the rest are optional fields and may appear in any
   combination:
   - `A:'<agent_name>'` — the name the agent wants to register under (required).
   - `V:'<version>'` — the agent's Wazuh version, used for the version-compatibility check.
   - `G:'<groups>'` — comma-separated centralized group(s) to assign the agent to at enrollment
     time, instead of the default group.
   - `IP:'<ip>'` — a client-supplied source IP to register the agent with, overriding the
     connection's actual source address (ignored if the value is `src`).
   - `K:'<key_hash>'` — the SHA-1 hash of the agent's current key, if it already has one. It is
     compared against the manager's stored key when deciding whether a `force` re-enrollment
     applies (see [Force re-enrollment](#force-re-enrollment)).
5. Authd validates the agent name, checks for existing registrations (applying `force` rules if configured), generates a random key pair, and queues the entry for persistence. If the request included a `G:` field, the agent is assigned to those centralized groups as part of this same enrollment.
6. The agent key is written to `/var/wazuh-manager/etc/client.keys` by a background writer thread.
7. The response is sent back to the agent over the same TLS connection.

## Threads

| Thread | Role |
|--------|------|
| Remote server | Accepts TLS connections on port 1515 (when `remote_enrollment` is `yes`) |
| Local server | Handles enrollment via the local Unix socket `queue/sockets/auth` |
| Writer | Periodically flushes the in-memory key queue to `client.keys` on disk, and — for each removed agent — asks the [Inventory Sync Server](../inventory-sync-server/README.md) to delete that agent's documents from the indexer |

## Storage

| File | Contents |
|------|----------|
| `/var/wazuh-manager/etc/client.keys` | One line per agent: `<id> <name> <ip> <key>` |
| `/var/wazuh-manager/etc/agents-timestamp` | Per-agent registration timestamp |
| `/var/wazuh-manager/etc/authd.pass` | Enrollment password (auto-generated on first start; required by default) |

## Agent removal and the indexer

Removing an agent has to clean up more than `client.keys`: the agent's documents in the indexer
(inventory state, reported configuration and statistics) have nothing to overwrite them once the
agent is gone. So, for every removed agent, the writer thread calls the Inventory Sync Server's
deletion route over its Unix socket (`queue/sockets/inventory-sync.sock`) and treats the HTTP status
as the outcome — this is not fire-and-forget.

A failed deletion is retried up to three times with a widening pause, and each pause is logged at
info level — the writer thread is single, so while it waits nothing else it owns progresses. When
authd gives up it logs a `WARNING` naming the agent, distinguishing a request that never completed
(modulesd down, or the transfer timed out) from one the server refused with a status. It is a warning
rather than an error because the agent itself IS gone and can no longer connect; what remains is
orphaned documents in the indexer, until an operator repeats the deletion, which is safe to re-run.
Retries are abandoned if the daemon is shutting down. See the
[Inventory Sync Server's deletion contract](../inventory-sync-server/api-reference.md) for what a
`200` guarantees.

## Force re-enrollment

The `<force>` sub-block controls when an agent may overwrite an existing registration:

- `enabled` — allow forced overwrite at all
- `key_mismatch` — overwrite if the agent's key does not match
- `disconnected_time` — overwrite only if the agent has been disconnected for at least this long
- `after_registration_time` — overwrite only if at least this much time has passed since the last registration

## Local socket enrollment protocol

In addition to the TLS enrollment path on port 1515, authd exposes a local-only enrollment API over
the Unix domain socket `queue/sockets/auth`. This is what `manage_agents` and the API's agent
registration endpoints use to add, remove, and query agents without going through TLS or the
enrollment password. It is only served on the master node — a worker rejects any JSON request here
(error `9015`, "Cannot execute this request on a worker node").

A request is a single-line JSON object:

```json
{"function": "add", "arguments": { "name": "myagent", "ip": "any" }}
```

`function` is one of:

- **`add`** — register a new agent (or replace an existing one, subject to the same duplicate
  ID/IP/name and `force` checks used by the network enrollment path). Arguments:
  - `name` (required), `ip` (required, or `"any"`)
  - `id` (optional) — request a specific agent ID instead of letting authd assign the next one
  - `groups` (optional) — comma-separated centralized group(s) to assign
  - `key` (optional) — a caller-supplied key instead of a randomly generated one
  - `key_hash` (optional) — hash of the agent's current key, used the same way as the `K:` field
    in the network protocol when deciding whether a `force` replacement applies
  - `force` (optional, object) — see below
- **`remove`** — delete an agent. Arguments: `id` (required), `purge` (optional boolean; same
  meaning as the [`purge`](configuration.md#purge) configuration option, but scoped to this one
  request)
- **`get`** — look up an agent's stored data. Arguments: `id` (required)

A successful `add` or `get` responds with:

```json
{"error": 0, "data": {"id": "001", "name": "myagent", "ip": "any", "key": "<key>"}}
```

a successful `remove` responds with `{"error": 0, "data": "Agent deleted successfully."}`, and any
failure responds with `{"error": <code>, "message": "<description>"}` (for example `9007`
"Duplicate IP" or `9013` "Maximum number of agents reached").

**Per-request force override:** the `force` object on an `add` request, when present, completely
replaces the daemon's configured [`<force>`](configuration.md#force) block for that single
request — including `disconnected_time` and `after_registration_time` — regardless of what is
configured in `wazuh-manager.conf`. This lets a local caller force an overwrite the running
configuration would otherwise reject, without changing authd's own configuration. If `force` is
omitted, the configured `<force>` settings apply as usual. Shape:

```json
{
  "enabled": true,
  "key_mismatch": true,
  "disconnected_time": { "enabled": true, "value": "1h" },
  "after_registration_time": "1h"
}
```

`disconnected_time.value` and `after_registration_time` each accept either a number of seconds or
a string with a time suffix (`s`, `m`, `h`, `d`), the same as their XML configuration equivalents.

The socket also accepts a small set of plain-text (non-JSON) administrative commands, handled
separately from the JSON API above: `getconfig auth` returns the daemon's current effective
`<auth>` configuration as JSON (`ok {"auth": {...}}`); any other section name or unrecognized
command returns an `err <message>` response.

## Certificate generation CLI

Running `wazuh-authd` with any of `-C`, `-B`, `-K`, `-X`, or `-S` switches it into a one-shot
certificate-generation mode instead of starting the enrollment service: it generates a self-signed
manager certificate and private key pair, writes them to disk, and exits — useful for
(re)generating the material referenced by [`ssl_manager_cert` and `ssl_manager_key`](configuration.md#ssl_manager_cert)
outside of the normal daemon flow. All five flags are required together; if any is given but
another is missing, authd exits with an error naming the missing one.

```
wazuh-authd -C <days> -B <bits> -K <key_path> -X <cert_path> -S <subject>
```

- `-C <days>` — certificate validity period, in days
- `-B <bits>` — RSA key size, in bits
- `-K <path>` — output path for the generated private key (PEM)
- `-X <path>` — output path for the generated certificate (PEM)
- `-S <subject>` — certificate subject, in OpenSSL slash-delimited form, e.g. `/C=US/ST=California/CN=Wazuh/`

The generated certificate is a self-signed, CA-capable (`basicConstraints CA:TRUE`) X.509v3
certificate signed with SHA-256, valid from the current time for the given number of days. Its
Subject Alternative Name always includes `DNS:localhost`, `IP:127.0.0.1`, and `IP:::1`, plus the
manager's own hostname and the `CN` parsed out of `-S` (when present and not already `localhost`).

## Key source files

| File | Purpose |
|------|---------|
| `src/main-server.c` | Main loop, thread management, client pool, CLI argument parsing, certificate-generation CLI mode |
| `src/auth.c` | Protocol parsing, agent validation, key generation |
| `src/local-server.c` | Local socket enrollment handler (JSON `add`/`remove`/`get` API) |
| `src/authcom.c` | Local socket admin commands (e.g. `getconfig`) |
| `src/config.c` | Configuration bootstrap: calls the `<auth>` XML parser and exports the live config as JSON |
| `include/auth.h` | Shared struct/function declarations (`struct client`, `struct keynode`, protocol and config prototypes) |

The actual `<auth>` XML element parsing, validation, and default values live in the shared config
subsystem at `src/config/src/authd-config.c`, not in `os_auth` itself.

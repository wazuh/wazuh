# Authd (Enrollment Service)

`wazuh-manager-authd` handles agent enrollment. It listens for agent registration requests over TLS, validates credentials, generates cryptographic keys, and writes the resulting entries to the agent keystore.

Agents can also enroll over HTTPS, through `remoted_module`'s `POST /enroll` (port 1517) — see
[HTTPS enrollment](../remoted/https-events-api.md#enrollment-endpoint-post-enroll). That endpoint
is a bridge, not a second implementation: it forwards to this same daemon's local socket (see
[Local socket enrollment protocol](#local-socket-enrollment-protocol) below), so every enrollment —
however it arrives — goes through the one business-logic path documented on this page. Port 1515
(this document) remains fully supported for legacy 4.x agents; `/enroll` is the manager's intended
long-term enrollment path going forward.

Source: `src/os_auth/`

For the diagrams — the two stores, the enrollment sequence, the force-guard chain, cluster
forwarding and the removal path — see [Authd Architecture](architecture.md). For configuration
options see [Authd Configuration](configuration.md).

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
5. Authd validates the agent name, checks for existing registrations (applying `force` rules if configured), generates the agent key (32 bytes from OpenSSL's CSPRNG, stored as 64 lowercase hex chars -- the HS256 secret of remoted's `wazuh-agent+jwt` bearer profile), and queues the entry for persistence. If the request included a `G:` field, the agent is assigned to those centralized groups as part of this same enrollment.
6. The agent key is written to `/var/wazuh-manager/etc/client.keys` by a background writer thread.
7. The response is sent back to the agent over the same TLS connection.

## Threads

| Thread | Role |
|--------|------|
| Remote server | Accepts TLS connections on port 1515 (when `remote_enrollment` and [`legacy_enrollment`](configuration.md#legacy_enrollment) are both `yes`) |
| Local server | Handles enrollment via the local Unix socket `queue/sockets/auth.sock` |
| Writer | Flushes the in-memory key queue to `client.keys` on disk, deletes each removed agent from wazuh-db, and hands the indexer purge of every removed agent to the relay. It never waits on the network |
| Purge relay | Sends the queued indexer purges to the [Inventory Sync Server](../inventory-sync-server/README.md), after the configured delay, and owns every retry |
| authpass watcher | On a worker with `use_password`, re-reads `etc/authd.pass` as the cluster syncs it down from the master. Until it arrives the worker fails closed and rejects enrollments |

The writer and the purge relay run on the **master only**. See [Cluster](#cluster) below.

## Cluster

A worker node does not own a keystore. An enrollment that arrives at a worker is forwarded to the
master, which validates it, assigns the id and generates the key; the worker relays the answer to the
agent and keeps nothing locally. The `<force>` settings are ignored on a worker — the master decides —
and a worker that cannot reach the master answers `9016`.

The key reaches the worker's own `client.keys` through the cluster's integrity sync, the same
mechanism that distributes `etc/authd.pass`. Until it does, the worker's remoted cannot verify a key
the agent already holds; see
[the two stores](architecture.md#the-two-stores) and [Cluster](architecture.md#cluster).

## Storage

| File | Contents |
|------|----------|
| `/var/wazuh-manager/etc/client.keys` | One line per agent: `<id> <name> <ip> <key>` |
| `/var/wazuh-manager/etc/agents-timestamp` | Per-agent registration timestamp |
| `/var/wazuh-manager/etc/authd.pass` | Enrollment password (auto-generated on first start; required by default) |
| `/var/wazuh-manager/queue/authd/pending-purges` | Indexer purges authd still owes, plus the highest agent id ever handed out |

> For the diagrams — the thread layout, the removal path and the three intervals the purge has to
> outlast — see [Architecture](architecture.md).

## Agent removal and the indexer

Removing an agent has to clean up more than `client.keys`: the agent's documents in the indexer
(inventory state, reported configuration and statistics) have nothing to overwrite them once the
agent is gone. Four places are involved, and only the first three are immediate:

| # | What is removed | Who reads it afterwards | When |
|---|---|---|---|
| 1 | the entry in the in-memory keystore | authd itself: duplicate checks, agent limit | on the request |
| 2 | the `client.keys` file | remoted, to authenticate agents | next writer pass |
| 3 | the row in wazuh-db | the server API, to list agents | next writer pass |
| 4 | the documents in the indexer | the dashboard | after `authd.purge_delay` |

**The writer thread never waits on the network.** It records the purge and moves on; a dedicated
relay thread sends it. This is deliberate and it is the reason the split exists: the writer is the
only thread that persists `client.keys`, so a slow or unreachable indexer used to stall every key
write behind it — on a fleet-wide removal, no freshly enrolled agent reached `client.keys` and
remoted answered `401` to all of them until the whole batch drained.

### The delay before a purge

A purge is not sent immediately. It waits at least `authd.purge_delay` seconds (see
[Configuration](configuration.md)), because a `_delete_by_query` is a *search* and can only match
what the indexer has already made searchable, and because in a cluster the worker nodes still hold
the previous `client.keys` for a few seconds. Sending it right away would let the last documents a
departing agent wrote survive the purge, with nothing left to ever overwrite them.

### What the deletion route answers

The Inventory Sync Server answers **at admission**: `200 {"status":"queued"}` means it recorded the
deletion and will purge it, not that the documents are already gone. So authd's responsibility ends
when it gets that `200` — from then on the purge's outcome is reported in modulesd's log. A `503` means
"not admitted, come back": no indexer host is healthy, the module is stopping, or its queue is full,
and the relay keeps the entry and retries. Anything else is treated the same way.

### Durability

Pending purges are persisted in `queue/authd/pending-purges` before the relay is woken, and removed
only once the Inventory Sync Server has accepted them. A restart replays whatever is left — with the
delay re-armed from the recorded timestamp — and logs how many purges were recovered. A relay that
cannot deliver keeps the entry and retries; nothing has to be repeated by hand.

The file also stores `last_id`, the highest agent id ever handed out. **An id is never reused**, even
when the agents holding the highest ids have been deleted and `client.keys` no longer mentions them:
a purge in flight matches by agent id, so recycling one would let it delete the documents of a *new*
agent. On startup the id counter is raised to that mark if needed, and the change is logged.

For the same reason, an insertion that names an id explicitly
(`POST /agents/insert`) is **refused** while that id still owes a purge, rather than cancelling the
purge: a queued purge always runs.

### What a manager rebuilt from scratch inherits

`queue/` survives an upgrade and a plain package removal, so the id mark and any pending purges
survive with it. A full purge of the package — or an install from sources into a clean tree — takes
the file with it, and the id counter starts over while the indexer still holds the previous fleet's
documents. **Deleting a manager should therefore include deleting its indexer data**; otherwise new
agents can inherit documents from the agents that held their ids before, in the indices they do not
resynchronise themselves.

## Force re-enrollment

The `<force>` sub-block controls when an agent may overwrite an existing registration:

- `enabled` — allow forced overwrite at all
- `key_mismatch` — overwrite if the agent's key does not match
- `disconnected_time` — overwrite only if the agent has been disconnected for at least this long
- `after_registration_time` — overwrite only if at least this much time has passed since the last registration

All four guards are evaluated together, and every one of them has to allow the replacement. With the
defaults (`enabled` on, `key_mismatch` on, `disconnected_time` 1 h, `after_registration_time` 1 h) an
agent is replaced when the one holding its name has never connected or has been disconnected for at
least an hour, was registered at least an hour ago, and presents a different key. A connected agent
is never replaced.

**A replacement is a deletion.** The agent that loses its name is removed exactly as if it had been
deleted through the API: it goes through the same removal queue, the same writer thread and the same
indexer purge. This matters for scale — a fleet that re-enrolls with names that already exist
generates one deletion per agent, without anyone calling the API — and it is why the delay and the
persistence above apply to enrollment just as much as to `DELETE /agents`.

**Replacement never reuses the id.** The replacing agent is a new registration and receives a new
id; the replaced id is not handed out again. The one case where a caller can name an id is
`POST /agents/insert`, and there authd refuses rather than replacing: an id that belongs to an
existing agent answers `9012 Duplicate ID`, and one whose purge is still pending answers
`9018 Agent ID has a pending deletion` (the server API reports it as `1763`). Delete the agent, let
its purge finish, and then the id can be reused.

## Local socket enrollment protocol

In addition to the TLS enrollment path on port 1515, authd exposes a local-only enrollment API over
the Unix domain socket `queue/sockets/auth.sock`. This is what `manage_agents`, the API's agent
registration endpoints, and `remoted_module`'s `POST /enroll` bridge (see
[HTTPS enrollment](../remoted/https-events-api.md#enrollment-endpoint-post-enroll)) all use to add,
remove, and query agents without going through TLS or the enrollment password directly.

On a cluster **worker** node: a self-enrollment-shaped `add` request (no caller-supplied `id` or
`key` — the only shape `/enroll` and port 1515 ever produce) is forwarded to the master over the
same cluster protocol port 1515's own worker-to-master enrollment forwarding already uses, and
answered with the master's result — a transport failure during that forward answers `9016` ("Cannot
communicate with master node"). An `add` that DOES carry a caller-chosen `id` and/or `key` (an
admin/restore-style add — `manage_agents`/the API can send this shape, self-enrollment never does)
is rejected outright with `9015`, same as `remove`/`get`: there is no cluster RPC to honor a
caller-chosen identity on a worker, so this is an explicit rejection rather than silently returning a
different id/key than the one requested.

A request is a single-line JSON object:

```json
{"function": "add", "arguments": { "name": "myagent", "ip": "any" }}
```

`function` is one of:

- **`add`** — register a new agent (or replace an existing one, subject to the same duplicate
  ID/IP/name and `force` checks used by the network enrollment path). Arguments:
  - `name` (required), `ip` (required, or `"any"`)

    The name must be *storable* in `client.keys`: non-empty, at most 128 characters, no whitespace
    or control bytes, and not starting with `#` or `!`. A name violating any of these is rejected
    with `9017` ("Invalid agent name") — distinct from `9005` ("No such name"), which means the
    argument was absent. This is deliberately a narrower rule than the `OS_IsValidName()` charset
    the two *enrollment* paths (port 1515 and `POST /enroll`) enforce on the names they mint: it
    refuses only what the `<id> <name> <ip> <key>` line format cannot represent, so names that
    `manage_agents` and the API have always accepted — containing `%`, a single character, or a
    leading `.` — keep working.
  - `id` (optional) — request a specific agent ID instead of letting authd assign the next one
  - `groups` (optional) — comma-separated centralized group(s) to assign
  - `key` (optional) — a caller-supplied key instead of a randomly generated one; must be exactly 64 lowercase hex chars (32 bytes), otherwise the request fails with `9019 Invalid agent key`
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

## Development

The in-repo companion to these pages (a plain path — it lives outside this book):

- `src/os_auth/README.md` — the developer's map of the module: the functional/non-functional
  requirements catalog (RF, RNF, and the `REQ-PURGE` contract with inventory-sync), the design
  decisions (D1–D8) with the reasoning behind each, the load-bearing invariants, the developer FAQ,
  and which test suite covers what.

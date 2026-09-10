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

Over `POST /enroll` the request can carry, instead of the enrollment password, an
[enrollment token](#enrollment-tokens) (a `wazuh-enroll+jwt` bearer whose `kid` is the token id) or
the agent's own [re-enrollment credential](#re-enrollment-secret) (`kid` = its agent id). Both reach
the same local-socket `add`, and every enrollment answered over that socket carries a fifth field,
`reenroll_secret`, next to the key; port 1515 answers without it.

## Threads

| Thread | Role |
|--------|------|
| Remote server | Accepts TLS connections on port 1515 (when `remote_enrollment` and [`legacy_enrollment`](configuration.md#legacy_enrollment) are both `yes`) |
| Local server | Handles enrollment via the local Unix socket `queue/sockets/auth.sock` |
| Writer | Flushes the in-memory key queue to `client.keys` on disk, deletes each removed agent from wazuh-db, and records the indexer purge of every removed agent as a Task Manager task. It never waits on the network |
| authpass watcher | On a worker with `use_password`, re-reads `etc/authd.pass` as the cluster syncs it down from the master. Until it arrives the worker fails closed and rejects enrollments |

The writer runs on the **master only**. See [Cluster](#cluster) below.

## Cluster

A worker node does not own a keystore. An enrollment that arrives at a worker is forwarded to the
master, which validates it, assigns the id and generates the key; the worker relays the answer to the
agent and keeps nothing locally. The `<force>` settings are ignored on a worker — the master decides —
and a worker that cannot reach the master answers `9016`.

The key reaches the worker's own `client.keys` through the cluster's integrity sync, the same
mechanism that distributes `etc/authd.pass`. Until it does, the worker's remoted cannot verify a key
the agent already holds; see
[the two stores](architecture.md#the-two-stores) and [Cluster](architecture.md#cluster).

`etc/enrollment_tokens.json` travels by the same sync (`cluster.json` lists it with `client.keys` and
`authd.pass`). Only the master mints, consumes and revokes tokens: a worker reads its replica, forwards
an `add` that carries `token_id` or `reenroll` to the master, answers `token_create` and `token_revoke`
with `9015`, and serves `token_list` from the copy it holds.

## Storage

| File | Contents |
|------|----------|
| `/var/wazuh-manager/etc/client.keys` | One line per agent: `<id> <name> <ip> <key>` |
| `/var/wazuh-manager/etc/agents-timestamp` | Per-agent registration timestamp |
| `/var/wazuh-manager/etc/authd.pass` | Enrollment password (auto-generated on first start; required by default) |
| `/var/wazuh-manager/etc/enrollment_tokens.json` | The [enrollment token](#enrollment-tokens) store, `{"version":1,"tokens":[…]}`: per token `id`, `secret` (`null` when minted with `--no-credential`), `adr`, `pin` or `ca`, `created`, `expires`, `max_uses`, `uses`, `revoked`, `description`. Written by the master only, whole, through a temporary file `chmod`ed to `0640` and renamed into place |
| `/var/wazuh-manager/queue/authd/pending-purges` | Deletions authd has begun recording but not yet finished, plus the highest agent id and sequence ever handed out. Normally empty |

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
| 4 | the documents in the indexer | the dashboard | a Task Manager task, first attempted after `authd.purge_delay` |

**The writer thread never waits on the network.** It records the deletion as a durable task and moves
on; the Task Manager's dispatcher executes it. This is deliberate and it is the reason the split
exists: the writer is the only thread that persists `client.keys`, so a slow or unreachable indexer
used to stall every key write behind it — on a fleet-wide removal, no freshly enrolled agent reached
`client.keys` and remoted answered `401` to all of them until the whole batch drained.

### The delay before a purge

A purge is not attempted immediately. The task's first attempt is set at least `authd.purge_delay`
seconds out (see [Configuration](configuration.md)), because a `_delete_by_query` is a *search* and
can only match what the indexer has already made searchable, and because in a cluster the worker
nodes still hold the previous `client.keys` for a few seconds. Running it right away would let the
last documents a departing agent wrote survive the purge, with nothing left to ever overwrite them.

### Where authd's responsibility ends

At the durable task row. There is no completion signal back to authd, by design — waiting for one is
what used to block the writer — and the purge's own outcome is the task's status, reported in
modulesd's log. The task type carries **no attempt budget**: once `client.keys` is written the agent is
gone and nobody will ask again, so the deletion is retried until it succeeds rather than given up on.

### Durability

The deletion is journaled in `queue/authd/pending-purges` **before** `client.keys` is rewritten, and
the line is dropped only once wazuh-db has acknowledged the task as committed. The journal is normally
empty: it drains as fast as wazuh-db answers, not as fast as the indexer does.

On the next start every surviving line is compared against the `client.keys` just read. An agent still
listed there means the deletion never became final, so the line is dropped; an absent one means the
task is still owed and is created now. That is what closes the window a crash between the key write
and the task's creation used to leave open — nothing else in the system knows those documents are
owed, since the agent is already out of `client.keys` and out of wazuh-db.

The file also stores `last_id`, the highest agent id ever handed out. **An id is never reused**, even
when the agents holding the highest ids have been deleted and `client.keys` no longer mentions them:
a pending purge matches by agent id, so recycling one would let it delete the documents of a *new*
agent. On startup the id counter is raised to that mark if needed, and the change is logged.

Both `client.keys` and the database keep the id in a signed 32-bit integer, so a fleet large or
long-lived enough can drive the counter all the way to `INT_MAX` on its own — no out-of-range input
anywhere. Authd refuses to hand out the next id rather than wrapping it to a negative value: the
auto-assigned enrollment fails the same way an ordinary `max_agents` refusal does — `9013 Maximum
number of agents reached` — instead of silently producing a record `client.keys` and the database
would disagree about.

For the same reason, an insertion that names an id explicitly (`POST /agents/insert`) is **refused**
while that id still owes a purge, rather than cancelling the purge: a recorded purge always runs.

### When a deletion is refused

A deletion can be turned down. If too many earlier ones are still waiting to reach the indexer, the
request answers `9021` (`1766` through the server API) and the agent is left **untouched** — the check
runs before the agent leaves the keystore, so retrying once the backlog drains is all that is needed.

This is new behaviour and it replaces a worse one: the limit used to be discovered after `client.keys`
had been written, where the only options left were to drop the purge silently or to log it while the
documents were orphaned.

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
persistence above apply to enrollment just as much as to a deletion through the API. The admission
bound applies as well: when too many deletions are already in progress the *enrollment* is refused,
rather than the replacement going ahead with a purge that cannot be recorded.

**Replacement never reuses the id.** The replacing agent is a new registration and receives a new
id; the replaced id is not handed out again. The one case where a caller can name an id is
`POST /agents/insert`, and there authd refuses rather than replacing: an id outside
`[1, 2147483647]`, or `0` (reserved for the manager), answers `9020 Invalid agent ID` (the server API
reports it as `1765`) before any keystore lookup even runs; an id that belongs to an existing agent
answers `9012 Duplicate ID`, and one whose purge is still pending answers
`9018 Agent ID has a pending deletion` (the server API reports it as `1763`). Delete the agent, let
its purge finish, and then the id can be reused.

`9018` also covers a wazuh-db that cannot answer whether the id still owes a deletion: the guard fails
closed, because allowing the reuse risks an outstanding purge deleting the new agent's documents.
Auto-assigned ids are unaffected — the id counter comes from authd's own journal.

## Enrollment tokens

An enrollment token is the credential a new agent pastes to enroll over `POST /enroll` without the
shared password: `{"ver":1,"adr":…,"pin"|"ca":…,"key":…}` in unpadded base64url, where `adr` is
`host[:port][/prefix]` (default port `1517` and default prefix `wazuh-manager` left out), `pin` is the
SHA-256 of the CA's SubjectPublicKeyInfo — or `ca` the whole PEM of `remote.https.ca_certificate` with
`--embed-ca` — and `key` is the 16-byte token id followed by the 16-byte secret. A token minted with
`--no-credential` has no `key`: it only says where to connect and which CA to trust, and remoted never
accepts its id as a bearer `kid`.

**Minting is master-only** and goes through the local socket, so authd must be running:

```
wazuh-manager-authd --create-enrollment-token --address <host> [--port N] [--prefix P] [--ttl 30d] \
    [--max-uses N] [--description S] [--embed-ca] [--no-credential]
wazuh-manager-authd --list-enrollment-tokens | --revoke-enrollment-token <id> | --show-token[=<token>]
wazuh-manager-authd --purge-enrollment-tokens [--all] [--force]
```

The CLI (root, or the `wazuh-manager` group) prints the token alone on stdout and its id, endpoint,
expiry and pin on stderr; `--show-token` decodes one offline (argument, `--token-file` or stdin) without
its credential. The server API offers the same operations as `POST`/`GET /agents/enrollment-tokens`
and `DELETE /agents/enrollment-tokens/{token_id}` (RBAC `enrollment_token:create`/`read`/`delete`).
The token text is returned once and never listed again.

A mint is checked against the listener as it is on disk, and a failed check answers `9025` with the
reason (`Enrollment token refused: address not in certificate SAN`): `--address` must be a subject
alternative name of `remote.https.certificate` (a DNS name without partial wildcards and never the
subject; an IP literal only against `iPAddress` entries, and accepted with a warning), the certificate
must name something other than loopback, and `remote.https.ca_certificate` must have signed it.
`--port`/`--prefix` default to the running `remote.https` values, `--ttl` to 30 days (`N[d|h|m|s]`),
`--max-uses` to unlimited.

The agent presents the token as a `wazuh-enroll+jwt` bearer whose `kid` is the token id, signed with
the key HKDF-SHA256 derives from the secret (label `WAZUH-ENROLL-TOKEN-KEY`). remoted verifies it
against its read-only replica of the store and forwards `add` with `token_id`; authd re-checks the
state — `9022` unknown or revoked, `9023` expired, `9024` out of uses — and reserves the use **before**
creating the agent, releasing it if the `add` is refused. Revocation is idempotent, the token stays
listed with `revoked: true`, and because the master re-checks on every `add` it takes effect at once,
even through a worker whose replica the cluster has not refreshed yet.

**Only one rotation at a time per agent.** A re-enrollment takes a reservation on the agent *before* reading its secret from the database, and the writer releases it
when the new credentials are stored. Two requests with the same bearer therefore produce **one** credential: the second is answered `9030` — *Re-enrollment already
in progress* — which remoted turns into **409** and counts as `remoted.enroll.reenroll.rejected_in_progress`. It means «retry», as opposed to the `9027`/401 a bearer
gets once the rotation has landed and its secret is the previous generation's. If the database write fails, the reservation is deliberately kept: the row still names
the old secret, so releasing it would let that secret authorise another rotation. The agent cannot re-enroll again on that manager until the transition is written,
and the log says so.

**A revoke that cannot be written says so.** If the store file cannot be rewritten, the token is refused
from that moment on this manager, but the answer is `9029` — *Enrollment token store write failed*, the
API's error `1771` with HTTP 500 — and not the `9022` of a token that does not exist: the id is real and
what the operator has to do is retry, not go looking for it. The pending revocation is remembered, so a
reload does not undo it and the next token verb writes it; the earlier behaviour, answering success on
the retry, let the token come back at the next restart. Two related contracts are worth stating: a
**use** counted while the file cannot be written is *not* durable (a restart may admit one more
enrollment with that token, or several if writes keep failing — expiry and revocation are what hold),
and a store file above the supported limits (5000 tokens, or the byte ceiling below what the replica
accepts) is **not loaded at all**, with a warning naming which limit it crossed.

**Purging is not revoking.** A revoked token stays in the store, listed and auditable; a purged one is
removed from the file. `--purge-enrollment-tokens` (`DELETE /agents/enrollment-tokens?status=dead`)
removes only what can no longer authorise an enrollment — revoked, expired, or out of uses — and never
a token that is merely unused: one minted this morning and not handed out yet is a live token, not a
leftover. `--all` (`status=all`) empties the store instead, and asks for confirmation unless `--force`
is given or there is no terminal to ask from. A purge that finds nothing to remove does not rewrite the
file, so it does not make every node reload a store that has not changed. Like minting and revoking,
purging is master-only (`9015` on a worker); the workers receive the pruned file through the cluster.

**The store is bounded.** authd refuses to mint beyond 5000 tokens, and refuses before the file would
grow past 7 MiB — one MiB under the 8 MiB above which remoted's replica stops accepting it, which would
otherwise leave every node quietly enrolling against a stale set of tokens. Reaching either limit
answers `9025` naming the purge. The count is about *usable* tokens: a mint that finds the store full
purges the dead entries by itself and only refuses when 5000 tokens are genuinely in use, and a warning
is logged from 80% of the cap onwards. A token measures about 240 bytes in the file, or 1.4 KB when it
embeds the CA, so the byte ceiling is the one that binds a fleet minting `--embed-ca` tokens.

## Re-enrollment secret

Every `add` answered over the local socket carries `reenroll_secret`: 32 random bytes as 64 lowercase
hex chars, stored **only** in the `agent.reenroll_secret` column of `global.db` — never in
`client.keys`, never returned by `get`; an agent enrolled over port 1515 has none. To re-enroll keeping
its id, the agent sends on `POST /enroll` a `wazuh-enroll+jwt` bearer whose `kid` is its own id, signed
with the key derived from that secret (label `WAZUH-REENROLL-KEY`). remoted holds no copy of the
secret, so it forwards `add` with `reenroll: {kid, bearer}` unverified and the **master** judges it,
inside the window of [`remoted.jwt_max_age` and `remoted.jwt_clock_skew`](configuration.md#remotedjwt_max_age-and-remotedjwt_clock_skew).

On success the entry is rotated in place — same id, new key, new secret — and the writer issues
`global set-agent-credentials` instead of an insert: nothing is deleted, no indexer purge is recorded,
groups are kept unless the request named some, and the `<force>` guards play no part. Refusals: `9026`
(no such agent, or a row without a secret — enrolled over 1515, or a `global.db` rebuilt from
`client.keys`), `9027` (malformed, another `kid`, bad signature, or combined with `token_id`, `id` or
`key`), `9028` (outside the window); a name or IP owned by *another* agent still answers `9008`/`9007`.

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
different id/key than the one requested. The same holds for an `add` carrying `token_id` or `reenroll`
and for the `token_*` verbs — see [Cluster](#cluster).

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
  - `id` (optional) — request a specific agent ID instead of letting authd assign the next one; must
    be a positive integer no greater than `2147483647` (the width `client.keys` and the database
    store it in) and other than `0` (reserved for the manager), or the request fails with
    `9020 Invalid agent ID`
  - `groups` (optional) — comma-separated centralized group(s) to assign
  - `key` (optional) — a caller-supplied key instead of a randomly generated one; must be exactly 64 lowercase hex chars (32 bytes), otherwise the request fails with `9019 Invalid agent key`
  - `key_hash` (optional) — hash of the agent's current key, used the same way as the `K:` field
    in the network protocol when deciding whether a `force` replacement applies
  - `force` (optional, object) — see below
  - `token_id` (optional) — the [enrollment token](#enrollment-tokens) being consumed: 22 base64url
    chars, or the request answers `9022`
  - `reenroll` (optional, object `{"kid": "<agent id>", "bearer": "<wazuh-enroll+jwt>"}`) — a
    [re-enrollment](#re-enrollment-secret); cannot be combined with `token_id`, `id` or `key` (`9027`)
- **`remove`** — delete an agent. Arguments: `id` (required), `purge` (optional boolean; same
  meaning as the [`purge`](configuration.md#purge) configuration option, but scoped to this one
  request)
- **`get`** — look up an agent's stored data. Arguments: `id` (required)
- **`token_create`** — mint an [enrollment token](#enrollment-tokens) (master only). Arguments:
  `address` (required), `port`, `prefix`, `ttl` (seconds), `max_uses` (`0` = unlimited),
  `description`, `embed_ca`, `no_credential` (booleans). Answers
  `{"error": 0, "data": {"token": "<token>", "id": "<id>", "adr": "<endpoint>", "expires": <epoch>, "pin_hex": "<sha256>"}}`
  (`pin_hex` only when the token pins rather than embeds the CA)
- **`token_list`** — no arguments. Answers `{"error": 0, "data": [{"id", "adr", "created", "expires",
  "max_uses", "uses", "revoked", "credential", "description"}, …]}` — never the secret
- **`token_revoke`** — arguments: `id` (required). Answers `{"error": 0, "data": {}}`; an unknown id
  answers `9022`
- **`token_purge`** — arguments (all optional): `scope`, either `dead` (the default, and what a
  request with no `arguments` at all asks for) or `all`. Answers
  `{"error": 0, "data": {"removed": <n>, "remaining": <n>, "ids": ["<id>", …]}}`; any other scope
  answers `9002`, and a worker `9015`

A successful `add` responds with:

```json
{"error": 0, "data": {"id": "001", "name": "myagent", "ip": "any", "key": "<key>", "reenroll_secret": "<secret>"}}
```

`get` answers the same shape without `reenroll_secret`, a successful `remove` responds with
`{"error": 0, "data": "Agent deleted successfully."}`, and any failure responds with
`{"error": <code>, "message": "<description>"}` (for example `9007` "Duplicate IP", `9013` "Maximum
number of agents reached", or `9022`–`9028` for the token and re-enrollment paths — see the
[error code table](architecture.md#error-codes)).

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

## Manager certificate

authd has no certificate-generation mode (the `-C/-B/-K/-X/-S` flags of earlier builds are gone) and
the manager generates no TLS material at all. The pair referenced by
[`ssl_manager_cert` and `ssl_manager_key`](configuration.md#ssl_manager_cert) is the HTTPS agent
listener's, provisioned by the operator with the Wazuh installation assistant's `wazuh-certs-tool`
(see [Deploy certificates](../../getting-started/installation.md#deploy-certificates)). Without it
the manager fails closed before authd runs (`wazuh-manager-control start` reports the validator's
`(1244) … file not found` verdict); when the files exist but the SSL context cannot be built — most
often because the service user cannot read them — authd logs
`SSL context setup failed (certificate '<cert>', key '<key>'). wazuh-manager does not generate TLS
certificates: provision them with wazuh-certs-tool (Wazuh installation assistant); see 'Deploy
certificates' in the installation guide. Exiting.` and exits.

## Key source files

| File | Purpose |
|------|---------|
| `src/main-server.c` | Main loop, thread management, client pool, CLI argument parsing |
| `src/auth.c` | Protocol parsing, agent validation, key generation |
| `src/local-server.c` | Local socket enrollment handler (JSON `add`/`remove`/`get` and `token_create`/`token_list`/`token_revoke` API) |
| `src/token_cli.c` | The `--*-enrollment-token` / `--show-token` utility mode: a client of the socket verbs above |
| `src/enrollment_token_mint.c` | What may be minted: the SAN, loopback and CA-signature checks against the listener certificate |
| `src/enrollment_token_store.c` | `etc/enrollment_tokens.json` and its in-memory replica: load, atomic rewrite, consume, revoke |
| `src/reenroll_verify.cpp` | The re-enrollment bearer check: a C bridge over the shared JWT verifier in `shared_modules/utils/jwt/` |
| `src/authcom.c` | Local socket admin commands (e.g. `getconfig`) |
| `src/config.c` | Configuration bootstrap: calls the `<auth>` XML parser and exports the live config as JSON |
| `include/auth.h` | Shared struct/function declarations (`struct client`, `struct keynode`, protocol and config prototypes) |

The actual `<auth>` XML element parsing, validation, and default values live in the shared config
subsystem at `src/config/src/authd-config.c`, not in `os_auth` itself; the token codec (the JSON
document, its base64url wrapping and the HKDF) is shared with the agent side at
`src/shared/src/enrollment_token.c`.

## Development

The in-repo companion to these pages (a plain path — it lives outside this book):

- `src/os_auth/README.md` — the developer's map of the module: the functional/non-functional
  requirements catalog (RF, RNF, and the `REQ-PURGE` contract with inventory-sync), the design
  decisions (D1–D12) with the reasoning behind each, the load-bearing invariants, the developer FAQ,
  and which test suite covers what.

# Wazuh DB

`wazuh-manager-db` is the manager's SQLite database daemon. It owns `global.db` (the agent registry and
group assignments) and answers queries on `mitre.db` (MITRE ATT&CK reference data).

Source: `src/wazuh_db/`

For backup configuration and internal options see [Wazuh DB Configuration](configuration.md); for the
HTTP routes see [the API reference](api-reference.md).

## Running the daemon

`wazuh-manager-control start` launches `/var/wazuh-manager/bin/wazuh-manager-db` (installed
`root:root`, mode `0750`) with no arguments: it reads its configuration, daemonizes, drops to the
`wazuh-manager` user and group, and serves until it receives `SIGTERM`, `SIGHUP` or `SIGINT`. Run by hand
(as `root`), it accepts:

```text
wazuh-manager-db -[Vhdtf] [-c config]
```

| Flag | Effect |
|------|--------|
| `-V` | Print the version and license, exit `0` |
| `-h` | Print the usage, exit `1` (an unknown flag does the same), like `wazuh-manager-remoted` and `wazuh-manager-modulesd` |
| `-d` | Debug output; repeat it (`-dd`) for more. When given, `wazuh_db.debug` is not read |
| `-t` | Test the configuration and exit: `0` when valid; otherwise the error is logged and it exits `1` with `Invalid configuration block for Wazuh-DB.` Unlike a normal start, the test also requires the certificate files the configuration names to exist |
| `-f` | Run in the foreground instead of daemonizing |
| `-c <config>` | Read this configuration file instead of `/etc/wazuh-manager/wazuh-manager.conf`. A relative path is resolved against the directory the command runs from |

The internal options (`wazuh_db.*`, see [Wazuh DB Configuration](configuration.md#internal-options)) are
read before the configuration file, so an invalid one makes even `-t` exit with `(2302)`; only `-V` and
`-h` exit before they are read.

The binary reads nothing from standard input: queries go to `wdb.sock` (below) or to the HTTP routes on
`wdb-http.sock`.

## Architecture

The daemon runs these threads:

| Thread | Role |
|--------|------|
| Dealer | Accepts connections on `wdb.sock` and hands each peer to the worker pool |
| Worker pool (`wazuh_db.worker_pool_size`, 8 by default) | Reads one framed query from a peer, runs it, sends the framed answer |
| HTTP server | Serves the REST routes on `wdb-http.sock` (see below) |
| Garbage collector | Once a second: commits open transactions that have aged past `commit_time_min`/`commit_time_max`, runs the fragmentation check (and `VACUUM`) every `check_fragmentation_interval` seconds (never on the read-only `mitre.db`), and closes handles above `open_db_limit` (never `global.db`) |
| Backup | Started only when `wdb.backup.global.enabled` is true: writes periodic backups of `global.db` |

An HTTP API (`queue/sockets/wdb-http.sock`) is also exposed for the framework and `clusterd`. If it
cannot start, the daemon logs `Failed to start HTTP API server: …` and keeps serving `wdb.sock`.

The routes it serves, their bodies and their failure modes are in
[the API reference](api-reference.md). One of them is worth knowing from here:
**`GET /v1/status`** reports whether this daemon can actually serve queries, which is not the same
question as whether the process is up — it can be running and accepting connections on this socket
while unable to query `global.db`.

```console
$ curl -s --unix-socket /var/wazuh-manager/queue/sockets/wdb-http.sock http://localhost/v1/status
{"status":"ok","module":"wazuh-db","global":{"available":true}}
```

## Socket protocol

Socket: `/var/wazuh-manager/queue/sockets/wdb.sock` (Unix stream, owned by `wazuh-manager`, mode
`0660`).

Every message in both directions is framed by a 4-byte little-endian length header followed by that
many bytes of text (at most 65536); a message longer than that is refused and the connection closed. A
plain `echo` into the socket is therefore not a valid query. The framework's `WazuhDBConnection`
(`framework/wazuh/core/wdb.py`) is a reference client; this one-off query, run as `root`, is enough to
try a command by hand:

```bash
python3 - <<'PY'
import socket, struct
s = socket.socket(socket.AF_UNIX)
s.connect('/var/wazuh-manager/queue/sockets/wdb.sock')
q = b'global select-groups'
s.sendall(struct.pack('<I', len(q)) + q)
n = struct.unpack('<I', s.recv(4))[0]
data = b''
while len(data) < n:
    data += s.recv(n - len(data))
print(data.decode())
PY
```

The text of a query is the target database, the command and its arguments:

```text
<database> <command> [<arguments>]
```

`<database>` is `global` (every command in [the catalog](#global-commands)) or `mitre` (only
`mitre sql <statement>`; the database is opened read-only, so a statement that would modify it answers
`err Cannot execute Mitre database query; attempt to write a readonly database`). Any other target
answers `err Invalid DB query actor: '<database>'`, and an unknown command
`err Invalid DB query syntax, near '<command>'`. Responses are:

```text
ok <JSON>
err <message>
due <JSON>
```

`due` is a partial page of a paginated answer: the caller asks again from the last id it received (for
`get-distinct-groups`, the last group hash). `get-all-agents context` instead streams every row as its
own `due` message on the same connection and ends with `ok []`.

### `global` commands

Every command the daemon accepts, with the components that send it. A JSON payload is one object (or
array) on the rest of the line, with nothing after it; a missing required field answers
`err Invalid JSON data, …` (`near '…'` for most commands) and malformed JSON `err Invalid JSON syntax, near '…'`. An id
argument is read with `atoi()`, so a non-numeric one (`{"agent_id":5}`, `abc`) is read as `0` and
addresses id `0` instead of failing.

| Command | Arguments | Answer | Sent by |
|---|---|---|---|
| `sql` | `<statement>` | `ok [<row objects>]`, see [`global sql`](#global-sql) | the framework (`WazuhDBQuery`) |
| `insert-agent` | JSON: `id` (number), `name` (string), `date_add` (number) required; `ip`, `register_ip`, `internal_key`, `reenroll_secret`, `group` optional strings | `ok` | `wazuh-manager-authd`; the [database module](../database-sync/README.md) |
| `set-agent-credentials` | JSON: `id` (number), `name`, `register_ip`, `internal_key`, `reenroll_secret` (strings), all required | `ok` | `wazuh-manager-authd`, when an agent re-enrolls with its re-enrollment secret: the row keeps its `id` and gains a new key and secret in place, so nothing is deleted and no indexer purge follows |
| `commit` | none | `ok`, or `err Cannot end transaction` | `wazuh-manager-authd`; see [Writes and commits](#writes-and-commits) |
| `update-agent-data` | JSON: `id` (number) required; `os_name`, `os_version`, `os_major`, `os_minor`, `os_type`, `os_platform`, `os_arch`, `version`, `agent_ip`, `connection_status`, `sync_status` (default `synced`) optional strings. Also stamps `last_keepalive` and resets `disconnection_time` and `status_code` to `0` | `ok` | `wazuh-manager-remoted` |
| `update-keepalive` | JSON: `id` (number), `connection_status`, `sync_status` (strings), all required. Stamps `last_keepalive` and resets `disconnection_time` and `status_code` to `0` | `ok` | `wazuh-manager-remoted` |
| `update-connection-status` | JSON: `id` (number), `connection_status`, `sync_status` (strings), `status_code` (number), all required. `disconnected` also stamps `disconnection_time` | `ok` | `wazuh-manager-remoted` |
| `update-status-code` | JSON: `id`, `status_code` (numbers), `sync_status` (string) required; `version`, `connection_status` optional strings (with `connection_status`, `last_keepalive` is stamped too) | `ok` | `wazuh-manager-remoted` |
| `delete-agent` | `<id>` | `ok` | `wazuh-manager-authd`; the database module |
| `get-agent-info` | `<id>` | `ok [<the agent row>]`: every column, `internal_key` and `reenroll_secret` included; `ok []` for an unknown id | `wazuh-manager-authd`, `wazuh-manager-remoted`, the task-manager module of `wazuh-manager-modulesd`, the vulnerability scanner |
| `get-all-agents` | `last_id <id>` | `ok` or `due [{"id":<n>},…]`, the agents with a greater id | the database module |
| `get-all-agents` | `context` | a stream of `due` rows (`id`, `version`, `name`, `ip`, `architecture`, `hostname`, `os_name`, `os_platform`, `os_version`, `group`, `connection_status`), then `ok []` | the vulnerability scanner |
| `get-agents-by-connection-status` | `<last_id> <status>` | `ok` or `due [{"id":<n>},…]` | the task-manager module |
| `disconnect-agents` | `<last_id> <keepalive> <sync_status>` | `ok` or `due [{"id":<n>},…]`: the `active` or `pending` agents whose `last_keepalive` (Unix time) is older than `<keepalive>`, each of them set `disconnected` with that `sync_status` | `wazuh-manager-remoted`; the task-manager module |
| `select-agent-group` | `<id>` | `ok [{"group":"<comma-separated groups>"}]` | `wazuh-manager-remoted` |
| `get-distinct-groups` | `[<last group hash>]` | `ok` or `due [{"group":…,"group_hash":…},…]`, one entry per distinct set of groups | `wazuh-manager-remoted` |
| `get-group-agents` | `<group> last_id <id>` | `ok` or `due [<agent ids>]` | the framework |
| `find-group` | `<group>` | `ok [{"id":<n>}]`, `ok []` when the group does not exist | the database module |
| `insert-agent-group` | `<group>` | `ok` | the database module |
| `delete-group` | `<group>` | `ok` | the database module |
| `select-groups` | none | `ok [{"name":…},…]` | the database module |
| `set-agent-groups` | JSON: `mode` (`override`, `append`, `empty_only` or `remove`) and `data` (an array of `{"id":<n>,"groups":[…]}`) required; `sync_status` optional (default `synced`). In `override` mode an entry's `name` (and `register_ip`) let the daemon create an agent row that does not exist yet | `ok`, or `err Invalid mode '<mode>' in set_agent_groups command` | `wazuh-manager-authd`, `wazuh-manager-remoted`, the framework, `wazuh-manager-clusterd` (agent-groups synchronization) |
| `sync-agent-groups-get` | JSON, every field optional: `condition` (`sync_status` or `all`), `last_id`, `set_synced`, `get_global_hash`, `agent_registration_delta` | `ok` or `due` with a page of agents and their groups (plus the global group hash when `get_global_hash` is `true`) | `wazuh-manager-clusterd` |
| `recalculate-agent-group-hashes` | none | `ok` | `wazuh-manager-clusterd` |
| `sync-agent-info-get` | `[last_id <id>]` | `ok` or `due` with the agents whose `sync_status` is pending | no component: the cluster's agent-info synchronization uses the [HTTP sync routes](api-reference.md#get-v1agentssync) |
| `sync-agent-info-set` | JSON array of agent objects | `ok` | no component (as above) |
| `backup` | `create`, `get`, or `restore [<JSON>]` | see [Backups on demand](#backups-on-demand) | no component: an operator or a test |

In `update-agent-data`, `update-keepalive`, `update-connection-status` and `update-status-code`, a
requested pending `sync_status` never replaces a broader pending one: an agent at `syncreq` keeps it
against a requested `syncreq_status` or `syncreq_keepalive`, and one at `syncreq_status` keeps it against
`syncreq_keepalive`. A requested `synced` is always applied.

### `global sql`

`global sql <statement>` runs one arbitrary SQLite statement on `global.db` and answers its rows as a
JSON array of objects (`ok [{"<column>":<value>,…},…]`, `ok []` when nothing matches), or `err Cannot
execute Global database query; <SQLite error>`. It is the framework's main read path: every
`WazuhDBQuery` over agents and groups (`framework/wazuh/core/utils.py`) is sent as `global sql
SELECT …`. Unlike `mitre sql`, nothing restricts it to reads: an `UPDATE`, `DELETE` or `DROP` sent
this way is executed on the live registry, outside the validation every dedicated command applies
(and inside the daemon's open deferred transaction, if there is one, so it commits on the same clock
as other writes). Only the first statement of the text is run. Whoever can write to `wdb.sock` — root
and the `wazuh-manager` user and group — can therefore change any row; the socket's permissions are
the whole access control. Any statement but a plain `SELECT` also clears the daemon's cached global
group hash, so the next agent-groups comparison recalculates it.

### Writes and commits

Every write answers `ok` from inside a DEFERRED transaction that this daemon commits later on its own
clock (`commit_time_min` / `commit_time_max`, see
[the internal options](configuration.md#internal-options)), so that `ok` is not a durability
acknowledgement. `global commit` ends the open transaction immediately; `wazuh-manager-authd` sends it
because it may forget a journaled identity transition only once the write is committed.

### Backups on demand

```text
global backup create
global backup get
global backup restore {"snapshot":"global.db-backup-2026-09-30-03:00:00.gz","save_pre_restore_state":true}
```

`create` writes a backup now (same file format and retention as the periodic one, see
[Backup files](configuration.md#backup-files)) and answers `ok ["<path>"]`; `get` lists the backup
files; `restore` replaces `global.db` with the named snapshot, or the most recent one when `snapshot`
is omitted, first taking a `-pre_restore` backup when `save_pre_restore_state` is `true`, and answers
`ok`.

`snapshot` must be a bare file name in `backup/db/` as `global backup get` lists it: the
`global.db-backup` prefix, a `.gz` suffix, only letters, digits and `-_.:`, no `..`. Any other name is
rejected with `err Invalid snapshot name` before any pre-restore backup is taken; the same check
applies to the most recent file chosen when `snapshot` is omitted. When `backup/db/` holds no backup
at all the answer is `err Unable to found a snapshot to restore`.

### JSON commands

A message that starts with `{` is not a database query but a JSON command:
`{"command":"getstats"}` returns the query counters and timings, and
`{"command":"getconfig","parameters":{"section":"wdb"}}` (or `"internal"`) returns the effective
configuration. Both answer `{"error":<code>,"message":…,"data":…}`, with `error` `0` on success; any
other section answers `{"error":6,"message":"Unrecognized or not configured section","data":{}}`.

`getstats`'s `data` holds:

| Field | Meaning |
|-------|---------|
| `uptime` | The **Unix time (seconds) the daemon started**, not a duration: the time it has been up is `timestamp - uptime` |
| `timestamp` | The Unix time (seconds) of this answer |
| `name` | `wazuh-manager-db` |
| `metrics.queries.received` | Queries received since start, all targets: socket commands and requests to the HTTP routes alike (each HTTP request counts once, under `global`) |
| `metrics.queries.received_breakdown` | The same count per target (`global`, `mitre`) and, under `global_breakdown`, per command: `db` (`backup`, `sql`, `commit`) and `tables` (`agent`, `belongs`, `group`, one counter per command named as on the wire, such as `insert-agent`). `mitre_breakdown.db.sql` counts the SQL queries run against the MITRE database |
| `metrics.time.execution` | Total time spent running queries since start, in milliseconds |
| `metrics.time.execution_breakdown` | That time with the same breakdown as the counters (`mitre_breakdown.db.sql` included), plus `global_breakdown.db.open` (time spent opening `global.db`), in milliseconds |

Counters and times are cumulative since the daemon started; nothing resets them while it runs.

## Databases

| Database | Path | Purpose |
|----------|------|---------|
| `global.db` | `queue/db/global.db` | Agent registry, groups, connection status. Created by the daemon on first use from the schema embedded at build time (`src/wazuh_db/schemas/schema_global.sql`), owned by `wazuh-manager`, mode `0640` |
| `mitre.db` | `var/db/mitre.db` | MITRE ATT&CK Enterprise reference data, generated at install time from `ruleset/mitre/enterprise-attack.json` by `tools/mitre/mitredb.py`; the daemon opens it read-only. The bundled dataset is the ATT&CK v19.2 release, but the database does not record which release it holds: its `metadata` row `mitre_version` stores the file's STIX `spec_version` (`2.0`), not the ATT&CK version, and `db_version` (`1`) is the schema of the database itself |

Only these two databases exist; the daemon accepts no other `<database>` target.

### global.db tables

| Table | Purpose |
|-------|---------|
| `agent` | One row per registered agent: identity, OS info, version, group, connection status, and the `reenroll_secret` column (64 hex chars) handed to the agent at enrollment — the only place it is stored (never in `client.keys`; `NULL` for rows imported from `client.keys` by the [database module](../database-sync/README.md), which cannot re-enroll until they enroll again) |
| `group` | Named agent groups |
| `belongs` | Agent-to-group assignments with priority ordering |
| `metadata` | Key-value store; the daemon keeps the time and fragmentation of the last `VACUUM` there (`last_vacuum_time`, `last_vacuum_value`) |

Connection status values: `pending`, `never_connected`, `active`, `disconnected`. `sync_status` (what the
cluster still has to replicate) is `synced`, `syncreq`, `syncreq_status` or `syncreq_keepalive`.

The schema's `user_version` is `1` and the upgrade runner has no migration step: a `global.db` whose
`user_version` is anything else is **disabled** when first opened (`DB(global) Unsupported schema
version <n> (expected: 1..1). Disabling database.` in the log), after which every `global` query
answers `err DB global disabled.`, the HTTP data routes answer `500` and `GET /v1/status` answers
`503`. Stop the manager and move the file away to have it recreated.

Tasks are not stored here: the [Task Manager](../task_manager/README.md) module owns `tasks.db` and
serves it over its own socket.

## Implementation

The source layout, threads and locking, transaction model and design decisions are in the developer
README, `src/wazuh_db/README.md`.

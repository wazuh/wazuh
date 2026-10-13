# Wazuh DB

`wazuh-manager-db` is the manager's SQLite database daemon. It owns `global.db` (the agent registry and
group assignments) and serves read-only queries on `mitre.db` (MITRE ATT&CK reference data).

Source: `src/wazuh_db/`

For backup configuration and internal options see [Wazuh DB Configuration](configuration.md); for the
HTTP routes see [the API reference](api-reference.md).

## Architecture

The daemon runs these threads:

| Thread | Role |
|--------|------|
| Dealer | Accepts connections on `wdb.sock` and hands each peer to the worker pool |
| Worker pool (`wazuh_db.worker_pool_size`, 8 by default) | Reads one framed query from a peer, runs it, sends the framed answer |
| HTTP server | Serves the REST routes on `wdb-http.sock` (see below) |
| Garbage collector | Once a second: commits open transactions that have aged past `commit_time_min`/`commit_time_max`, runs the fragmentation check (and `VACUUM`) every `check_fragmentation_interval` seconds, and closes handles above `open_db_limit` (never `global.db`) |
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

Socket: `/var/wazuh-manager/queue/sockets/wdb.sock` (Unix stream).

Every message in both directions is framed by a 4-byte little-endian length header followed by that
many bytes of text (at most 65536); a message longer than that is refused and the connection closed. A
plain `echo` into the socket is therefore not a valid query. The framework's `WazuhDBConnection`
(`framework/wazuh/core/wdb.py`) is a reference client.

The text of a query is the target database, the command and its arguments:

```
<database> <command> [<arguments>]
```

`<database>` is `global` (every command below) or `mitre` (only `mitre sql <SELECT …>`). Responses are:

```
ok <JSON>
err <message>
due <JSON>
```

`due` is a partial page of a paginated answer (`get-group-agents`, `sync-agent-info-get`,
`sync-agent-groups-get`); the caller asks again from the last id it received.

A message that starts with `{` is not a database query but a JSON command:
`{"command":"getstats"}` returns the query counters and timings, and
`{"command":"getconfig","parameters":{"section":"wdb"}}` (or `"internal"`) returns the effective
configuration. Both answer `{"error":<code>,"message":…,"data":…}`.

### Example queries

```
global insert-agent {"id":5,"name":"ubuntu-agent","register_ip":"10.0.0.5","date_add":1700000000}
global update-connection-status {"id":5,"connection_status":"active","sync_status":"synced","status_code":0}
global get-agent-info 5
global set-agent-credentials {"id":5,"name":"ubuntu-agent","register_ip":"10.0.0.5","internal_key":"<64 hex>","reenroll_secret":"<64 hex>"}
global commit
global backup create
global backup get
global backup restore {"snapshot":"global.db-backup-2026-09-30-03:00:00.gz","save_pre_restore_state":true}
```

> **Note on `backup restore`:** `snapshot` must be a bare file name in `backup/db/` as `global backup get`
> lists it: the `global.db-backup` prefix, a `.gz` suffix, only letters, digits and `-_.:`, no `..`. Any
> other name, including the most recent file when `snapshot` is omitted, is rejected with
> `err Invalid snapshot name` before any pre-restore backup is taken.

> **Note on `insert-agent`:** `id` (number), `name` (string) and `date_add` (number) are required; `ip`,
> `register_ip`, `internal_key`, `reenroll_secret` and `group` are optional strings. A missing required
> field is rejected with `err Invalid JSON data, near '…'`.

> **Note on `set-agent-credentials`:** the query `wazuh-manager-authd` issues when an agent re-enrolls with its
> re-enrollment secret (a `wazuh-enroll+jwt` bearer whose `kid` is its own id): the row keeps its `id` and gains
> a new `internal_key` and a new `reenroll_secret` in place, so nothing is deleted from `global.db` and no
> indexer purge follows. All five fields are mandatory; a missing one is rejected with
> `err Invalid JSON data, near '…'`. The daemon's statistics count it under `set-agent-credentials`, next to
> `insert-agent`.

> **Note on `commit`:** `global commit` ends the open transaction of `global.db` immediately and
> answers `ok` (or `err Cannot end transaction`). Every other write answers `ok` from inside a
> DEFERRED transaction that this daemon commits later on its own clock (`commit_time_min` /
> `commit_time_max`), so that `ok` is not a durability acknowledgement. `wazuh-manager-authd` is the
> only caller: it may forget a journaled identity transition only once the write is committed
> (issue #39078). The daemon's statistics count it under `commit`, next to `vacuum`.

> **Note on `update-connection-status`:** the `status_code` field (numeric) is required in addition to `id`, `connection_status`, and `sync_status`. Omitting it causes the query to be rejected with `err Invalid JSON data, near '…'`.

> **Note on `get-agent-info`:** the agent ID argument is a **plain integer**, not a JSON object — the parser (`wdb_parse_global_get_agent_info`) runs `atoi()` directly on the raw token. Passing a JSON object such as `{"agent_id":5}` does **not** produce an error: `atoi()` silently parses it as `0`, so the query resolves to agent `0` instead of failing. Always use the bare-integer syntax shown above.

> **Note on `backup`:** `create` writes a backup now (same file format and retention as the periodic
> one, see [Backup files](configuration.md#backup-files)) and answers `ok ["<path>"]`; `get` lists the
> backup files; `restore` replaces `global.db` with the named snapshot, or the most recent one when
> `snapshot` is omitted, first taking a `-pre_restore` backup when `save_pre_restore_state` is `true`.

## Databases

| Database | Path | Purpose |
|----------|------|---------|
| `global.db` | `queue/db/global.db` | Agent registry, groups, connection status. Created by the daemon on first use from `schemas/schema_global.sql`, owned by `wazuh-manager`, mode `0640` |
| `mitre.db` | `var/db/mitre.db` | MITRE ATT&CK Enterprise reference data (ATT&CK v19.2), generated at install time from `ruleset/mitre/enterprise-attack.json` by `tools/mitre/mitredb.py` |

Only these two databases exist; the daemon accepts no other `<database>` target.

### global.db tables

| Table | Purpose |
|-------|---------|
| `agent` | One row per registered agent: identity, OS info, version, group, connection status, and the `reenroll_secret` column (64 hex chars) handed to the agent at enrollment — the only place it is stored (never in `client.keys`; `NULL` for rows imported from `client.keys` by the [database module](../database-sync/README.md), which cannot re-enroll until they enroll again). Declared in `schema_global.sql` with `user_version` still 1 — no upgrade step, so a `global.db` created by an earlier 5.0.0 development build lacks the column and must be recreated |
| `group` | Named agent groups |
| `belongs` | Agent-to-group assignments with priority ordering |
| `metadata` | Key-value store for global metadata |

Connection status values: `pending`, `never_connected`, `active`, `disconnected`.

> **Note on tasks:** `wazuh-manager-db` no longer stores tasks. `tasks.db` and the `task` actor moved
> to the Task Manager module, which owns that database outright and serves it over its own socket.
> See the [Task Manager](../task_manager/README.md).

## Key source files

| File | Purpose |
|------|---------|
| `src/wazuh_db/src/main.c` | Daemon entry: internal options, socket setup, thread launch |
| `src/wazuh_db/src/wdb_parser.c` | Query routing for the `global` and `mitre` targets |
| `src/wazuh_db/src/wdb_global.c` | `global` subcommands, backup create/restore |
| `src/wazuh_db/src/wdb.c` | SQLite handle management, prepared statement cache, commit and vacuum logic |
| `src/wazuh_db/src/wdb_com.c` | JSON command handler (`getstats`, `getconfig`) |
| `src/wazuh_db/src/wdb_metadata.c` | Schema `user_version` reader used by the upgrade runner |
| `src/wazuh_db/src/wdb_pool.c` | Global pool of open `wdb_t` handles keyed by name (red-black tree), used by the worker threads |
| `src/wazuh_db/src/wdb_state.c` | Runtime statistics (query counters, timings) exposed via `getstats` |
| `src/wazuh_db/src/wdb_upgrade.c` | Sequential schema migration runner for `global.db` (`wdb_upgrade_global`); it has no steps yet |
| `src/wazuh_db/src/http/` | HTTP API (`wdb_http.cpp` plus one header per endpoint) backing `wdb-http.sock` |
| `src/wazuh_db/schemas/schema_global.sql` | DDL for `global.db` |
| `src/config/src/wazuh_db-config.c` | Reader of the `wdb` configuration section |

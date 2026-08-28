# Wazuh DB

`wazuh-manager-db` is the persistent database daemon for the Wazuh Manager. It manages SQLite databases for agent registration, group assignments, task tracking, and MITRE framework data.

Source: `src/wazuh_db/`

For backup configuration see [Wazuh-DB Configuration](configuration.md).

## Architecture

The daemon runs four threads:

| Thread | Role |
|--------|------|
| Dealer | Accepts incoming Unix socket connections and enqueues peers |
| Worker pool (×8 default) | Dequeues peers, executes queries, sends responses |
| Garbage collector | Closes stale database handles and removes inactive connections |
| Backup | Creates periodic backups of `global.db` |

An HTTP API endpoint (`queue/sockets/wdb-http.sock`) is also exposed for internal components that prefer a REST interface (cluster, server API).

## Socket protocol

Socket: `/var/wazuh-manager/queue/sockets/wdb.sock` (Unix stream)

Queries are plain-text strings terminated by a null byte or newline. The first token selects the target database; the rest is the command and its arguments.

```
<database> <command> [<JSON payload>]
```

Responses follow one of two formats:

```
ok <JSON>
err <message>
```

### Example queries

```
global insert-agent {"id":5,"name":"ubuntu-agent","ip":"10.0.0.5","date_add":1700000000}
global update-connection-status {"id":5,"connection_status":"active","sync_status":"synced","status_code":0}
global get-agent-info 5
task create {"task_id":"a1b2c3","agent_id":"5","task_type":"upgrade","payload":"{\"version\":\"5.0.0\"}"}
task get_pending {"agent_id":"5","max_tasks":50}
task mark_delivered {"task_id":"a1b2c3","delivery_time":1700000500}
task update_status {"task_id":"a1b2c3","status":"pending"}
```

> **Note on `update-connection-status`:** the `status_code` field (numeric) is required in addition to `id`, `connection_status`, and `sync_status`. Omitting it causes the query to be rejected with `err Invalid JSON data`.

> **Note on `get-agent-info`:** the agent ID argument is a **plain integer**, not a JSON object — the parser (`wdb_parse_global_get_agent_info`) runs `atoi()` directly on the raw token. Passing a JSON object such as `{"agent_id":5}` does **not** produce an error: `atoi()` silently parses it as `0`, so the query resolves to agent `0` instead of failing. Always use the bare-integer syntax shown above.

The `task` subcommands are: `create`, `get_pending`, `mark_delivered`, `update_status`, `cleanup_expired`, `delete_old`, and `sql` (raw SQL against `tasks.db`, analogous to the `sql` subcommand on other databases).

## Databases

| Database | Path | Purpose |
|----------|------|---------|
| `global.db` | `queue/db/global.db` | Agent registry, groups, connection status |
| `tasks.db` | `queue/tasks/tasks.db` | Long-running task lifecycle (upgrades) |
| `mitre.db` | `var/db/mitre.db` | MITRE ATT&CK reference data |
| `{id}.db` | `queue/db/{id}.db` | Per-agent inventory (legacy — 4.x only; see note below) |

> **Note on {id}.db (4.x legacy):** In Wazuh 4.x, each agent had a dedicated SQLite database at `queue/db/{agent_id}.db` storing per-agent inventory data (FIM events, packages, processes, network interfaces). In Wazuh 5.0 this data is shipped directly to OpenSearch indices via the Indexer Connector (e.g. `wazuh-states-fim-files`, `wazuh-states-inventory-packages`). The per-agent SQLite databases are no longer created or used; existing files from a 4.x installation can be removed after migration.

### global.db tables

| Table | Purpose |
|-------|---------|
| `agent` | One row per registered agent: identity, OS info, version, group, connection status |
| `group` | Named agent groups |
| `belongs` | Agent-to-group assignments with priority ordering |
| `metadata` | Key-value store for global metadata |

Connection status values: `pending`, `never_connected`, `active`, `disconnected`.

### tasks.db tables

| Table | Columns | Purpose |
|-------|---------|---------|
| `TASKS` | `TASK_ID TEXT PRIMARY KEY`, `AGENT_ID TEXT NOT NULL`, `TASK_TYPE TEXT NOT NULL`, `PAYLOAD TEXT NOT NULL`, `CREATE_TIME INTEGER NOT NULL`, `DELIVERY_TIME INTEGER`, `STATUS TEXT NOT NULL` | One row per task instance |
| `metadata` | `key TEXT PRIMARY KEY`, `value TEXT` | Schema version tracking |

Indexes: `idx_agent_status (AGENT_ID, STATUS)`, `idx_create_time (CREATE_TIME)`, `idx_status (STATUS)`.

Task status values (see `src/wazuh_db/src/wdb_task.c`):

| Status | Set by | When |
|--------|--------|------|
| `pending` | `wdb_task_create()` (`task create`); or `wdb_task_update_status()` (`task update_status`, `status: "pending"`) resetting a `delivered` row | Default status on insert; or a delivery attempt reported back as retryable |
| `delivered` | `wdb_task_mark_delivered()` (`task mark_delivered`) | Task has been handed to the agent/consumer; also stamps `DELIVERY_TIME` |
| `failed` | `wdb_task_update_status()` (`task update_status`, `status: "failed"`) | A `delivered` task whose delivery attempt was reported back as a permanent failure — terminal, distinguishable from a successful delivery |
| `expired` | `wdb_task_cleanup_expired()` (`task cleanup_expired`) | Task is still `pending` and its `CREATE_TIME` is older than the given TTL cutoff |

There is no `In progress`, `Done`, `Timeout`, or `Cancelled` status. `pending` and `delivered` are no
longer a one-way street: `task update_status` can move a `delivered` row back to `pending` (retried
on a future `get_pending` call) or forward to `failed` (terminal). Nothing does this automatically —
it only happens if a consumer explicitly reports a delivery outcome; a task that's never reported on
still just stays `delivered`, same as before this action existed. `task delete_old`
(`wdb_task_delete_old()`) permanently **deletes** rows that are `expired` (past their `CREATE_TIME`
cutoff) or `delivered`/`failed` (past their `DELIVERY_TIME` cutoff, which `update_status` does not
clear) — it does not set a status.

## Key source files

| File | Purpose |
|------|---------|
| `src/main.c` | Daemon entry: socket setup, thread launch |
| `src/wdb_parser.c` | Query routing for all database targets |
| `src/wdb_global.c` | All `global` subcommands |
| `src/wdb_task.c` | All `task` subcommands |
| `src/wdb.c` | SQLite handle management, prepared statement cache |
| `src/wdb_com.c` | JSON command handler (`getstats`, `getconfig`) |
| `src/wdb_metadata.c` | Schema `user_version` read/write helpers used during DB upgrades |
| `src/wdb_pool.c` | Global pool of open `wdb_t` handles keyed by name (red-black tree), used by the worker threads |
| `src/wdb_state.c` | Runtime statistics/state tracking (query counters, timings) exposed via `getstats` |
| `src/wdb_upgrade.c` | Sequential schema migration runner for `global.db` (`wdb_upgrade_global`) |
| `src/http/` | HTTP API implementation (`wdb_http.cpp`/`.h` plus per-endpoint handlers) backing the `wdb-http.sock` REST interface described above |
| `schemas/schema_global.sql` | DDL for `global.db` |
| `schemas/schema_task_manager.sql` | DDL for `tasks.db` |

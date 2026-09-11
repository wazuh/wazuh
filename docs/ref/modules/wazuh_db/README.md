# Wazuh DB

`wazuh-manager-db` is the persistent database daemon for the Wazuh Manager. It manages SQLite databases for agent registration, group assignments and MITRE framework data.

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
```

> **Note on `update-connection-status`:** the `status_code` field (numeric) is required in addition to `id`, `connection_status`, and `sync_status`. Omitting it causes the query to be rejected with `err Invalid JSON data`.

> **Note on `get-agent-info`:** the agent ID argument is a **plain integer**, not a JSON object — the parser (`wdb_parse_global_get_agent_info`) runs `atoi()` directly on the raw token. Passing a JSON object such as `{"agent_id":5}` does **not** produce an error: `atoi()` silently parses it as `0`, so the query resolves to agent `0` instead of failing. Always use the bare-integer syntax shown above.

## Databases

| Database | Path | Purpose |
|----------|------|---------|
| `global.db` | `queue/db/global.db` | Agent registry, groups, connection status |
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

> **Note on tasks:** `wazuh-manager-db` no longer stores tasks. `tasks.db` and the `task` actor moved
> to the Task Manager module, which owns that database outright and serves it over its own socket.
> See the [Task Manager](../task_manager/README.md).

## Key source files

| File | Purpose |
|------|---------|
| `src/main.c` | Daemon entry: socket setup, thread launch |
| `src/wdb_parser.c` | Query routing for all database targets |
| `src/wdb_global.c` | All `global` subcommands |
| `src/wdb.c` | SQLite handle management, prepared statement cache |
| `src/wdb_com.c` | JSON command handler (`getstats`, `getconfig`) |
| `src/wdb_metadata.c` | Schema `user_version` read/write helpers used during DB upgrades |
| `src/wdb_pool.c` | Global pool of open `wdb_t` handles keyed by name (red-black tree), used by the worker threads |
| `src/wdb_state.c` | Runtime statistics/state tracking (query counters, timings) exposed via `getstats` |
| `src/wdb_upgrade.c` | Sequential schema migration runner for `global.db` (`wdb_upgrade_global`) |
| `src/http/` | HTTP API implementation (`wdb_http.cpp`/`.h` plus per-endpoint handlers) backing the `wdb-http.sock` REST interface described above |
| `schemas/schema_global.sql` | DDL for `global.db` |

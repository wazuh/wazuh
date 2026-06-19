# Wazuh DB

`wazuh-manager-db` is the persistent database daemon for the Wazuh Manager. It manages SQLite databases for agent registration, group assignments, task tracking, and MITRE framework data.

Source: `src/wazuh_db/`

For backup configuration see [Wazuh-DB Configuration](../../configuration/wazuh-db.md).

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

Socket: `/var/wazuh-manager/queue/db/wdb` (Unix stream)

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
global update-connection-status {"id":5,"connection_status":"active","sync_status":"synced"}
global get-agent-info {"agent_id":5}
task upgrade {"agent":5,"node":"master-node","module":"upgrade_module"}
task upgrade_update_status {"agent":5,"node":"master-node","status":"Done"}
```

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
| `TASKS` | `TASK_ID`, `AGENT_ID`, `NODE`, `MODULE`, `COMMAND`, `CREATE_TIME`, `LAST_UPDATE_TIME`, `STATUS`, `ERROR_MESSAGE` | One row per task instance |
| `metadata` | `key`, `value` | Schema version tracking |

Task status values: `Pending`, `In progress`, `Done`, `Failed`, `Timeout`, `Cancelled`.

## Key source files

| File | Purpose |
|------|---------|
| `src/main.c` | Daemon entry: socket setup, thread launch |
| `src/wdb_parser.c` | Query routing for all database targets |
| `src/wdb_global.c` | All `global` subcommands |
| `src/wdb_task.c` | All `task` subcommands |
| `src/wdb.c` | SQLite handle management, prepared statement cache |
| `src/wdb_com.c` | JSON command handler (`getstats`, `getconfig`) |
| `schemas/schema_global.sql` | DDL for `global.db` |
| `schemas/schema_task_manager.sql` | DDL for `tasks.db` |

# Database Schema

The `agent_info` module uses a local SQLite database to persist agent metadata, group memberships, and its own operational state. This enables change detection and ensures that the module can resume its functions correctly after a restart.

---

## Tables

### `agent_metadata`

This table stores the primary identity and operating system information for the agent. It contains a single row that is periodically updated.

```sql
CREATE TABLE IF NOT EXISTS agent_metadata (
    agent_id          TEXT NOT NULL PRIMARY KEY,
    agent_name        TEXT,
    agent_version     TEXT,
    host_architecture TEXT,
    host_hostname     TEXT,
    host_os_name      TEXT,
    host_os_type      TEXT,
    host_os_platform  TEXT,
    host_os_version   TEXT
);
```

| Mandatory | Column              | Data Type | Description                                           | ECS Mapping                  |
| :-------: | ------------------- | --------- | ----------------------------------------------------- | ---------------------------- |
|     ✔️    | `agent_id`          | TEXT      | The unique ID of the agent (e.g., "001").             | `wazuh.agent.id`             |
|           | `agent_name`        | TEXT      | The name of the agent.                                | `wazuh.agent.name`           |
|           | `agent_version`     | TEXT      | The version of the Wazuh agent.                       | `wazuh.agent.version`        |
|           | `host_architecture` | TEXT      | The hardware architecture of the host (e.g., x86_64). | `host.architecture`          |
|           | `host_hostname`     | TEXT      | The hostname of the host machine.                     | `host.hostname`              |
|           | `host_os_name`      | TEXT      | The name of the operating system (e.g., Ubuntu).      | `host.os.name`               |
|           | `host_os_type`      | TEXT      | The type of the operating system (e.g., Linux).       | `host.os.type`               |
|           | `host_os_platform`  | TEXT      | The OS platform identifier (e.g., ubuntu).            | `host.os.platform`           |
|           | `host_os_version`   | TEXT      | The version of the operating system (e.g., 22.04).    | `host.os.version`            |

---

### `agent_groups`

This table stores the group memberships assigned to the agent. Each row represents a single group assignment.

```sql
CREATE TABLE IF NOT EXISTS agent_groups (
    agent_id          TEXT NOT NULL,
    group_name        TEXT NOT NULL,
    PRIMARY KEY (agent_id, group_name),
    FOREIGN KEY (agent_id) REFERENCES agent_metadata(agent_id) ON DELETE CASCADE
);
```

| Mandatory | Column       | Data Type | Description                                           | ECS Mapping        |
| :-------: | ------------ | --------- | ----------------------------------------------------- | ------------------ |
|     ✔️    | `agent_id`   | TEXT      | The ID of the agent, linking to `agent_metadata`.     | `agent.id`         |
|     ✔️    | `group_name` | TEXT      | The name of a group the agent belongs to.             | `agent.groups`     |

---

### `db_metadata`

This internal table stores operational state for the `agent_info` module itself. It helps manage synchronization flags and timestamps for integrity checks. It contains only a single row with `id = 1`.

```sql
CREATE TABLE IF NOT EXISTS db_metadata (
    id                         INTEGER PRIMARY KEY CHECK (id = 1),
    should_sync_metadata       INTEGER NOT NULL DEFAULT 0,
    should_sync_groups         INTEGER NOT NULL DEFAULT 0,
    last_metadata_integrity    INTEGER NOT NULL DEFAULT 0,
    last_groups_integrity      INTEGER NOT NULL DEFAULT 0,
    is_first_run               INTEGER NOT NULL DEFAULT 1,
    is_first_groups_run        INTEGER NOT NULL DEFAULT 1
);
```

| Column                    | Data Type | Description                                                                                    |
| ------------------------- | --------- | ---------------------------------------------------------------------------------------------- |
| `id`                      | INTEGER   | Primary key, always `1`.                                                                       |
| `should_sync_metadata`    | INTEGER   | A boolean flag (`0` or `1`) indicating if `agent_metadata` changes need to be synchronized.    |
| `should_sync_groups`      | INTEGER   | A boolean flag (`0` or `1`) indicating if `agent_groups` changes need to be synchronized.      |
| `last_metadata_integrity` | INTEGER   | A Unix timestamp of the last successful integrity check for the `agent_metadata` table.        |
| `last_groups_integrity`   | INTEGER   | A Unix timestamp of the last successful integrity check for the `agent_groups` table.          |
| `is_first_run`            | INTEGER   | A boolean flag that is true if the module is running for the first time with a new database.   |
| `is_first_groups_run`     | INTEGER   | A boolean flag that is true if agent groups are being populated for the first time.            |

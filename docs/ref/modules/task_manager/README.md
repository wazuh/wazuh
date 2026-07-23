# Task Manager Module

The Task Manager is a generic manager-side task-broker that stores tasks addressed to agents and lets other manager components (Agent Upgrade, Active Response, API) hand off asynchronous work to be picked up by agents on their next poll.

**Daemon:** Part of `wazuh-modulesd`

**Platform:** Manager only (Linux)

**Type:** Manager-only

**Configuration file:** `/var/wazuh-manager/etc/wazuh-manager.conf`

**XML Section:** `<task-manager>`

Source: [src/wazuh_modules/src/task_manager/](../../../../src/wazuh_modules/src/task_manager/)

---

## Overview

The Task Manager owns the lifecycle of *tasks* — small, typed JSON records that instruct an agent to perform an action. It exposes a JSON-based IPC interface over a Unix domain socket, persists tasks in the `tasks.db` SQLite database (managed by Wazuh DB), and serves pending tasks to agents via the manager's HTTPS control endpoint. Tasks addressed to legacy 4.x agents are also supported through a compatibility push path that reuses the existing agent-manager channel.

Key properties of the current implementation:

- **Task-type based** — a task is not tied to a single module. Four task types are supported today: `active_response`, `remote_upgrade`, `agent_restart`, and `agent_reload`.
- **Deterministic task IDs** — task IDs are UUID-like strings derived from `SHA-256(source_id : agent_id : task_type : create_time)`, so the same logical task produced on different cluster nodes has the same ID and is not duplicated.
- **Fire-and-forget** — the Task Manager does not track task execution results. It stores tasks, delivers them to the agent, marks them as delivered, and expires them after their TTL.
- **In-memory read cache** — pending tasks per agent are cached in memory to serve high-frequency agent polls without hitting the database on every request.
- **Runs on every manager node** — the listener and cleanup thread start on both master and worker nodes so any node can create tasks and serve them to the agents connected to it.

---

## Task types

| Type              | Purpose                                        | Created by                        |
| ----------------- | ---------------------------------------------- | --------------------------------- |
| `active_response` | Execute an Active Response script on the agent | Engine / Active Response pipeline |
| `remote_upgrade`  | Trigger a WPK-based agent upgrade              | Agent Upgrade module              |
| `agent_restart`   | Restart the `wazuh-agent` service              | Server API                        |
| `agent_reload`    | Reload the agent configuration                 | Server API                        |

Each task carries a free-form JSON `payload` whose contents are defined by the producer of the task and interpreted by the agent.

---

## IPC interface

The Task Manager listens on the Unix domain socket `queue/tasks/task` (`TASK_QUEUE` / `WM_TASK_MODULE_SOCK`). Messages are JSON documents; the socket uses the Wazuh secure TCP framing (`OS_SendSecureTCP` / `OS_RecvSecureTCP`).

Two actions are accepted:

### `create_task`

Request:

```json
{
  "action": "create_task",
  "agent_id": "001",
  "task_type": "remote_upgrade",
  "create_time": 1734879600,
  "source_id": "optional-source-identifier",
  "payload": {
    "wpk_file": "wazuh_agent_v5.0.0_linux_x86_64.wpk",
    "wpk_sha1": "aabbccdd...",
    "installer": "upgrade.sh"
  }
}
```

- `agent_id` — required string.
- `task_type` — required, one of the values listed above.
- `create_time` — required Unix timestamp. Must be within `[now - 1 year, now + 60 s]`.
- `source_id` — optional. When present it is mixed into the deterministic task ID (useful for Active Response, which uses the source document ID).
- `payload` — required JSON object. Any structure is accepted; the module validates it is well-formed JSON and its serialized size does not exceed `max_payload_bytes`.

Successful response:

```json
{"status": "ok", "task_id": "a3f5e2d1-4c6b-8a9e-1f2d-3c4b5a6e7d8f"}
```

Error response:

```json
{"error": "<code>", "message": "<description>"}
```

Possible error codes returned by the module: `invalid_json`, `parsing_error`, `create_failed`, `query_failed`, `parsing_failed`, `serialization_failed`.

### `get_pending_tasks`

Request:

```json
{"action": "get_pending_tasks", "agent_id": "001"}
```

Successful response:

```json
{
  "status": "ok",
  "tasks": [
    {
      "task_id": "a3f5e2d1-4c6b-8a9e-1f2d-3c4b5a6e7d8f",
      "task_type": "remote_upgrade",
      "payload": { "...": "..." }
    }
  ]
}
```

Calling `get_pending_tasks` also **marks the returned tasks as delivered** in `tasks.db`. Delivery is recorded only on the node that served the request; the Task Manager does not propagate delivery state across cluster nodes.

---

## Task lifecycle

```
create_task ─► pending (stored in tasks.db)
                 │
                 ▼
       get_pending_tasks ─► delivered (delivery_time recorded, cache updated)
                              │
                              ▼
        (after task_ttl)   expired (marked by cleanup thread)
                              │
                              ▼
        (after 24 h)        deleted (removed by cleanup thread)
```

- The cleanup thread runs every `cleanup_interval` seconds. It sends `task cleanup_expired` and `task delete_old` queries to Wazuh DB and, once a day, `task sql VACUUM;`.
- A task that never got picked up by an agent transitions `pending → expired → deleted`.
- A task that was delivered stays as `delivered` until it is deleted by the cleanup thread.

---

## In-memory cache

`get_pending_tasks` first consults an in-process cache indexed by `agent_id`. Cache entries live for `cache_ttl` seconds. Cache invalidation happens automatically when:

- A new task is created for the agent (invalidates that agent's entry).
- The entry TTL elapses.

The cache dramatically reduces the number of database round-trips generated by agents polling every few seconds. Its size grows linearly with the number of distinct agents that have queried recently.

---

## Cluster behavior

- The listener socket and the cleanup thread run on every manager node — master and workers alike. Any node can accept `create_task` requests from local producers and serve `get_pending_tasks` to the agents connected to it.
- Task IDs are deterministic, so the same logical request routed to different manager nodes produces the same `task_id` and collapses into a single row in `tasks.db`.
- Delivery bookkeeping is node-local: `mark_delivered` is issued by the node that returned the task, and no cross-node broadcast is performed. If the same task is served by two different manager nodes before the row is updated, both responses include the task and the agent is expected to deduplicate.

---

## Storage

Tasks are stored in the `tasks.db` database managed by Wazuh DB. The Task Manager talks to Wazuh DB through the standard `task <command> <parameters>` protocol; commands used by this module are:

| Command                | Direction               | Purpose                                                   |
| ---------------------- | ----------------------- | --------------------------------------------------------- |
| `task create`          | Task Manager → wazuh-db | Persist a new task row                                    |
| `task get_pending`     | Task Manager → wazuh-db | Fetch pending tasks for an agent                          |
| `task mark_delivered`  | Task Manager → wazuh-db | Record `delivery_time` for a task                         |
| `task cleanup_expired` | Task Manager → wazuh-db | Mark tasks older than `task_ttl` as expired               |
| `task delete_old`      | Task Manager → wazuh-db | Remove tasks older than one day from the expiration point |
| `task sql VACUUM;`     | Task Manager → wazuh-db | Daily database compaction                                 |

See the [Wazuh DB module documentation](../wazuh_db/README.md) for the underlying schema.

---

## Configuration

For every option and defaults, see the [Task Manager Configuration Reference](configuration.md).

Minimal example:

```xml
<task-manager>
  <task_ttl>3600</task_ttl>
  <cleanup_interval>300</cleanup_interval>
  <cache_ttl>60</cache_ttl>
  <max_payload_bytes>1048576</max_payload_bytes>
  <max_tasks_per_poll>100</max_tasks_per_poll>
</task-manager>
```

---

## Key source files

| File                         | Purpose                                                                      |
| ---------------------------- | ---------------------------------------------------------------------------- |
| `wm_task_manager.c`          | Module entry point, listener loop and dispatcher                             |
| `wm_task_manager_parsing.c`  | JSON request parsing and response building                                   |
| `wm_task_manager_commands.c` | Wazuh DB IPC, `create_task` and `get_pending_tasks` handlers, cleanup thread |
| `wm_task_manager_tasks.c`    | Deterministic task ID generation and in-memory task cache                    |

---

## See Also

- [Task Manager Configuration Reference](configuration.md)
- [Agent Upgrade Module](../agent_upgrade/README.md) — main producer of `remote_upgrade` tasks
- [Wazuh DB Module](../wazuh_db/README.md) — persistence backend

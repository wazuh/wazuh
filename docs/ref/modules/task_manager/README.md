# Task Manager Module

The Task Manager owns two kinds of work: **agent tasks**, which it stores for agents to pick up, and **manager tasks**, which it executes itself and retries until they reach an outcome.

**Daemon:** Part of `wazuh-manager-modulesd`

**Platform:** Manager only (Linux)

**Type:** Manager-only

**Configuration file:** `/var/wazuh-manager/etc/wazuh-manager.conf`

**XML Section:** `<task-manager>`

Source: [src/wazuh_modules/task_manager/](../../../../src/wazuh_modules/task_manager/)

---

## Overview

The module exposes an HTTP/1.1 interface over `queue/sockets/task.sock` and **owns `queue/tasks/tasks.db` outright** — it is the only process that opens that database.

Key properties:

- **Two task kinds, one database.** An agent task is *stored and handed out*, and the manager never learns what came of it. A manager task is *claimed, executed and retired with an outcome*. They live in separate tables and share nothing but the file.
- **Deterministic agent-task IDs** derived from `SHA-256(source_id : agent_id : task_type : create_time)`, so the same logical request produced on different cluster nodes collapses to one row.
- **Fire-and-forget agent delivery.** `POST /v1/tasks/pending` marks everything it returns as `delivered` as a *read side effect*; delivery itself is the caller's job, and remoted keeps its own retry list for what it could not hand over.
- **Negative cache.** Only the *absence* of pending tasks is cached, per agent, so an idle poll never reaches SQLite. Creating a task for an agent evicts its entry.
- **No polling.** The scheduler sleeps until the earliest backed-off row becomes eligible, and producers wake it on insert. A task created through the socket starts immediately.
- **Runs on every manager node.** Any node can accept task creation and serve its own agents; master-scoped recurring work checks the cluster role before spawning.

---

## Agent task types

| Type              | Purpose                                        | Created by                        |
| ----------------- | ---------------------------------------------- | --------------------------------- |
| `active_response` | Execute an Active Response script on the agent | Engine / Active Response pipeline |
| `remote_upgrade`  | Trigger a WPK-based agent upgrade              | Agent Upgrade module              |
| `agent_restart`   | Restart the `wazuh-agent` service              | Server API                        |
| `agent_reload`    | Reload the agent configuration                 | Server API                        |

Each carries a free-form JSON `payload` defined by the producer and interpreted by the agent.

Manager tasks are described in [Manager tasks](manager-tasks.md); the three recurring ones in [Recurring manager tasks](schedules.md).

---

## HTTP interface

The module listens on `queue/sockets/task.sock`, serving HTTP/1.1 through the shared
[uds_http_server](../utils/uds-http-server/) transport — the same one wazuh-db and inventory-sync use.

**Every route is a POST**, including the reads. Routing is exact-match with no path parameters, and
the C clients that call this speak POST only, so a GET-shaped read surface would need either
query-string parsing or a second client. The liveness probe is the one exception.

### Agent tasks

| Route | Body | Answers |
| --- | --- | --- |
| `POST /v1/tasks` | `agent_id`, `task_type`, `create_time`, `payload`, optional `source_id` | `{"task_id": "..."}` |
| `POST /v1/tasks/bulk` | `{"tasks": [ … ]}` | `{"results": [{"agent_id", "task_id", "created"}, …]}` |
| `POST /v1/tasks/pending` | `{"agent_id": "001"}` | `{"tasks": [{"task_id", "task_type", "payload"}, …]}` |

`create_time` must fall within `[now - 1 year, now + 60 s]`. `payload` is capped at
`max_payload_bytes`; over it the answer is `413`.

**The bulk route exists for fleet-wide operations.** Restarting a fleet used to open one socket
connection per agent inside a chunk of 500; it is now one request and one database transaction.

### Manager tasks

| Route | Body | Answers |
| --- | --- | --- |
| `POST /v1/manager-tasks` | the row to create | `{"result", "task_id"}` |
| `POST /v1/manager-tasks/get` | `{"task_id"}` | the full row |
| `POST /v1/manager-tasks/by-agent` | `{"agent_id", "task_type"}` | `{"task": …}` or `{}` |
| `POST /v1/manager-tasks/list` | `{"task_type", "status"?, "last_task_id"?, "limit"?}` | a narrow listing |
| `POST /v1/manager-tasks/count` | `{"task_type", "status"}` | `{"count": N}` |

`result` is one of `created`, `coalesced`, `collided` or `queue_full`. **On a coalesce the
`task_id` is the SURVIVING row's**, not the one that was requested — returning the requested one
would hand the caller an id with no row behind it.

**Coalescing and the admission bound are the module's decision, not the request's.** A registered
task type takes both from its own descriptor; a producer cannot contradict it. Both fields are
honoured from the body only for a task type this build does not know, which is how a test fixture
registers a synthetic one.

### Operations

| Route | Class | Purpose |
| --- | --- | --- |
| `GET /v1/health` | Liveness | Answered from resident state, so it survives any pressure |
| `POST /v1/metrics` | Control | Queue depth per type, executor occupancy, handler durations, transport diagnostics |

---

## Architecture

```
   producers ──HTTP──▶ ┌─────────────────────────────────────────┐
                       │  uds_http_server   (2 I/O threads)      │
                       ├─────────────────────────────────────────┤
                       │  ApiHandlers ──▶ SqliteTaskStore        │
                       │                    (owns tasks.db)      │
                       ├─────────────────────────────────────────┤
   scheduler ─────────▶│  Executor  (4–8 workers, group caps)    │
   (1 timer thread)    │      │                                  │
                       │      ├─▶ HttpHandler ──▶ consumers      │
                       │      └─▶ local handlers ──▶ host ops    │
                       └─────────────────────────────────────────┘
```

- **The store owns the database.** One connection behind one mutex, WAL with `synchronous=FULL`,
  every statement prepared at open. `create` and `claim` commit inline because their return is
  treated as durable; outcomes, re-queues and retention are **group-committed** on a short timer,
  which is safe for the same reason the design already tolerates a lost outcome write: the row stays
  claimed, the sweep reclaims it, and every handler is idempotent.
- **The executor is one worker pool**, not a set of lanes. Isolation comes from a per-**group**
  concurrency cap in each task type's descriptor. Adding a task type is one descriptor plus a
  handler — no lane assignment, no rotation logic, no change to the store or the schema.
- **The scheduler is one timer thread.** It spawns scheduled runs, sweeps ownership, applies
  retention, runs the daily VACUUM and reports stalls. It sleeps until the earliest of those is due
  rather than polling.

**Threads:** 2 HTTP I/O + 4–8 executor workers + 1 scheduler. The module's modulesd thread returns
immediately after `start()`.

---

## Storage

`queue/tasks/tasks.db`, opened only by this module.

| Table | Holds |
| --- | --- |
| `TASKS` | Agent tasks: `pending` → `delivered` → `expired` → removed |
| `MANAGER_TASKS` | Manager tasks and their outcomes |
| `MANAGER_TASK_SCHEDULES` | The mutable half of each recurring schedule |
| `metadata` | Module bookkeeping (last VACUUM) |

**Agent tasks age out while pending; manager tasks never do.** That asymmetry is deliberate: ageing
out a pending manager task would destroy exactly the long-outage work the queue exists to survive.

The schema lives in [storage/schema.hpp](../../../../src/wazuh_modules/task_manager/src/storage/schema.hpp)
as a raw string literal, applied on every open with `CREATE ... IF NOT EXISTS`. Because it cannot
alter an existing table, any change to a table's shape needs a real step in the module's `migrate()`.

---

## Clients

| Client | Uses |
| --- | --- |
| `wazuh-manager-remoted` (C poller and C++ `TaskClient`) | `/v1/tasks/pending` |
| Agent Upgrade module | `/v1/tasks` |
| Server API / framework | `/v1/tasks`, `/v1/tasks/bulk` via `wazuh.core.task_http` |
| `wazuh-manager-authd` | `/v1/manager-tasks`, `/count`, `/by-agent` via `manager_task_op.h` |
| Vulnerability scanner | `/v1/manager-tasks`, through a callback modulesd hands it at start |

---

## Configuration

For every option and default, see the [Task Manager Configuration Reference](configuration.md).

```xml
<task-manager>
  <task_ttl>3600</task_ttl>
  <cleanup_interval>300</cleanup_interval>
  <max_payload_bytes>1048576</max_payload_bytes>
  <max_tasks_per_poll>100</max_tasks_per_poll>
</task-manager>
```

Everything else is an internal option, resolved **before modulesd daemonizes**, so an out-of-range
value fails `wazuh-modulesd -t` rather than aborting a module thread later.

---

## Key source files

| Path | Purpose |
| --- | --- |
| `include/task_manager.h` | The C ABI: config struct, host-operations table, start/stop |
| `src/storage/` | Schema, statement catalogue, the SQLite store |
| `src/registry/` | Task type descriptors, retry and deferral ladders, HTTP result mapping |
| `src/execution/` | The worker pool, ownership, the sweep and the watchdog |
| `src/schedule/` | Cadence arithmetic and the timer thread |
| `src/handlers/` | The routed handler, its UDS client, and the three local handlers |
| `src/http/` | Route wiring and per-route request logic |
| `src/wazuh_modules/src/wm_task_manager.c` | modulesd's shim: loads the module, implements the host operations |

---

## See Also

- [Task Manager Configuration Reference](configuration.md)
- [Manager tasks](manager-tasks.md) — states, retry, concurrency groups, and finding what failed
- [Recurring manager tasks](schedules.md) — the disconnection sweep, agent retention and log rotation
- [Agent Upgrade Module](../agent_upgrade/README.md)
- [Inventory Sync Server](../inventory-sync-server/README.md) — executes the two routed task types

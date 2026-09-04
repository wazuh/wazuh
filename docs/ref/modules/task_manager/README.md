# Task Manager Module

The Task Manager owns two kinds of work: **agent tasks**, which it stores for agents to pick up, and **manager tasks**, which it executes itself and retries until they reach an outcome. It also **serves remote agent upgrades**, whose output is an agent task — see [Agent upgrades](#agent-upgrades) below.

**Daemon:** Part of `wazuh-manager-modulesd`

**Platform:** Manager only (Linux)

**Type:** Manager-only

**Configuration file:** `/var/wazuh-manager/etc/wazuh-manager.conf`

**XML Section:** `<task-manager>`

Source: [src/wazuh_modules/task_manager/](../../../../src/wazuh_modules/task_manager/)

---

## Overview

The module exposes an HTTP/1.1 interface over `queue/sockets/task-http.sock` and **owns `queue/tasks/tasks.db` outright** — it is the only process that opens that database.

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
| `remote_upgrade`  | Trigger a WPK-based agent upgrade              | This module's own upgrade routes  |
| `agent_restart`   | Restart the `wazuh-agent` service              | Server API                        |
| `agent_reload`    | Reload the agent configuration                 | Server API                        |

Each carries a free-form JSON `payload` defined by the producer and interpreted by the agent.

Manager tasks are described in [Manager tasks](manager-tasks.md); the three recurring ones in [Recurring manager tasks](schedules.md).

---

## HTTP interface

The module listens on `queue/sockets/task-http.sock`, serving HTTP/1.1 through the shared
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

### Agent upgrades

| Route | Body | Answers |
| --- | --- | --- |
| `POST /v1/agents/upgrade` | `agents`, `request_time`, optional `version`, `wpk_repo`, `use_http`, `force_upgrade`, `package_type` | the per-agent envelope below |
| `POST /v1/agents/upgrade-custom` | `agents`, `request_time`, `file_path`, optional `installer` | the same envelope |

These two behave unlike every other route here, in two ways that are deliberate.

**They are asynchronous.** The handler parses, hands the batch to a worker pool and returns without
answering; the reply is sent later through a retained responder. Everything else on this socket is a
bounded store operation measured in microseconds, but an upgrade batch reads wazuh-db once per agent
and may download 100 MB — doing that on an I/O thread would head-of-line-block every agent's task
polling.

**They always answer `200`**, including for a body that could not be parsed. The response is a
per-agent envelope, and the Server API turns each entry into an exception code by adding 1810:

```json
{"error": 0,
 "data": [{"error": 0,  "message": "Success", "agent": 4},
          {"error": 12, "message": "The repository is not reachable", "agent": 5}],
 "message": "Success"}
```

A non-2xx would make that client raise before it ever read the entries, replacing a precise
per-agent reason with a generic transport error. Refusing a batch under load is the same 200 with
per-agent error 4, which is the one code the Server API answers by halving the chunk and retrying.

See [Agent upgrades](agent-upgrades.md) for the flow, and
[configuration](configuration.md#agent-upgrades) for the options.

### Operations

| Route | Class | Purpose |
| --- | --- | --- |
| `GET /v1/health` | Liveness | Answered from resident state, so it survives any pressure |
| `GET /v1/metrics` | Control | Queue depth per type, executor occupancy, handler durations, upgrade counters, transport diagnostics |

These two are the only `GET`s on the socket. Every other route is a `POST`, including the reads,
because the C clients that call them speak `POST` only; these two have no C client and no body.

```bash
curl --unix-socket /var/wazuh-manager/queue/sockets/task-http.sock http://localhost/v1/metrics
```

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
                       ├─────────────────────────────────────────┤
                       │  UpgradeService  (2 batch workers)      │
                       │      └─▶ WPK repository (outbound HTTPS)│
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

- **The upgrade pool is separate from the executor**, and is the one place on this socket where a
  request is answered later rather than inline. Its workers count *batches*, not agents: per-agent
  work is one wazuh-db call on a shared socket plus arithmetic, so parallelising agents would only
  multiply contention. It is also the only outbound connection this module makes to anything off
  the machine.

**Threads:** 2 HTTP I/O + 4–8 executor workers + 1 scheduler + 2 upgrade batch workers. The module's
modulesd thread returns immediately after `start()`.

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
| Server API / framework | `/v1/tasks`, `/v1/tasks/bulk` via `wazuh.core.task_http` |
| Server API / framework, upgrades | `/v1/agents/upgrade`, `/v1/agents/upgrade-custom`, same client |
| `wazuh-manager-authd` | `/v1/manager-tasks`, `/count`, `/by-agent` via `manager_task_op.h` |
| Vulnerability scanner | `/v1/manager-tasks`, through a callback modulesd hands it at start |

The upgrade routes are not in this table because they are part of this module: their agent tasks are
written straight to the store, in one transaction per batch.

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
| `src/upgrade/` | The manager side of the Agent Upgrade module: the two routes, the batch orchestrator, the WPK and repository-index caches |
| `src/wazuh_modules/src/wm_task_manager.c` | modulesd's shim: loads the module, implements the host operations |

---

## See Also

- [Task Manager Configuration Reference](configuration.md)
- [Manager tasks](manager-tasks.md) — states, retry, concurrency groups, and finding what failed
- [Recurring manager tasks](schedules.md) — the disconnection sweep, agent retention and log rotation
- [Agent upgrades](agent-upgrades.md) — request validation, WPK resolution and task creation
- [Inventory Sync Server](../inventory-sync-server/README.md) — executes the two routed task types

# Task Manager Module

The Task Manager owns two kinds of work: **agent tasks**, which it stores for agents to pick up, and **manager tasks**, which it executes itself and retries until they reach an outcome. It also **serves remote agent upgrades**, whose output is an agent task — see [Agent upgrades](agent-upgrades.md).

**Daemon:** Part of `wazuh-manager-modulesd`

**Platform:** Manager only (Linux)

**Type:** Manager-only

**Configuration file:** `/var/wazuh-manager/etc/wazuh-manager.conf`

**XML Section:** `<task-manager>`

**Source:** `src/wazuh_modules/task_manager/` (the module), `src/wazuh_modules/src/wm_task_manager.c`
(modulesd shim), `src/config/src/wmodules-task-manager.c` (configuration reader)

---

## Overview

The module exposes an HTTP/1.1 interface over `queue/sockets/task-http.sock` and **owns `queue/tasks/tasks.db` outright** — it is the only process that opens that database.

Key properties:

- **Two task kinds, one database.** An agent task is *stored and handed out*, and the manager never learns what came of it. A manager task is *claimed, executed and retired with an outcome*. They live in separate tables and share nothing but the file.
- **Deterministic agent-task IDs**: the first 128 bits of `SHA-256("[source_id:]agent_id:task_type:create_time")`, formatted as a UUID (the `source_id:` segment is left out when it is empty), so the same logical request produced on different cluster nodes collapses to one row.
- **Fire-and-forget agent delivery.** `POST /v1/tasks/pending` marks everything it returns as `delivered` as a *read side effect*; delivery itself is the caller's job (remoted's legacy poller keeps its own retry list for pushes that got no answer).
- **Negative cache.** Only the *absence* of pending tasks is cached, per agent, so an idle poll never reaches SQLite. Creating a task for an agent evicts its entry.
- **No polling.** The scheduler sleeps until the earliest backed-off row becomes eligible, and producers wake it on insert. A task created through the socket starts immediately.
- **Runs on every manager node.** Any node can accept task creation and serve its own agents; master-scoped recurring work checks the cluster role before spawning.

---

## Agent task types

| Type              | Purpose                                        | Created by |
| ----------------- | ---------------------------------------------- | ---------- |
| `active_response` | Execute an Active Response script on the agent | `wazuh-manager-clusterd`'s active-response poller, on every node: it reads the `wazuh-active-responses*` indices and creates one task per target agent through `POST /v1/tasks`, with the response document's id as `source_id` |
| `remote_upgrade`  | Trigger a WPK-based agent upgrade              | This module's own upgrade routes |
| `agent_restart`   | Restart the `wazuh-agent` service              | Server API, through `POST /v1/tasks/bulk` |
| `agent_reload`    | Reload the agent configuration                 | Server API, through `POST /v1/tasks/bulk` |

Each carries a free-form JSON `payload` defined by the producer and interpreted by the agent.
`task_type` is not checked against this list: the store accepts any non-empty type.

Manager tasks are described in [Manager tasks](manager-tasks.md); the three recurring ones in [Recurring manager tasks](schedules.md).

---

## HTTP interface

The module listens on `queue/sockets/task-http.sock`, serving HTTP/1.1 through the shared
[uds_http_server](../utils/uds-http-server/README.md) transport. This section is the summary; the
per-route contract (fields, limits, status codes, the upgrade envelope) is the
[API reference](api-reference.md), and every metric is in [Metrics](metrics.md).

| Group | Routes | Used for |
| --- | --- | --- |
| Agent tasks | `POST /v1/tasks`, `/v1/tasks/bulk`, `/v1/tasks/pending` | storing tasks for agents and handing them out on a poll |
| Manager tasks | `POST /v1/manager-tasks`, `/get`, `/by-agent`, `/list`, `/count` | creating manager tasks and looking them up |
| Agent upgrades | `POST /v1/agents/upgrade`, `/v1/agents/upgrade-custom` | the manager side of remote agent upgrades |
| Operations | `GET /v1/health`, `GET /v1/metrics` | liveness and the metrics dump |

**Every route is a `POST` except the two operations routes**, including the reads. Routing is
exact-match with no path parameters, and the C clients that call these routes speak `POST` only; the
two `GET`s have no C client and no body.

**The upgrade routes behave unlike every other route here.** They are asynchronous — the handler
hands the batch to a worker pool and the answer is sent when the batch finishes, because a batch reads
wazuh-db once per agent and may download a 100 MB WPK, which on an I/O thread would block every
agent's task polling — and they always answer `200` with a per-agent envelope, which the Server API
turns into exception codes by adding 1810. See [Agent upgrade routes](api-reference.md#agent-upgrade-routes).

```bash
curl --unix-socket /var/wazuh-manager/queue/sockets/task-http.sock http://localhost/v1/health
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
   scheduler ─────────▶│  Executor  (2–8 workers, group caps)    │
   (1 timer thread)    │      │                                  │
                       │      ├─▶ HttpHandler ──▶ consumers      │
                       │      └─▶ local handlers ──▶ host ops    │
                       ├─────────────────────────────────────────┤
                       │  UpgradeService  (1–4 batch workers)    │
                       │      └─▶ WPK repository (outbound HTTPS)│
                       └─────────────────────────────────────────┘
```

- **The store owns the database.** One connection behind one mutex, WAL with `synchronous=FULL`,
  every statement prepared at open. `create` and `claim` commit inline because their return is
  treated as durable; outcomes, re-queues and retention are **group-committed** in a 20 ms window,
  which is safe for the same reason the design already tolerates a lost outcome write: the row stays
  claimed, the sweep reclaims it, and every handler is idempotent.
- **The executor is one worker pool**, not a set of lanes. Isolation comes from a per-**group**
  concurrency cap in each task type's descriptor. Adding a task type is one descriptor plus a
  handler — no lane assignment, no rotation logic, no change to the store or the schema.
- **The scheduler is one timer thread.** It spawns scheduled runs, sweeps ownership, applies
  retention, returns the freed space to the filesystem a step at a time and reports stalls. It
  sleeps until the earliest of those is due rather than polling.
- **The upgrade pool is separate from the executor**, and is the one place on this socket where a
  request is answered later rather than inline. Its workers count *batches*, not agents: per-agent
  work is one wazuh-db call on a shared socket plus arithmetic, so parallelising agents would only
  multiply contention. It is also the only outbound connection this module makes to anything off
  the machine.

**Threads, at the defaults:** 2 HTTP I/O (`manager_task_io_threads`) + `clamp(cores, 2, 8)` executor
workers (`manager_task_executor_threads`) + 1 scheduler + `cores / 2` upgrade batch workers clamped to
1–4 (`upgrade_workers`). The module's modulesd thread returns immediately after `start()`.

---

## Storage

`queue/tasks/tasks.db`, opened only by this module.

| Table | Holds |
| --- | --- |
| `TASKS` | Agent tasks: `pending` → `delivered`, or `pending` → `expired` after `task_ttl`; a delivered task is removed 24 h after delivery, an expired one once it is 24 h old |
| `MANAGER_TASKS` | Manager tasks and their outcomes |
| `MANAGER_TASK_SCHEDULES` | The mutable half of each recurring schedule |
| `metadata` | Module bookkeeping |

**Agent tasks age out while pending; manager tasks never do.** That asymmetry is deliberate: ageing
out a pending manager task would destroy exactly the long-outage work the queue exists to survive.

The schema lives in `src/wazuh_modules/task_manager/src/storage/schema.hpp`
as a raw string literal, applied on every open with `CREATE ... IF NOT EXISTS`. Because it cannot
alter an existing table, any change to a table's shape needs a real step in the module's `migrate()`.

---

## Clients

| Client | Uses |
| --- | --- |
| `wazuh-manager-remoted` (legacy C poller and the C++ `TaskClient` behind `POST /control`) | `/v1/tasks/pending` |
| `wazuh-manager-clusterd` (active-response poller) | `/v1/tasks`, via `wazuh.core.task_http` |
| Server API / framework (agent restart and reload) | `/v1/tasks/bulk`, same client |
| Server API / framework and the `agent_upgrade` CLI | `/v1/agents/upgrade`, `/v1/agents/upgrade-custom`, same client |
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
  <upgrade_enabled>yes</upgrade_enabled>
</task-manager>
```

`<task-manager>` has these five options plus `<wpk_repository>`. Everything else is an internal
option in the `wazuh_modules` namespace, resolved **before modulesd daemonizes**, so an out-of-range
value fails `wazuh-manager-modulesd -t` rather than aborting a module thread later.

---

## Key source files

| Path | Purpose |
| --- | --- |
| `src/wazuh_modules/task_manager/include/task_manager.h` | The C ABI: config struct, host-operations table, start/stop |
| `src/wazuh_modules/task_manager/src/storage/` | Schema, statement catalogue, the SQLite store |
| `src/wazuh_modules/task_manager/src/registry/` | Task type descriptors, retry and deferral ladders, HTTP result mapping |
| `src/wazuh_modules/task_manager/src/execution/` | The worker pool, ownership, the sweep and the watchdog |
| `src/wazuh_modules/task_manager/src/schedule/` | Cadence arithmetic and the timer thread |
| `src/wazuh_modules/task_manager/src/handlers/` | The routed handler, its UDS client, and the three local handlers |
| `src/wazuh_modules/task_manager/src/http/` | Route wiring and per-route request logic |
| `src/wazuh_modules/task_manager/src/upgrade/` | The manager side of remote agent upgrades: the two routes, the batch orchestrator, the WPK and repository-index caches |
| `src/wazuh_modules/src/wm_task_manager.c` | modulesd's shim: loads the module, implements the host operations |
| `src/config/src/wmodules-task-manager.c` | Reads `<task-manager>`, `global`, `remote` and every internal option |

---

## See Also

- [Task Manager Configuration Reference](configuration.md)
- [Manager tasks](manager-tasks.md) — states, retry, concurrency groups, and finding what failed
- [Recurring manager tasks](schedules.md) — the disconnection sweep, agent retention and log rotation
- [Agent upgrades](agent-upgrades.md) — request validation, WPK resolution and task creation
- [Inventory Sync Server](../inventory-sync-server/README.md) — executes the two routed task types

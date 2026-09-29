# Task Manager API Reference

All routes are served over a Unix domain socket at `queue/sockets/task-http.sock`, relative to the
installation directory (`/var/wazuh-manager/queue/sockets/task-http.sock` by default). There is no TCP
listener and no authentication: the socket's filesystem permissions (group `wazuh-manager`) are the
whole access control. Requests are HTTP/1.1, `Content-Length` delimited, one request per connection
(`Connection: close`); routing is exact-match on the path, with no path parameters.

The [README](README.md#http-interface) summarises the surface; this page is the per-route contract.

## Routes

| Method | Path | Class | Handler |
|---|---|---|---|
| `POST` | `/v1/tasks` | Data | [Create an agent task](#post-v1tasks) |
| `POST` | `/v1/tasks/bulk` | Data | [Create a batch of agent tasks](#post-v1tasksbulk) |
| `POST` | `/v1/tasks/pending` | Data | [Take an agent's pending tasks](#post-v1taskspending) |
| `POST` | `/v1/manager-tasks` | Control | [Create a manager task](#post-v1manager-tasks) |
| `POST` | `/v1/manager-tasks/get` | Control | [Get a manager task by id](#post-v1manager-tasksget) |
| `POST` | `/v1/manager-tasks/by-agent` | Control | [Get an agent's manager task of one type](#post-v1manager-tasksby-agent) |
| `POST` | `/v1/manager-tasks/list` | Control | [List manager tasks of one type](#post-v1manager-taskslist) |
| `POST` | `/v1/manager-tasks/count` | Control | [Count manager tasks of one type and status](#post-v1manager-taskscount) |
| `POST` | `/v1/agents/upgrade` | Control | [Agent upgrades](#agent-upgrade-routes) — asynchronous |
| `POST` | `/v1/agents/upgrade-custom` | Control | [Agent upgrades](#agent-upgrade-routes) — asynchronous |
| `GET` | `/v1/health` | Liveness | `200` `{"status":"ok"}`, answered from resident state |
| `GET` | `/v1/metrics` | Control | The metrics dump — see [Metrics](metrics.md) |

Every path is versioned, the two `GET`s included; an unversioned or unknown path answers `404`
`{"error":"Unknown endpoint","code":404}`. The upgrade routes are registered only when the upgrade
subsystem is built, and `/v1/metrics` only when a metrics registry is attached.

**Classes** are the transport's shedding contract ([uds_http_server](../utils/uds-http-server/)):

- **Data** — the agent-task routes carry producer-authored payloads whose volume something outside
  the manager can drive, so they are charged the in-flight byte budget and shed first (`503`) under
  memory pressure.
- **Control** — other daemons depend on these (authd's deletion record is created here), so agent-task
  pressure never sheds them; each is bounded by its own body and session cap instead.
- **Liveness** — `/v1/health` keeps answering under any pressure.

## Limits

| Limit | Value | Over it |
|---|---|---|
| Server-wide body cap | 8 MiB, or the manager-task create cap if larger | `413` from the transport |
| `POST /v1/manager-tasks` body cap | `max_payload_bytes` + 64 KiB of envelope | `413` from the transport, before the handler |
| Other Control routes' body cap | the Control class default (64 KiB) | `413` from the transport |
| Serialized `payload` | [`max_payload_bytes`](configuration.md#max_payload_bytes) (1 MiB) | `413` `payload_too_large` from the handler |
| Concurrent `POST /v1/manager-tasks` connections | 128 | `503` from the transport |
| Concurrent connections per upgrade route | 32 (over the class cap) | `503` from the transport |
| Tasks handed out per poll | [`max_tasks_per_poll`](configuration.md#max_tasks_per_poll) (100) | the rest stay `pending` for the next poll |

## Errors

Every JSON route (all but the upgrade routes and the two `GET`s) answers errors as
`{"error": "<code>", "message": "<text>"}`:

| Status | `error` | When |
|---|---|---|
| `400` | `invalid_json` | the body is not valid JSON (a valid non-object body is treated as `{}`) |
| `400` | `parsing_error` | a required field is missing, empty or out of range — the message names it |
| `404` | `not_found` | `/v1/manager-tasks/get` for an id with no row |
| `413` | `payload_too_large` | the serialized `payload` exceeds `max_payload_bytes` |
| `500` | `create_failed` | `/v1/tasks` could not store the row |
| `500` | `internal_error` | an unexpected exception in the handler (logged; the message says "see the manager log") |
| `503` | `queue_full` | `/v1/manager-tasks`: the type's admission bound is reached (body also carries `"result":"queue_full"`) |

## Agent tasks

### `POST /v1/tasks`

```json
{"agent_id": "001", "task_type": "remote_upgrade", "create_time": 1759132800,
 "payload": {"...": "..."}, "source_id": "optional"}
```

| Field | Required | Rule |
|---|---|---|
| `agent_id` | yes | non-empty string |
| `task_type` | yes | non-empty string |
| `create_time` | yes | number, Unix seconds, within `[now - 1 year, now + 60 s]` — otherwise `Timestamp is too old (>1 year)` / `Timestamp is in the future` |
| `payload` | yes | any JSON value; stored serialized, capped at `max_payload_bytes` |
| `source_id` | no | string; part of the task id derivation — **an absent `source_id` and an empty one produce the same id** |

Answers `200` `{"task_id": "<id>"}`. The id is derived deterministically from `source_id`, `agent_id`,
`task_type` and `create_time`, so repeating a create is idempotent: an existing id is success, not an
error. A create evicts the agent from the negative poll cache before answering.

### `POST /v1/tasks/bulk`

`{"tasks": [ <entry>, … ]}`, each entry shaped like a `POST /v1/tasks` body. **Every entry is validated
before any is written**: one malformed entry fails the whole request with that entry's `400`, and
nothing is stored. The rows are then written in one transaction.

Answers `200` `{"results": [{"agent_id", "task_id", "created"}, …]}`, one per entry in order. An id
that already exists counts as `"created": true` — ids are deterministic, so a repeat is the same task.
A store failure rolls the whole transaction back and is reported as `"created": false` on **every**
row rather than as a `500`, so the framework's halve-and-retry path handles it.

### `POST /v1/tasks/pending`

`{"agent_id": "001"}` (required). Answers `200` `{"tasks": [{"task_id", "task_type", "payload"}, …]}`,
at most `max_tasks_per_poll` of them, or `{"tasks": []}`. `payload` is the JSON value the producer
stored, not a string. **Handing a task out marks it delivered** — a read with a side effect; delivery
retries are the caller's (remoted's) job. An agent known to have nothing pending is answered from the
negative cache without touching the database.

## Manager tasks

Rows are described in [Manager tasks](manager-tasks.md). Statuses: `pending`, `claimed`, `completed`,
`failed`, `dead_letter`, `superseded`.

### `POST /v1/manager-tasks`

| Field | Required | Rule |
|---|---|---|
| `task_id` | yes | non-empty string, chosen by the producer (deterministic per type) |
| `task_type` | yes | non-empty string |
| `payload` | yes | a JSON string is stored as-is; any other value is serialized; capped at `max_payload_bytes` |
| `agent_id`, `schedule_id` | no | strings |
| `scheduled_run_at`, `next_attempt_at` | no | Unix seconds |
| `create_time` | no | Unix seconds; defaults to now |
| `coalesce`, `max_pending` | no | **honoured only for a task type this build does not know** — a registered type takes both from its descriptor |

Answers `200` `{"result": "created"|"coalesced"|"collided", "task_id": "<id>"}`, or `503` with
`"result": "queue_full"`. On `coalesced` the `task_id` is the **surviving** row's, not the requested one.
A `created` row is handed to the executor immediately — there is no poll interval.

### `POST /v1/manager-tasks/get`

`{"task_id": "<id>"}` (required). Answers `200` `{"task": <row>}` or `404` `not_found`. The row carries
`task_id`, `task_type`, `payload`, `create_time`, `status`, `attempts`, `defer_count`,
`next_attempt_at`, and — only when set, never as `null` — `agent_id`, `owner`, `claim_time`,
`last_error`, `schedule_id`, `scheduled_run_at`, `end_time`.

### `POST /v1/manager-tasks/by-agent`

`{"agent_id", "task_type"}` (both required). Answers `200` `{"task": <row>}`, or `200` `{}` when the
agent has no such task — "none" is an answer here, not an error (it is what authd's pending-purge check
asks).

### `POST /v1/manager-tasks/list`

`{"task_type"}` (required), plus optional `status` (an unknown value is a `400`), `last_task_id` and
`limit` (default 100). Answers `200` `{"tasks": [{"task_id", "status", "create_time", "agent_id"?,
"last_error"?}, …]}` — deliberately narrow; use `/get` for the full row. Paged on task id: pass the last
id back as `last_task_id` until a page comes back empty.

### `POST /v1/manager-tasks/count`

`{"task_type", "status"}` (both required; an unknown status is a `400`). Answers `200` `{"count": N}`.

## Agent upgrade routes

`POST /v1/agents/upgrade` and `POST /v1/agents/upgrade-custom` differ from every other route in two
deliberate ways: they are **asynchronous** (the batch is handed to a worker pool and answered later),
and they **always answer `200`** with a per-agent envelope, including for a body that could not be
parsed. The request fields and the envelope are in the [README](README.md#agent-upgrades); the flow in
[Agent upgrades](agent-upgrades.md); the options in [configuration](configuration.md#agent-upgrades).

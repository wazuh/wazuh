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
`{"error":"Unknown endpoint","code":404}`. All twelve routes are registered on every start; the
upgrade routes stay registered with `<upgrade_enabled>no</upgrade_enabled>` and refuse every agent
instead.

**Classes** are the transport's shedding contract ([uds_http_server](../utils/uds-http-server/README.md)):

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
| Concurrent Control-class connections | 256 (the transport's class default) | `503` from the transport |
| Concurrent `POST /v1/manager-tasks` connections | 128, in addition to the class cap | `503` from the transport |
| Concurrent connections per upgrade route | 32, in addition to the class cap | `503` from the transport (the Server API retries it like a per-agent error 4) |
| Tasks handed out per poll | [`max_tasks_per_poll`](configuration.md#max_tasks_per_poll) (100) | the rest stay `pending` for the next poll |

## Errors

Every JSON route (all but the upgrade routes and the two `GET`s) answers errors as
`{"error": "<code>", "message": "<text>"}`; the transport's own refusals (`404`, `413`, `503`) are
`{"error": "<text>", "code": <status>}` instead:

| Status | `error` | When |
|---|---|---|
| `400` | `invalid_json` | the body is not valid JSON (a valid non-object body is treated as `{}`) |
| `400` | `parsing_error` | a required field is missing, empty or out of range — the message names it |
| `404` | `not_found` | `/v1/manager-tasks/get` for an id with no row |
| `413` | `payload_too_large` | the serialized `payload` exceeds `max_payload_bytes` (message `payload exceeds max_payload_bytes`) |
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
`"result": "queue_full"`. `collided` means a row with that `task_id` already exists and nothing was
written. On `coalesced` the `task_id` is the **surviving** row's, not the requested one — returning the
requested one would hand the caller an id with no row behind it. A `created` row is handed to the
executor immediately — there is no poll interval.

`task_type` is not validated against the registered types. A row of a type this build has no handler
for is stored and never run; the next start of the module retires it as `failed` with `last_error`
`unknown task type`, and logs it at ERROR.

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
`limit` (default 100, at most 1000; a value of 0 or less means the default). Answers `200` `{"tasks": [{"task_id", "status", "create_time", "agent_id"?,
"last_error"?}, …]}` — deliberately narrow; use `/get` for the full row. Paged on task id: pass the last
id back as `last_task_id` until a page comes back empty.

### `POST /v1/manager-tasks/count`

`{"task_type", "status"}` (both required; an unknown status is a `400`). Answers `200` `{"count": N}`.

## Agent upgrade routes

`POST /v1/agents/upgrade` and `POST /v1/agents/upgrade-custom` differ from every other route in two
deliberate ways:

- **They are asynchronous.** The handler parses the body, hands the batch to the upgrade worker pool
  and returns without answering; the reply is sent from the pool when the batch finishes, at most
  [`upgrade_batch_deadline`](configuration.md#internal-options-the-upgrade-path-adds) (180 s) later.
- **They always answer `200`**, including for a body that could not be parsed. The verdicts are in
  the body, and the Server API turns each per-agent `error` into an exception code by adding 1810; a
  non-2xx would make that client raise before it ever read them.

### Request

| Field | Route | Required | Rule |
|---|---|---|---|
| `agents` | both | yes | non-empty array of positive integer agent ids |
| `request_time` | both | yes | number, Unix seconds, non-zero, within `[now - 1 year, now + 60 s]`; it becomes the task's `create_time`, so every cluster node derives the same task id |
| `version` | `/upgrade` | no | target version; defaults to the manager's own |
| `wpk_repo` | `/upgrade` | no | repository for this request; overrides [`<wpk_repository>`](configuration.md#xml-options) |
| `use_http` | `/upgrade` | no | boolean; `http://` instead of `https://` when the repository names no scheme |
| `force_upgrade` | `/upgrade` | no | boolean; lifts the version gates that can be forced ([Version constraints](agent-upgrades.md#version-constraints)) |
| `package_type` | `/upgrade` | no | `rpm` or `deb` |
| `file_path` | `/upgrade-custom` | yes | the WPK, which must resolve to a file directly inside `var/upgrade/` |
| `installer` | `/upgrade-custom` | no | installer script name; defaults to `upgrade.bat` on Windows and `upgrade.sh` elsewhere |

### Response

```json
{"error": 0,
 "data": [{"error": 0,  "message": "Success", "agent": 4},
          {"error": 12, "message": "The repository is not reachable", "agent": 5}],
 "message": "Success"}
```

One `data` entry per requested agent, in order. A body that cannot be admitted at all (invalid JSON,
a missing or malformed field) answers with that error at the top level and a single `data` entry
without an `agent`. The per-agent codes:

| `error` | Server API code | Message |
|---|---|---|
| 0 | — | `Success` |
| 1 | 1811 | `Could not parse message JSON` |
| 2 | 1812 | `Required parameters in json message where not found` (or the parser's own text) |
| 3 | 1813 | `JSON parameter not recognized` (or the parser's own text) |
| 4 | 1814 | `Task manager communication error` — the batch queue is full, the module is shutting down, or the rows could not be stored; the Server API halves the chunk and retries |
| 6 | 1816 | `Agent information not found in database` |
| 7 | 1817 | `The WPK for this platform is not available` |
| 8 | 1818 | `Remote upgrade is not available for this agent version` |
| 9 | 1819 | `Direct upgrade to v5.0.0 is not supported. Please upgrade to v4.14.x first` |
| 10 | 1820 | `Current agent version is greater or equal` |
| 11 | 1821 | `Upgrading an agent to a version higher than the manager requires the force flag` |
| 12 | 1822 | `The repository is not reachable` — also when the batch runs out of `upgrade_batch_deadline` |
| 13 | 1823 | `The version of the WPK does not exist in the repository` |
| 14 | 1824 | `The WPK file does not exist` |
| 15 | 1825 | `The WPK sha1 of the file is not valid` |
| 16 | 1826 | `The manager's HTTPS verification_mode is not 'none'; …` |
| 17 | 1827 | `Upgrade procedure could not start` — also the answer to every agent while `<upgrade_enabled>` is `no` |
| 18 | 1828 | `The agent is below v5.0.0 and the manager's legacy delivery (remote.legacy.enabled) is disabled; …` |

The flow is in [Agent upgrades](agent-upgrades.md); the options in
[configuration](configuration.md#agent-upgrades).

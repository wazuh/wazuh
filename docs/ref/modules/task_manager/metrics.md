# Metrics

The Task Manager keeps its runtime statistics in a `wazuh_metrics` registry (the shared library at
`src/shared_modules/metrics/`) and serves a JSON dump of it on **`GET /v1/metrics` over its own socket**,
`queue/sockets/task-http.sock`. The route is UDS-local and in the transport's Control class, so it is
never shed by agent-task pressure.

This page is the full catalog. The **Tuning** column names the option to act on; *diagnostic* means
there is deliberately no setting behind the number — the fix is elsewhere (a consumer, the producer, or
nothing at all).

## Querying

```bash
curl -s --unix-socket /var/wazuh-manager/queue/sockets/task-http.sock http://localhost/v1/metrics | jq
```

**The path is `/v1/metrics`, not `/metrics`** — every route on this socket is versioned, and an
unversioned request answers `404`. (`inventory-sync-http.sock` does use a bare `/metrics`; the two are
not interchangeable.)

The envelope is the shared `wazuh_metrics` dump: the daemon name, a UTC timestamp and one entry per
metric, sorted by name. A histogram's `value` is its observation count, and it adds a `summary`
object (`count`, `sum`, `min`, `max`, `p50`, `p90`, `p99`).

```json
{
  "name": "task_manager",
  "timestamp": "2026-09-04T12:44:54Z",
  "metrics": [
    {"name": "task_manager.agent_tasks.created", "type": "counter", "enabled": true, "value": 0,
     "description": "Agent tasks stored", "unit": "count"},
    {"name": "task_manager.queue.pending.agent_delete_indexer", "type": "pull", "enabled": true,
     "value": 0.0, "description": "Pending manager tasks of type agent_delete_indexer", "unit": "tasks"}
  ]
}
```

Counters and pull values are cheap — the counters are already maintained and each queue gauge is one
indexed query — but this is a cold path by design. Scrape it on the order of seconds, not per request.

**Per-type names appear on first use.** The `manager_tasks.created.*`, `manager_tasks.retired.*` and
`handler.outcome.*` counters are created the first time that (type, result) pair occurs, so a name that
is missing from the dump means *zero so far*, not *not instrumented*. The `queue.pending.<task_type>`
gauges, by contrast, exist for every registered type from start-up.

## Catalog

### Agent tasks

| Metric | Type | Unit | Meaning | Tuning |
|---|---|---|---|---|
| `task_manager.agent_tasks.created` | counter | count | Agent tasks accepted by `POST /v1/tasks` and `/v1/tasks/bulk`; a repeated id is counted again. Rows written by the upgrade routes are not counted | *diagnostic* — producer volume |
| `task_manager.agent_tasks.delivered` | counter | count | Agent tasks handed to a poller (and marked delivered) | [`max_tasks_per_poll`](configuration.md#max_tasks_per_poll) bounds each hand-out |
| `task_manager.agent_tasks.empty_cache_entries` | pull | agents | Agents the negative cache knows have nothing pending — their polls never touch the database | *diagnostic* |

### Manager tasks

`<task_type>` is a registered type ([Manager tasks](manager-tasks.md)); `<result>` is `created`,
`coalesced`, `collided` or `queue_full`; `<status>` is a terminal status — `completed`, `failed`,
`dead_letter` or `superseded`; `<outcome>` is `ok`, `retryable`, `timeout`, `terminal`, `not_ready`,
`busy` or `incomplete`.

| Metric | Type | Unit | Meaning | Tuning |
|---|---|---|---|---|
| `task_manager.queue.pending.<task_type>` | pull | tasks | Pending rows of that type, read from `tasks.db` | [`manager_task_executor_threads`](manager-tasks.md#threading), though per-type concurrency is a code constant |
| `task_manager.manager_tasks.created.<task_type>.<result>` | counter | count | Create requests by outcome | `queue_full` means the type's admission bound is reached: [`manager_task_max_pending_{deletes,scans}`](manager-tasks.md#per-type-bounds) |
| `task_manager.manager_tasks.retired.<task_type>.<status>` | counter | count | Rows that reached a terminal status | `dead_letter` follows the attempt and deferral budgets: [`manager_task_max_{attempts,defer}`](manager-tasks.md#queue-mechanics) |
| `task_manager.manager_tasks.reclaimed` | counter | count | Claimed rows the ownership sweep returned to pending (their worker died or overran) | [`manager_task_claim_grace`, `manager_task_sweep_interval`](manager-tasks.md#queue-mechanics) |
| `task_manager.handler.outcome.<task_type>.<outcome>` | counter | count | What each handler run returned | *diagnostic* — `not_ready` / `busy` point at the consumer |
| `task_manager.handler.duration` | histogram | microseconds | Handler wall time, all types together (count/sum/min/max/p50/p90/p99) | the per-type deadlines in [Manager tasks](manager-tasks.md#per-type-bounds) |
| `task_manager.executor.busy_workers` | gauge_int | workers | Executor workers running a handler right now | [`manager_task_executor_threads`](manager-tasks.md#threading) |

### Agent upgrades

| Metric | Type | Unit | Meaning | Tuning |
|---|---|---|---|---|
| `task_manager.upgrade.queue_depth` | pull | batches | Upgrade batches waiting for a worker | [`upgrade_workers`](configuration.md#internal-options-the-upgrade-path-adds) |
| `task_manager.upgrade.batches_shed` | pull | requests | Upgrade requests refused because the queue was full (answered per agent with error 4) | [`upgrade_queue_depth`](configuration.md#internal-options-the-upgrade-path-adds) |
| `task_manager.upgrade.wpk_downloads` | pull | downloads | WPK downloads performed | [`upgrade_max_concurrent_downloads`](configuration.md#internal-options-the-upgrade-path-adds) bounds them in flight |
| `task_manager.upgrade.wpk_cache_hits` | pull | requests | Upgrade requests answered from an already-verified WPK | *diagnostic* |
| `task_manager.upgrade.versions_fetches` | pull | requests | Repository `versions` files fetched | [`upgrade_versions_ttl`](configuration.md#internal-options-the-upgrade-path-adds) |
| `task_manager.upgrade.versions_cache_hits` | pull | requests | `versions` lookups answered from cache | [`upgrade_versions_ttl`](configuration.md#internal-options-the-upgrade-path-adds) |

### Transport

| Metric | Type | Unit | Meaning | Tuning |
|---|---|---|---|---|
| `task_manager.http.live_sessions` | pull | connections | Open connections on the socket | *diagnostic* |
| `task_manager.http.inflight_requests` | pull | requests | Requests holding an in-flight budget reservation (Data routes) | *diagnostic* |
| `task_manager.http.inflight_bytes` | pull | bytes | Bytes reserved from the in-flight budget | *diagnostic* — see the [limits](api-reference.md#limits) |

## Triage

- **Is anything stuck?** `queue.pending.<type>` that does not fall, with `executor.busy_workers` at
  zero, means nothing is eligible yet — list the pending ids through
  [`/v1/manager-tasks/list`](api-reference.md#post-v1manager-taskslist) and read `next_attempt_at`
  on one through [`/v1/manager-tasks/get`](api-reference.md#post-v1manager-tasksget).
- **Is a consumer down?** `handler.outcome.<type>.not_ready` climbing means the consumer socket is not
  listening; `.busy` means it answered `409`.
- **Is work being abandoned?** Any increase in `manager_tasks.retired.<type>.dead_letter` deserves a
  look at the log line that accompanies it — it carries the task id.
- **Are upgrades being refused?** `upgrade.batches_shed` rising means requests arrive faster than
  `upgrade_workers` drain `upgrade_queue_depth`; the Server API retries those agents by halving its chunk.

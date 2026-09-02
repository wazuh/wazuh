# Manager tasks

A **manager task** is work the manager owes itself — deleting an agent's documents from the Indexer,
rescanning one agent for vulnerabilities, sweeping disconnected agents — as opposed to the agent
tasks the rest of this module brokers. The two are deliberately separate: an agent task is *stored
and handed out*, and the manager never learns what came of it; a manager task is *claimed, executed
and retired with an outcome*, and is retried until it reaches one.

They live in the `MANAGER_TASKS` table of `tasks.db` and are executed by dispatcher threads inside
`wazuh-manager-modulesd`. Recurring ones are described in
[Recurring manager tasks](schedules.md); this page describes the queue they all run on.

---

## Why a queue at all

The problem it solves is a `200` that means "queued". Before this existed, deleting an agent purged
the Indexer synchronously: if the Indexer was down, the documents were orphaned and nothing
remembered to try again. A task row is the memory. It survives a manager restart, an Indexer outage
and a `wazuh-db` restart, and it is only retired once the consumer says the work is done — not once
it says the request was accepted.

That distinction runs through the whole design. A task's execution route must **answer at
completion**, never at admission, or the row would read `completed` while the work was still queued
somewhere else.

---

## Task types

| Type | Runs | Executed by | Created by |
| --- | --- | --- | --- |
| `agent_delete_indexer` | on the `delete` lane (4 threads) | `POST /_internal/agents/delete` on inventory-sync | `wazuh-manager-authd`, after writing `client.keys` |
| `vd_scan` | on the `scan` lane (1 thread) | `POST /_internal/vd/scan` on inventory-sync | the vulnerability scanner's admission route |
| `agent_disconnect_sweep` | on the `local` lane (1 thread) | in-process handler | its schedule |
| `agent_delete_old` | on the `local` lane | in-process handler | its schedule |
| `log_rotate_daily` | on the `local` lane | in-process handler | its schedule |

Adding a type is a descriptor in the registry plus either a route or a handler. It is not a change
to the dispatcher, and it is not a change to `wazuh-db`, which treats `TASK_TYPE` as opaque text.

**Lanes exist to stop head-of-line blocking.** A 300-second vulnerability scan must not sit in front
of a bulk deletion. The three periodic types share one lane because they run every fifteen minutes,
every hour and once a day — three always-alive threads to avoid a daily rotation delaying a sweep by
minutes would be a poor trade.

---

## States

```
                    create
                      │
                      ▼
                  ┌────────┐   claim    ┌─────────┐
                  │pending │───────────►│ claimed │
                  └────────┘            └─────────┘
                    ▲   ▲                    │
        re-queue    │   │  reclaim           │ outcome
   (retry / defer)  │   └────────────────────┤
                    │                        │
                    └────────────────────────┤
                                             ▼
              completed ── failed ── dead_letter ── superseded
```

| Status | Meaning |
| --- | --- |
| `pending` | Waiting to be claimed. Eligible once `NEXT_ATTEMPT_AT` has passed. |
| `claimed` | A named lane worker is executing it. |
| `completed` | The consumer reported the work done. |
| `failed` | Declared impossible — a `4xx` from a type that allows terminal failure. |
| `dead_letter` | Gave up after exhausting its retry or deferral budget. |
| `superseded` | A newer pending row for the same agent took its place while it was running. |

**A pending manager task is never expired by age.** That is the opposite of what the agent-task TTL
does, and it is deliberate: ageing out pending rows would destroy exactly the long-outage work this
queue exists to survive. Only terminal rows are ever removed, by retention.

---

## Retry, deferral and giving up

A handler reports one of six outcomes, and the row's next state follows from it:

| Outcome | Effect | Costs an attempt? |
| --- | --- | --- |
| ok | `completed` | — |
| retryable / timeout | back to `pending`, after a backoff delay | yes |
| terminal | `failed` | no — it is not being given up on after trying, it is being declared impossible |
| not ready / busy | back to `pending`, after a *deferral* delay | no |
| incomplete | back to `pending`, eligible immediately | no |

**Two ladders, not one.** Retry backoff doubles from `manager_task_backoff_base` (30 s) to
`manager_task_backoff_cap` (900 s) — at the defaults, eight attempts span about forty-five minutes.
Deferral starts much lower, at `manager_task_defer_base` (5 s), because the common cause is a boot
race: the dispatcher starts before its in-process consumers bind their sockets, and starting at the
cap would tax every restart with a fifteen-minute delay to price a failure that resolves in seconds.

**`agent_delete_indexer` never gives up.** No attempt budget, no deferral budget, and a `4xx`
re-queues rather than failing. Once `client.keys` is written the agent is gone and nobody will ask
again, so the row is the only remaining record of the obligation. Setting only the budgets would not
be enough — a `4xx` maps to terminal, which is just as final.

**Every handler must be idempotent.** An outcome write can fail after the work is done — `wazuh-db`
restarting at the wrong moment — leaving the row `claimed` for the next sweep to reclaim and re-run.
There is no way to make that atomic across two processes, so the design absorbs the repeat instead.

---

## Ownership and stuck tasks

A claimed row records an `OWNER` naming the process instance and the lane worker inside it. Every
`manager_task_sweep_interval` (60 s) the scheduler checks its own workers' claimed rows and returns
to `pending` any whose owner is not actually running them. At startup it does the same over *every*
claimed row, whoever owns it — those are the rows the previous process left behind.

**A watchdog observes; it cannot fix.** There is no cancellation primitive available, so a handler
that overruns is reported, not stopped. The report is at most one per `cleanup_interval` (300 s), so
it is a post-hoc record rather than a live signal.

---

## Finding out what failed

A `dead_letter` row is the record of work the manager gave up on. Both halves of reaching it matter:
the log line carries the id, and the id can be looked up afterwards.

The log line is at ERROR and names the task:

```
Manager task '<task_id>' of type '<type>' dead-lettered after <n> attempts: <reason>
```

To fetch one by id, or to list what failed without having caught the line, query the task actor
directly. These are manager-internal commands on `queue/sockets/wdb.sock`, not REST endpoints:

```bash
# One task, by id
echo 'task get_manager_task {"task_id":"<task_id>"}' \
  | nc -U /var/wazuh-manager/queue/sockets/wdb.sock

# Everything of one type that dead-lettered, paged by task id
echo 'task get_manager_tasks_by_type {"task_type":"agent_delete_indexer","status":"dead_letter"}' \
  | nc -U /var/wazuh-manager/queue/sockets/wdb.sock
```

`get_manager_tasks_by_type` pages: results are ordered by `task_id`, at most `limit` per call (100 by
default, and its maximum), so pass the last `task_id` you received back as `last_task_id` until the
result comes back empty. Omit `status` to see every row of that type.

Both answer `ok <json>`, but they return different shapes. The list is deliberately narrow — one row
is `task_id`, `agent_id`, `status`, `create_time` and `last_error`, enough to see *what* failed and
why without paging whole payloads. `get_manager_task` returns the full row: add `attempts`,
`defer_count`, `owner`, `claim_time`, `next_attempt_at`, `end_time`, the `payload`, and — for a
scheduled run — the `schedule_id` and `scheduled_run_at` it belongs to.

So the usual sequence is: list the dead letters of a type, then fetch the interesting ids in full.

---

## Retention

Terminal rows are retired by the module's cleanup thread, on the same tick that expires agent tasks,
because they live in the same database and nothing else prunes them. Four rules apply, in order:

| Rule | Option | Default |
| --- | --- | --- |
| Terminal rows older than N days, measured from when they *reached* a terminal state | `wazuh_modules.manager_task_retention_days` | 7 |
| `dead_letter` rows older than N days | `wazuh_modules.manager_task_dead_letter_retention_days` | 30 |
| Keep at most N finished runs per schedule | `wazuh_modules.manager_task_history_per_schedule` | 20 |
| Hard ceiling on the table, evicting terminal rows | `wazuh_modules.manager_task_max_rows` | 100000 |

Dead letters outlive ordinary terminal rows because they are the only record of work that was
abandoned. Retention is measured from `END_TIME`, not `CREATE_TIME` — a task created eight days ago
and completed a minute ago would otherwise be evicted immediately.

---

## Configuration

Everything below is an internal option in `wazuh-manager-internal-options.conf`. **None of them
ships in a file**: the manager reads only that overrides file, so the defaults here live in code and
an option you have not written is at the value shown.

### Queue mechanics

| Option | Default | Meaning |
| --- | --- | --- |
| `wazuh_modules.manager_task_max_attempts` | 8 | Attempts before `dead_letter`, for types that have a budget |
| `wazuh_modules.manager_task_max_defer` | 48 | Consecutive deferrals before `dead_letter` |
| `wazuh_modules.manager_task_backoff_base` | 30 s | First retry delay; doubles from here |
| `wazuh_modules.manager_task_backoff_cap` | 900 s | Ceiling for both ladders |
| `wazuh_modules.manager_task_defer_base` | 5 s | First deferral delay |
| `wazuh_modules.manager_task_poll_interval` | 5 s | How often the scheduler looks for work |
| `wazuh_modules.manager_task_sweep_interval` | 60 s | How often ownership is swept |
| `wazuh_modules.manager_task_claim_grace` | 30 s | Slack before a claimed row is considered reclaimable |
| `wazuh_modules.manager_task_wdb_timeout` | 10 s | Deadline on the dispatcher's own `wazuh-db` calls |

`manager_task_max_attempts` and `manager_task_max_defer` are **defaults**. The registry carries
per-type overrides, and `agent_delete_indexer` sets both to unbounded. Those overrides are not
operator knobs: a deployment that gave the deletion lane a finite budget would silently reintroduce
the orphaned documents this feature exists to prevent.

### Per-type bounds

| Option | Default | Meaning |
| --- | --- | --- |
| `wazuh_modules.manager_task_delete_timeout` | 600 s | Deadline on one deletion call. Must exceed the scan timeout; asserted at startup |
| `wazuh_modules.manager_task_vd_scan_timeout` | 300 s | Deadline on one scan call |
| `wazuh_modules.manager_task_max_pending_deletes` | 20000 | Admission bound on pending deletions |
| `wazuh_modules.manager_task_max_pending_scans` | 64 | Admission bound on pending on-demand scans |
| `wazuh_modules.manager_task_create_timeout` | 2 s | Deadline on the scanner's own call to create a row |

The delete timeout must exceed the scan timeout because a scan holding an agent parks that agent's
deletion behind it in the consumer's per-agent queue; with both deadlines equal, the deletion would
expire while parked and be re-queued over work that was never its own fault.

Options governing the recurring tasks are listed in the
[configuration reference](configuration.md#recurring-manager-tasks).

---

## See Also

- [Recurring manager tasks](schedules.md) — the three scheduled jobs
- [Task Manager Configuration Reference](configuration.md)
- [Authd](../authd/README.md) — creates `agent_delete_indexer` rows
- [Inventory Sync Server](../inventory-sync-server/README.md) — executes the two routed types

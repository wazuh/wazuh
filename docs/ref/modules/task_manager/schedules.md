# Recurring manager tasks

The Task Manager runs three recurring jobs on the manager: the agent disconnection sweep, the
retention deletion of long-disconnected agents, and the daily log rotation. Each is a **schedule** —
a row in `MANAGER_TASK_SCHEDULES` inside `tasks.db` that records when it next runs and whether it
runs at all — and each fires by creating an ordinary manager task, which an executor worker then
claims, executes and retires with an outcome.

Size-based log rotation is the exception. It is not a task; see
[Size-based rotation](#size-based-rotation-is-not-a-task) below.

---

## The three schedules

| Schedule | Task type | Window it applies | How often it runs | Node scope |
| --- | --- | --- | --- | --- |
| `agent_disconnect_sweep` | `agent_disconnect_sweep` | `<global><agents_disconnection_time>` — 900 s | window ÷ 4, in [60 s, 300 s] — **225 s** at the default | master |
| `agent_delete_old` | `agent_delete_old` | `agents_disconnection_time` + `wazuh_modules.manager_task_delete_old_agents` × 60 — **disabled** at 0 | the retention minutes ÷ 4, in [60 s, 3600 s] | master |
| `log_rotate_daily` | `log_rotate_daily` | — | daily, at `00:00` + `wazuh_modules.manager_task_log_day_wait` — 00:00:10 local | any node |

Note that the sweep's **window** is `agents_disconnection_time`, which merely *defaults* to 900 — it
is not a hardcoded fifteen minutes, and `remoted` reads the same `<global>` value for its own
purposes, so it is shared configuration rather than something this module owns.

### Window and interval are not the same number

The window is an *age* — how long an agent must have been silent. The interval is how often that age
is applied. Keeping them apart is what bounds the detection SLA.

They used to be one value, and the cost was a detection window of `[T, 2T]`: an agent that went
silent just after a run waited out a whole second one, so a configured fifteen minutes delivered
anywhere from fifteen to thirty. The interval is now derived from the window instead of being it:

```
interval = clamp(window / 4, 60 s, ceiling)   # then never coarser than the window itself
```

with a ceiling of 300 s for the disconnection sweep and 3600 s for retention deletion — the sweep is
one `UPDATE` whose latency is visible in the API, while retention deletion re-reads the whole
disconnected list per run to delete agents that have already been silent for hours.

| `agents_disconnection_time` | Interval | An agent is marked `disconnected` within |
| --- | --- | --- |
| `4m` | 60 s | 4 m – 5 m |
| `15m` (default) | 225 s | 15 m – 18 m 45 s |
| `1h` | 300 s | 1 h – 1 h 5 m |

The quarter bounds the overshoot at 25 %; the ceiling bounds it in absolute terms instead, so raising
the threshold to quieten the log costs five minutes of imprecision rather than fifteen. Below the
floor the interval collapses back to the window, which is the old behaviour and no worse than it.

**The window itself is unchanged by any of this.** Which agents cross the threshold is decided by
`agents_disconnection_time` alone; the interval decides only how promptly crossing it is noticed. The
same derivation applies to `agent_delete_old`, whose window remains
`agents_disconnection_time + delete_old_agents × 60`.

The internal options are not shipped in any file: the manager reads only an empty overrides file, so
the defaults above are the whole of their contract. Every option, including the ones that bound the
retention sweep, is listed in the
[Task Manager Configuration Reference](configuration.md#recurring-manager-tasks) — which also covers
how to read back what a running manager actually resolved.

---

## When a schedule fires

The scheduler thread asks `tasks.db` for the schedules whose next run has come due, once per
the scheduler's own wake, and applies four rules to each.

### Node scope

`master`-scoped schedules do not spawn on a cluster worker. A configuration whose cluster stanza
**cannot be parsed** is treated as "not the master" rather than falling through to master: a node
whose own configuration cannot be read is not a node to hand cluster-wide work to.

Scope is evaluated at spawn time, so a demoted master leaves already-pending master-scope rows
behind and its own executor still runs them. That is deliberate: the work was already decided
on, and a node that stops spawning is not a node that abandons obligations.

### Overlap

A schedule does not spawn while a non-terminal instance of its own is still outstanding. **This
interacts with `agent_delete_old`'s batching, and the interaction is intended**: a multi-batch
retention sweep holds a pending instance for the whole sweep, which suppresses its own next
scheduled run until it finishes. Correct — a retention sweep should not start again while the
previous one is still walking — but it means the effective interval under a large backlog is *however
long the sweep takes*, not the derived one.

Overlap-skip is also why the shorter derived intervals cannot pile work up: a slot that comes due
while the previous run is still going is forfeited, not queued.

### Missed runs coalesce

After downtime spanning several slots, one instance is spawned and the next run advances to the next
*future* slot. A manager down for a day does not wake up owing 384 disconnect sweeps.

The slot grid itself survives the outage: the next run is computed from the missed slot, not from
the moment the manager came back, so the cadence does not drift with every restart.

### Spawn idempotency

The instance's task id is derived from the schedule and its slot, so a crash between creating the
instance and advancing the next run is harmless: the slot is still due, the retry derives the same
id, and the primary-key collision makes the double spawn a no-op. No transaction across the two
tables is needed.

---

## Enabling and disabling

`ENABLED` is **persisted**, not merely read from configuration on each start. Configuration wins on
the startup upsert, but the previous value has to be read first, because detecting a
disabled → enabled transition is the only way to know whether to recompute the next run — and that
transition can straddle a restart.

- **Disabling** stops spawning and leaves already-spawned instances to reach a terminal state. It
  does not cancel them: a pending disconnect sweep is work the manager already decided to do.
- **Re-enabling** recomputes the next run as `now + interval`. **Disabled time is not downtime.**
  Otherwise a schedule switched back on after a week would carry a week-old next run, missed-run
  coalescing would see an overdue slot, and it would fire immediately — and for `agent_delete_old`,
  which is destructive and off by default, an operator flipping the switch and getting an instant
  sweep is a surprise worth not shipping.
- **Lowering an interval** takes effect at the next restart. A stored next run that is further out
  than one whole interval from now cannot have been produced by the interval configured today, so it
  is recomputed. Raising an interval needs no correction: the stored slot merely falls sooner than
  the new interval would place it, so it fires once early and re-anchors. Lowering
  `agents_disconnection_time` lowers the derived interval with it, and the same rule applies.

---

## What each handler does

### `agent_disconnect_sweep`

Transitions every agent whose last keepalive is older than `agents_disconnection_time` to
`disconnected`, and logs each transition at DEBUG as
`wazuh: Agent disconnected: [NNN] (name).`

The database transition and the log line are one job, not two: the transition already returns the ids
it just changed, so the set is in hand and no second pass — nor the in-memory queue one would need —
is required. The only remaining lookup is one name per *newly disconnected* agent, once per sweep.

`wazuh_modules.manager_task_monitor_agents = 0` silences the log line and nothing else: the
transition still happens, because an agent that stopped answering has to reach the `disconnected`
state whatever else is configured.

**The sweep runs on the master only**, and the scope is enforced rather than assumed — running it on
two nodes at once would have both writing the same transitions.

### `agent_delete_old`

Deletes agents that have been disconnected for longer than the retention window, which is
`agents_disconnection_time` **plus** `delete_old_agents × 60` — an agent is eligible one whole
retention period after it is marked disconnected, not the moment it is marked.

**Bounded per attempt**, by `wazuh_modules.manager_task_delete_old_batch` (200 agents examined) and
`wazuh_modules.manager_task_delete_old_budget` (30 s elapsed), whichever comes first, returning
`incomplete` and resuming where it left off. The time bound is the one that matters: what is being
protected is how long the handler holds its executor slot, measured in seconds, while the batch is
counted in agents.

If `wazuh-authd` refuses a removal because its own deletion backlog is full, the sweep stops there
and retries on the queue's backoff ladder rather than reporting success — the agent is still there.
An agent that is already gone, or one whose deletion `wazuh-authd` has already journaled, counts as
done.

**Deletion is by agent id**, which is in hand from the candidate query. Nothing round-trips through
an agent name, which would be ambiguous for duplicate names.

### `log_rotate_daily`

Rotates `logs/wazuh-manager.log` and `logs/wazuh-manager.json` into the day's archive directory,
honouring `wazuh_modules.manager_task_log_compress`, `wazuh_modules.manager_task_log_keep_days` and
`wazuh_modules.manager_task_log_daily_rotations`.

**The offset is a slot, not a sleep.** `day_wait` is the schedule's next-run time rather than a delay
the handler blocks on. That matters because the handler shares its concurrency group with
size-based rotation,
which a blocking sleep of up to 600 seconds would suspend for its whole duration.

**Daily rotation survives a same-day restart**, because its baseline is the persisted next run rather
than a day-change comparison re-seeded from *now* at every start.

### Size-based rotation is not a task

Rotating either log that has grown past `wazuh_modules.manager_task_log_size_rotate` is two `stat`
calls, checked once a minute. Routing that through insert, poll, claim, commit, execute and retention would cost about 1440
rows a day for work that is idempotent, instantaneous and harmless to miss — a skipped tick just
rotates a minute later. It runs as a **periodic action** on the executor instead: it gets no schedule
row, no task type, no retry and no history.

It runs on an *executor* thread rather than on the scheduler that signals it, because rotation with
compression enabled gzips the file inline and the scheduler is also the work poller and the ownership
sweeper. It joins the `rotation` concurrency group, which is what keeps it from ever overlapping the
daily rotation, and repeated signals before it runs coalesce
into one run — so with `agent_delete_old` bounded at its own budget, worst-case size-rotation latency
is one bounded task in that group, not one minute.

---

## Where a run ends up

All three run on the module's shared executor, each with a concurrency cap of one, so no schedule can
ever have two runs in flight at once. Only `log_rotate_daily` shares a group with anything: it joins
`rotation` alongside the size-triggered rotation, because those two rewrite the same files. The
disconnection sweep and the retention deletion have groups of their own and can therefore run at the
same time as each other and as a rotation.

That is a change from the retired implementation, where all three shared one thread purely to avoid
keeping three alive. Nothing about the work required it. The executor picks types round-robin so a
busy one cannot starve its siblings.

Each instance is stamped with its `SCHEDULE_ID` and `SCHEDULED_RUN_AT`, which is what makes a
schedule's run history queryable and what the per-schedule retention cap counts on. A run that fails
its whole retry budget lands in `dead_letter` and stays queryable by task id; the schedule keeps
spawning regardless, because a failed run is not a broken schedule.

### If a run overruns

A handler that runs inside `wazuh-modulesd` cannot be interrupted — there is no cancellation
primitive available — so an overrun is **observed, not stopped**. Each of the three types carries a
budget past which the watchdog logs a warning naming the task type and the task id:

| Task type | Budget | Where it comes from |
| --- | --- | --- |
| `agent_delete_old` | `manager_task_delete_old_budget` + 60 s | derived, because the budget is configurable |
| `agent_disconnect_sweep` | 300 s | a judgement: one sweep plus one name lookup per transitioned agent |
| `log_rotate_daily` | 900 s | two files gzipped inline at up to the rotation threshold each |

The warning is a post-hoc record rather than a live signal: it is emitted at most once per
`task-manager` `cleanup_interval` (300 s by default). A run that overruns still finishes, and still
records its outcome.

---

## See Also

- [Manager tasks](manager-tasks.md) — the queue these run on: states, retry, retention, operator lookup
- [Task Manager Configuration Reference](configuration.md)
- [Task Manager](README.md)
- [Authd](../authd/README.md) — executes the removals `agent_delete_old` requests

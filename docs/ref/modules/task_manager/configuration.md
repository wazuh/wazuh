# Task Manager Configuration Reference

Complete configuration reference for the Wazuh Task Manager module.

The Task Manager stores tasks addressed to agents (agent upgrades, active response, agent restart, agent reload) and serves them on the agent's next poll, runs the manager's own tasks, and serves remote agent upgrades. For module overview and architecture, see [Task Manager Module](README.md).

---

## Manager Configuration

**Configuration file:** `/var/wazuh-manager/etc/wazuh-manager.conf`

**XML Section:** `<task-manager>`

**Internal Options:** many — see [Recurring manager tasks](#recurring-manager-tasks),
[Agent upgrades](#agent-upgrades) and [Manager tasks](manager-tasks.md#configuration). Everything in
the `<task-manager>` block below is XML; everything that tunes the queue, the schedules or the
upgrade path is an internal option.

The `<task-manager>` block accepts the four queue options below and the two
[agent-upgrade options](#xml-options). The four below are non-negative integers (seconds unless noted);
a value of `0` — or omitting the option — makes the module fall back to its built-in default. They
are read once, when `wazuh-manager-modulesd` starts.

### task_ttl

Time-to-live for a **pending** agent task, measured from its `create_time`. On each cleanup pass
(every `cleanup_interval`), pending tasks older than `task_ttl` are moved to `expired` and are never
handed out. Manager tasks are never expired by age. (The schema's one-line description, "Seconds a
finished task is kept", does not describe what the module does with it.)

- **Default value:** `3600` (1 hour)
- **Allowed values:** integer ≥ 0 (seconds). `0` means "use default".
- **Note:** for agents below v5.0.0, `remoted`'s own `remoted.legacy_task_polling_interval` (default
  `900`s, see [remoted configuration](../remoted/configuration.md)) must be configured comfortably
  smaller than this value, or a `remote_upgrade` task created just after a poll cycle can expire
  before the next cycle ever picks it up. Nothing checks this relationship for you — the two options
  belong to different daemons and neither reads the other's — so it is worth confirming by hand
  whenever either is changed.

### cleanup_interval

Interval between cleanup passes. Each pass expires pending agent tasks older than `task_ttl`, deletes
`expired` agent tasks created more than 24 h ago and `delivered` ones delivered more than 24 h ago,
applies the [manager-task retention rules](manager-tasks.md#retention), returns the space those
deletions freed to the filesystem in 1 MiB steps, and checkpoints the database WAL. There is no
separate daily `VACUUM`.

- **Default value:** `300` (5 minutes)
- **Allowed values:** integer ≥ 0 (seconds). `0` means "use default".

### max_payload_bytes

Maximum accepted size of a single task payload, after JSON serialization. A request over the limit is
rejected with HTTP `413` and a `payload_too_large` body. It applies to agent tasks and manager tasks alike.

- **Default value:** `1048576` (1 MiB)
- **Allowed values:** integer ≥ 0 (bytes). `0` means "use default".
- **Note:** the manager-task routes are served in the transport's `Control` class, whose own body cap
  defaults to 64 KiB. The module raises that cap to this value plus envelope overhead, so the limit
  you configure is the one that applies — but a value raised far beyond the payloads a producer
  actually sends only widens what one request can reserve.

### max_tasks_per_poll

Maximum number of tasks returned by one `POST /v1/tasks/pending` call, oldest first. Additional pending tasks remain `pending` and are returned on subsequent polls.

- **Default value:** `100`
- **Allowed values:** integer ≥ 0. `0` means "use default".

---

## Manager Configuration Examples

### Default Configuration

The section can be omitted entirely — the module runs with all built-in defaults, on every manager
node in the cluster:

```xml
<task-manager>
</task-manager>
```

Or explicit:

```xml
<task-manager>
  <task_ttl>3600</task_ttl>
  <cleanup_interval>300</cleanup_interval>
  <max_payload_bytes>1048576</max_payload_bytes>
  <max_tasks_per_poll>100</max_tasks_per_poll>
</task-manager>
```

### High-Volume Environment

For deployments with many agents and frequent task creation, enlarge the response batch size and give tasks more time before they are considered expired:

```xml
<task-manager>
  <task_ttl>7200</task_ttl>
  <cleanup_interval>600</cleanup_interval>
  <max_tasks_per_poll>500</max_tasks_per_poll>
</task-manager>
```

### Larger Active Response Payloads

The default 1 MiB limit is enough for the majority of tasks. Raise it only if the payload the producer is attaching is legitimately large (e.g. an Active Response event with rich context):

```xml
<task-manager>
  <max_payload_bytes>4194304</max_payload_bytes>
</task-manager>
```

---

## Validation and Troubleshooting

### Validate Configuration

After editing configuration:

```bash
/var/wazuh-manager/bin/wazuh-manager-conf validate
```

`wazuh-manager-modulesd -t` additionally resolves every internal option below, and exits with
`(2302): Invalid definition for wazuh_modules.<option>: '<value>'.` when one is out of range:

```bash
/var/wazuh-manager/bin/wazuh-manager-modulesd -t
```

### Check Module Status

The Task Manager runs on every manager node in the cluster (both master and workers), inside
`wazuh-manager-modulesd`. It logs `Task manager started: <n> executor workers, database '<path>'` when
it is up, and answers its liveness probe:

```bash
curl --unix-socket /var/wazuh-manager/queue/sockets/task-http.sock http://localhost/v1/health
# {"status":"ok"}
```

If the module cannot bind its socket or open `tasks.db`, modulesd exits with `Cannot start the task
manager module.`; a missing `lib/libtask_manager.so` exits with `Unable to load libtask_manager.so
(<reason>); the installation is broken.`

### Inspect the tasks database

The Task Manager is the **sole owner** of `tasks.db`: Wazuh DB no longer has a `task` actor, and
there is no protocol to query it through. Read it directly, and only read it — the module holds the
database open in WAL mode:

```bash
sqlite3 -readonly /var/wazuh-manager/queue/tasks/tasks.db \
  "SELECT STATUS, COUNT(*) FROM TASKS GROUP BY STATUS;"
```

Manager tasks live in the same file and are better inspected through the module's own endpoints,
which is what [Manager tasks](manager-tasks.md) documents.

### Monitor Logs

```bash
# Module tag wazuh-manager-modulesd:task-manager, with the sub-tags
# :executor, :scheduler, :http and :upgrade
tail -f /var/wazuh-manager/logs/wazuh-manager.log | grep task-manager
```

Debug output is enabled through modulesd's debug level in `wazuh-manager-internal-options.conf`
(`0`–`2`):

```ini
wazuh_modules.debug=2
```

### Read the metrics

`GET /v1/metrics` on the module's own socket. No body, no headers, no authentication — it is a local
Unix socket readable by the `wazuh-manager` group:

```bash
curl --unix-socket /var/wazuh-manager/queue/sockets/task-http.sock \
     http://localhost/v1/metrics | jq
```

**The path is `/v1/metrics`, not `/metrics`.** Every metric, what it means, the option to act on and a
short triage guide are in [Metrics](metrics.md).

### Common Issues

**Issue:** A task shows up as `expired` before an agent could pick it up.
**Solution:** Increase `task_ttl` if the target agents may be offline for long periods, or make sure the agents actually poll on their `notify` cadence. Each cleanup pass logs how many pending agent tasks it expired at debug level (`Expired N pending agent task(s) created more than Ns ago (task_ttl)`). In a cluster, some expiries are expected rather than a fault: an agent command is queued on every node, only the node the agent polls delivers it, and the other nodes' copies age out.

**Issue:** `413` answers with `payload exceeds max_payload_bytes` when creating tasks.
**Solution:** Producers should reduce payload size, or raise `max_payload_bytes`. This limit protects the manager from unbounded task payloads.

**Issue:** `tasks.db` keeps growing.
**Solution:** Agent-task rows are deleted 24 h after they expire or are delivered, on the next
cleanup pass, and the same pass returns the freed space to the filesystem; a long `cleanup_interval`
delays deletion, expiry and the shrink. Manager-task rows are bounded by the
[retention rules](manager-tasks.md#retention). If the log shows `Could not checkpoint the tasks
database`, the `tasks.db-wal` file is what is growing. If it shows `The tasks database was created
without incremental auto-vacuum`, the database predates the incremental compaction: its freed space
is reused but the file never shrinks. Stop the manager and run
`sqlite3 /var/wazuh-manager/queue/tasks/tasks.db 'PRAGMA auto_vacuum=INCREMENTAL; VACUUM;'` once to
convert it.

---

## Recurring manager tasks

The Task Manager's three recurring jobs — the agent disconnection sweep, the retention deletion of
long-disconnected agents and log rotation — have **no `<task-manager>` options of their own**. They
take their window from `<global><agents_disconnection_time>` and everything else from the internal
options below; their behaviour is described in [Recurring manager tasks](schedules.md).

### agents_disconnection_time

`<global>` holds this one option. It is shared configuration rather than the Task Manager's own:
the disconnection sweep uses it as its window, and `wazuh-manager-remoted` reads the same value (it
stops pushing to an agent silent for longer, and warns when `remoted.control_keepalive_throttle` is
at or above half of it).

- **Default value:** `15m`
- **Allowed values:** seconds as an integer, or a number with a unit suffix `s`, `m`, `h`, `d` or `w`;
  at least 1 second. `0` (in any unit) is rejected by `wazuh-manager-conf validate` and by the
  pre-start check of `wazuh-manager-control` with `(1244): Invalid configuration at
  '/global/agents_disconnection_time': ...`, so no daemon starts.
- **Effect:** an agent whose last keepalive is older than this is marked `disconnected` by the
  [disconnection sweep](schedules.md#agent_disconnect_sweep), which runs on the master node only.
  Read when `wazuh-manager-modulesd` starts; if `global` cannot be read the module logs `Cannot read
  the global configuration; the agent disconnection sweep will use its default window.` and uses
  900 s.

```xml
<global>
  <agents_disconnection_time>15m</agents_disconnection_time>
</global>
```

### Where their settings come from

| Setting | Where it lives | Default | Range | Governs |
| --- | --- | --- | --- | --- |
| `agents_disconnection_time` | `<global>` in `wazuh-manager.conf` | `15m` | ≥ 1 s | how long an agent must be silent before it is marked `disconnected` |
| `wazuh_modules.manager_task_delete_old_agents` | internal option | 0 (disabled) | 0–9600 | retention window in minutes, on top of `agents_disconnection_time` |
| `wazuh_modules.manager_task_monitor_agents` | internal option | 1 | 0–1 | whether the disconnection sweep runs at all (the retention sweep is governed by `manager_task_delete_old_agents`) |
| `wazuh_modules.manager_task_log_rotate` | internal option | 1 | 0–1 | whether either kind of log rotation happens — `0` disables the daily schedule *and* the size-triggered one |
| `wazuh_modules.manager_task_log_day_wait` | internal option | 10 s | 1–600 | offset from local midnight for the daily rotation; `0` is out of range (the slot cannot sit exactly at midnight) |
| `wazuh_modules.manager_task_log_compress` | internal option | 1 | 0–1 | whether rotated logs are gzipped |
| `wazuh_modules.manager_task_log_keep_days` | internal option | 31 | 0–500 | how many days rotated logs are kept; `0` keeps none |
| `wazuh_modules.manager_task_log_size_rotate` | internal option | 512 (MB) | 0–4096 | threshold for size-based rotation; `0` disables size rotation while leaving the daily one alone |
| `wazuh_modules.manager_task_log_daily_rotations` | internal option | 12 | 1–256 | rotated slots per day per file |

**None of the internal options ships in a file.** The manager reads only
`/var/wazuh-manager/etc/wazuh-manager-internal-options.conf`, which ships comments only — there is no
manager defaults file to consult. Every default above lives in code, so an option you have not written
is at the value in this table, and writing one is the only way to change it. All are read once, when
`wazuh-manager-modulesd` starts.

> **Renamed in 5.0.** These were `monitord.*` while log rotation and agent monitoring belonged to
> `wazuh-manager-monitord`. If you set any of them in `wazuh-manager-internal-options.conf` on an
> earlier build, rename the key — an override under the old name is silently ignored, because the
> lookup compares the part before the first `.` as well as the part after it.
>
> **The agent is unaffected.** It keeps `monitord.*` for its own log rotation; see the
> [Agent configuration reference](../client/configuration.md). Only the manager's keys moved.

**The first two settings are windows, not intervals.** Each names an *age* — how long an agent must
have been silent — and the schedule that applies it runs on an interval derived from it, at a quarter
of the window bounded to `[60 s, 300 s]` for the disconnection sweep and `[60 s, 3600 s]` for
retention deletion. At the default that is a sweep every 225 s against a 900 s window, so an agent is
marked `disconnected` between 15 and 18 m 45 s after its last keepalive. There is no option for the
interval; see [Window and interval are not the same
number](schedules.md#window-and-interval-are-not-the-same-number).

### Reading back what modulesd read

Because these are internal options with no XML element, configuration on disk does not show what is
in effect. The values `wazuh-manager-modulesd` read at start-up are reported by the node's
active-configuration endpoint, in the `task-manager` entry of `wmodules`, under `recurring_tasks`
(and the upgrade options under `agent_upgrade`):

```bash
curl -k -X GET "https://localhost:55000/cluster/<node_name>/configuration/wmodules/wmodules" \
     -H "Authorization: Bearer $TOKEN"
```

`recurring_tasks` carries `agents_disconnection_time`, `delete_old_agents`, `monitor_agents`,
`log_rotate`, `log_compress`, `log_keep_days`, `log_daily_rotations`, `log_size_rotate`,
`delete_old_batch` and `delete_old_budget`. They are the values as read, before the module applies
its defaults. `monitor_agents`, `log_rotate`, `log_compress` and `delete_old_agents` are the effective
values (`0` turns them off); for the others `0` means "not set, the default in the tables on this page
applies", and for `log_keep_days` and `log_size_rotate` a `-1` means "explicitly set to `0`". `log_day_wait`,
`disconnect_log_max` and the queue options on [Manager tasks](manager-tasks.md#configuration) are
not reported.

### Options that bound the two sweeps

All three are internal options in the `wazuh_modules` namespace.

| Option | Default | Range | Meaning |
| --- | --- | --- | --- |
| `wazuh_modules.manager_task_delete_old_batch` | 200 | 1–100000 | agents the retention sweep examines per attempt |
| `wazuh_modules.manager_task_delete_old_budget` | 30 | 1–3600 | seconds a retention-sweep attempt may hold its executor slot |
| `wazuh_modules.manager_task_disconnect_log_max` | 200 | 0–1000000 | agents the disconnection sweep names individually per run; `0` names none |

**The retention sweep's two bounds** keep a large backlog from holding the shared executor slot for
the whole sweep. The time bound is the one that binds in practice: the deadline on each removal
request to `wazuh-manager-authd` is `wazuh_modules.manager_task_wdb_timeout` (default 10 s), so 200
agents against a wedged `wazuh-manager-authd` would otherwise be a worst case measured in tens of
minutes while holding one executor slot. Counting agents bounds the work; counting seconds bounds the
occupancy. Whichever is reached first, the attempt returns `incomplete` — neither success nor failure
— and the executor re-claims the row and resumes where it stopped.

**`manager_task_disconnect_log_max` bounds the diagnostics, not the work.** The sweep's database
transition is a single query and always completes for every agent. Turning each of those ids into a
name for the log line is one round trip per agent, and a partition — or a manager that was down long
enough for a fleet to age out — can transition tens of thousands at once. The lookups are also capped
at 30 s per run, which is not configurable. Past either bound, agents are still transitioned; they are
just not named individually, and the run reports how many were skipped. Unlike the retention sweep
this does not return `incomplete` and resume: the ids exist only within one call, so a later attempt
would have no list to resume from.

---

## Agent upgrades

Remote agent upgrades are served by this module, on `POST /v1/agents/upgrade` and
`POST /v1/agents/upgrade-custom`. It validates each agent, fetches and verifies the WPK, and writes
one `remote_upgrade` agent task per agent.

### XML options

| Option | Default | Meaning |
| --- | --- | --- |
| `<upgrade_enabled>` | `yes` | `no` refuses every upgrade request, per agent, with *Upgrade procedure could not start* (Server API error 1827) |
| `<wpk_repository>` | none | Repository to fetch WPKs from, `host/path` with or without a scheme; with no scheme, `https://` is prepended (`http://` when the request sets `use_http`). A request's own `wpk_repo` overrides it. Unset, the repository is derived from the target version: `packages.wazuh.com/<major>.x/wpk/`, or `packages.wazuh.com/wpk/` for a target below v4.0.0 |

```xml
<task-manager>
  <wpk_repository>https://packages.internal.company.com/wazuh/wpk/</wpk_repository>
</task-manager>
```

**`<agent-upgrade>` is not a manager section, and the schema rejects it.** A manager configuration
carrying one is refused with `Invalid configuration at '/agent-upgrade'`, and the manager will not
start. That module and its settings exist only on an agent, where they control what that agent
accepts; the two settings above are the manager's half.

Two settings outside `<task-manager>` also matter: `remote.legacy.enabled` decides whether a pre-v5.0.0
agent can be reached at all, and `remote.https.verification_mode` decides whether an agent that
is about to become v5.x will be able to reconnect afterwards. The Task Manager reads both **once, when
`wazuh-manager-modulesd` starts**, so after changing either run `wazuh-manager-control restart`
(`reload` restarts modulesd but not remoted). If the `remote` section cannot be read, the module logs
`Cannot read the remote configuration; the agent upgrade delivery checks will be skipped.` and both
gates let every agent through.

### Internal options the upgrade path adds

All in the `wazuh_modules` namespace, all resolved before the daemon forks, so an out-of-range value
fails `wazuh-manager-modulesd -t` rather than aborting later.

| Option | Default | Range | Meaning |
| --- | --- | --- | --- |
| `wazuh_modules.upgrade_workers` | `cores / 2`, clamped to 1–4 | 1–16 | upgrade **batches** run at once |
| `wazuh_modules.upgrade_queue_depth` | 8 | 1–1000 | batches queued before a request is refused |
| `wazuh_modules.upgrade_batch_deadline` | 180 | 10–3600 | seconds one batch may take before its remaining agents are failed |
| `wazuh_modules.upgrade_max_agents` | 500 | 1–100000 | largest batch accepted in one request |
| `wazuh_modules.upgrade_download_attempts` | 3 | 1–10 | tries per WPK before giving up |
| `wazuh_modules.upgrade_download_timeout` | 45000 | 1000–600000 | milliseconds per download attempt |
| `wazuh_modules.upgrade_max_concurrent_downloads` | 2 | 1–32 | WPK downloads in flight across all batches |
| `wazuh_modules.upgrade_versions_ttl` | 300 | 0–86400 | seconds a repository's `versions` file is cached; `0` fetches every time |

**`upgrade_workers` counts batches, not agents, and it is deliberately small.** Per-agent work is one
wazuh-db query on a shared, mutex-guarded socket plus arithmetic; running agents in parallel would
multiply contention on that mutex to buy nothing. What genuinely arrives in parallel is whole
requests — the Server API chunks a fleet at 500, and every cluster node broadcasts. There is a second
reason to keep it low: the WPK client is `shared_modules/http-request`, which caches curl handlers in
a process-wide queue of five entries shared with the vulnerability scanner and the indexer connector,
so a large pool here costs *them* connection reuse.

Note also that `upgrade_max_concurrent_downloads` — not `upgrade_workers` — is what bounds transfers.
A batch that cannot get a download slot inside `upgrade_batch_deadline` reports *The repository is not
reachable* for that package rather than waiting past the deadline.

**Three deadlines have to stay ordered**, shortest first:

```
upgrade_batch_deadline  <  the Server API's client timeout  <  the route's response backstop
       180 s                          240 s                             300 s
```

The module answering first is what makes a slow repository produce a per-agent envelope the API can
act on, instead of a connection the transport tore down. `upgrade_batch_deadline` is checked between
download attempts and while queued for a download slot, not only between packages, so a batch cannot
overrun it by `upgrade_download_attempts` × `upgrade_download_timeout` per package. One transfer
already in flight still runs out its own timeout.

**`upgrade_versions_ttl` is what keeps a fleet-wide upgrade cheap.** Agents that resolve to the same
package share one `versions` fetch and one download, so 500 agents on one platform cost one of each
rather than 500. The TTL bounds how long a newly published release goes unnoticed; set it to `0` to
fetch every time. Within a single batch the dedup does not depend on the TTL at all — one fetch per
distinct repository path is decided by grouping, not by caching — so `0` costs one request per batch,
not one per agent.

### Monitoring agent upgrades

Upgrade work logs under its own sub-tag, `wazuh-manager-modulesd:task-manager:upgrade`:

```bash
tail -f /var/wazuh-manager/logs/wazuh-manager.log | grep 'task-manager:upgrade'
```

The counters are also published on the module's metrics endpoint — `wpk_downloads`,
`wpk_cache_hits`, `versions_fetches`, `versions_cache_hits`, `queue_depth` and `batches_shed`:

```bash
curl --unix-socket /var/wazuh-manager/queue/sockets/task-http.sock http://localhost/v1/metrics
```

Each request produces one `remote_upgrade` row per accepted agent, inspectable like any other task
type. Whether the agent then picked it up, downloaded the WPK and ran the installer is visible in
the agent's own log — the manager is never told the outcome.

### Troubleshooting agent upgrades

**Requests are rejected.** Check `<upgrade_enabled>`, then the per-agent code in the response: the
version gates are listed under
[Version constraints](agent-upgrades.md#version-constraints).

**WPK downloads fail.** Confirm outbound HTTPS access to `<wpk_repository>`, or place the WPK under
`/var/wazuh-manager/var/upgrade/` and use the custom-upgrade endpoint. A custom WPK **must** be
inside that directory; anything else is refused with *The WPK file does not exist*.

*A missing CA bundle fails every repository request, by design.* Peer verification is never disabled: the
SHA-1 a WPK is checked against comes from the repository's own index over the same connection, so an
unverified channel would let a man in the middle supply a matching pair and the integrity check
would confirm his work rather than ours. The module says so once at start-up:

```
No CA bundle was found on this host. HTTPS requests to the WPK repository will fail;
agent upgrades over https are unavailable until one is installed.
```

Install the distribution's CA certificates package. Pointing `<wpk_repository>` at an `http://` URL
does not work around it: without a bundle the client refuses every repository request, whatever the
scheme.

**Requests are refused under load.** Every agent answered with *Task manager communication error*
(`1814`) means the batch queue was full (the log says `Refusing an upgrade request for <n> agents: the
queue is full.`) or the module was stopping. The Server API halves the chunk and retries automatically,
so this is usually self-correcting; if it persists the repository is likely slow, and
`wazuh_modules.upgrade_queue_depth` or `upgrade_workers` can be raised.

**A task never completes.** The manager only records that the task was created. If it stays
`pending` past `task_ttl` it is marked `expired` by the next cleanup pass.

---

## See Also

- [Manager tasks](manager-tasks.md) — the queue's own options, states and operator lookup
- [Recurring manager tasks](schedules.md) — the three schedules and how they fire
- [Agent upgrades](agent-upgrades.md) — the manager-side flow end to end
- [Task Manager Module](README.md) — Module overview and architecture
- [Wazuh DB](../wazuh_db/README.md) — no longer involved in `tasks.db`; the module owns it outright
- [Manager Configuration Reference](../../configuration/manager/README.md)

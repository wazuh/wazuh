# Task Manager Configuration Reference

Complete configuration reference for the Wazuh Task Manager module.

The Task Manager stores tasks addressed to agents (agent upgrades, active response, agent restart, agent reload) and serves them to agents on their next poll. For module overview and architecture, see [Task Manager Module](README.md).

---

## Manager Configuration

**Configuration file:** `/var/wazuh-manager/etc/wazuh-manager.conf`

**XML Section:** `<task-manager>`

**Internal Options:** None

The `<task-manager>` block accepts the options below. All values are non-negative integers expressed in seconds (except where noted). A value of `0` — or omitting the option — makes the module fall back to its built-in default.

### task_ttl

Time-to-live for a task, measured from `create_time`. Tasks whose age exceeds `task_ttl` are moved to the `expired` state by the cleanup thread.

- **Default value:** `3600` (1 hour)
- **Allowed values:** integer ≥ 0 (seconds). `0` means "use default".
- **Note:** for agents below v5.0.0, `remoted`'s own `remoted.legacy_task_polling_interval` (default `900`s,
  see [remoted configuration](../remoted/configuration.md)) must be configured comfortably smaller than
  this value, or a `remote_upgrade` task created just after a poll cycle can expire before the next cycle
  ever picks it up. At startup, the Task Manager reads `remoted.legacy_task_polling_interval` from
  `internal_options.conf` (via `getDefine_Int_default`, the same generic lookup-by-section-name mechanism
  `remoted` itself uses — it is not restricted to the daemon that defines the option) and logs an
  `mtwarn` if `legacy_task_polling_interval >= task_ttl`. This is a startup-time check only; it does not
  react to a config change made without restarting `wazuh-modulesd`.

### cleanup_interval

Interval between cleanup runs. Each run marks expired tasks and deletes rows that have been expired for more than 24 h. A database `VACUUM` is issued once a day, independently of this interval.

- **Default value:** `300` (5 minutes)
- **Allowed values:** integer ≥ 0 (seconds). `0` means "use default".

### max_payload_bytes

Maximum accepted size of a single task payload, after JSON serialization. Requests exceeding this limit are rejected with a `create_failed` error and logged.

- **Default value:** `1048576` (1 MiB)
- **Allowed values:** integer ≥ 0 (bytes). `0` means "use default".

### max_tasks_per_poll

Maximum number of tasks returned by a single `get_pending_tasks` call. Additional pending tasks remain in `pending` state and are returned on subsequent polls.

- **Default value:** `100`
- **Allowed values:** integer ≥ 0. `0` means "use default".

---

## Manager Configuration Examples

### Default Configuration

The section can be omitted entirely — the module runs with all built-in defaults and is always started on the master node:

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
/var/wazuh-manager/bin/wazuh-logtest-config
```

### Check Module Status

```bash
/var/wazuh-manager/bin/wazuh-modulesd --test
```

The Task Manager runs on every manager node in the cluster (both master and workers).

### Inspect the tasks database

Task rows live in the `tasks.db` database managed by Wazuh DB and can be inspected via the `task` protocol or directly:

```bash
sqlite3 /var/wazuh-manager/queue/db/tasks.db \
  "SELECT status, COUNT(*) FROM tasks GROUP BY status;"
```

### Monitor Logs

```bash
# Task Manager logs (module tag: wazuh-modulesd:task-manager)
tail -f /var/wazuh-manager/logs/wazuh-manager.log | grep task-manager
```

Debug output can be enabled through the shared wodle debug switch in `wazuh-manager-internal-options.conf`:

```ini
wazuh_modules.debug=2
```

### Common Issues

**Issue:** A task shows up as `expired` before an agent could pick it up.
**Solution:** Increase `task_ttl` if the target agents may be offline for long periods, or make sure the agents actually poll on their `notify` cadence.

**Issue:** `Task payload too large` errors when creating tasks.
**Solution:** Producers should reduce payload size, or raise `max_payload_bytes`. This limit protects the manager from unbounded task payloads.

**Issue:** `tasks.db` keeps growing.
**Solution:** Ensure the cleanup thread is running — it deletes rows 24 h after they expire and issues a daily `VACUUM`. Very short `task_ttl` combined with a very long `cleanup_interval` can leave rows around longer than expected.

---

## Recurring manager tasks

The Task Manager's three recurring jobs — the agent disconnection sweep, the retention deletion of
long-disconnected agents and log rotation — have **no `<task-manager>` options of their own**. They
are configured through the internal options below, and their behaviour is described in
[Recurring manager tasks](schedules.md).

### Where their intervals come from

| Setting | Where it lives | Default | Governs |
| --- | --- | --- | --- |
| `agents_disconnection_time` | `<global>` in `wazuh-manager.conf` | 900 s | how often the disconnection sweep runs, and how long an agent must be silent |
| `wazuh_modules.manager_task_delete_old_agents` | internal option | 0 (disabled) | retention window in minutes, and the retention sweep's interval |
| `wazuh_modules.manager_task_monitor_agents` | internal option | 1 | whether the retention sweep runs and whether disconnections are logged |
| `wazuh_modules.manager_task_log_rotate` | internal option | 1 | whether either kind of log rotation happens |
| `wazuh_modules.manager_task_log_day_wait` | internal option | 10 s | offset from local midnight for the daily rotation |
| `wazuh_modules.manager_task_log_compress` | internal option | 1 | whether rotated logs are gzipped |
| `wazuh_modules.manager_task_log_keep_days` | internal option | 31 | how long rotated logs are kept |
| `wazuh_modules.manager_task_log_size_rotate` | internal option | 512 MB | threshold for size-based rotation |
| `wazuh_modules.manager_task_log_daily_rotations` | internal option | 12 | rotated slots per day per file |

**None of these ships in a file.** The manager reads only
`/var/wazuh-manager/etc/wazuh-manager-internal-options.conf`, which is an empty overrides file —
there is no manager defaults file to consult. Every default above lives in code, so an option you
have not written is at the value in this table, and writing one is the only way to change it.

> **Renamed in 5.0.** These were `monitord.*` while log rotation and agent monitoring belonged to
> `wazuh-manager-monitord`. If you set any of them in `wazuh-manager-internal-options.conf` on an
> earlier build, rename the key — an override under the old name is silently ignored, because
> `getDefine_Int` compares the part before the first `.` as well as the part after it.
>
> **The agent is unaffected.** It keeps `monitord.*` for its own log rotation; see the
> [Agent configuration reference](../client/configuration.md). Only the manager's keys moved.

`agents_disconnection_time` is also read by `remoted`, so `<global>` is shared configuration rather
than something the Task Manager owns.

### Reading back what a running manager resolved

Because these are internal options with no XML element, configuration on disk does not tell you what
is in effect. The resolved values are reported through the active-configuration endpoint, under the
`task-manager` module's `recurring_tasks` object:

```bash
curl -k -X GET "https://localhost:55000/manager/configuration/wmodules/wmodules" \
     -H "Authorization: Bearer $TOKEN"
```

`recurring_tasks` is absent while the module is not running — the values are resolved once at
startup, and reporting compiled defaults instead would be indistinguishable from a live reading.

### Options the retention sweep adds

Both are internal options in the `wazuh_modules` namespace, and both bound one attempt of
`agent_delete_old` so that a large backlog spans several claims instead of holding the shared local
executor slot for the whole sweep.

| Option | Default | Range | Meaning |
| --- | --- | --- | --- |
| `wazuh_modules.manager_task_delete_old_batch` | 200 | 1–100000 | agents examined per attempt |
| `wazuh_modules.manager_task_delete_old_budget` | 30 | 1–3600 | seconds an attempt may hold its executor slot |
| `wazuh_modules.manager_task_disconnect_log_max` | 200 | 0–1000000 | agents the disconnection sweep names individually per run |

The time bound is the one that binds in practice: the send timeout on the connection to
`wazuh-authd` is a fixed five seconds, so 200 agents against a wedged `wazuh-authd` would otherwise
be a worst case measured in minutes while holding one executor slot. Counting agents bounds the work;
counting seconds bounds the occupancy.

Whichever is reached first, the attempt returns `incomplete` — neither success nor failure — and the
executor re-claims the row and resumes where it stopped.

### The option the disconnection sweep adds

`manager_task_disconnect_log_max` bounds a different thing: not the work, but the *diagnostics*. The
sweep's database transition is a single query and always completes for every agent. Turning each of
those ids into a name for the log line is one round trip per agent, and a partition — or a manager
that was down long enough for a fleet to age out — can transition tens of thousands at once.

Past the bound, agents are still transitioned; they are just not named individually, and the run
reports how many were skipped. Set it to `0` to transition silently. Unlike the retention sweep this
does not return `incomplete` and resume: the ids exist only within one call, so a later attempt would
have no list to resume from.

---

## Agent upgrades

Remote agent upgrades are served by this module, on `POST /v1/agents/upgrade` and
`POST /v1/agents/upgrade-custom`. It validates each agent, fetches and verifies the WPK, and writes
one `remote_upgrade` agent task per agent.

### XML options

| Option | Default | Meaning |
| --- | --- | --- |
| `<upgrade_enabled>` | `yes` | `no` refuses every upgrade request, per agent, with *Upgrade procedure could not start* |
| `<wpk_repository>` | none | Overrides the default, which is derived from the target version as `packages.wazuh.com/<major>.x/wpk/` |

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
is about to become v5.x will be able to reconnect afterwards. Both are read **once, at start-up**,
so changing either requires restarting `wazuh-modulesd` as well as `wazuh-remoted`.

### Internal options the upgrade path adds

All in the `wazuh_modules` namespace, all resolved before the daemon forks, so an out-of-range value
fails `wazuh-modulesd -t` rather than aborting later.

| Option | Default | Range | Meaning |
| --- | --- | --- | --- |
| `wazuh_modules.upgrade_workers` | 2 | 1–16 | upgrade **batches** run at once |
| `wazuh_modules.upgrade_queue_depth` | 8 | 1–1000 | batches queued before a request is refused |
| `wazuh_modules.upgrade_batch_deadline` | 180 | 10–3600 | seconds one batch may take before its remaining agents are failed |
| `wazuh_modules.upgrade_max_agents` | 500 | 1–100000 | largest batch accepted in one request |
| `wazuh_modules.upgrade_download_attempts` | 3 | 1–10 | tries per WPK before giving up |
| `wazuh_modules.upgrade_download_timeout` | 45000 | 1000–600000 | milliseconds per download attempt |
| `wazuh_modules.upgrade_max_concurrent_downloads` | 2 | 1–32 | WPK downloads in flight across all batches |
| `wazuh_modules.upgrade_versions_ttl` | 300 | 0–86400 | seconds a repository's `versions` file is cached |

**`upgrade_workers` counts batches, not agents, and it is deliberately small.** Per-agent work is one
wazuh-db query on a shared, mutex-guarded socket plus arithmetic; running agents in parallel would
multiply contention on that mutex to buy nothing. What genuinely arrives in parallel is whole
requests — the Server API chunks a fleet at 500, and every cluster node broadcasts. There is a second
reason to keep it low: the shared HTTP client caches curl handlers in a process-wide queue of five
entries, shared with the vulnerability scanner and the indexer connector, so a large pool here costs
*them* connection reuse.

**Three deadlines have to stay ordered**, shortest first:

```
upgrade_batch_deadline  <  the Server API's client timeout  <  the route's response backstop
       180 s                          240 s                             300 s
```

The module answering first is what makes a slow repository produce a per-agent envelope the API can
act on, instead of a connection the transport tore down.

**`upgrade_versions_ttl` is what keeps a fleet-wide upgrade cheap.** Agents that resolve to the same
package share one `versions` fetch and one download, so 500 agents on one platform cost one of each
rather than 500. The TTL bounds how long a newly published release goes unnoticed; set it to `0` to
fetch every time.

### Monitoring agent upgrades

Upgrade work logs under its own sub-tag:

```bash
tail -f /var/wazuh-manager/logs/wazuh-manager.log | grep 'task-manager:upgrade'
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

*A missing CA bundle fails every download, by design.* Peer verification is never disabled: the
SHA-1 a WPK is checked against comes from the repository's own index over the same connection, so an
unverified channel would let a man in the middle supply a matching pair and the integrity check
would confirm his work rather than ours. The module says so once at start-up:

```
No CA bundle was found on this host. HTTPS requests to the WPK repository will fail;
agent upgrades over https are unavailable until one is installed.
```

Install the distribution's CA certificates package. Do not work around it by pointing
`<wpk_repository>` at an `http://` URL unless the repository is on a trusted network.

**Requests are refused under load.** Every agent answered with *Task manager communication error*
(`1814`) means the batch queue was full. The Server API halves the chunk and retries automatically,
so this is usually self-correcting; if it persists the repository is likely slow, and
`wazuh_modules.upgrade_queue_depth` or `upgrade_workers` can be raised.

**A task never completes.** The manager only records that the task was created. If it stays
`pending` past `task_ttl` it is marked `expired` by the cleanup thread.

---

## See Also

- [Manager tasks](manager-tasks.md) — the queue's own options, states and operator lookup
- [Recurring manager tasks](schedules.md) — the three schedules and how they fire
- [Agent upgrades](agent-upgrades.md) — the manager-side flow end to end
- [Task Manager Module](README.md) — Module overview and architecture
- [Wazuh DB Configuration](../wazuh_db/configuration.md) — persistence backend for `tasks.db`
- [Manager Configuration Reference](../../configuration/manager/README.md)

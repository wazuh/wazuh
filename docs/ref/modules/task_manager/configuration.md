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

### cleanup_interval

Interval between cleanup runs. Each run marks expired tasks and deletes rows that have been expired for more than 24 h. A database `VACUUM` is issued once a day, independently of this interval.

- **Default value:** `300` (5 minutes)
- **Allowed values:** integer ≥ 0 (seconds). `0` means "use default".

### cache_ttl

Time-to-live of an entry in the in-memory pending-tasks cache. Higher values reduce database load; lower values reduce the window during which a freshly-created task might not appear in the response of a `get_pending_tasks` call for another agent (own-agent entries are invalidated immediately on task creation).

- **Default value:** `60` (seconds)
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
  <cache_ttl>60</cache_ttl>
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
  <cache_ttl>60</cache_ttl>
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

### Faster Cache Invalidation

If freshly-created tasks must be picked up as soon as possible from any manager node (at the cost of more database reads), lower the cache TTL:

```xml
<task-manager>
  <cache_ttl>5</cache_ttl>
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

## See Also

- [Task Manager Module](README.md) — Module overview and architecture
- [Agent Upgrade Configuration](../agent_upgrade/configuration.md) — main producer of `remote_upgrade` tasks
- [Wazuh DB Configuration](../wazuh_db/configuration.md) — persistence backend for `tasks.db`
- [Manager Configuration Reference](../../configuration/manager/README.md)

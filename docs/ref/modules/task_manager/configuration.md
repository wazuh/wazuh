# Task Manager Configuration Reference

Complete configuration reference for the Wazuh Task Manager module.

The Task Manager orchestrates asynchronous operations across agents, primarily handling agent upgrades and other distributed tasks. It manages task lifecycles, queuing, and execution monitoring.

For module overview and architecture, see [Task Manager Module](index.html).

---

## Manager Configuration

**Configuration file:** `/var/wazuh-manager/etc/wazuh-manager.conf`

**XML Section:** `<task-manager>`

**Internal Options:** None

The Task Manager controls task orchestration, queuing, and execution across the Wazuh deployment.


### cleanup_time

Time interval for cleaning up completed tasks from the database.

- **Default value:** `15m`
- **Allowed values:** Time string with suffix: `s` (seconds), `m` (minutes), `h` (hours), `d` (days)
- **Note:** Must be greater than `task_timeout`. Shorter intervals reduce database size but increase processing overhead

### task_timeout

Default timeout for task execution.

- **Default value:** `15m`
- **Allowed values:** Time string with suffix: `s` (seconds), `m` (minutes), `h` (hours), `d` (days)
- **Note:** Must be less than `cleanup_time`. Tasks exceeding this duration are marked as timed out. Increase for long-running operations like agent upgrades

---

## Manager Configuration Examples

### Default Configuration

Suitable for most deployments:

```xml
<task-manager>
  <cleanup_time>15m</cleanup_time>
  <task_timeout>300</task_timeout>
</task-manager>
```

### High-Volume Environment

For environments with many agents and frequent tasks:

```xml
<task-manager>
  <cleanup_time>30m</cleanup_time>
  <task_timeout>600</task_timeout>
</task-manager>
```

### Low-Resource Environment

For smaller deployments or resource-constrained managers:

```xml
<task-manager>
  <cleanup_time>5m</cleanup_time>
  <task_timeout>180</task_timeout>
</task-manager>
```

### Agent Upgrade Focused

Optimized for agent upgrade tasks:

```xml
<task-manager>
  <cleanup_time>1h</cleanup_time>
  <task_timeout>900</task_timeout>  <!-- 15 minutes for upgrades -->
</task-manager>
```

### Minimal Configuration


```xml
<task-manager>
</task-manager>
```


---

## Performance Considerations

### Resource Usage

Each concurrent task consumes:
- **Memory:** ~1-5 MB per task (depends on task type)
- **CPU:** Minimal when idle, peaks during task distribution
- **Database:** Grows with task history

### Tuning Guidelines

**For 100-500 agents:**
```xml
```

**For 500-2000 agents:**
```xml
```

**For 2000+ agents:**
```xml
```

### Cleanup Strategy

**Frequent cleanup (less disk usage):**
```xml
<cleanup_time>5m</cleanup_time>
```

**Infrequent cleanup (better performance):**
```xml
<cleanup_time>1h</cleanup_time>
```

**Balance (recommended):**
```xml
<cleanup_time>15m</cleanup_time>
```

---

## Validation and Troubleshooting

### Validate Configuration

After editing configuration:

```bash
/var/wazuh-manager/bin/wazuh-logtest-config
```

### Check Module Status

Verify task manager is running:

```bash
/var/wazuh-manager/bin/wazuh-modulesd --test
```

### View Task Statistics

Check task queue and active tasks:

```bash
# Via API
curl -k -X GET "https://localhost:55000/tasks?status=In%20progress" \
  -H "Authorization: Bearer $TOKEN"

# Via database
sqlite3 /var/wazuh-manager/db/tasks.db "SELECT status, COUNT(*) FROM tasks GROUP BY status;"
```

### Monitor Logs

```bash
# Task manager logs
tail -f /var/wazuh-manager/logs/wazuh-manager.log | grep "task-manager"

# Debug mode (set in internal options)
```

### Common Issues

**Issue:** Tasks timing out frequently
**Solution:** Increase `task_timeout` or check agent connectivity

**Issue:** Task queue full (tasks rejected)

**Issue:** High CPU usage

**Issue:** Database growing too large
**Solution:** Reduce `cleanup_time` interval

---

## See Also

- [Task Manager Module](index.html) - Module overview and architecture
- [Agent Upgrade Configuration](../agent_upgrade/configuration.md) - Uses Task Manager for agent upgrades
- [Wazuh DB Configuration](../wazuh_db/configuration.md) - Task storage backend
- [Manager Configuration Reference](../../configuration/manager/README.md) - All manager configuration options

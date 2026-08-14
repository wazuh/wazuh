# Database Sync Configuration Reference

Complete configuration reference for the Database Sync module.

The Database Sync module handles agent status, groups, and connection state synchronization between manager and the global database. It is configured exclusively through internal options, with no XML or YAML configuration sections.

- **Module:** Manager-only (part of wazuh-db)
- **Configuration method:** Internal options only
- **Daemon:** `wazuh-db`

For module overview, see [Database Sync Module](index.html).

---

## Configuration

**Configuration file:** `/var/wazuh-manager/etc/wazuh-manager-internal-options.conf`

**XML Section:** None

**YAML Section:** None

**Internal Options:** `wazuh_database.*`

The Database Sync module is configured exclusively through internal options. There is no dedicated XML block or YAML configuration file for this module. All settings are tuned via the internal options file.

---

## Internal Options Reference

Database sync settings are configured in `/var/wazuh-manager/etc/wazuh-manager-internal-options.conf`:

### wazuh_database.sync_agents

Enable or disable agent database synchronization.

```ini
wazuh_database.sync_agents=1
```

- **Default value:** `1` (enabled)
- **Allowed values:** `0` (disabled), `1` (enabled)

When enabled, the manager synchronizes agent status, groups, and connection states to the global database.

### wazuh_database.real_time

Enable real-time synchronization mode.

```ini
wazuh_database.real_time=1
```

- **Default value:** `1` (enabled)
- **Allowed values:** `0` (disabled), `1` (enabled)

When enabled, agent updates are synchronized immediately. When disabled, updates are batched and synchronized at intervals defined by `wazuh_database.interval`.

### wazuh_database.interval

Synchronization interval in seconds (used when real-time mode is disabled).

```ini
wazuh_database.interval=60
```

- **Default value:** `60` seconds
- **Allowed values:** Positive integer (1-86400)
- **Note:** Only applies when `wazuh_database.real_time=0`

### wazuh_database.max_queued_events

Maximum number of events held in the Database Sync module's internal queue.

```ini
wazuh_database.max_queued_events=10000
```

- **Default value:** `0` (use the internal default of `16384` entries)
- **Allowed values:** `0` or a positive integer

This option no longer changes the kernel's `fs.inotify.max_queued_events` setting. If the configured value exceeds the kernel limit, the module logs a warning and the system limit must be adjusted separately by an administrator.

---

## Configuration Examples

### Default Configuration

Standard real-time synchronization:

```ini
wazuh_database.sync_agents=1
wazuh_database.real_time=1
wazuh_database.interval=60
wazuh_database.max_queued_events=10000
```

### Interval-Based Synchronization

For reduced database load in large deployments:

```ini
wazuh_database.sync_agents=1
wazuh_database.real_time=0
wazuh_database.interval=300
wazuh_database.max_queued_events=50000
```

This configuration:
- Disables real-time sync
- Syncs every 5 minutes
- Allows larger event queue before forcing sync

### High-Frequency Updates

For environments requiring minimal latency:

```ini
wazuh_database.sync_agents=1
wazuh_database.real_time=1
wazuh_database.interval=30
wazuh_database.max_queued_events=5000
```

### Disabled Synchronization

For testing or specific deployment scenarios:

```ini
wazuh_database.sync_agents=0
wazuh_database.real_time=0
wazuh_database.interval=60
wazuh_database.max_queued_events=10000
```

**Warning:** Disabling sync may cause agent status and group information to become stale.

---

## Performance Considerations

### Real-Time vs Interval Mode

**Real-Time Mode** (`real_time=1`):
- **Pros:** Immediate updates, current agent status
- **Cons:** Higher database write frequency
- **Best for:** Small to medium deployments (<1000 agents)

**Interval Mode** (`real_time=0`):
- **Pros:** Reduced database load, batched writes
- **Cons:** Delayed status updates
- **Best for:** Large deployments (>1000 agents)

### Queue Sizing

The `max_queued_events` parameter controls memory usage and sync frequency:

- **Small (<1000 agents):** 5000-10000 events
- **Medium (1000-5000 agents):** 10000-25000 events
- **Large (>5000 agents):** 25000-100000 events

### Database Impact

Agent synchronization involves:
- INSERT/UPDATE operations on agent table
- Group hash recalculation
- Connection status updates
- SQLite transaction commits

High-frequency sync may increase database file fragmentation. Monitor using `wazuh_db.fragmentation_threshold` settings.

---

## Monitoring

### Check Sync Status

View agent sync status in the database:

```bash
echo 'global sql SELECT id,name,connection_status,sync_status FROM agent' | \
  /var/wazuh-manager/bin/wazuh-db
```

### View Queue Statistics

Monitor wazuh-db logs for queue warnings:

```bash
grep "queued_events" /var/wazuh-manager/logs/wazuh-manager.log
```

### Database Activity

Check database writes:

```bash
tail -f /var/wazuh-manager/logs/wazuh-manager.log | grep "wazuh-db"
```

---

## Troubleshooting

### Agents Showing as Disconnected

**Cause:** Database sync disabled or failing

**Solution:**
1. Verify `wazuh_database.sync_agents=1`
2. Check wazuh-db is running: `ps aux | grep wazuh-db`
3. Review logs for database errors

### High Database CPU Usage

**Cause:** Too frequent synchronization with many agents

**Solution:**
1. Switch to interval mode: `wazuh_database.real_time=0`
2. Increase interval: `wazuh_database.interval=300`
3. Increase queue size: `wazuh_database.max_queued_events=50000`

### Agent Groups Not Updating

**Cause:** Sync queue full or sync disabled

**Solution:**
1. Check queue size is appropriate for agent count
2. Verify `wazuh_database.sync_agents=1`
3. Check logs for "max_queued_events exceeded" warnings

---

## See Also

- [Database Sync Module](index.html) - Module overview
- [Wazuh DB Configuration](../wazuh_db/configuration.md) - Database backup and tuning
- [Agent Management](../agent-management/index.html) - Agent lifecycle management
- [Manager Configuration Reference](../../configuration/manager/README.md) - All manager configuration options

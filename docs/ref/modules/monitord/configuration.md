# Monitord Configuration Reference

Complete configuration reference for the Wazuh monitoring daemon (monitord).

The monitord daemon handles agent disconnection detection, alerting, and log rotation on the Wazuh manager. It monitors agent keep-alive messages and maintains connection status.

For module overview and architecture, see [Monitord Module](index.html).

---

## Manager Configuration

**Configuration file:** `/var/wazuh-manager/etc/wazuh-manager.conf`

**XML Section:** `<global>`

**Internal Options:** `monitord.*`

The monitoring daemon consumes agent connection settings from the `<global>` section and provides log rotation and disconnection monitoring services.


### agents_disconnection_time

Time without communication after which an agent is marked as disconnected.

- **Default value:** `15m` (900 seconds)
- **Allowed values:** Positive integer with optional time unit suffix: `s` (seconds), `m` (minutes), `h` (hours), `d` (days)
- **Note:** Minimum value is `1s`. Shorter intervals provide faster disconnection detection but may cause false positives on unreliable networks

### agents_disconnection_alert_time

Time after an agent disconnects before a disconnection alert is generated.

- **Default value:** `0` (alert fires immediately, on the next alert-check cycle)
- **Allowed values:** Non-negative integer with optional time unit suffix: `s`, `m`, `h`, `d`
- **Note:** The alert check fires whenever the internal alert counter is greater than or equal to this value (`check_alert_trigger()` in `src/monitord/src/monitord.c`). With the default of `0`, that condition (`0 >= 0`) is always true, so the disconnection alert is generated immediately and continuously — it does **not** disable alerting. Non-zero values specify the delay after `agents_disconnection_time` before the alert fires.

> **Important:** `agents_disconnection_alert_time=0` does **not** disable disconnection alerts — it makes them fire immediately. To disable disconnection alerting entirely, set the internal option `monitord.monitor_agents=0` (see [Internal Options](#internal-options)). `check_alert_trigger()` only evaluates when `monitord.monitor_agents != 0`; when it is `0`, no disconnection alerts are ever generated, regardless of `agents_disconnection_alert_time`.

---

## Internal Options

**Configuration file:** `/var/wazuh-manager/etc/wazuh-manager-internal-options.conf`

Additional monitord settings can be configured in the internal options file:

```ini
# Monitord debug level (0-2)
monitord.debug=0

# Rotate logs daily (0=disabled, 1=enabled)
monitord.rotate_log=1

# Keep rotated logs for N days
monitord.keep_log_days=31

# Size-based log rotation in MB (0=disabled)
monitord.size_rotate=512

# Delay, in seconds, before performing the daily log rotation (settle time; not a report interval)
monitord.day_wait=10

# Compress rotated logs (0=disabled, 1=enabled)
monitord.compress=1

# Monitor agent connection changes (0=disabled, 1=enabled)
# Setting this to 0 also disables disconnection alerting entirely, regardless
# of agents_disconnection_alert_time (see check_alert_trigger() in monitord.c)
monitord.monitor_agents=1

# Maximum number of daily rotated logs to keep [1-256]
monitord.daily_rotations=12

# Minutes a disconnected agent is kept before being removed from the manager (0=disabled) [0-9600]
# WARNING: DESTRUCTIVE. When non-zero, monitor_agents_deletion() permanently
# removes agents from the manager once they have been disconnected for longer
# than agents_disconnection_time + monitord.delete_old_agents (minutes).
# An administrator can unknowingly enable automatic agent removal by setting this value.
monitord.delete_old_agents=0
```

**Note:** Use `wazuh-manager-internal-options.conf` instead of modifying the default `internal_options.conf` to preserve settings across upgrades.

---

## Manager Configuration Examples

### Default Configuration

Standard settings. Note that `agents_disconnection_alert_time` of `0` means the disconnection alert fires immediately once an agent is marked disconnected, not that alerts are disabled:

```xml
<global>
  <agents_disconnection_time>15m</agents_disconnection_time>
  <agents_disconnection_alert_time>0</agents_disconnection_alert_time>
</global>
```

To disable disconnection alerting entirely, set the internal option `monitord.monitor_agents=0` instead (see [Internal Options](#internal-options)).

### Enable Disconnection Alerts

Alert after 30 minutes of disconnection:

```xml
<global>
  <agents_disconnection_time>15m</agents_disconnection_time>
  <agents_disconnection_alert_time>30m</agents_disconnection_alert_time>
</global>
```

### Aggressive Disconnection Detection

Detect disconnections faster (for critical environments):

```xml
<global>
  <agents_disconnection_time>5m</agents_disconnection_time>
  <agents_disconnection_alert_time>10m</agents_disconnection_alert_time>
</global>
```

### Relaxed Disconnection Detection

For unreliable networks or agents that report infrequently:

```xml
<global>
  <agents_disconnection_time>1h</agents_disconnection_time>
  <agents_disconnection_alert_time>2h</agents_disconnection_alert_time>
</global>
```

---

## Behavior

### Disconnection Detection

1. **Keep-alive messages:** Agents send keep-alive messages every 60 seconds (configurable on agent side)
2. **Disconnection threshold:** After `agents_disconnection_time` without a keep-alive, agent marked as disconnected
3. **Alert generation:** After an additional `agents_disconnection_alert_time`, a disconnection alert is generated
4. **Reconnection:** When an agent reconnects (its status becomes `active`), monitord removes it from the internal pending-alert tracking table (`OSHash_Delete` in `monitor_agents_alert()`) so no disconnection alert is generated for it. This does **not** produce a log entry — there is no `minfo`/`mdebug` call on the reconnection path

### Alert Format

Disconnection alerts use rule ID `5715`:

```
** Alert 1234567890.123456: - ossec,
2024 Jan 01 12:00:00 (agent-01) 192.168.1.100->ossec
Rule: 5715 (level 3) -> 'Agent disconnected.'
wazuh: Agent disconnected: [001] (agent-01).
```

---

## Monitoring

### Check Monitord Status

```bash
# Check if monitord is running
/var/wazuh-manager/bin/wazuh-control status | grep monitord

# View monitord logs
tail -f /var/wazuh-manager/logs/wazuh-manager.log | grep monitord
```

### View Agent Connection Status

```bash
# List all agents with connection status
/var/wazuh-manager/bin/agent_control -l

# Check specific agent
/var/wazuh-manager/bin/agent_control -i 001
```

### View Disconnection Events

```bash
# View recent disconnection alerts
tail -100 /var/wazuh-manager/logs/alerts/alerts.log | grep 5715
```

---

## Performance Considerations

### Impact of Settings

**Short disconnection time:**
- Faster detection of agent issues
- More frequent state changes
- Higher alert volume if alerts enabled

**Long disconnection time:**
- Delayed detection of agent issues
- Fewer state changes
- Lower alert volume

### Recommended Settings

**For critical infrastructure:**
```xml
<agents_disconnection_time>5m</agents_disconnection_time>
<agents_disconnection_alert_time>10m</agents_disconnection_alert_time>
```

**For standard deployments:**
```xml
<agents_disconnection_time>15m</agents_disconnection_time>
<agents_disconnection_alert_time>30m</agents_disconnection_alert_time>
```

**For unreliable networks:**
```xml
<agents_disconnection_time>30m</agents_disconnection_time>
<agents_disconnection_alert_time>1h</agents_disconnection_alert_time>
```

---

## Troubleshooting

### Agents Frequently Marked as Disconnected

**Possible causes:**
- Network issues between agent and manager
- Agent keep-alive interval too long
- `agents_disconnection_time` too short

**Solutions:**
- Increase `agents_disconnection_time`
- Check network connectivity
- Verify agent `notify_time` setting (agent-side)

### No Disconnection Alerts

**Possible causes:**
- Internal option `monitord.monitor_agents` set to `0` (this, not `agents_disconnection_alert_time=0`, is what disables disconnection alerting)
- Alert rules disabled
- Agents not actually disconnecting

**Solutions:**
- Verify `monitord.monitor_agents` is set to `1` in the internal options
- Verify rule 5715 is enabled
- Check agent connection status

### Too Many Disconnection Alerts

**Possible causes:**
- `agents_disconnection_alert_time` too short
- Network instability
- Agents frequently restarting

**Solutions:**
- Increase `agents_disconnection_alert_time`
- Investigate network or agent issues
- Consider disabling alerts if normal behavior

---

## Log Rotation

Monitord handles log rotation for Wazuh manager logs. Configuration via internal options:

```ini
# Rotate logs daily
monitord.rotate_log=1

# Keep logs for 31 days
monitord.keep_log_days=31

# Rotate when log reaches 512 MB (0=disabled)
monitord.size_rotate=512

# Compress rotated logs
monitord.compress=1
```

### Manual Log Rotation

Force log rotation:

```bash
kill -HUP $(cat /var/wazuh-manager/var/run/wazuh-monitord-*.pid)
```

---

## See Also

- [Monitord Module](index.html) - Module overview and architecture
- [Manager Configuration Reference](../../configuration/manager/README.md) - All manager configuration options
- [Agent Configuration Reference](../../configuration/agent/README.md) - All agent configuration options including keep-alive settings

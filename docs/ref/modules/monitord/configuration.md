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

- **Default value:** `0` (alerts disabled)
- **Allowed values:** Non-negative integer with optional time unit suffix: `s`, `m`, `h`, `d`
- **Note:** Set to `0` to disable disconnection alerts entirely. Otherwise, specifies delay after `agents_disconnection_time` before generating alert

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

# Daily report generation interval (seconds)
monitord.day_wait=10

# Compress rotated logs (0=disabled, 1=enabled)
monitord.compress=1

# Monitor agent connection changes (0=disabled, 1=enabled)
monitord.monitor_agents=1
```

**Note:** Use `wazuh-manager-internal-options.conf` instead of modifying the default `internal_options.conf` to preserve settings across upgrades.

---

## Manager Configuration Examples

### Default Configuration

Standard settings with disconnection alerts disabled:

```xml
<global>
  <agents_disconnection_time>15m</agents_disconnection_time>
  <agents_disconnection_alert_time>0</agents_disconnection_alert_time>
</global>
```

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
4. **Reconnection:** When agent reconnects, monitord logs the reconnection event

### Alert Format

Disconnection alerts use rule ID `5715`:

```
** Alert 1234567890.123456: - ossec,
2024 Jan 01 12:00:00 (agent-01) 192.168.1.100->ossec
Rule: 5715 (level 3) -> 'Agent disconnected.'
ossec: Agent 'agent-01' disconnected.
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
- `agents_disconnection_alert_time` set to `0`
- Alert rules disabled
- Agents not actually disconnecting

**Solutions:**
- Set `agents_disconnection_alert_time` > 0
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

# Agent Info Configuration Reference

Complete configuration reference for the Agent Info module.

The agent info module collects and synchronizes agent metadata including system information, network configuration, and group memberships. This module is agent-only.

For module overview and architecture, see [Agent Info Module](README.md).

---

## Configuration

**Configuration file:** `/var/ossec/etc/ossec.conf`

**XML Section:** `<agent-info>`

**Module:** Agent-only

**Internal Options:** `agent_info.max_entries`, `agent_info.ttl` (see [Internal Options](#internal-options))

The `<agent-info>` block is only parsed on agent builds. If it is present in a manager's `ossec.conf`, the manager silently ignores it (it is not read or applied in any way) and logs a debug-level message noting that the module is not supported on managers.

### interval

Time between periodic scans to collect agent metadata.

- **Default value:** `60`
- **Allowed values:** Integer from 60 to 86400 (seconds). Out-of-range values are ignored with a warning and the previous value is kept
- **Note:** Lower values increase metadata freshness but consume more resources

### integrity_interval

Time between integrity checks to verify that the agent's state is synchronized with the manager.

- **Default value:** `86400` (24 hours)
- **Allowed values:** Integer from 60 to 604800 (seconds, 1 minute to 7 days). Out-of-range values are ignored with a warning and the previous value is kept
- **Note:** Periodic verification ensures consistency between agent and manager state

---

## Internal Options

Set these in `local_internal_options.conf`, next to `ossec.conf` (`/var/ossec/etc/` on Linux, `C:\Program Files (x86)\ossec-agent\` on Windows). They bound the [`tasks`](database-schema.md#tasks) table, which remembers the `/control` task IDs already handled so a redelivered task is not run twice. Both limits are applied on every `interval` cycle.

| Option | Default | Allowed values | Description |
|---|---|---|---|
| `agent_info.max_entries` | `4096` | `1`–`1000000` | Maximum number of task IDs kept. The oldest are removed first. |
| `agent_info.ttl` | `86400` | `1`–`31536000` (seconds) | How long a task ID is kept. |

---

## Configuration Examples

### Default Configuration

Standard agent info settings for most deployments:

```xml
<agent-info>
  <interval>60</interval>
  <integrity_interval>86400</integrity_interval>
</agent-info>
```

### High-Frequency Scanning

Scan at the minimum interval and check integrity every hour, for dynamic environments:

```xml
<agent-info>
  <interval>60</interval>
  <integrity_interval>3600</integrity_interval>
</agent-info>
```

### Low-Resource Systems

Reduce scanning frequency to minimize resource usage:

```xml
<agent-info>
  <interval>300</interval>
  <integrity_interval>86400</integrity_interval>
</agent-info>
```

---

## Metadata Collection

### Collected Information

The agent info module collects:

- **System information:** OS name, version, architecture, hostname
- **Network configuration:** IP addresses, MAC addresses, network interfaces
- **Agent configuration:** Group memberships, labels, configuration hash
- **Resource usage:** CPU, memory, disk space (depending on configuration)

### Collection Flow

1. **Periodic scan:** Module wakes up based on `interval` setting
2. **Data gathering:** Collects current system and agent metadata
3. **Change detection:** Compares with previous scan to detect changes
4. **Synchronization:** If changes detected, initiates coordination with other modules
5. **Update manager:** Sends updated metadata to manager (agents only)
6. **Integrity check:** Periodically verifies consistency based on `integrity_interval`

---

## Synchronization Protocol

### Coordination Events

When agent metadata changes (e.g., group assignment, label update):

1. **Pause:** Pauses FIM, SCA and Syscollector and has them flush pending data
2. **Version:** Reads each module's synchronization version and sets the new one on all of them
3. **Synchronize:** Sends the changed metadata to the manager
4. **Resume:** Resumes the paused modules

See [Architecture](architecture.md) for the full protocol.

---

## Performance Considerations

### Scan Intervals

**Default scans (60 seconds, also the minimum):**
- Fastest detection of configuration changes
- Suitable for most deployments, including dynamic cloud environments

**Infrequent scans (300+ seconds):**
- Suitable for static environments
- Minimizes resource consumption
- Slower change detection

### Integrity Checks

**Frequent checks (1-6 hours):**
- Ensures tight consistency
- Higher network and processing overhead

**Standard checks (24 hours):**
- Default recommended setting
- Balances consistency and performance

**Infrequent checks (48+ hours):**
- Suitable for stable environments
- Minimizes overhead

---

## Troubleshooting

### Metadata Not Updating on Manager

**Check scan interval:**
```bash
grep -A5 "<agent-info>" /var/ossec/etc/ossec.conf
```

**View agent info logs:**
```bash
tail -f /var/ossec/logs/ossec.log | grep agent-info
```

**Force metadata collection:**
```bash
# Restart agent to trigger immediate scan
/var/ossec/bin/wazuh-control restart
```

### High Resource Usage

**Reduce scan frequency:**
```xml
<interval>300</interval>  <!-- 5 minutes -->
```

---

## Monitoring

### View Collected Metadata

**On manager (query agent info through the Server API, master node):**
```bash
# View agent system information
TOKEN=$(curl -s -k -u wazuh:<WAZUH_PASSWORD> -X POST "https://localhost:55000/security/user/authenticate?raw=true")
curl -s -k -X GET "https://localhost:55000/agents?agents_list=001&pretty=true" \
    -H "Authorization: Bearer $TOKEN"
```

**On agent (check synchronization status):**
```bash
tail -f /var/ossec/logs/ossec.log | grep "agent-info.*sync"
```

### Monitor Scan Activity

**On agent:**
```bash
# View metadata collection events
tail -f /var/ossec/logs/ossec.log | grep "agent-info.*scan"
```

---

## Configuration Validation

The module performs the following validation at startup:

- **Time Values:** Validates time format and acceptable ranges
- **Integer Values:** Ensures integer values are within valid ranges
- **Interval Constraints:** Verifies `interval` and `integrity_interval` are positive

If the configuration is invalid, the module will log a warning and use default values or, in case of critical errors, fail to start.

---

## See Also

- [Agent Info Module](README.md) - Module overview and architecture
- [Agent Configuration Reference](../../configuration/agent/README.md) - All agent configuration options
- [Manager Configuration Reference](../../configuration/manager/README.md) - All manager configuration options

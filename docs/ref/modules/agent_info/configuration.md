# Agent Info Configuration Reference

Complete configuration reference for the Agent Info module.

The agent info module collects and synchronizes agent metadata including system information, network configuration, and group memberships. This module is agent-only.

For module overview and architecture, see [Agent Info Module](README.md).

---

## Configuration

**Configuration file:** `/var/ossec/etc/ossec.conf`

**XML Section:** `<agent-info>`

**Module:** Agent-only

**Internal Options:** None

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

### enabled (synchronization)

Enables or disables the module coordination and synchronization features.

- **Default value:** `yes`
- **Allowed values:** `yes`, `no`
- **Parent:** `<synchronization>`
- **Note:** Controls whether the module participates in coordination with other modules

---

## Configuration Examples

### Default Configuration

Standard agent info settings for most deployments:

```xml
<agent-info>
  <interval>60</interval>
  <integrity_interval>86400</integrity_interval>
  <synchronization>
    <enabled>yes</enabled>
  </synchronization>
</agent-info>
```

### High-Frequency Scanning

Collect metadata more frequently for dynamic environments:

```xml
<agent-info>
  <interval>30</interval>
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

### Disable Synchronization

Run metadata collection without coordination features:

```xml
<agent-info>
  <interval>60</interval>
  <integrity_interval>86400</integrity_interval>
  <synchronization>
    <enabled>no</enabled>
  </synchronization>
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

**Frequent scans (30-60 seconds):**
- Suitable for dynamic cloud environments
- Faster detection of configuration changes
- Higher resource usage

**Standard scans (60-120 seconds):**
- Balanced for most deployments
- Default recommended setting

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

### Synchronization Failures

**Check synchronization settings:**
```bash
grep -A10 "<synchronization>" /var/ossec/etc/ossec.conf
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

- **Boolean Values:** Ensures boolean values are either `yes` or `no`
- **Time Values:** Validates time format and acceptable ranges
- **Integer Values:** Ensures integer values are within valid ranges
- **Interval Constraints:** Verifies `interval` and `integrity_interval` are positive

If the configuration is invalid, the module will log a warning and use default values or, in case of critical errors, fail to start.

---

## See Also

- [Agent Info Module](README.md) - Module overview and architecture
- [Agent Configuration Reference](../../configuration/agent/README.md) - All agent configuration options
- [Manager Configuration Reference](../../configuration/manager/README.md) - All manager configuration options

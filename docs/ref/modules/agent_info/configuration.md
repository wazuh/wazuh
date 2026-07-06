# Agent Info Configuration Reference

Complete configuration reference for the Agent Info module.

The agent info module collects and synchronizes agent metadata including system information, network configuration, and group memberships. This module runs on both managers and agents.

For module overview and architecture, see [Agent Info Module](index.html).

---

## Configuration

**Configuration file:** `/var/ossec/etc/ossec.conf`

**XML Section:** `<agent-info>`

**Module:** Agent-only

**Internal Options:** None

The agent info module is configured identically on both managers and agents.

### interval

Time between periodic scans to collect agent metadata.

- **Default value:** `60`
- **Allowed values:** Positive integer (seconds)
- **Note:** Lower values increase metadata freshness but consume more resources

### integrity_interval

Time between integrity checks to verify that the agent's state is synchronized with the manager.

- **Default value:** `86400` (24 hours)
- **Allowed values:** Positive integer (seconds)
- **Note:** Periodic verification ensures consistency between agent and manager state

### enabled (synchronization)

Enables or disables the module coordination and synchronization features.

- **Default value:** `yes`
- **Allowed values:** `yes`, `no`
- **Parent:** `<synchronization>`
- **Note:** Controls whether the module participates in coordination with other modules

### sync_end_delay (synchronization)

Delay before sending the synchronization end message.

- **Default value:** `1s`
- **Allowed values:** Time string with suffix: `s` (seconds), `m` (minutes), `h` (hours), `d` (days)
- **Parent:** `<synchronization>`
- **Note:** Allows buffering before signaling completion

### response_timeout (synchronization)

Timeout to wait for a response from other modules during coordination.

- **Default value:** `30s`
- **Allowed values:** Time string with suffix: `s` (seconds), `m` (minutes), `h` (hours), `d` (days)
- **Parent:** `<synchronization>`
- **Note:** Controls how long to wait for coordination responses

### retries (synchronization)

Number of retry attempts when a coordination command fails.

- **Default value:** `5`
- **Allowed values:** Positive integer
- **Parent:** `<synchronization>`
- **Note:** Prevents transient failures from blocking synchronization

### max_eps (synchronization)

Maximum events per second to send during synchronization.

- **Default value:** `50`
- **Allowed values:** Positive integer
- **Parent:** `<synchronization>`
- **Note:** Rate limiting prevents overwhelming the receiver during bulk updates

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
    <sync_end_delay>1s</sync_end_delay>
    <response_timeout>30s</response_timeout>
    <retries>5</retries>
    <max_eps>50</max_eps>
  </synchronization>
</agent-info>
```

### High-Frequency Scanning

Collect metadata more frequently for dynamic environments:

```xml
<agent-info>
  <interval>30</interval>
  <integrity_interval>3600</integrity_interval>
  <synchronization>
    <enabled>yes</enabled>
    <sync_end_delay>1s</sync_end_delay>
    <response_timeout>30s</response_timeout>
    <retries>5</retries>
    <max_eps>100</max_eps>
  </synchronization>
</agent-info>
```

### Low-Resource Systems

Reduce scanning frequency to minimize resource usage:

```xml
<agent-info>
  <interval>300</interval>
  <integrity_interval>86400</integrity_interval>
  <synchronization>
    <enabled>yes</enabled>
    <sync_end_delay>2s</sync_end_delay>
    <response_timeout>60s</response_timeout>
    <retries>3</retries>
    <max_eps>25</max_eps>
  </synchronization>
</agent-info>
```

### Unreliable Networks

Adjust timeouts and retries for networks with high latency or packet loss:

```xml
<agent-info>
  <interval>60</interval>
  <integrity_interval>86400</integrity_interval>
  <synchronization>
    <enabled>yes</enabled>
    <sync_end_delay>5s</sync_end_delay>
    <response_timeout>120s</response_timeout>
    <retries>10</retries>
    <max_eps>25</max_eps>
  </synchronization>
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

1. **Initiate sync:** Agent info module detects change
2. **Notify peers:** Sends coordination messages to other modules
3. **Wait for responses:** Collects acknowledgments within `response_timeout`
4. **Retry on failure:** Retries up to `retries` times if responses fail
5. **Complete sync:** Sends end message after `sync_end_delay`
6. **Rate limiting:** Respects `max_eps` limit during bulk updates

### Rate Limiting

The `max_eps` setting prevents synchronization storms:

- Controls maximum events per second during sync
- Prevents overwhelming the manager during mass updates
- Useful when many agents synchronize simultaneously

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

**Check coordination timeouts:**
```bash
grep -A10 "<synchronization>" /var/ossec/etc/ossec.conf
```

**Increase timeout and retries:**
```xml
<synchronization>
  <response_timeout>120s</response_timeout>
  <retries>10</retries>
</synchronization>
```

### High Resource Usage

**Reduce scan frequency:**
```xml
<interval>300</interval>  <!-- 5 minutes -->
```

**Lower event rate during sync:**
```xml
<synchronization>
  <max_eps>25</max_eps>
</synchronization>
```

---

## Monitoring

### View Collected Metadata

**On manager (query agent info):**
```bash
# View agent system information
/var/wazuh-manager/bin/wazuh-control info agent 001
```

**Check synchronization status:**
```bash
tail -f /var/ossec/logs/ossec.log | grep "agent-info.*sync"
```

### Monitor Scan Activity

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

- [Agent Info Module](index.html) - Module overview and architecture
- [Agent Configuration Reference](../../configuration/agent/README.md) - All agent configuration options
- [Manager Configuration Reference](../../configuration/manager/README.md) - All manager configuration options

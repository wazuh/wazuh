# Agent Upgrade Configuration Reference

Complete configuration reference for the Agent Upgrade module.

The agent upgrade module handles remote agent upgrades using WPK (Wazuh Package) files. Configuration differs between manager and agent:

- **Manager:** Controls WPK distribution, transfer, and upgrade orchestration
- **Agent:** Controls whether the agent accepts upgrades and notification behavior

For module overview and architecture, see [Agent Upgrade Module](index.html).

---

## Manager Configuration

**Configuration file:** `/var/wazuh-manager/etc/wazuh-manager.conf`

**XML Section:** `<agent-upgrade>`

**Internal Options:** None

The manager-side configuration controls how the manager distributes WPK packages to agents.

### enabled

Enable or disable the agent upgrade module.

- **Default value:** `yes`
- **Allowed values:** `yes`, `no`
- **Note:** Disabling prevents all agent upgrade operations

### wpk_repository

Base URL from which WPK upgrade packages are downloaded.

- **Default value:** none (auto-derived as `packages.wazuh.com/<major>.x/wpk/` using manager version)
- **Allowed values:** Any valid URL
- **Note:** A trailing `/` is added automatically at runtime if absent

### chunk_size

Size in bytes of each chunk sent to the agent during WPK transfer.

- **Default value:** `32768` (32 KB)
- **Allowed values:** Integer from `64` to `60000`
- **Note:** Smaller chunks reduce memory usage but increase transfer overhead

### max_threads

Maximum number of simultaneous upgrade operations.

- **Default value:** `8`
- **Allowed values:** `0` (use CPU count) or integer from `1` to `256`
- **Note:** Set to `0` to automatically use the number of available CPU cores

---

## Manager Configuration Examples

### Default Configuration

Standard upgrade settings for most deployments:

```xml
<agent-upgrade>
  <enabled>yes</enabled>
  <chunk_size>32768</chunk_size>
  <max_threads>8</max_threads>
</agent-upgrade>
```

### Custom WPK Repository

Use an internal or custom WPK repository instead of the official Wazuh repository:

```xml
<agent-upgrade>
  <enabled>yes</enabled>
  <wpk_repository>https://packages.internal.company.com/wazuh/wpk/</wpk_repository>
</agent-upgrade>
```

### Large Deployments

High-performance configuration for upgrading many agents simultaneously:

```xml
<agent-upgrade>
  <enabled>yes</enabled>
  <chunk_size>60000</chunk_size>
  <max_threads>0</max_threads>  <!-- Use all CPU cores -->
</agent-upgrade>
```

### Low-Bandwidth Networks

Optimize for bandwidth-constrained or unreliable networks:

```xml
<agent-upgrade>
  <enabled>yes</enabled>
  <chunk_size>8192</chunk_size>
  <max_threads>2</max_threads>
</agent-upgrade>
```

### Disable Remote Upgrades

Prevent all remote agent upgrades on the manager:

```xml
<agent-upgrade>
  <enabled>no</enabled>
</agent-upgrade>
```

---

## Agent Configuration

**Configuration file:** `/var/ossec/etc/ossec.conf` (Linux/Unix) or `C:\Program Files (x86)\ossec-agent\ossec.conf` (Windows)

**XML Section:** `<agent-upgrade>`

**Internal Options:** None

The agent-side configuration controls whether the agent accepts remote upgrades from the manager.

### enabled

Allow or prevent this agent from being upgraded remotely.

- **Default value:** `yes`
- **Allowed values:** `yes`, `no`
- **Note:** When disabled, the agent rejects all upgrade commands from the manager

### ca_verification

Verify WPK package digital signature before installation.

- **Default value:** `yes`
- **Allowed values:** `yes`, `no`
- **Note:** Disabling verification is not recommended as it allows unsigned packages

**Sub-option:**

#### ca_store

Custom path(s) to CA certificate file(s) for WPK signature verification.

- **Default value:** Built-in CA certificates
- **Allowed values:** Valid file path (tag can be repeated for multiple certificates)
- **Note:** Only effective when `ca_verification` is `yes`; allows using custom CA for WPK signing

**Format for multiple certificates:**
```xml
<ca_verification>
  <ca_store>/etc/ssl/certs/ca1.pem</ca_store>
  <ca_store>/etc/ssl/certs/ca2.pem</ca_store>
</ca_verification>
```

### notification_wait_start

Initial wait time (in seconds) before the agent notifies the manager of upgrade results.

- **Default value:** `60`
- **Allowed values:** Positive integer
- **Note:** Used for exponential backoff when manager is unreachable

### notification_wait_max

Maximum wait time (in seconds) between notification retry attempts.

- **Default value:** `3600` (1 hour)
- **Allowed values:** Positive integer
- **Note:** Prevents infinite retry delays

### notification_wait_factor

Exponential backoff multiplier for notification retries.

- **Default value:** `2`
- **Allowed values:** Positive integer
- **Note:** Each retry waits `previous_wait * factor`, capped at `notification_wait_max`

---

## Agent Configuration Examples

### Default Configuration

Standard agent upgrade settings:

```xml
<agent-upgrade>
  <enabled>yes</enabled>
  <ca_verification>yes</ca_verification>
</agent-upgrade>
```

### Disable Remote Upgrades on Agent

Prevent this specific agent from being upgraded remotely:

```xml
<agent-upgrade>
  <enabled>no</enabled>
</agent-upgrade>
```

### Custom Notification Timing

Adjust notification retry behavior for unreliable networks:

```xml
<agent-upgrade>
  <enabled>yes</enabled>
  <ca_verification>yes</ca_verification>
  <notification_wait_start>30</notification_wait_start>
  <notification_wait_max>1800</notification_wait_max>
  <notification_wait_factor>3</notification_wait_factor>
</agent-upgrade>
```

---

## Upgrade Process

### Manager-Side Flow

1. **API request:** Upgrade initiated via Wazuh API or CLI
2. **Task creation:** Task Manager creates upgrade task
3. **WPK download:** Manager downloads WPK from repository (if not cached)
4. **WPK transfer:** Manager transfers WPK to agent in chunks
5. **Execution trigger:** Manager signals agent to execute upgrade
6. **Status monitoring:** Manager monitors upgrade task status
7. **Completion:** Task marked as complete or failed

### WPK Cache

Downloaded WPKs are cached in `/var/wazuh-manager/var/upgrade/`:

```bash
ls -lh /var/wazuh-manager/var/upgrade/
```

---

## Performance Considerations

### Simultaneous Upgrades

**Small deployments (<100 agents):**
```xml
<max_threads>4</max_threads>
```

**Medium deployments (100-1000 agents):**
```xml
<max_threads>8</max_threads>
```

**Large deployments (1000+ agents):**
```xml
<max_threads>0</max_threads>  <!-- Use all CPU cores -->
```

### Transfer Chunk Size

**High bandwidth:**
```xml
<chunk_size>60000</chunk_size>
```

**Low bandwidth or unreliable networks:**
```xml
<chunk_size>8192</chunk_size>
```

**Balanced (default):**
```xml
<chunk_size>32768</chunk_size>
```

---

## Monitoring

### Check Upgrade Status

Via API:
```bash
curl -k -X GET "https://localhost:55000/agents/upgrade" \
  -H "Authorization: Bearer $TOKEN"
```

Via CLI:
```bash
/var/wazuh-manager/bin/agent_upgrade -l
```

### View Upgrade Logs

```bash
# Manager upgrade logs
tail -f /var/wazuh-manager/logs/wazuh-manager.log | grep agent-upgrade

# Task manager logs
tail -f /var/wazuh-manager/logs/wazuh-manager.log | grep task-manager
```

### Check WPK Cache

```bash
# List cached WPK files
ls -lh /var/wazuh-manager/var/upgrade/

# Check disk usage
du -sh /var/wazuh-manager/var/upgrade/
```

---

## Troubleshooting

### Upgrade Fails to Start

**Check module is enabled:**
```bash
grep -A5 "<agent-upgrade>" /var/wazuh-manager/etc/wazuh-manager.conf
```

**Verify WPK repository:**
```bash
# Test repository URL
curl -I https://packages.wazuh.com/4.x/wpk/
```

### WPK Download Failures

**Check network connectivity:**
```bash
curl -v https://packages.wazuh.com/
```

**Verify firewall rules allow outbound HTTPS:**
```bash
iptables -L OUTPUT -n -v | grep 443
```

### Upgrade Timeouts

Increase task timeout in Task Manager configuration:

```xml
<task-manager>
  <task_timeout>30m</task_timeout>  <!-- Increase from 15m default -->
</task-manager>
```

---

## See Also

- [Agent Upgrade Module](index.html) - Module overview and architecture
- [Task Manager Configuration](../task_manager/configuration.md) - Task lifecycle management
- [Manager Configuration Reference](../../configuration/manager/README.md) - All manager configuration options
- [Agent Configuration Reference](../../configuration/agent/README.md) - All agent configuration options

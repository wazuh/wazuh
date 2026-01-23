# Rootcheck Configuration

This document describes all configuration options for the rootcheck module.

## Configuration Location

Rootcheck is configured in the agent's `ossec.conf` file within the `<rootcheck>` section:

```xml
<rootcheck>
  <!-- Configuration options -->
</rootcheck>
```

## Configuration Options

### Core Options

#### `disabled`

Enable or disable the rootcheck module.

| Attribute | Value |
|-----------|-------|
| **Type** | Boolean |
| **Default** | no |
| **Allowed values** | yes, no |

**Example:**
```xml
<rootcheck>
  <disabled>no</disabled>
</rootcheck>
```

#### `frequency`

Time interval between rootcheck scans, specified in seconds.

| Attribute | Value |
|-----------|-------|
| **Type** | Integer |
| **Default** | 43200 (12 hours) |
| **Allowed values** | Any positive integer |

**Example:**
```xml
<rootcheck>
  <frequency>86400</frequency> <!-- 24 hours -->
</rootcheck>
```

### Detection Options

#### `check_dev`

Enable or disable checking of the `/dev` directory for suspicious files.

| Attribute | Value |
|-----------|-------|
| **Type** | Boolean |
| **Default** | yes |
| **Allowed values** | yes, no |
| **Platform** | Unix/Linux only |

The `/dev` directory should only contain device-specific files. Rootcheck inspects all files in this directory because malware can use this partition to hide files.

**Example:**
```xml
<rootcheck>
  <check_dev>yes</check_dev>
</rootcheck>
```

#### `check_sys`

Enable or disable checking for anomalous file system objects.

| Attribute | Value |
|-----------|-------|
| **Type** | Boolean |
| **Default** | yes |
| **Allowed values** | yes, no |

Scans the system for unusual files, permissions, and hidden files. Checks include:
- Files owned by root with world-writable permissions
- SUID files
- Hidden directories
- File size discrepancies

**Example:**
```xml
<rootcheck>
  <check_sys>yes</check_sys>
</rootcheck>
```

#### `check_pids`

Enable or disable checking for hidden processes.

| Attribute | Value |
|-----------|-------|
| **Type** | Boolean |
| **Default** | yes |
| **Allowed values** | yes, no |

Inspects all process IDs (PIDs) using different system calls to detect processes hidden from standard listing tools like `ps`.

**Example:**
```xml
<rootcheck>
  <check_pids>yes</check_pids>
</rootcheck>
```

#### `check_ports`

Enable or disable checking for hidden network ports.

| Attribute | Value |
|-----------|-------|
| **Type** | Boolean |
| **Default** | yes |
| **Allowed values** | yes, no |

Scans for ports not visible in `netstat` output by attempting to bind to each port.

**Example:**
```xml
<rootcheck>
  <check_ports>yes</check_ports>
</rootcheck>
```

#### `check_if`

Enable or disable checking network interfaces for promiscuous mode.

| Attribute | Value |
|-----------|-------|
| **Type** | Boolean |
| **Default** | yes |
| **Allowed values** | yes, no |

Detects network interfaces running in promiscuous mode, which can capture all network traffic and may indicate packet sniffing malware.

**Example:**
```xml
<rootcheck>
  <check_if>yes</check_if>
</rootcheck>
```

### Additional Options

#### `skip_nfs`

Enable or disable scanning of network-mounted filesystems.

| Attribute | Value |
|-----------|-------|
| **Type** | Boolean |
| **Default** | yes |
| **Allowed values** | yes, no |
| **Platform** | Linux, FreeBSD |

When enabled, rootcheck will skip checking files on CIFS or NFS mounts to avoid performance issues.

**Example:**
```xml
<rootcheck>
  <skip_nfs>yes</skip_nfs>
</rootcheck>
```

#### `base_directory`

Base directory that will be prefixed to the `/dev` directory scan.

| Attribute | Value |
|-----------|-------|
| **Type** | String (path) |
| **Default (Unix)** | / |
| **Default (Windows)** | C:\ |
| **Allowed values** | Any valid directory path |

> **Note:** In Wazuh 5.0, this option only affects `/dev` directory scanning since file check and trojan scan features have been removed.

**Example:**
```xml
<rootcheck>
  <base_directory>/</base_directory>
</rootcheck>
```

#### `ignore`

List of files or directories to ignore during scans (one entry per line).

| Attribute | Value |
|-----------|-------|
| **Type** | String (regex) |
| **Allowed values** | Simple regex (sregex) |
| **Valid for** | check_sys, check_dev |

**Attributes:**
- `type="sregex"`: Simple regex expression

**Example:**
```xml
<rootcheck>
  <ignore type="sregex">^/etc/mtab$</ignore>
  <ignore type="sregex">^/etc/hosts.deny$</ignore>
  <ignore type="sregex">^/etc/mail/statistics$</ignore>
  <ignore type="sregex">^/etc/random-seed$</ignore>
</rootcheck>
```

### Deprecated Options (No Effect in 5.0)

The following options existed in previous versions but no longer have any effect in Wazuh 5.0:

#### `scanall`

> **Deprecated in 5.0:** This option was used for comprehensive rootkit file scanning, which has been removed.

#### `readall`

> **Deprecated in 5.0:** This option controlled whether rootcheck would read all system files to compare bytes read with file size, which has been removed.

## Complete Configuration Example

### Default Configuration

```xml
<rootcheck>
  <disabled>no</disabled>

  <!-- Detection options -->
  <check_dev>yes</check_dev>
  <check_sys>yes</check_sys>
  <check_pids>yes</check_pids>
  <check_ports>yes</check_ports>
  <check_if>yes</check_if>

  <!-- Scan every 12 hours -->
  <frequency>43200</frequency>

  <!-- Skip network filesystems -->
  <skip_nfs>yes</skip_nfs>

  <!-- Ignore specific paths -->
  <ignore type="sregex">^/etc/mtab$</ignore>
  <ignore type="sregex">^/etc/hosts.deny$</ignore>
</rootcheck>
```

### Minimal Configuration

```xml
<rootcheck>
  <disabled>no</disabled>
  <frequency>43200</frequency>
</rootcheck>
```

### High-Frequency Monitoring

For environments requiring more frequent checks:

```xml
<rootcheck>
  <disabled>no</disabled>

  <check_dev>yes</check_dev>
  <check_sys>yes</check_sys>
  <check_pids>yes</check_pids>
  <check_ports>yes</check_ports>
  <check_if>yes</check_if>

  <!-- Scan every 6 hours -->
  <frequency>21600</frequency>

  <skip_nfs>yes</skip_nfs>
</rootcheck>
```

### Selective Detection

Enable only specific detection types:

```xml
<rootcheck>
  <disabled>no</disabled>

  <!-- Only check for hidden processes and ports -->
  <check_dev>no</check_dev>
  <check_sys>no</check_sys>
  <check_pids>yes</check_pids>
  <check_ports>yes</check_ports>
  <check_if>no</check_if>

  <frequency>43200</frequency>
</rootcheck>
```

## Performance Considerations

### Scan Frequency

- **Default (12 hours)**: Suitable for most environments
- **6-8 hours**: Recommended for high-security environments
- **24 hours**: Acceptable for low-risk systems with limited resources

Rootcheck scans can be resource-intensive. Consider your system's capabilities when setting the frequency.

### Impact on System Resources

- **CPU**: Moderate during scan execution
- **I/O**: Can be significant when scanning large filesystems
- **Network**: Minimal (only sends alerts)

### Recommendations

1. **Skip network mounts**: Keep `skip_nfs` enabled to avoid performance issues
2. **Use ignore patterns**: Exclude directories known to change frequently
3. **Schedule appropriately**: Consider running scans during off-peak hours
4. **Monitor impact**: Watch system resources during initial scans

## Troubleshooting

### Rootcheck Not Running

Check if rootcheck is enabled:
```bash
grep -A 5 "<rootcheck>" /var/ossec/etc/ossec.conf
```

Check logs for errors:
```bash
grep rootcheck /var/ossec/logs/ossec.log
```

### No Alerts Generated

1. Verify rootcheck is not disabled
2. Check scan frequency - wait for next scheduled scan
3. Force immediate scan:
   ```bash
   /var/ossec/bin/wazuh-control restart
   ```
4. Check agent connection to manager

### False Positives

Use the `<ignore>` option to exclude known benign files or directories:

```xml
<rootcheck>
  <ignore type="sregex">/path/to/benign/file</ignore>
</rootcheck>
```

### High Resource Usage

1. Increase scan frequency (reduce frequency of scans)
2. Enable `skip_nfs` if not already enabled
3. Add ignore patterns for large, frequently-changing directories
4. Consider disabling specific checks not needed for your environment

## See Also

- [Architecture](architecture.md) - Technical details of detection methods
- [Output Samples](output-samples.md) - Example alerts and their meanings
- [SCA Module](../sca/README.md) - Policy and configuration assessment
- [FIM Module](../fim/README.md) - File integrity monitoring

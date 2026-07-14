# Rootcheck Configuration Reference

Complete configuration reference for the Rootcheck module.

The rootcheck module performs anomaly and behavior-based detection on monitored endpoints to identify potential security threats such as hidden processes, hidden network ports, unusual file system objects, and network interfaces in promiscuous mode.

**Configuration file:** `/var/ossec/etc/ossec.conf`

**XML Section:** `<rootcheck>`

**Module:** Agent-only

**Internal Options:** `rootcheck.*`

For module overview and architecture, see [Rootcheck Module](index.html).

---

## Configuration Options

**Deprecated options:** The following tags are parsed for backward compatibility but print migration messages. Functionality has been replaced by SCA and FIM:
- `<windows_malware>`, `<windows_apps>` - Use SCA policies instead
- `<check_files>`, `<check_trojans>` - Use FIM instead
- `<check_unixaudit>`, `<check_winapps>`, `<check_winaudit>`, `<check_winmalware>` - Use SCA policies instead

### disabled

Enable or disable the rootcheck module.

- **Default value:** `no`
- **Allowed values:** `yes`, `no`
- **Note:** When disabled, all rootcheck detection capabilities are stopped

**Example:**
```xml
<rootcheck>
  <disabled>no</disabled>
</rootcheck>
```

### frequency

Time interval between rootcheck scans, specified in seconds.

- **Default value:** `43200` (12 hours)
- **Allowed values:** Any positive integer
- **Note:** Consider system resources when setting scan frequency

**Example:**
```xml
<rootcheck>
  <frequency>86400</frequency> <!-- 24 hours -->
</rootcheck>
```

### check_dev

Enable or disable checking of the `/dev` directory for suspicious files.

- **Default value:** `yes`
- **Allowed values:** `yes`, `no`
- **Platform:** Unix/Linux only
- **Note:** The `/dev` directory should only contain device-specific files; malware can use this partition to hide files

**Example:**
```xml
<rootcheck>
  <check_dev>yes</check_dev>
</rootcheck>
```

### check_sys

Enable or disable checking for anomalous file system objects.

- **Default value:** `yes`
- **Allowed values:** `yes`, `no`
- **Note:** Scans for unusual files, permissions, and hidden files including files owned by root with world-writable permissions, SUID files, hidden directories, and file size discrepancies

**Example:**
```xml
<rootcheck>
  <check_sys>yes</check_sys>
</rootcheck>
```

### check_pids

Enable or disable checking for hidden processes.

- **Default value:** `yes`
- **Allowed values:** `yes`, `no`
- **Note:** Inspects all process IDs (PIDs) using different system calls to detect processes hidden from standard listing tools like `ps`

**Example:**
```xml
<rootcheck>
  <check_pids>yes</check_pids>
</rootcheck>
```

### check_ports

Enable or disable checking for hidden network ports.

- **Default value:** `yes`
- **Allowed values:** `yes`, `no`
- **Note:** Scans for ports not visible in `netstat` output by attempting to bind to each port

**Example:**
```xml
<rootcheck>
  <check_ports>yes</check_ports>
</rootcheck>
```

### check_if

Enable or disable checking network interfaces for promiscuous mode.

- **Default value:** `yes`
- **Allowed values:** `yes`, `no`
- **Note:** Detects network interfaces running in promiscuous mode, which can capture all network traffic and may indicate packet sniffing malware

**Example:**
```xml
<rootcheck>
  <check_if>yes</check_if>
</rootcheck>
```

### skip_nfs

Enable or disable scanning of network-mounted filesystems.

- **Default value:** `yes`
- **Allowed values:** `yes`, `no`
- **Platform:** Linux, FreeBSD
- **Note:** When enabled, rootcheck will skip checking files on CIFS or NFS mounts to avoid performance issues

**Example:**
```xml
<rootcheck>
  <skip_nfs>yes</skip_nfs>
</rootcheck>
```

### base_directory

Base directory that will be prefixed to the `/dev` directory scan.

- **Default value (Unix):** `/`
- **Default value (Windows):** `C:\`
- **Allowed values:** Any valid directory path
- **Note:** In Wazuh 5.0, this option only affects `/dev` directory scanning since file check and trojan scan features have been removed

**Example:**
```xml
<rootcheck>
  <base_directory>/</base_directory>
</rootcheck>
```

### ignore

List of files or directories to ignore during scans (one entry per line).

- **Default value:** none
- **Allowed values:** Simple regex (sregex)
- **Valid for:** `check_sys`, `check_dev`
- **Attributes:** `type="sregex"` - Simple regex expression

**Example:**
```xml
<rootcheck>
  <ignore type="sregex">^/etc/mtab$</ignore>
  <ignore type="sregex">^/etc/hosts.deny$</ignore>
  <ignore type="sregex">^/etc/mail/statistics$</ignore>
  <ignore type="sregex">^/etc/random-seed$</ignore>
</rootcheck>
```

---

## Internal Options

**Configuration file:** `/var/ossec/etc/local_internal_options.conf`

Internal options provide low-level control over module behavior. These options are rarely needed for normal operation.

### rootcheck.sleep

Sleep time (in milliseconds) between each iteration of the rootcheck scan loop.

- **Default value:** `50`
- **Allowed values:** Positive integer
- **Note:** Lower values increase scan speed but may impact system performance

**Example:**
```
rootcheck.sleep=50
```

---

## Configuration Examples

### Default Configuration

Standard rootcheck settings for most deployments:

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

Basic configuration with default values:

```xml
<rootcheck>
  <disabled>no</disabled>
  <frequency>43200</frequency>
</rootcheck>
```

### High-Frequency Monitoring

Configuration for environments requiring more frequent checks:

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

### Disable Rootcheck

Prevent all rootcheck detection:

```xml
<rootcheck>
  <disabled>yes</disabled>
</rootcheck>
```

---

## See Also

- [Rootcheck Module](index.html) - Module overview and features
- [Architecture](architecture.md) - Technical architecture and detection methods
- [Output Samples](output-samples.md) - Alert formats and examples
- [Security Configuration Assessment (SCA)](../sca/index.html) - Policy and configuration compliance checking
- [File Integrity Monitoring (FIM)](../fim/index.html) - File change detection and monitoring

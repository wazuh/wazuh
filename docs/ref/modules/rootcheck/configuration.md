# Rootcheck Configuration Reference

Complete configuration reference for the Rootcheck module.

The rootcheck module performs anomaly and behavior-based detection on monitored endpoints to identify potential security threats such as hidden processes, hidden network ports, unusual file system objects, and network interfaces in promiscuous mode.

**Configuration file:** `/var/ossec/etc/ossec.conf`

**XML Section:** `<rootcheck>`

**Module:** Agent-only

**Internal Options:** `rootcheck.*`

For module overview and architecture, see [Rootcheck Module](README.md).

---

## Configuration Options

Rootcheck runs inside `wazuh-syscheckd` and logs under the `wazuh-rootcheck` tag. An invalid value or an unknown tag in `<rootcheck>` is a configuration error: the configuration test of `wazuh-syscheckd` fails, so `wazuh-control start` and `restart` stop with `wazuh-syscheckd: Configuration error. Exiting`.

**Deprecated options:** The following tags are accepted for backward compatibility, have no effect, and each logs `Rootcheck option '<option>' is no longer supported.` at INFO level, followed by the replacement where there is one:
- `<windows_malware>`, `<windows_apps>` - Use SCA policies instead
- `<check_files>`, `<check_trojans>` - Use FIM instead
- `<check_unixaudit>`, `<check_winapps>`, `<check_winaudit>`, `<check_winmalware>` - Use SCA policies instead
- `<rootkit_files>`, `<rootkit_trojans>`, `<system_audit>`, `<windows_audit>` - No replacement

### disabled

Enable or disable the rootcheck module.

- **Default value:** `no` when the configuration has a `<rootcheck>` section. Without one, rootcheck is disabled
- **Allowed values:** `yes`, `no`
- **Note:** When disabled, all rootcheck detection capabilities are stopped and the agent logs `Rootcheck disabled.`

**Example:**
```xml
<rootcheck>
  <disabled>no</disabled>
</rootcheck>
```

### frequency

Time interval between rootcheck scans, specified in seconds.

- **Default value:** `43200` (12 hours)
- **Allowed values:** A number of seconds, digits only (no `s`, `m`, `h` suffix)
- **Note:** The first scan runs when the agent starts; the next one starts once `frequency` seconds have passed since the previous scan ended. Consider system resources when setting scan frequency

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
- **Note:** Scans `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`, `/dev`, `/lib`, `/etc`, `/root`, `/var/log`, `/var/mail`, `/var/lib`, `/var/www`, `/usr/lib`, `/usr/include`, `/tmp`, `/boot`, `/usr/local`, `/var/tmp` and `/sys` (on Windows, `C:\WINDOWS` and `C:\Program Files`), or the whole file system with [`scanall`](#scanall). It reports world-writable files owned by root, files listed in a directory that `lstat()` cannot find, directories whose link count does not match their entries, and files whose size differs from the bytes read (checked for the files under `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`, `/dev`, `/etc` and `/boot`, or for every file with [`readall`](#readall)). On Windows it reports only NTFS alternate data streams

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
- **Platform:** Linux, macOS and other Unix systems (not Windows)
- **Note:** Probes every process ID (PID) with `kill`, `getsid` and `getpgid` and compares the answers with `/proc` and `ps` to detect processes hidden from standard listing tools. On Linux the PIDs checked go up to [`rootcheck.max_pid`](#rootcheckmax_pid)

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
- **Platform:** Linux, macOS and other Unix systems (not Windows)
- **Note:** Attempts to bind every TCP and UDP port and reports a port that cannot be bound and is not in the output of `ss` (Linux) or `netstat`. Skipped when neither tool is installed

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
- **Platform:** Linux, macOS and other Unix systems (not Windows)
- **Note:** Detects network interfaces running in promiscuous mode, which can capture all network traffic and may indicate packet sniffing malware

**Example:**
```xml
<rootcheck>
  <check_if>yes</check_if>
</rootcheck>
```

### skip_nfs

Enable or disable scanning of network-mounted filesystems.

- **Default value:** `no`. The shipped `ossec.conf` sets it to `yes`.
- **Allowed values:** `yes`, `no`
- **Platform:** Linux
- **Note:** When enabled, the file system check (`check_sys`) skips directories on CIFS or NFS mounts to avoid performance issues

**Example:**
```xml
<rootcheck>
  <skip_nfs>yes</skip_nfs>
</rootcheck>
```

### base_directory

Base directory prefixed to the paths that `check_dev` and `check_sys` scan.

- **Default value (Unix):** `/`
- **Default value (Windows):** `C:`
- **Allowed values:** Any valid directory path; a trailing `/` is removed
- **Note:** Not used by `check_sys` when [`scanall`](#scanall) is enabled, which always starts at `/` (`C:\` on Windows)

**Example:**
```xml
<rootcheck>
  <base_directory>/</base_directory>
</rootcheck>
```

### ignore

A file or directory to ignore during scans. Repeat the element for each entry.

- **Default value:** none. The shipped Linux configuration ignores `/var/lib/containerd` and `/var/lib/docker/overlay2`
- **Allowed values:** A full path, matched exactly (case-insensitively on Windows), or, with `type="sregex"`, an OSMatch simple regular expression
- **Valid for:** `check_sys`, `check_dev`
- **Attributes:** `type="sregex"`. Any other attribute or value is a configuration error

**Example:**
```xml
<rootcheck>
  <ignore type="sregex">^/etc/mtab$</ignore>
  <ignore type="sregex">^/etc/hosts.deny$</ignore>
  <ignore type="sregex">^/etc/mail/statistics$</ignore>
  <ignore type="sregex">^/etc/random-seed$</ignore>
</rootcheck>
```

### scanall

Scan the whole file system in `check_sys` instead of the fixed list of directories.

- **Default value:** `no`
- **Allowed values:** `yes`, `no`
- **Note:** Starts at `/` (`C:\` on Windows) and ignores `base_directory`. Slower than the default list

### readall

In `check_sys`, read every regular file and compare the bytes read with the size `stat()` reports. Without it, only the files under `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`, `/dev`, `/etc` and `/boot` are read. Not used on Windows.

- **Default value:** `no`
- **Allowed values:** `yes`, `no`
- **Note:** A mismatch is reported as `Anomaly detected in file '<path>'. File size doesn't match what we found. Possible kernel level rootkit.` Reading every file makes the scan slower and heavier on disk I/O

---

## Internal Options

**Configuration file:** `/var/ossec/etc/local_internal_options.conf` (Linux/Unix) or `C:\Program Files (x86)\ossec-agent\local_internal_options.conf` (Windows). A value out of range stops `wazuh-syscheckd` with `(2302): Invalid definition for rootcheck.<option>: '<value>'.`

Internal options provide low-level control over module behavior. These options are rarely needed for normal operation.

### rootcheck.sleep

Sleep time, in milliseconds, before re-checking each suspicious port, and after each PID on systems other than Linux.

- **Default value:** `50`
- **Allowed values:** `0` to `1000`
- **Note:** Lower values increase scan speed but may impact system performance

**Example:**
```
rootcheck.sleep=50
```

### rootcheck.max_pid

Highest PID probed by the hidden process check. Linux only.

- **Default value:** `32768`
- **Allowed values:** `32768` to `4194304`
- **Note:** Kernels with a larger `pid_max` (4194304 on most 64-bit systems) can assign PIDs above the default, and those are not checked. Raising the value up to `4194304` covers the whole range at a higher CPU cost per scan. The default also applies when the option is in neither `internal_options.conf` nor `local_internal_options.conf`.

At startup, when `check_pids` is enabled, the limit in use is logged:

```
wazuh-rootcheck: INFO: Hidden process check: checking PIDs up to 32768 (default, 'rootcheck.max_pid' not set).
wazuh-rootcheck: INFO: Hidden process check: PIDs from 32769 to 4194303 are not checked. Raise 'rootcheck.max_pid' up to 4194304 to check them.
```

**Example:**
```
rootcheck.max_pid=4194304
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

- [Rootcheck Module](README.md) - Module overview and features
- [Architecture](architecture.md) - Technical architecture and detection methods
- [Output Samples](output-samples.md) - Alert formats and examples
- [Security Configuration Assessment (SCA)](../sca/README.md) - Policy and configuration compliance checking
- [File Integrity Monitoring (FIM)](../fim/README.md) - File change detection and monitoring

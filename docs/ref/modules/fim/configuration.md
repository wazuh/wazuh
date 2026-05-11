# File Integrity Monitoring (Syscheck)

## Overview

File Integrity Monitoring (FIM) is a core security capability in Wazuh that tracks changes to files, directories, and Windows registry entries. The FIM engine, implemented through the **syscheck** module, detects unauthorized modifications, deletions, or creations that could indicate a compromise, misconfiguration, or policy violation.

FIM operates in two complementary modes:

- **Scheduled scans**: Periodic baseline comparisons triggered by the `frequency` setting.
- **Real-time monitoring**: Continuous event-driven monitoring via `realtime` or `whodata` directory attributes.

> **Note:** All configuration resides in `ossec.conf` (manager or agent) inside the `<syscheck>` XML block, or in `agent.conf` for centralized agent configuration.

---

## XML Section

```xml
<syscheck>
  <!-- configuration options -->
</syscheck>
```

---

## Configuration Reference


### `diff`

Configures diff-related settings for change reporting. This block contains sub-elements.

```xml
<diff>
  <disk_quota>
    <enabled>yes</enabled>
    <limit>1GB</limit>
  </disk_quota>
  <file_size>
    <enabled>yes</enabled>
    <limit>50MB</limit>
  </file_size>
  <nodiff>/etc/ssl/private.key</nodiff>
</diff>
```

#### `diff > disk_quota`

Limits the total size of the `queue/diff/local` folder, which holds compressed file snapshots used for diff operations when `report_changes` is enabled. Once the limit is reached, diff information is suppressed from alerts until disk usage drops below the threshold.

| Sub-element | Default | Allowed values | Description |
|---|---|---|---|
| `enabled` | `yes` | `yes`, `no` | Enable or disable the disk quota limit |
| `limit` | `1GB` | Any positive number followed by `KB`, `MB`, or `GB` | Maximum allowed size |

#### `diff > file_size`

Limits the maximum individual file size eligible for diff reporting. Files exceeding this threshold will not include diff output in alerts until their size falls back under the limit.

| Sub-element | Default | Allowed values | Description |
|---|---|---|---|
| `enabled` | `yes` | `yes`, `no` | Enable or disable the per-file size limit |
| `limit` | `50MB` | Any positive number followed by `KB`, `MB`, or `GB` | Maximum file size for diff |

#### `diff > nodiff`

List of files (one per line) for which diff content must never be computed or sent in alerts. This prevents sensitive data — such as private keys, credentials, or database config files — from leaking through alerts.

| | |
|---|---|
| **Allowed values** | Any file path |
| **Attribute: `type`** | `sregex` — use a regex pattern to match multiple files |

```xml
<nodiff>/etc/ssl/private.key</nodiff>
<nodiff type="sregex">\.key$|\.pem$|password</nodiff>
```

#### `diff > registry_nodiff` *(Windows only)*

Same as `nodiff` but for Windows registry values. The path must include the value name.

| | |
|---|---|
| **Allowed values** | Any registry path including the value name |
| **Attribute: `type`** | `sregex` — use a regex pattern to match multiple registry values |
| **Attribute: `arch`** | `32bit`, `64bit`, `both` — select the Windows registry view to monitor |

```xml
<registry_nodiff>HKEY_LOCAL_MACHINE\SOFTWARE\test_key\value_name</registry_nodiff>
<registry_nodiff type="sregex">password</registry_nodiff>
<registry_nodiff arch="64bit">HKEY_LOCAL_MACHINE\SOFTWARE\test_key\value_name</registry_nodiff>
```

---

### `directories`

Defines which directories to monitor. This is the primary configuration element for FIM on Linux, Unix, macOS, and Windows.

| | |
|---|---|
| **Default** | <directories>/etc,/usr/bin,/usr/sbin</directories> and <directories>/bin,/sbin,/boot</directories> |
| **Allowed values** | Any directory path or environment variable |

Rules:
- Multiple directories can be comma-separated on a single line, or defined across multiple `<directories>` lines.
- All subdirectories and files within a monitored path are included recursively (up to `recursion_level`).
- A maximum of **64 comma-separated directories** per line.
- Wildcard characters `?` and `*` are supported and are re-evaluated on each scheduled scan.
- Drive letters without a trailing backslash are valid on Windows (e.g., `D:`).

```xml
<directories>/etc,/usr/bin,/usr/sbin</directories>
<directories>/bin,/sbin,/boot</directories>
<directories realtime="yes">/var/www/html</directories>
<directories whodata="yes" report_changes="yes">/home</directories>
```

#### Directory Attributes

| Attribute | Default | Allowed values | Description |
|---|---|---|---|
| `realtime` | `no` | `yes`, `no` | Enable real-time (inotify/Windows) monitoring. Applies to directories only, not individual files. |
| `whodata` | `no` | `yes`, `no` | Enable who-data monitoring to capture the user, process, and program triggering each change. |
| `report_changes` | `no` | `yes`, `no` | Report the actual diff of changed text files in alerts. |
| `diff_size_limit` | `50MB` | Positive number + `KB`/`MB`/`GB` | Per-directory override for the maximum file size eligible for diff reporting. |
| `check_all` | `yes` | `yes`, `no` | Master toggle for all `check_*` attributes below. Setting to `no` disables all checks; individual `check_*` attributes can then re-enable specific ones. |
| `check_sum` | `yes` | `yes`, `no` | Shorthand to enable/disable MD5, SHA-1, and SHA-256 hashing simultaneously. |
| `check_md5sum` | `yes` | `yes`, `no` | Check the MD5 hash. |
| `check_sha1sum` | `yes` | `yes`, `no` | Check the SHA-1 hash. |
| `check_sha256sum` | `yes` | `yes`, `no` | Check the SHA-256 hash. |
| `check_size` | `yes` | `yes`, `no` | Check the file size. |
| `check_owner` | `yes` | `yes`, `no` | Check file ownership (UID). On Windows, UID is always `0`. |
| `check_group` | `yes` | `yes`, `no` | Check the group owner (GID). Available on UNIX. On Windows, GID is always `0` and group name is blank. |
| `check_perm` | `yes` | `yes`, `no` | Check file/directory permissions. On Windows, lists allowed and denied permissions per user or group (NTFS partitions only). |
| `check_attrs` | `yes` | `yes`, `no` | Check file attributes. Windows only. |
| `check_mtime` | `yes` | `yes`, `no` | Check the file modification time. |
| `check_inode` | `yes` | `yes`, `no` | Check the file inode. Available on UNIX. On Windows, inode is always `0`. |
| `check_device` | `yes` | `yes`, `no` | Check the file device identifier. Available on UNIX only. |
| `restrict` | N/A | `sregex` | Limit monitoring to files whose names match the given regex. |
| `tags` | N/A | Comma-separated strings | Attach custom tags to all alerts from this directory. |
| `recursion_level` | `256` | Integer `0`–`320` | Maximum recursion depth. `0` means only the top-level directory is monitored. |
| `follow_symbolic_link` | `no` | `yes`, `no` | UNIX only. When enabled, symbolic links are followed and the linked content is monitored. When disabled, the link itself is monitored. |

#### Attribute Precedence Rules

Some `<directories>` attributes can conflict, such as `check_all` and specific `check_*` flags. Syscheck applies these attributes sequentially in the order they appear, so later attributes can override earlier ones:

```xml
<directories check_all="no" check_sha256sum="yes">/etc</directories>

<directories check_sha256sum="yes" check_all="no">/etc</directories>
```

When a path without wildcards overlaps with a wildcard block, the **non-wildcard** (specific) block takes precedence for that exact path:

```xml
<!-- All user Downloads folders monitored in scheduled mode -->
<directories>C:\Users\*\Downloads</directories>

<!-- vagrant's Downloads folder is monitored in real time (specific rule wins) -->
<directories realtime="yes">C:\Users\vagrant\Downloads</directories>
```

---

### `disabled`

Disables or enables the entire syscheck module.

| | |
|---|---|
| **Default** | `no` |
| **Allowed values** | `yes`, `no` |

```xml
<disabled>no</disabled>
```

---

### `file_limit`

Sets a hard cap on the number of files FIM can monitor. Once the database reaches this limit, newly discovered files are ignored until the count drops below it.

| | |
|---|---|
| **Default (enabled)** | `yes` |
| **Default (entries)** | `100000` |

```xml
<file_limit>
  <enabled>yes</enabled>
  <entries>100000</entries>
</file_limit>
```

| Sub-element | Default | Allowed values |
|---|---|---|
| `enabled` | `yes` | `yes`, `no` |
| `entries` | `100000` | Integer `1`–`2147483647` |

---

### `frequency`

Sets how often syscheck runs a full scheduled scan, in seconds.

| | |
|---|---|
| **Default** | `43200` (12 hours) |
| **Allowed values** | Any positive integer (seconds) |

```xml
<frequency>43200</frequency>
```

---

### `ignore`

Files or directories to exclude from monitoring and scanning. Paths that match ignore are not processed by syscheck.

| | |
|---|---|
| **Default** | Varies by OS |
| **Allowed values** | Any file or directory path |
| **Attribute: `type`** | `sregex` — use a regex pattern |

```xml
<ignore>/etc/mtab</ignore>
<ignore>/etc/hosts.deny</ignore>
<ignore type="sregex">.log$|.swp$</ignore>
```

---

### `max_eps`

Controls the maximum number of FIM alert events sent to the manager per second. This applies to stateless and real-time events. Setting to `0` disables rate limiting.

| | |
|---|---|
| **Default** | `50` |
| **Allowed values** | Integer `0`–`1000000` |

```xml
<max_eps>50</max_eps>
```

> **Note:** This is separate from `synchronization > max_eps`, which limits synchronization messages only.

---

### `max_files_per_second`

Limits the number of files processed per second during a scheduled scan, reducing CPU impact. `0` means no limit.

| | |
|---|---|
| **Default** | `0` |
| **Allowed values** | Any non-negative integer |

```xml
<max_files_per_second>100</max_files_per_second>
```

---

### `notify_first_scan`

Controls whether FIM generates stateless events for every file found during the very first scan after agent startup.

| | |
|---|---|
| **Default** | `no` |
| **Allowed values** | `yes`, `no` |

```xml
<notify_first_scan>no</notify_first_scan>
```

When set to `yes`, every file in the monitored directories produces an alert on the initial baseline scan. This is useful for immediately populating a dashboard or confirming coverage, but can generate high alert volume on first run.

---

### `process_priority`

Sets the `nice` value for the syscheck process, controlling CPU scheduling priority.

| | |
|---|---|
| **Default** | `10` |
| **Allowed values** | Integer `-20` to `19` |

On Linux, `-20` is highest priority and `19` is lowest. On Windows, values are mapped to thread priority constants:

| Linux range | Windows priority |
|---|---|
| -20 to -10 | `THREAD_PRIORITY_HIGHEST` |
| -9 to -5 | `THREAD_PRIORITY_ABOVE_NORMAL` |
| -4 to 0 | `THREAD_PRIORITY_NORMAL` |
| 1 to 5 | `THREAD_PRIORITY_BELOW_NORMAL` |
| 6 to 10 | `THREAD_PRIORITY_LOWEST` |
| 11 to 19 | `THREAD_PRIORITY_IDLE` |

```xml
<process_priority>10</process_priority>
```

---

### `registry_ignore` *(Windows only)*

Registry entries to exclude from processing. Ignored keys and values are skipped during enumeration, so no events are generated for them and no further processing is performed.

| | |
|---|---|
| **Attribute: `arch`** | `32bit` (default), `64bit`, `both` |
| **Attribute: `type`** | `sregex` |

```xml
<registry_ignore>HKEY_LOCAL_MACHINE\Security\Policy\Secrets</registry_ignore>
<registry_ignore type="sregex">\Enum$</registry_ignore>
```

---

### `registry_limit` *(Windows only)*

Sets a hard cap on the number of registry entries FIM can monitor.

```xml
<registry_limit>
  <enabled>yes</enabled>
  <entries>100000</entries>
</registry_limit>
```

| Sub-element | Default | Allowed values |
|---|---|---|
| `enabled` | `yes` | `yes`, `no` |
| `entries` | `100000` | Integer `1`–`2147483647` |

---

### `scan_day`

Restricts scheduled scans to a specific day of the week. One entry per line.

| | |
|---|---|
| **Default** | N/A |
| **Allowed values** | Day name (e.g., `monday`, `thursday`) |

```xml
<scan_day>thursday</scan_day>
```

---

### `scan_time`

Restricts scheduled scans to a specific time of day. Can be combined with `scan_day`.

| | |
|---|---|
| **Default** | N/A |
| **Allowed values** | Time in `HH:MM` or `Xpm`/`Xam` format |

```xml
<scan_time>8:30</scan_time>
```

> **Note:** Setting `scan_time` may delay the initialization of real-time monitoring.

---

### `skip_dev`

Skips scanning the `/dev` directory. Recommended to leave enabled to avoid high noise from device files.

| | |
|---|---|
| **Default** | `yes` |
| **Allowed values** | `yes`, `no` |
| **Platforms** | Linux, FreeBSD |

```xml
<skip_dev>yes</skip_dev>
```

---

### `skip_nfs`

Skips scanning network-mounted filesystems (CIFS and NFS). Avoids performance issues and alerts from remote mounts.

| | |
|---|---|
| **Default** | `yes` |
| **Allowed values** | `yes`, `no` |
| **Platforms** | Linux, FreeBSD |

```xml
<skip_nfs>yes</skip_nfs>
```

---

### `skip_proc`

Skips scanning the `/proc` virtual filesystem.

| | |
|---|---|
| **Default** | `yes` |
| **Allowed values** | `yes`, `no` |
| **Platforms** | Linux, FreeBSD |

```xml
<skip_proc>yes</skip_proc>
```

---

### `skip_sys`

Skips scanning the `/sys` virtual filesystem.

| | |
|---|---|
| **Default** | `yes` |
| **Allowed values** | `yes`, `no` |
| **Platforms** | Linux |

```xml
<skip_sys>yes</skip_sys>
```

---

### `synchronization`

Controls how the agent synchronizes its local FIM database with the manager to ensure consistency. Synchronization is the mechanism that guarantees the manager always reflects the current state of monitored files, even after network interruptions or agent restarts.

```xml
<synchronization>
  <enabled>yes</enabled>
  <interval>300</interval>
  <response_timeout>60</response_timeout>
  <max_eps>75</max_eps>
  <integrity_interval>86400</integrity_interval>
</synchronization>
```

#### Synchronization Parameters

| Parameter | Default | Allowed values | Description |
|---|---|---|---|
| `enabled` | `yes` | `yes`, `no` | Enable or disable FIM synchronization persistence. When disabled, FIM only generates stateless events. |
| `interval` | `300` (5 minutes) | Any integer ≥ 1, with optional suffix `s`, `m`, `h`, `d` | How often the agent initiates a sync with the manager. |
| `response_timeout` | `60` | Any integer ≥ 1, with optional suffix `s`, `m`, `h`, `d` | Seconds to wait for a manager response before marking the synchronization attempt as failed or timed out. A value that is too low causes unnecessary retries; a value that is too high delays failure detection. |
| `max_eps` | `75` | Integer `0`–`1000000` (`0` = unlimited) | Maximum synchronization messages per second. |
| `integrity_interval` | `86400` (24h)| Any integer ≥ 1, with optional suffix `s`, `m`, `h`, `d` | How often the agent performs a full integrity validation by comparing checksums with the manager. |

> **Note:** The retry logic automatically retries failed sync operations up to **3 times** before giving up. Database files are stored at fixed paths: `queue/fim/db/fim.db` and `queue/fim/db/fim_sync.db`.

---

### `whodata`

Configures who-data monitoring options. When a directory is monitored with `whodata="yes"`, FIM captures the user account, process, and program responsible for each change.

```xml
<whodata>
  <provider>audit</provider>
  <restart_audit>yes</restart_audit>
  <audit_key>auditkey1,auditkey2</audit_key>
  <startup_healthcheck>yes</startup_healthcheck>
  <queue_size>16384</queue_size>
</whodata>
```

#### Whodata Parameters

| Parameter | Default | Allowed values | Platforms | Description |
|---|---|---|---|---|
| `provider` | `audit` | `audit`, `ebpf` | Linux | Who-data collection backend. Defaults to `audit`. Set to `ebpf` for better performance on kernels 5.x+; if `ebpf` is configured but unsupported by the kernel, configure `audit` explicitly. |
| `restart_audit` | `yes` | `yes`, `no` | Linux | Automatically restarts Auditd after installing the FIM plugin. If set to `no`, new whodata rules are not applied automatically. |
| `audit_key` | Empty | Comma-separated strings | Linux (Audit) | FIM will also collect events from Audit that use these keys, enabling integration with existing Audit rules. |
| `startup_healthcheck` | `yes` | `yes`, `no` | Linux (Audit) | Validates at startup that Audit rules can be set and events can be captured. Disabling this may cause silent failures. |
| `queue_size` | `16384` | Integer `10`–`1048576` | Linux (Audit) | Maximum queue capacity for Audit dispatcher events. If the queue fills up, some events may be dropped (the next scheduled scan will recover them). |

> **Warning:** Disabling `startup_healthcheck` may result in broken who-data monitoring with no error indication.

---

### `windows_audit_interval` *(Windows only)*

How often (in seconds) the Windows agent checks that Local Audit Policies and SACLs for who-data monitored directories are still correctly configured.

| | |
|---|---|
| **Default** | `300` |
| **Allowed values** | Integer `1`–`9999` |

```xml
<windows_audit_interval>300</windows_audit_interval>
```

---

### `windows_registry` *(Windows only)*

Defines Windows registry paths to monitor. Supports wildcards (`?` and `*`) for scheduled scans.

```xml
<windows_registry arch="both">HKEY_LOCAL_MACHINE\Software\Classes\Protocols</windows_registry>
<windows_registry arch="both" restrict_value="^some_value_name$">HKEY_LOCAL_MACHINE\Software\Policies</windows_registry>
<windows_registry tags="services-registry">HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services</windows_registry>
<windows_registry arch="64bit" recursion_level="3">HKEY_LOCAL_MACHINE\SYSTEM\Setup</windows_registry>
```

#### Windows Registry Attributes

| Attribute | Default | Allowed values | Description |
|---|---|---|---|
| `arch` | `32bit` | `32bit`, `64bit`, `both` | Registry view (32-bit or 64-bit hive). |
| `tags` | N/A | Comma-separated strings | Custom tags for all alerts from this registry path. |
| `report_changes` | `no` | `yes`, `no` | Report value diffs for supported types: `REG_SZ`, `REG_MULTI_SZ`, `REG_DWORD`, `REG_DWORD_BIG_ENDIAN`, `REG_QWORD`. |
| `diff_size_limit` | `50MB` | Positive number + `KB`/`MB`/`GB` | Per-entry override for the maximum value size eligible for diff. |
| `check_all` | `yes` | `yes`, `no` | Master toggle for all `check_*` attributes. |
| `check_sum` | `yes` | `yes`, `no` | Enable MD5, SHA-1, and SHA-256 hashing. |
| `check_md5sum` | `yes` | `yes`, `no` | MD5 hash check. |
| `check_sha1sum` | `yes` | `yes`, `no` | SHA-1 hash check. |
| `check_sha256sum` | `yes` | `yes`, `no` | SHA-256 hash check. |
| `check_size` | `yes` | `yes`, `no` | Size check. |
| `check_owner` | `yes` | `yes`, `no` | Owner check. |
| `check_group` | `yes` | `yes`, `no` | Group check (GID only; group name is always blank). |
| `check_perm` | `yes` | `yes`, `no` | Permissions check (allowed/denied per user or group). |
| `check_mtime` | `yes` | `yes`, `no` | Modification time check. |
| `check_type` | `yes` | `yes`, `no` | Value type check. Detects changes for `REG_NONE`, `REG_SZ`, `REG_EXPAND_SZ`, `REG_BINARY`, `REG_DWORD`, `REG_DWORD_BIG_ENDIAN`, `REG_LINK`, `REG_MULTI_SZ`, `REG_RESOURCE_LIST`, `REG_FULL_RESOURCE_DESCRIPTOR`, `REG_RESOURCE_REQUIREMENTS_LIST`, `REG_QWORD`. |
| `restrict_key` | N/A | `sregex` | Limit checks to registry keys whose name matches the pattern. |
| `restrict_value` | N/A | `sregex` | Limit checks to registry values whose name matches the pattern. |
| `recursion_level` | `512` | Integer `0`–`512` | Maximum recursion depth. |

#### Registry Precedence

Specific key configurations take precedence over wildcard configurations:

```xml
<!-- Wildcard: no hash checking for all SOFTWARE subkeys -->
<windows_registry arch="both" check_sum="no">HKEY_LOCAL_MACHINE\SOFTWARE\*</windows_registry>

<!-- Specific: hash checking enabled for TEST_KEY (overrides the wildcard) -->
<windows_registry arch="both" check_sum="yes">HKEY_LOCAL_MACHINE\SOFTWARE\TEST_KEY</windows_registry>
```

---

## Example Configurations

> These are representative examples. For the exact shipped defaults, refer to `etc/ossec.conf` and `etc/ossec-agent.conf` in the Wazuh installation directory.

### Wazuh Manager

```xml
<!-- File integrity monitoring -->
<syscheck>
  <disabled>no</disabled>
  <frequency>43200</frequency>
  <directories>/etc,/usr/bin,/usr/sbin</directories>
  <ignore>/etc/mtab</ignore>
  <ignore type="sregex">.log$|.swp$</ignore>
  <nodiff>/etc/ssl/private.key</nodiff>
  <process_priority>10</process_priority>
  <max_eps>50</max_eps>
  <synchronization>
    <max_eps>75</max_eps>
  </synchronization>
</syscheck>
```

### Wazuh Agent — Linux/Unix

```xml
<syscheck>
  <disabled>no</disabled>
  <frequency>43200</frequency>
  <directories>/etc,/usr/bin</directories>

  <directories realtime="yes">/home/alice/public_html</directories>
  <directories whodata="yes">/home/bob/sensitive_data</directories>

  <ignore type="sregex">.log$|.swp$</ignore>
  <nodiff>/etc/ssl/private.key</nodiff>
  <process_priority>10</process_priority>
  <max_eps>50</max_eps>
  <synchronization>
    <max_eps>75</max_eps>
  </synchronization>
</syscheck>
```

### Wazuh Agent — Windows

```xml
<syscheck>
  <disabled>no</disabled>
  <frequency>43200</frequency>

  <directories recursion_level="0">%WINDIR%\System32\drivers\etc</directories>
  <directories realtime="yes">C:\Users\bob\Documents\Important</directories>
  <ignore type="sregex">.log$|.tmp$|.evtx$</ignore>

  <windows_registry arch="both">HKEY_LOCAL_MACHINE\Software\Policies</windows_registry>
  <registry_ignore>HKEY_LOCAL_MACHINE\Security\Policy\Secrets</registry_ignore>

  <windows_audit_interval>300</windows_audit_interval>
  <process_priority>10</process_priority>
  <max_eps>50</max_eps>
  <synchronization>
    <max_eps>75</max_eps>
  </synchronization>
</syscheck>
```

### Wazuh Agent — macOS

```xml
<syscheck>
  <disabled>no</disabled>
  <frequency>43200</frequency>
  <directories>/etc,/usr/bin</directories>
  <directories>/Users/alice/Documents</directories>
  <ignore type="sregex">.log$|.swp$</ignore>
  <process_priority>10</process_priority>
  <max_eps>50</max_eps>
  <synchronization>
    <max_eps>75</max_eps>
  </synchronization>
</syscheck>
```

---

## Advanced Configuration Examples

### High-Performance Environment

For systems with high file change rates (CI/CD nodes, busy web servers):

```xml
<syscheck>
  <disabled>no</disabled>
  <frequency>21600</frequency>         <!-- Scan every 6 hours -->
  <max_eps>1000</max_eps>              <!-- High event throughput -->
  <max_files_per_second>500</max_files_per_second>
  <notify_first_scan>no</notify_first_scan>

  <directories realtime="yes">/var/www/html</directories>
  <directories>/etc,/usr/bin,/usr/sbin,/bin,/sbin</directories>

  <synchronization>
    <enabled>yes</enabled>
    <interval>60</interval>
    <response_timeout>60</response_timeout>
    <max_eps>500</max_eps>
    <integrity_interval>43200</integrity_interval>  <!-- Integrity check every 12 hours -->
  </synchronization>
</syscheck>
```

### Security-Sensitive Deployment (Who-Data + Diff)

For environments that require full audit trails on critical configuration files:

```xml
<syscheck>
  <disabled>no</disabled>
  <frequency>43200</frequency>

  <!-- Monitor /etc with who-data and diff reporting -->
  <directories whodata="yes" report_changes="yes" diff_size_limit="5MB">/etc</directories>

  <!-- Monitor critical binaries — no diff needed, just hash changes -->
  <directories check_all="yes">/usr/bin,/usr/sbin,/bin,/sbin</directories>

  <!-- Protect private key from diff leaking -->
  <diff>
    <nodiff>/etc/ssl/private.key</nodiff>
    <nodiff type="sregex">\.pem$|\.key$</nodiff>
    <disk_quota>
      <enabled>yes</enabled>
      <limit>2GB</limit>
    </disk_quota>
    <file_size>
      <enabled>yes</enabled>
      <limit>10MB</limit>
    </file_size>
  </diff>

  <whodata>
    <provider>audit</provider>
    <startup_healthcheck>yes</startup_healthcheck>
    <queue_size>32768</queue_size>
  </whodata>

  <synchronization>
    <enabled>yes</enabled>
    <interval>5m</interval>
    <response_timeout>60</response_timeout>
    <max_eps>75</max_eps>
    <integrity_interval>86400</integrity_interval>
  </synchronization>
</syscheck>
```

### Windows Registry Monitoring

```xml
<syscheck>
  <disabled>no</disabled>
  <frequency>43200</frequency>

  <!-- Monitor run keys for persistence detection (both architectures) -->
  <windows_registry arch="both">HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run</windows_registry>
  <windows_registry arch="both">HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce</windows_registry>

  <!-- Monitor all SOFTWARE subkeys without hashing (performance optimization) -->
  <windows_registry arch="both" check_sum="no">HKEY_LOCAL_MACHINE\SOFTWARE\*</windows_registry>

  <!-- Override: enable hashing for a specific key -->
  <windows_registry arch="both" check_sum="yes">HKEY_LOCAL_MACHINE\SOFTWARE\CriticalApp</windows_registry>

  <!-- Ignore noisy or known-changing entries -->
  <registry_ignore>HKEY_LOCAL_MACHINE\Security\Policy\Secrets</registry_ignore>
  <registry_ignore type="sregex">\Enum$</registry_ignore>

  <registry_limit>
    <enabled>yes</enabled>
    <entries>200000</entries>
  </registry_limit>
</syscheck>
```

### Scheduled Scan on Specific Day and Time

```xml
<syscheck>
  <disabled>no</disabled>
  <scan_day>sunday</scan_day>
  <scan_time>2:00</scan_time>

  <directories>/etc,/usr/bin,/usr/sbin,/bin,/sbin</directories>
  <process_priority>19</process_priority>  <!-- Lowest priority — weekend maintenance window -->
</syscheck>
```

---

## Use Cases and E2E Test Scenarios

The following use cases describe concrete end-to-end test scenarios for verifying FIM behavior. Each scenario includes preconditions, steps, and expected outcomes.

---

### UC-01: Detect file modification in a monitored directory (scheduled scan)

**Objective:** Verify that syscheck detects and reports changes to file content and metadata during a scheduled scan.

**Configuration:**
```xml
<syscheck>
  <disabled>no</disabled>
  <frequency>60</frequency>
  <directories>/tmp/fim-test</directories>
</syscheck>
```

**Steps:**
1. Create directory `/tmp/fim-test` and place a file `test.txt` with known content.
2. Wait for the first scheduled scan to complete (baseline).
3. Modify the content of `test.txt`.
4. Wait for the next scheduled scan.

**Expected result:** An alert with rule ID `550` (integrity checksum changed) is generated. The alert includes the modified file path, the changed attributes (hash, size, mtime), and the agent name.

---

### UC-02: Detect new file creation

**Objective:** Verify that syscheck generates an alert when a new file is created inside a monitored directory.

**Configuration:**
```xml
<syscheck>
  <disabled>no</disabled>
  <frequency>60</frequency>
  <directories>/tmp/fim-test</directories>
</syscheck>
```

**Steps:**
1. Ensure the monitored directory exists and a baseline scan has completed.
2. Create a new file `newfile.txt` inside `/tmp/fim-test`.
3. Wait for the next scheduled scan.

**Expected result:** An alert with rule ID `554` (file added to the system) is generated with the new file's path and attributes.

---

### UC-03: Detect file deletion

**Objective:** Verify that syscheck detects and reports file deletions.

**Steps:**
1. Ensure a monitored file exists and a baseline scan has completed.
2. Delete the file.
3. Wait for the next scheduled scan.

**Expected result:** An alert with rule ID `553` (file deleted) is generated.

---

### UC-04: Real-time monitoring — immediate change detection

**Objective:** Verify that real-time monitoring detects changes immediately without waiting for a scheduled scan.

**Configuration:**
```xml
<directories realtime="yes">/tmp/fim-realtime</directories>
```

**Steps:**
1. Create `/tmp/fim-realtime` and wait for FIM to begin monitoring.
2. Create, modify, and delete a file inside the directory.

**Expected result:** Alerts are generated within seconds, not after the next scheduled scan interval.

---

### UC-05: Who-data monitoring — identity capture

**Objective:** Verify that who-data monitoring captures the user and process responsible for a file change.

**Configuration:**
```xml
<directories whodata="yes">/tmp/fim-whodata</directories>
<whodata>
  <provider>ebpf</provider>
  <startup_healthcheck>yes</startup_healthcheck>
</whodata>
```

**Steps:**
1. Create `/tmp/fim-whodata` and wait for FIM to begin monitoring.
2. As a specific user (e.g., `www-data`), modify a file inside the directory.

**Expected result:** The generated alert includes `audit.effective_user.name`, `audit.process.name`, and `audit.process.id` fields identifying the user and process that made the change.

---

### UC-06: `nodiff` — sensitive file content not leaked

**Objective:** Verify that diff content is never included in alerts for files listed in `nodiff`.

**Configuration:**
```xml
<directories report_changes="yes">/tmp/fim-test</directories>
<diff>
  <nodiff>/tmp/fim-test/secret.key</nodiff>
</diff>
```

**Steps:**
1. Create `/tmp/fim-test/secret.key` with content `SECRET_VALUE`.
2. Wait for baseline scan.
3. Change the content of `secret.key`.
4. Wait for next scan.

**Expected result:** An alert is generated for the file change, but it does not contain diff content or any part of the file's contents.

---

### UC-07: `ignore` — suppressed alerts for excluded paths

**Objective:** Verify that changes to ignored paths do not produce alerts.

**Configuration:**
```xml
<directories>/tmp/fim-test</directories>
<ignore>/tmp/fim-test/logs</ignore>
<ignore type="sregex">.tmp$</ignore>
```

**Steps:**
1. Create `/tmp/fim-test/logs/app.log` and `/tmp/fim-test/data.tmp`.
2. Wait for baseline scan.
3. Modify both files.
4. Wait for next scan.

**Expected result:** No alerts are generated for either file.

---

### UC-08: `file_limit` enforcement

**Objective:** Verify that FIM stops tracking new files once the configured limit is reached.

**Configuration:**
```xml
<file_limit>
  <enabled>yes</enabled>
  <entries>10</entries>
</file_limit>
<directories>/tmp/fim-limit</directories>
```

**Steps:**
1. Create 10 files in `/tmp/fim-limit` and wait for baseline scan.
2. Create an 11th file.
3. Wait for the next scheduled scan.

**Expected result:** No alert is generated for the 11th file. A warning log entry indicates the database limit has been reached.

---

### UC-09: Windows registry change detection

**Objective:** Verify that FIM detects changes to monitored Windows registry values.

**Configuration:**
```xml
<windows_registry arch="both">HKEY_LOCAL_MACHINE\Software\TestApp</windows_registry>
```

**Steps:**
1. Create the registry key `HKEY_LOCAL_MACHINE\Software\TestApp` with a value.
2. Wait for baseline scan.
3. Modify the registry value.
4. Wait for next scan.

**Expected result:** An alert is generated with the registry path and the changed attributes (value, hash, mtime).

---

### UC-10: Synchronization recovery after network interruption

**Objective:** Verify that FIM synchronization correctly reconciles agent and manager databases after a connectivity gap.

**Configuration:**
```xml
<synchronization>
  <enabled>yes</enabled>
  <interval>60</interval>
  <response_timeout>30</response_timeout>
  <integrity_interval>3600</integrity_interval>
</synchronization>
```

**Steps:**
1. Confirm that the agent and manager databases are in sync.
2. Disconnect the agent from the network for a period longer than `integrity_interval`.
3. During the disconnected period, modify several files in a monitored directory.
4. Reconnect the agent.

**Expected result:** After reconnection, the synchronization mechanism detects the discrepancy during the next `integrity_interval` check and triggers recovery. All missed changes appear as alerts on the manager.

---

### UC-11: `notify_first_scan` — baseline event generation

**Objective:** Verify that enabling `notify_first_scan` causes FIM to generate an event for every file on the first scan after restart.

**Configuration:**
```xml
<notify_first_scan>yes</notify_first_scan>
<directories>/etc</directories>
```

**Steps:**
1. Restart the Wazuh agent.
2. Wait for the first FIM scan to complete.

**Expected result:** Stateless events are generated for all files in `/etc`, visible in the manager as initial scan events.

---

### UC-12: `report_changes` — diff content in alerts

**Objective:** Verify that text file changes include a diff in the alert when `report_changes` is enabled.

**Configuration:**
```xml
<directories report_changes="yes">/tmp/fim-diff</directories>
```

**Steps:**
1. Create `/tmp/fim-diff/config.txt` with the content `setting=old`.
2. Wait for baseline scan.
3. Change the file content to `setting=new`.
4. Wait for next scan.

**Expected result:** Alert includes a `diff` block showing `- setting=old` and `+ setting=new`.

---

## Best Practices

**Scope monitoring carefully.** Start with the default directories (`/etc`, `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`) and expand only as needed. Monitoring too broadly increases CPU usage, alert noise, and database size.

**Use `realtime` or `whodata` for high-priority paths.** Scheduled scans have inherent detection delays. Apply `realtime="yes"` or `whodata="yes"` to directories where immediate detection is required (e.g., `/etc/sudoers`, startup folders, web roots).

**Protect sensitive files with `nodiff`.** Any file containing credentials, private keys, or personal data should be listed in `<nodiff>` to prevent content from appearing in alerts or being forwarded to external systems.

**Tune `max_eps` to match your infrastructure.** The default of `50` events per second is appropriate for most deployments. High-traffic systems may benefit from a higher value; resource-constrained environments should lower it to avoid overwhelming the manager.

**Set `process_priority` conservatively.** The default of `10` (low priority) is appropriate for most production systems. Avoid lowering this below `0` unless scan latency is a documented requirement, as it competes with application workloads.

**Manage `file_limit` proactively.** The default cap of `100,000` files is sufficient for most workloads. Monitor agent logs for warnings about the limit being reached, and raise `entries` if legitimate monitored paths are being excluded.

**Keep `synchronization > integrity_interval` at 24 hours or lower.** This controls how often the agent fully validates its database against the manager. A lower value reduces the window in which undetected divergence can exist, at the cost of slightly more CPU and network usage.

**Use `tags` to enrich alerts.** Adding descriptive tags to directory and registry entries (e.g., `tags="critical-config,pci-dss"`) makes downstream alert triage and SIEM correlation significantly faster.

**Test `ignore` rules with regex carefully.** The `sregex` type uses POSIX extended regex. Always validate patterns against real file paths before deploying to production to avoid accidentally suppressing genuine alerts.

---

## Troubleshooting

### No alerts are generated

- Confirm `<disabled>no</disabled>` in the agent's `ossec.conf`.
- Verify the agent is connected to the manager (`wazuh-agentd` service running, agent listed as active in the dashboard).
- Check that the monitored path exists on the agent.
- Confirm a baseline scan has run — new-file and modification alerts require a completed initial scan to have a baseline to compare against. Check agent logs (`/var/ossec/logs/ossec.log`) for `syscheck: INFO` messages indicating scan completion.

### Real-time monitoring not triggering

- Confirm `realtime="yes"` is set on a **directory**, not an individual file.
- On Linux, check that `inotify` watches are not exhausted: `cat /proc/sys/fs/inotify/max_user_watches`. Increase with `sysctl -w fs.inotify.max_user_watches=524288`.
- If using NFS or virtual filesystems, note that `realtime` does not work on those. Use scheduled scans instead.

### Who-data showing no user information

- On Linux with `ebpf`: verify the kernel version supports eBPF (4.4+ recommended; 5.x+ for full support). If unsupported, set `<provider>audit</provider>`.
- On Linux with `audit`: confirm `auditd` is installed and running. Check that `<startup_healthcheck>yes</startup_healthcheck>` did not report failures in the agent log.
- On Windows: verify that `whodata="yes"` is set and that the Windows agent has sufficient permissions to configure SACLs.

### High CPU usage during scans

- Increase `<process_priority>` (e.g., to `15` or `19`) to reduce scheduling weight.
- Use `<max_files_per_second>` to throttle scan throughput (e.g., `100`).
- Extend `<frequency>` to reduce scan frequency.
- Review monitored directories — remove any that are not security-relevant.

### `file_limit` warning in logs

- The agent log will show a database-capacity warning such as: File database is 100% full.
- Increase `<entries>` under `<file_limit>` to accommodate the actual monitored file count.
- Alternatively, narrow the monitored scope by adding `<ignore>` entries or reducing `recursion_level`.

### Diff not appearing in alerts

- Confirm `report_changes="yes"` is set on the directory.
- Check `<diff> <file_size> <limit>` — files larger than this will not produce diffs.
- Check `<diff> <disk_quota> <limit>` — if the diff folder has exceeded the disk quota, diffs are suppressed.
- Confirm the file is a text file (diff is not supported for binary files).

### Synchronization divergence after agent reinstall

- After reinstalling an agent, the FIM database is rebuilt from scratch. The `integrity_interval` mechanism will detect the mismatch and trigger a full reconciliation. Monitor `ossec.log` for sync-related messages. If persistent divergence is suspected, reset the agent's FIM database by stopping the agent, deleting `queue/fim/db/fim.db`, and restarting.

---

## Related Documentation

- [Wazuh FIM Overview](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)
- [Who-data Monitoring](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/auditing-whodata.html)
- [FIM Alerts Reference](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/fim-alerts.html)
- [agent.conf — Centralized Agent Configuration](https://documentation.wazuh.com/current/user-manual/reference/centralized-configuration.html)
- [Wazuh Rules Reference](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html)

# Rootcheck Architecture

This document describes the technical architecture and internal workings of the rootcheck module.

## Overview

Rootcheck is an agent-side anomaly detection module that performs periodic scans to identify potential security threats. In Wazuh 5.0, rootcheck operates in a **stateless mode**, meaning all detection happens on the agent and only alerts are sent to the manager without persistent storage.

## Architecture Diagram

```
┌──────────────────────────────────────────┐
│ Wazuh Agent                              │
│                                          │
│  wazuh-syscheckd                         │
│  ┌────────────────────────────────────┐  │
│  │ Rootcheck thread                   │  │
│  │  scan scheduler (frequency)        │  │
│  │   ├─ check_dev   (/dev files)      │  │
│  │   ├─ check_sys   (file system)     │  │
│  │   ├─ check_pids  (hidden PIDs)     │  │
│  │   ├─ check_ports (hidden ports)    │  │
│  │   └─ check_if    (promiscuous)     │  │
│  └──────────────┬─────────────────────┘  │
│                 │ local queue, queue '9',│
│                 │ location 'rootcheck'   │
│                 ▼                        │
│  wazuh-agentd                            │
└─────────────────┼────────────────────────┘
                  │ agent connection
                  ▼
┌──────────────────────────────────────────┐
│ Wazuh Manager                            │
│                                          │
│  wazuh-manager-remoted                   │
│                 │                        │
│                 ▼                        │
│  wazuh-manager-analysisd (engine)        │
│   decoder/wazuh-rootcheck/0              │
│                 │                        │
│                 ▼                        │
│  Wazuh indexer (wazuh-events-v5-security)│
│  and file outputs, if configured         │
└──────────────────────────────────────────┘
```

## Components

### 1. Scan Scheduler

**Responsibility:** Triggers rootcheck scans at configured intervals

**Operation:**
- Reads `frequency` configuration option
- Runs the first scan as soon as the module starts, then a new one once `frequency` seconds have passed since the previous scan ended
- Runs inside `wazuh-syscheckd`, in its own thread

**Default:** Every 12 hours (43200 seconds)

### 2. Detection Engines

Each detection engine runs independently and performs specific checks:

#### Hidden Process Detection Engine

**Method:**
1. Walk every PID from 1 up to the highest PID checked
2. For each PID, call multiple system functions:
   - `kill(pid, 0)` - Check whether the process exists
   - `getsid(pid)` - Get session ID
   - `getpgid(pid)` - Get process group ID
   - Compare results with `/proc/<pid>` (`stat`, `opendir`, read), where `/proc` exists
   - Compare with `ps -p <pid>`
3. If the answers disagree (a PID visible to some calls and not to others, or not visible in `/proc` or `ps`), trigger alert; threads are not reported. More than 15 hidden processes raise an "Excessive number of hidden processes" alert and end the check

**Detection Logic:**
```
if (pid exists in system call) AND (pid NOT in /proc or ps) {
    Alert: Hidden process detected
}
```

**Platform-specific:**
- **Linux:** Checks `/proc`; the highest PID checked is `rootcheck.max_pid` (see [Configuration](configuration.md#rootcheckmax_pid))
- **Other Unix systems:** The same probes, without `/proc` where it does not exist
- **Windows:** Not implemented

#### Hidden Port Detection Engine

**Method:**
1. Iterate through every TCP port and then every UDP port (0-65535); skipped when neither `ss` (Linux) nor `netstat` is available
2. For each port:
   - Attempt to bind using `bind()` system call
   - If the bind fails (port in use), check if port appears in `ss` or `netstat` output
   - If not, sleep `rootcheck.sleep` and re-check both
3. If bind still fails but port is still not in netstat, trigger alert (more than 20 hidden ports in one protocol raises an "Excessive number" alert and stops that protocol)

**Detection Logic:**
```
for port in 0..65535 {
    if (bind(port) == EADDRINUSE) AND (port NOT in netstat) {
        Alert: Hidden port detected
    }
}
```

**Optimization:**
- Sleeps before re-checking a suspicious port (configurable in internal options)
- Not implemented on Windows

#### File System Anomaly Detection Engine

**Checks performed:**

1. **Hidden Files Detection:**
   - A file listed by `readdir()` that `lstat()` cannot find
   - Compare the `stat()` size with the bytes read from the file (files under `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`, `/dev`, `/etc` and `/boot`, or every file with `readall`); if they differ, the file may be hidden

2. **Directory Entry Count:**
   - Count files with `opendir()` + `readdir()`
   - Compare with `stat.st_nlink`
   - Discrepancies indicate hidden files

3. **Unusual Permissions:**
   - Find world-writable regular files owned by root

**Scanned directories (Unix), under `base_directory`:**
```
/bin, /sbin, /usr/bin, /usr/sbin, /dev, /lib, /etc,
/root, /var/log, /var/mail, /var/lib, /var/www,
/usr/lib, /usr/include, /tmp, /boot, /usr/local,
/var/tmp, /sys
```

On Windows, `C:\WINDOWS` and `C:\Program Files`, where the only check is for NTFS alternate data streams. With `scanall`, the whole file system. `/proc`, `/sys` (when reached
from `/`) and the `<ignore>` entries are skipped.

#### Device Directory Scan Engine

**Target:** `/dev` directory

**Method:**
1. Walk `/dev` (under `base_dir`) recursively; directories are descended into, not reported
2. Skip known benign names (for example `MAKEDEV`, `.udev`, `fd`, `cgroup`, `oprofile`) and the paths `shm`, `shm/sysconfig`, `bus/usb/.usbfs` and `gpmctl` directly under `/dev`, so nothing below `/dev/shm` is reported
3. Skip paths matched by a configured `<ignore>`
4. Report every remaining **regular file**; device nodes, sockets, symlinks and other special files are not reported

**Detection Logic:**
```
for entry in walk(/dev) {
    if ignored(entry) { continue }
    if is_directory(entry) { recurse }
    else if is_regular_file(entry) {
        Alert: File '<path>' present on /dev. Possible hidden file.
    }
}
```

#### Promiscuous Mode Detection Engine

**Method:**
1. Enumerate all network interfaces
2. For each interface:
   - Check interface flags using `ioctl(SIOCGIFFLAGS)`
   - Look for `IFF_PROMISC` flag
3. Trigger alert if promiscuous mode detected

**Detection Logic:**
```
for interface in network_interfaces {
    flags = ioctl(interface, SIOCGIFFLAGS)
    if (flags & IFF_PROMISC) {
        Alert: Interface in promiscuous mode
    }
}
```

### 3. Alert Generator

**Responsibility:** Send detection results as messages

**Process:**
1. Each check builds a plain-text message with the detection details (PID, port number, file path, etc.)
2. Detections, and the `Starting rootcheck scan.` and `Ending rootcheck scan.` markers, are sent; the per-check "no problem found" summaries are not
3. The message is written to the agent's local queue with queue `9` and location `rootcheck`

**Message example:**
```
File '/dev/e2etest' present on /dev. Possible hidden file.
```

Every message the agent sends is listed in [Output Samples](output-samples.md).

### 4. Agent Communication

**Mechanism:** Uses standard Wazuh agent communication channel

**Flow:**
1. Rootcheck writes the message to the agent's local queue
2. `wazuh-agentd` forwards it to the manager over the agent connection
3. The manager's engine (`wazuh-manager-analysisd`) decodes it

**No Database Persistence (5.0 Change):**
- Alerts are processed and logged but not stored in manager database
- Historical rootcheck data is not retained
- Each scan is independent

## State Management

### Agent-Side

**No Persistent State (5.0):**
- Each scan runs independently
- No tracking of previous scan results
- No local database for rootcheck data

**Temporary State:**
- In-memory tracking during active scan
- Cleared after scan completes

### Manager-Side

**No Persistent State (5.0):**
- Events processed by the engine (`wazuh-manager-analysisd`)
- Sent to the Wazuh indexer, and to a file under `/var/wazuh-manager/logs/<channel>/` only when a policy has a `file` output
- Not stored in wazuh-manager-db

## Performance Characteristics

The file system check (`check_sys`) and the port check (`check_ports`, which tries to bind 131072 TCP and UDP ports)
are the most expensive; `check_dev` and `check_if` are fast. The duration depends on the number of files and
processes on the host.

### Optimization Techniques

1. **Sleep intervals:** Between checks to reduce CPU load
2. **Skip network mounts:** Avoid scanning NFS/CIFS
3. **Ignore patterns:** Skip known benign paths
4. **Selective checks:** Disable unnecessary detection types

## Security Considerations

### Evasion Techniques

Rootcheck is designed to detect common evasion techniques:

1. **Process Hiding:**
   - Detects kernel-level rootkits that hide processes from some system calls
   - Identifies trojaned userland tools (`ps`)
   - Cross-references multiple data sources

2. **Port Hiding:**
   - Direct system call binding vs. netstat comparison
   - Difficult to hide from both simultaneously

3. **File Hiding:**
   - Multiple verification methods
   - Stat vs. read size comparison
   - Directory entry count verification

### Limitations

1. **Kernel-Level Rootkits:**
   - Very sophisticated rootkits can evade detection if they hook all system calls
   - Rootcheck runs in userspace and relies on kernel honesty

2. **Timing Attacks:**
   - Malware can detect scan timing and hide temporarily
   - Randomizing scan times (not currently supported) could help

3. **Performance Impact:**
   - Complete evasion detection requires expensive checks
   - Trade-off between detection coverage and performance

## Integration with Other Modules

### File Integrity Monitoring (FIM)

- Complementary capabilities
- FIM monitors specific files/directories continuously
- Rootcheck performs system-wide anomaly scans
- Together provide comprehensive file monitoring

### Security Configuration Assessment (SCA)

- SCA focuses on configuration compliance
- Rootcheck focuses on runtime behavior
- SCA replaced rootcheck's policy checking (removed in 5.0)

### Syscollector

- Syscollector provides system inventory
- Can help contextualize rootcheck alerts
- Process list from syscollector can supplement rootcheck data

## Event Flow

### Complete Detection Flow

```
1. Scan Trigger (frequency or agent restart)
         ↓
2. Execute Enabled Checks, one after another
   - check_dev
   - check_sys
   - check_pids
   - check_ports
   - check_if
         ↓
3. Anomaly Detected?
   NO → End scan
   YES → Continue
         ↓
4. Format Alert Message
         ↓
5. Send to the local queue; wazuh-agentd forwards it
         ↓
6. Manager analysisd receives
         ↓
7. Decode rootcheck message (decoder/wazuh-rootcheck/0)
         ↓
8. Normalize to ECS fields (event.*, file.*, threat.indicator.*)
         ↓
9. Send to the indexer (and file outputs, if configured)
```

### Alert Processing on Manager

The engine has no rules: `decoder/core-wazuh-message/0` and then `decoder/wazuh-rootcheck/0` (from the content the
manager synchronizes) decode each rootcheck message into an event of the `wazuh-rootcheck` integration, which is
indexed in the `wazuh-events-v5-security` data stream. Event shapes and fields: [Output Samples](output-samples.md).
Nothing is stored in a manager database, unlike pre-5.0 versions.

## Changes in Wazuh 5.0

### Architectural Changes

| Aspect | Pre-5.0 | 5.0+ |
|--------|---------|------|
| **Manager Database** | pm_event table stored all results | No database storage |
| **File Signatures** | rootkit_files.txt checked | Signature checking removed |
| **Trojan Signatures** | rootkit_trojans.txt checked | Signature checking removed |
| **Policy Checking** | system_audit_*.txt processed | Policy checking removed |
| **State** | Stateful (stored history) | Stateless (alerts only) |
| **API Endpoints** | `/rootcheck` endpoints | None |

### Rationale for Changes

1. **Performance:** Stateless operation reduces manager overhead
2. **Simplicity:** Clearer separation of concerns
3. **Overlap:** SCA provides better policy checking
4. **Maintenance:** Signature files difficult to maintain

### Migration Impact

- The Server API has no rootcheck endpoints
- Historical rootcheck data not migrated
- Configuration remains compatible (deprecated options ignored)

## Internal Options

`rootcheck.sleep` and `rootcheck.max_pid` tune the hidden process and hidden port checks. They are described in
[Configuration](configuration.md#internal-options); set them in `local_internal_options.conf`.

## Debugging

Enable verbose logging:

```bash
# Add to local_internal_options.conf. Rootcheck runs inside wazuh-syscheckd, so its
# debug level is syscheck.debug (0-2); there is no rootcheck.debug key.
syscheck.debug=2

# Restart agent
/var/ossec/bin/wazuh-control restart
```

Check rootcheck-specific logs:
```bash
grep rootcheck /var/ossec/logs/ossec.log
```

## See Also

- [Configuration](configuration.md) - Configuration options and examples
- [Output Samples](output-samples.md) - Alert examples and formats
- [README](README.md) - Module overview and quick start

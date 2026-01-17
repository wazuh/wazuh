# Rootcheck Architecture

This document describes the technical architecture and internal workings of the rootcheck module.

## Overview

Rootcheck is an agent-side anomaly detection module that performs periodic scans to identify potential security threats. In Wazuh 5.0, rootcheck operates in a **stateless mode**, meaning all detection happens on the agent and only alerts are sent to the manager without persistent storage.

## Architecture Diagram

```
┌─────────────────────────────────────────┐
│           Wazuh Agent                    │
│                                          │
│  ┌────────────────────────────────────┐ │
│  │     Rootcheck Module               │ │
│  │                                    │ │
│  │  ┌──────────────────────────────┐ │ │
│  │  │   Scan Scheduler             │ │ │
│  │  │   (frequency-based)          │ │ │
│  │  └──────────┬───────────────────┘ │ │
│  │             │                      │ │
│  │             ├─────────────────┐    │ │
│  │             ▼                 ▼    │ │
│  │  ┌──────────────┐   ┌────────────┐│ │
│  │  │   Detection  │   │  Detection ││ │
│  │  │   Engines    │   │   Engines  ││ │
│  │  └──────────────┘   └────────────┘│ │
│  │     │   │   │   │        │        │ │
│  │     ▼   ▼   ▼   ▼        ▼        │ │
│  │  ┌─────────────────────────────┐  │ │
│  │  │  • Hidden Process Check     │  │ │
│  │  │  • Hidden Port Check        │  │ │
│  │  │  • File System Anomalies    │  │ │
│  │  │  • Device Directory Scan    │  │ │
│  │  │  • Promiscuous Mode Check   │  │ │
│  │  └───────────┬─────────────────┘  │ │
│  │              │                     │ │
│  │              ▼                     │ │
│  │  ┌──────────────────────────────┐ │ │
│  │  │    Alert Generator           │ │ │
│  │  └──────────┬───────────────────┘ │ │
│  └─────────────┼─────────────────────┘ │
│                │                        │
│                ▼                        │
│  ┌──────────────────────────────────┐  │
│  │    Agent Communication           │  │
│  │    (logcollector)                │  │
│  └──────────┬───────────────────────┘  │
└─────────────┼──────────────────────────┘
              │
              │ (Real-time alerts only)
              ▼
┌─────────────────────────────────────────┐
│          Wazuh Manager                   │
│                                          │
│  ┌────────────────────────────────────┐ │
│  │      analysisd                     │ │
│  │  (Processes rootcheck alerts)      │ │
│  └────────────┬───────────────────────┘ │
│               │                          │
│               ▼                          │
│  ┌────────────────────────────────────┐ │
│  │   Rules Engine                     │ │
│  │   (Matches against rootcheck rules)│ │
│  └────────────┬───────────────────────┘ │
│               │                          │
│               ▼                          │
│  ┌────────────────────────────────────┐ │
│  │   Alert Logs & Indexer             │ │
│  │   (alerts.log, alerts.json)        │ │
│  └────────────────────────────────────┘ │
└──────────────────────────────────────────┘
```

## Components

### 1. Scan Scheduler

**Responsibility:** Triggers rootcheck scans at configured intervals

**Operation:**
- Reads `frequency` configuration option
- Schedules periodic scans
- Can be triggered immediately on agent restart

**Default:** Every 12 hours (43200 seconds)

### 2. Detection Engines

Each detection engine runs independently and performs specific checks:

#### Hidden Process Detection Engine

**Method:**
1. Enumerate all PIDs in the system
2. For each PID, call multiple system functions:
   - `getsid(pid)` - Get session ID
   - `getpgid(pid)` - Get process group ID
   - Compare results with `/proc` directory entries (Linux)
   - Compare with process listing tools output
3. If a PID exists but is not visible in `/proc` or process lists, trigger alert

**Detection Logic:**
```
if (pid exists in system call) AND (pid NOT in /proc or ps) {
    Alert: Hidden process detected
}
```

**Platform-specific:**
- **Linux:** Checks `/proc` filesystem
- **Windows:** Uses Windows API calls (OpenProcess, EnumProcesses)
- **macOS/BSD:** Uses `sysctl` and `kvm` interfaces

#### Hidden Port Detection Engine

**Method:**
1. Iterate through all possible ports (1-65535)
2. For each port:
   - Attempt to bind using `bind()` system call
   - Check if port appears in `netstat` output
   - Compare results
3. If bind fails (port in use) but port not in netstat, trigger alert

**Detection Logic:**
```
for port in 1..65535 {
    if (bind(port) == EADDRINUSE) AND (port NOT in netstat) {
        Alert: Hidden port detected
    }
}
```

**Optimization:**
- Sleeps between checks to reduce CPU usage (configurable in internal options)
- Skip reserved/privileged ports if running as non-root

#### File System Anomaly Detection Engine

**Checks performed:**

1. **Hidden Files Detection:**
   - Compare `stat()` results with `fopen()` + `read()`
   - If sizes don't match, file may be hidden

2. **Directory Entry Count:**
   - Count files with `opendir()` + `readdir()`
   - Compare with `stat.st_nlink`
   - Discrepancies indicate hidden files

3. **Unusual Permissions:**
   - Find world-writable files owned by root
   - Find SUID/SGID files
   - Detect unusual permission combinations

4. **File Attributes:**
   - Check for immutable flags
   - Verify file ownership patterns

**Scanned directories (Unix):**
```
/bin, /sbin, /usr/bin, /usr/sbin, /dev, /lib, /etc,
/root, /var/log, /var/mail, /var/lib, /var/www,
/usr/lib, /usr/include, /tmp, /boot, /usr/local,
/var/tmp, /sys
```

#### Device Directory Scan Engine

**Target:** `/dev` directory

**Method:**
1. Enumerate all files in `/dev`
2. For each file:
   - Check if it's a character or block device (expected)
   - Check if it's a regular file or directory (suspicious)
   - Verify naming patterns
3. Trigger alert for non-device files

**Detection Logic:**
```
for file in /dev/* {
    if NOT (is_character_device OR is_block_device) {
        Alert: Suspicious file in /dev
    }
}
```

#### Promiscuous Mode Detection Engine

**Method:**
1. Enumerate all network interfaces
2. For each interface:
   - Check interface flags using `ioctl(SIOCGIFFLAGS)`
   - Look for `IFF_PROMISC` flag
   - Parse `ifconfig` output as secondary check
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

**Responsibility:** Format and send detection results as alerts

**Process:**
1. Receive detection result from engine
2. Format alert message with:
   - Alert type (hidden process, port, file, etc.)
   - Detection details (PID, port number, file path, etc.)
   - Timestamp
3. Send to agent communication layer

**Alert Format:**
```
ossec: output: 'rootcheck' message: <detection_details>
```

### 4. Agent Communication

**Mechanism:** Uses standard Wazuh agent communication channel

**Flow:**
1. Rootcheck generates alert
2. Alert sent to logcollector component
3. logcollector forwards to manager via encrypted connection
4. Manager's analysisd receives and processes alert

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
- Alerts processed through rules engine
- Logged to `alerts.log` and `alerts.json`
- Not stored in wazuh-db
- No `/rootcheck` API data persistence

## Performance Characteristics

### Resource Usage

| Resource | Usage Level | Notes |
|----------|-------------|-------|
| **CPU** | Moderate during scan | Spikes during port scanning and file system checks |
| **Memory** | Low | Minimal state, streaming processing |
| **Disk I/O** | Moderate | File system scanning |
| **Network** | Minimal | Only sends alerts (a few KB per scan typically) |

### Scan Duration

Typical scan durations (varies by system):

| Check Type | Duration |
|------------|----------|
| Hidden processes | 1-5 seconds |
| Hidden ports | 30-60 seconds (full port range) |
| File system anomalies | 2-10 minutes (depends on file count) |
| Device directory | <1 second |
| Promiscuous mode | <1 second |

**Total:** 2-15 minutes for complete scan

### Optimization Techniques

1. **Sleep intervals:** Between checks to reduce CPU load
2. **Skip network mounts:** Avoid scanning NFS/CIFS
3. **Ignore patterns:** Skip known benign paths
4. **Selective checks:** Disable unnecessary detection types

## Security Considerations

### Evasion Techniques

Rootcheck is designed to detect common evasion techniques:

1. **Process Hiding:**
   - Detects kernel-level rootkits (e.g., Diamorphine)
   - Identifies trojaned userland tools
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
2. Execute Enabled Checks (parallel)
   - check_pids
   - check_ports
   - check_sys
   - check_dev
   - check_if
         ↓
3. Anomaly Detected?
   NO → End scan
   YES → Continue
         ↓
4. Format Alert Message
         ↓
5. Send via logcollector
         ↓
6. Manager analysisd receives
         ↓
7. Decode rootcheck message
         ↓
8. Match against rules (50x series)
         ↓
9. Generate indexed alert
         ↓
10. Store in alerts.log, alerts.json, indexer
```

### Alert Processing on Manager

Rootcheck alerts are processed by rules in the 510-550 range:

- **Rule 510:** Generic rootcheck alert
- **Rule 51x:** Specific detection types
- **No database storage:** Unlike pre-5.0 versions

## Changes in Wazuh 5.0

### Architectural Changes

| Aspect | Pre-5.0 | 5.0+ |
|--------|---------|------|
| **Manager Database** | pm_event table stored all results | No database storage |
| **File Signatures** | rootkit_files.txt checked | Signature checking removed |
| **Trojan Signatures** | rootkit_trojans.txt checked | Signature checking removed |
| **Policy Checking** | system_audit_*.txt processed | Policy checking removed |
| **State** | Stateful (stored history) | Stateless (alerts only) |
| **API Endpoints** | Full CRUD operations | Limited (no historical data) |

### Rationale for Changes

1. **Performance:** Stateless operation reduces manager overhead
2. **Simplicity:** Clearer separation of concerns
3. **Overlap:** SCA provides better policy checking
4. **Maintenance:** Signature files difficult to maintain

### Migration Impact

- Existing rootcheck queries against API return limited data
- Historical rootcheck data not migrated
- Configuration remains compatible (deprecated options ignored)

## Internal Options

Advanced tuning via `/var/ossec/etc/internal_options.conf`:

```
# rootcheck.sleep
# Number of milliseconds to sleep between PID/port checks
# Lower = faster but higher CPU
# Default: 50
rootcheck.sleep=50
```

## Debugging

Enable verbose logging:

```bash
# Add to internal_options.conf
rootcheck.debug=2

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

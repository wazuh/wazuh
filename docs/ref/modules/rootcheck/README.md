# Rootcheck Module

The **Rootcheck** module performs anomaly and behavior-based detection on monitored endpoints to identify potential security threats. It focuses on detecting hidden processes, hidden network ports, unusual file system objects, and network interfaces operating in promiscuous mode.

> **Important Changes in Wazuh 5.0:**
> Starting in version 5.0, rootcheck no longer performs signature-based detection of rootkit files and trojans, nor does it support policy checking capabilities. The manager also no longer persists rootcheck data in a database. Rootcheck now operates in a stateless mode, sending real-time alerts without server-side storage.
>
> For policy and configuration assessment, use the [Security Configuration Assessment (SCA)](../sca/README.md) module instead.

## Overview

Rootcheck operates by inspecting system internals using various techniques to detect anomalies that may indicate malware presence. Unlike signature-based detection, rootcheck focuses on behavioral patterns and system inconsistencies that malicious software commonly exploits.

### Key Features

- **Hidden Process Detection**: Identifies processes hidden from standard process listing tools
- **Hidden Port Detection**: Detects network ports not visible in standard network status commands
- **File System Anomaly Detection**: Identifies unusual files, permissions, and hidden files
- **Device Directory Monitoring**: Scans `/dev` directory for suspicious files
- **Network Interface Monitoring**: Detects interfaces running in promiscuous mode
- **System Integrity Checks**: Compares system call results to detect discrepancies
- **Stateless Operation**: Sends real-time alerts without persistent storage on the manager

### How It Works

1. **Periodic Scanning**: Rootcheck runs a first scan when the agent starts and then every `frequency` seconds (default: every 12 hours)
2. **Anomaly Detection**: Performs various system checks based on enabled options
3. **Real-time Alerting**: Generates alerts immediately when anomalies are detected
4. **Agent-side Only**: All detection occurs on the agent, inside `wazuh-syscheckd`; manager receives alerts only

## Quick Start

### Basic Configuration

Add to your agent's `ossec.conf`. Rootcheck runs only when the agent's configuration has a `<rootcheck>` section; the
shipped configuration has one:

```xml
<rootcheck>
  <disabled>no</disabled>

  <!-- Anomaly detection checks -->
  <check_dev>yes</check_dev>
  <check_sys>yes</check_sys>
  <check_pids>yes</check_pids>
  <check_ports>yes</check_ports>
  <check_if>yes</check_if>

  <!-- Scan frequency - every 12 hours -->
  <frequency>43200</frequency>

  <!-- Skip network mounted filesystems -->
  <skip_nfs>yes</skip_nfs>
</rootcheck>
```

### Verify Operation

Check that rootcheck is running: each scan logs `Starting rootcheck scan.` and `Rootcheck scan ended.` under the
`wazuh-rootcheck` tag.
```bash
grep rootcheck /var/ossec/logs/ossec.log
```

Force an immediate scan (the first scan runs as soon as the agent starts):
```bash
/var/ossec/bin/wazuh-control restart
```

## Detection Capabilities

### Hidden Processes

Rootcheck probes every process ID (PID), on Linux up to [`rootcheck.max_pid`](configuration.md#rootcheckmax_pid), with `kill(pid, 0)`, `getsid` and `getpgid`, and compares the answers with `/proc` and with `ps`, looking for discrepancies. Malware can hide processes from tools like `ps` by replacing them with trojaned versions or using kernel-level rootkits.

### Hidden Ports

Scans every TCP and UDP port using the `bind()` system call. If a port cannot be bound and doesn't appear in the output of `ss` (Linux) or `netstat`, it may indicate hidden malware using that port for communication. The check is skipped when neither tool is available.

### File System Anomalies

- Identifies world-writable files owned by root
- Detects hidden files: a file listed by `readdir()` that `lstat()` cannot find, or a directory whose link count does not match its entries
- Compares each file's `stat` size with the bytes read from it, for the files under `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`, `/dev`, `/etc` and `/boot`, or for every file with [`readall`](configuration.md#readall)

### Device Directory (`/dev`)

The `/dev` directory should only contain device-specific files. Rootcheck inspects all files here because malware may use this location to hide files.

### Promiscuous Mode Detection

Scans network interfaces for promiscuous mode, which allows capturing all network traffic. This mode is often enabled by malware for packet sniffing.

## Supported Platforms

| Platform | Hidden Processes | Hidden Ports | File System | Device Scan | Promiscuous |
|----------|------------------|--------------|-------------|-------------|-------------|
| Linux    | ✓                | ✓            | ✓           | ✓           | ✓           |
| Windows  | —                | —            | ✓           | N/A         | —           |
| macOS    | ✓                | ✓            | ✓           | ✓           | ✓           |
| BSD      | ✓                | ✓            | ✓           | ✓           | ✓           |

On Windows only the file system check runs, over `C:\WINDOWS` and `C:\Program Files`, and it looks only for NTFS
alternate data streams.

## Documentation

| Document | Description |
|----------|-------------|
| [Configuration](configuration.md) | Complete configuration options and examples |
| [Architecture](architecture.md) | Technical architecture and detection methods |
| [Output Samples](output-samples.md) | Alert formats and examples |

## Migration from Deprecated Features

If you were using rootcheck features removed in Wazuh 5.0, here are the recommended alternatives:

| Removed Feature | Alternative Solution |
|----------------|---------------------|
| **File check** (rootkit_files.txt) | Use [FIM](../fim/README.md) |
| **Trojan scan** (rootkit_trojans.txt) | Use [FIM](../fim/README.md) |
| **Policy check** (system_audit_*.txt) | Use [SCA](../sca/README.md) module with YAML policies |

## Related Modules

- **[Security Configuration Assessment (SCA)](../sca/README.md)**: Policy and configuration compliance checking
- **[File Integrity Monitoring (FIM)](../fim/README.md)**: Monitor file changes and detect malicious files
- **[Syscollector](../syscollector/README.md)**: System inventory and change detection

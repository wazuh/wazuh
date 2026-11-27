# Syscollector

The **Syscollector** module collects system inventory information from Wazuh agents and detects changes in system state over time. The module has been enhanced with a reliable synchronization mechanism that ensures system inventory changes are persisted and synchronized with the manager even during network interruptions or agent restarts.

The module implements a **dual event system** that provides both real-time alerts and reliable state synchronization. It leverages the **Agent Sync Protocol** to persist differences in a local SQLite database and synchronizes them periodically with the manager through a session-based protocol.

Syscollector persistence supports **stateful synchronization** for complete system inventory including hardware, OS, network, packages, ports, processes, users, groups, services, and browser extensions, while maintaining **stateless real-time events** for immediate inventory change detection.

> **Note:** Vulnerability detection runs on the manager. Syscollector sends the OS, packages and hotfixes tables, which feed it, through a second sync protocol instance of its own (`syscollector_vd`); see [Architecture](architecture.md).

## Overview

Syscollector performs periodic scans to gather inventory data and only sends changes to the Wazuh manager, providing efficient monitoring of system state across your infrastructure.

### Key Features

- **Comprehensive Inventory**: Collects hardware, OS, packages, network, processes, users, services, and browser extensions
- **Change Detection**: Only reports modifications, not full inventory
- **Cross-Platform**: Full inventory on Linux, macOS and Windows; partial on other Unix builds (see [Inventory Categories](#inventory-categories))
- **Configurable**: Flexible scan intervals and component selection
- **Local Storage**: SQLite database for change detection and state persistence
- **Document Limits**: Manager-controlled limits on synchronized items per inventory type to optimize resource consumption
- **Automatic Data Cleanup**: When individual collectors (packages, OS, hotfixes, etc.) are disabled, Syscollector automatically notifies the manager and cleans up associated data

### How It Works

1. **Periodic Scanning**: Collects current system inventory based on configured interval
2. **Change Detection**: Compares with previous scan stored in local SQLite database
3. **Delta Events**: Generates events only for changes (additions, modifications, deletions)
4. **Event Transmission**: Sends inventory events to manager for processing and indexing

## Inventory Categories

| Category | Description | Platforms |
|----------|-------------|-----------|
| **Hardware** | CPU, memory and serial number | Linux, macOS, Windows |
| **Operating System** | OS version, kernel, architecture | Linux, macOS, Windows |
| **Packages** | Installed software and applications | Linux, macOS, Windows |
| **Network Interfaces** | Network configuration and traffic stats | Linux, macOS, Windows |
| **Network Addresses** | IP addresses and network settings | Linux, macOS, Windows |
| **Network Protocols** | Per-interface protocol settings (DHCP, gateway, metric) | Linux, macOS, Windows |
| **Ports** | Open network ports and listening services | Linux, macOS, Windows |
| **Processes** | Running processes and resource usage | Linux, macOS, Windows |
| **Users** | System user accounts and properties | Linux, macOS, Windows |
| **Groups** | System groups and membership | Linux, macOS, Windows |
| **Services** | System services and their status | Linux, macOS, Windows |
| **Browser Extensions** | Installed browser add-ons | Linux, macOS, Windows |
| **Hotfixes** | Windows updates and patches | Windows only |

Agent builds for other systems collect less: FreeBSD collects hardware, OS, network and packages; OpenBSD hardware, OS and network; any other Unix hardware and OS only. The remaining categories return no data there.

## Quick Start

### Basic Configuration

Add to your agent's `ossec.conf`:

```xml
<wodle name="syscollector">
    <disabled>no</disabled>
    <interval>1h</interval>
    <scan_on_start>yes</scan_on_start>

    <!-- Enable inventory categories -->
    <hardware>yes</hardware>
    <os>yes</os>
    <network>yes</network>
    <packages>yes</packages>
    <ports>yes</ports>
    <processes>yes</processes>
    <users>yes</users>
    <groups>yes</groups>
    <services>yes</services>
    <browser_extensions>yes</browser_extensions>
    <hotfixes>yes</hotfixes> <!-- Windows only -->
</wodle>
```

### Verify Operation

Check that syscollector is running:
```bash
grep syscollector /var/ossec/logs/ossec.log
```

## Documentation

| Document | Description |
|----------|-------------|
| [Configuration](configuration.md) | Complete configuration options and examples |
| [Architecture](architecture.md) | Technical architecture and data flow |
| [Events](events.md) | Event formats and field reference |
| [Database Schema](database-schema.md) | Local SQLite database structure |
| [API Reference](api-reference.md) | Internal APIs and integration details |

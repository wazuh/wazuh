# Syscollector

The **Syscollector** module collects system inventory information from Wazuh agents and detects changes in system state over time.

## Overview

Syscollector performs periodic scans to gather inventory data and only sends changes to the Wazuh manager, providing efficient monitoring of system state across your infrastructure.

### Key Features

- **Comprehensive Inventory**: Collects hardware, OS, packages, network, processes, users, services, and browser extensions
- **Change Detection**: Only reports modifications, not full inventory
- **Cross-Platform**: Supports Windows, Linux, macOS, and Unix systems
- **Configurable**: Flexible scan intervals and component selection
- **Local Storage**: SQLite database for change detection and state persistence

### How It Works

1. **Periodic Scanning**: Collects current system inventory based on configured interval
2. **Change Detection**: Compares with previous scan stored in local SQLite database
3. **Delta Events**: Generates events only for changes (additions, modifications, deletions)
4. **Event Transmission**: Sends inventory events to manager for processing and indexing

## Inventory Categories

| Category | Description | Platforms |
|----------|-------------|-----------|
| **Hardware** | CPU, memory, storage specifications | All |
| **Operating System** | OS version, kernel, architecture | All |
| **Packages** | Installed software and applications | All |
| **Network Interfaces** | Network configuration and traffic stats | All |
| **Network Addresses** | IP addresses and network settings | All |
| **Network Protocols** | Protocol configuration (DHCP, routes) | All |
| **Ports** | Open network ports and listening services | All |
| **Processes** | Running processes and resource usage | All |
| **Users** | System user accounts and properties | All |
| **Groups** | System groups and membership | All |
| **Services** | System services and their status | All |
| **Browser Extensions** | Installed browser add-ons | All |
| **Hotfixes** | Windows updates and patches | Windows only |

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
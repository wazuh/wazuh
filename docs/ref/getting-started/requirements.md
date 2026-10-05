# Requirements

## Server

### Operating System Requirements

The following operating systems are recommended for Wazuh 5.x:

- Amazon Linux 2023
- Ubuntu 22.04, 24.04
- Red Hat Enterprise Linux 9, 10

### Hardware Requirements

#### Minimum Specifications

- **CPU**: 4 cores
- **RAM**: 8 GB

#### Storage Requirements

Disk space requirements depend on:
- Alert generation rate
- Retention period (days of storage)

The storage capacity should be calculated based on your expected alert volume and desired retention policy.

## Agent

### Operating System Requirements

The agent supports a wider set of operating systems and architectures than the server, including Windows and macOS. See [Packages](packages.md#agent) for the full list.

### Hardware Requirements

#### Minimum Specifications

- **CPU**: 1 core
- **RAM**: 128 MB available for the agent
- **Disk**: 200 MB

#### Measured Usage

Usage measured with the default configuration on an Ubuntu 24.04 server VM (1 CPU, 2 GB of RAM) and a Windows 11 VM (2 CPUs, 4 GB of RAM):

| Resource | Linux | Windows |
| -------- | ----- | ------- |
| CPU | Under 1% when idle. Up to half a core for about a minute during the startup scans | Under 1% when idle. Up to two cores for a few minutes during the startup scans |
| RAM | About 60 MB | About 40 MB during the startup scans, 25 MB when idle |
| Disk | About 50 MB | About 50 MB |

Usage grows with the monitored content (directories under file integrity monitoring, installed packages, log volume) and with the modules enabled.

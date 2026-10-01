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

The agent has no dedicated hardware requirements. It runs on the monitored endpoint with a small footprint; actual CPU, memory and disk usage depend on the modules enabled and on the endpoint's activity.

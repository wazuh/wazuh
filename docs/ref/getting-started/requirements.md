# Requirements

## Server

### Operating System Requirements

The following operating systems are recommended for Wazuh 5.x:

- Amazon Linux 2023
- Ubuntu 24.04, 26.04
- Red Hat Enterprise Linux 9, 10

### Hardware Requirements

#### Minimum Specifications

- **CPU**: 4 cores
- **RAM**: 8 GB

#### Storage Requirements

Right after installation, before any agent connects, each manager node takes about 8 GB under `/var/wazuh-manager` (measured on 5.0.0 with the default configuration). Almost all of it is the vulnerability detection feed in `queue/vd/feed`, about 7.6 GB: every node downloads its own copy from the indexer once the indexer's vulnerability feed is ready, and it grows as the feed does. Count it on top of the operating system and keep free space for logs and agent data.

Beyond that baseline, disk space requirements depend on:
- Alert generation rate
- Retention period (days of storage)

The storage capacity should be calculated based on your expected alert volume and desired retention policy.

#### All-in-one hosts

The minimum specifications are for the manager alone. When the indexer (and the dashboard) run on the
same host, size the host for all of them: the indexer's memory comes on top of the manager's, and its
heap must be large enough for the content the manager downloads from it. On a host with about 8 GB of
RAM, the indexer's default 1 GB heap was observed to trip its circuit breaker: the indexer answers `429`
to the manager's content requests, some indicator-of-compromise types never finish loading into the engine, and
the engine and the node keep reporting `ready: false`. Give the indexer a larger heap and the host the
memory for it, following the indexer's own sizing guidance; the manager log shows the
`Indexer node '<host>' is throttling requests` warning (see the
[indexer connector](../modules/indexer_connector/configuration.md)) while it lasts.

The manager does not monitor its own host. To monitor it, install an agent on it (see [Monitoring the server host](installation.md#monitoring-the-server-host)) and add the agent usage below.

## Agent

### Operating System Requirements

The agent supports a wider set of operating systems and architectures than the server, including Windows and macOS. See [Packages](packages.md#agent) for the full list.

### Hardware Requirements

#### Minimum Specifications

- **CPU**: 1 core
- **RAM**: 1 GB
- **Disk**: 10 GB

#### Measured Usage

Usage measured with the default configuration on an Ubuntu 24.04 server VM (1 CPU, 2 GB of RAM) and a Windows 11 VM (2 CPUs, 4 GB of RAM):

| Resource | Linux | Windows |
| -------- | ----- | ------- |
| CPU | Under 1% when idle. Up to half a core for about a minute during the startup scans | Under 1% when idle. Up to two cores for a few minutes during the startup scans |
| RAM | About 60 MB | About 40 MB during the startup scans, 25 MB when idle |
| Disk | About 50 MB | About 50 MB |

Usage grows with the monitored content (directories under file integrity monitoring, installed packages, log volume) and with the modules enabled. The minimum specifications leave headroom for high load and for logs, which keep growing as they rotate.

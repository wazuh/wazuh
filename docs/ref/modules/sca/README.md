# Security Configuration Assessment (SCA) Module

## Introduction

The **SCA** module (Security Configuration Assessment) is responsible for assessing the security posture of the system by evaluating it against predefined policies. These policies are written in YAML and contain rules that check system configuration, permissions, and the presence or absence of specific files, commands, or settings.

The module implements a **dual event system** that provides both real-time alerts and reliable state synchronization. It leverages the **Agent Sync Protocol** to persist differences in a local SQLite database and synchronizes them periodically with the manager through a session-based protocol.

SCA persistence supports **stateful synchronization** for complete security check metadata including results and compliance mapping, while maintaining **stateless real-time alerts** for immediate threat detection.

SCA includes **automatic recovery capabilities** to detect and resolve synchronization inconsistencies between agent and manager databases. Recovery is triggered automatically during a periodic synchronization cycle determined by the `integrity_interval` option.

## Configuration

```xml
<sca>
  <enabled>yes</enabled>
  <scan_on_start>yes</scan_on_start>
  <interval>1h</interval>
  <policies>
    <policy>etc/shared/cis_debian10.yml</policy>
    <policy>/my/custom/policy/path/my_policy.yaml</policy>
    <policy enabled="no">ruleset/sca/cis_debian9.yml</policy>
  </policies>
</sca>
```

| Mandatory | Option              | Description                                                                 | Default |
| :-------: | ------------------- | --------------------------------------------------------------------------- | ------- |
|           | `enabled`           | Enables or disables the SCA module                                          | yes     |
|           | `scan_on_start`     | Runs an assessment as soon as the agent starts                              | yes     |
|           | `interval`          | Time between scans (uses scheduling tags)                                   | —       |
|           | `policies`          | Section containing policy file configurations                                | auto-loaded |
|           | `policy`            | Individual policy file path (can use `enabled="no"` attribute)              | —       |

## Policy Files

Each policy file is a YAML file defining checks (rules) grouped by sections and metadata. These rules are executed during the scan, and the results are stored for reporting and compliance auditing.

## Key Features

- **Policy-based scanning**: Support for CIS benchmarks and custom policies
- **Multiple rule types**: File, command, registry, directory, and process checks
- **Conditional evaluation**: Complex logic with `all`, `any`, and `none` conditions
- **Compliance mapping**: Built-in support for CIS, NIST, and other standards
- **Result persistence**: Local database storage with reliable synchronization
- **Dual event system**: Stateful events for synchronization and stateless for real-time alerts

## Document Limits (Internal)

The manager can provide an internal **sync limit** during the SCA synchronization handshake. When enabled, the agent
keeps the full local SCA state but synchronizes only the first **N** stateful documents (FIFO order). A limit of `0`
or an unset value means **unlimited** synchronization.

Important behavior:
- The limit applies **only** to stateful SCA documents sent to the indexer.
- **Stateless** real-time SCA alerts are still generated for the **full** local state.
- This is an **internal manager setting** and is not a user-facing configuration option.

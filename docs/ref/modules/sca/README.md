# Security Configuration Assessment (SCA) Module

## Introduction

The **SCA** module (Security Configuration Assessment) is responsible for assessing the security posture of the system by evaluating it against predefined policies. These policies are written in YAML and contain rules that check system configuration, permissions, and the presence or absence of specific files, commands, or settings.

The module implements a **dual event system** that provides both real-time alerts and reliable state synchronization. It leverages the **Agent Sync Protocol** to persist differences in a local SQLite database and synchronizes them periodically with the manager through a session-based protocol.

SCA persistence supports **stateful synchronization** for complete security check metadata including results and compliance mapping, while maintaining **stateless real-time alerts** for immediate threat detection.

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
# Security Configuration Assessment (SCA) Module

## Introduction

The **SCA** module (Security Configuration Assessment) is responsible for assessing the security posture of the system by evaluating it against predefined policies. These policies are written in YAML and contain rules that check system configuration, permissions, and the presence or absence of specific files, commands, or settings.

The module implements a **dual event system** that provides both real-time alerts and reliable state synchronization. It leverages the **Agent Sync Protocol** to persist differences in a local SQLite database and synchronizes them periodically with the manager through a session-based protocol.

SCA persistence supports **stateful synchronization** for complete security check metadata including results and compliance mapping, while maintaining **stateless real-time alerts** for immediate threat detection.

SCA includes **automatic recovery capabilities** to detect and resolve synchronization inconsistencies between agent and manager databases. Recovery is triggered automatically during a periodic synchronization cycle determined by the `integrity_interval` option.

## Configuration

SCA runs on the agent and is configured in the `<sca>` section of its `ossec.conf`:

```xml
<sca>
  <enabled>yes</enabled>
  <scan_on_start>yes</scan_on_start>
  <interval>12h</interval>
  <policies>
    <policy>/opt/wazuh-sca/custom_linux.yml</policy>
  </policies>
</sca>
```

Every option, its default and its validation are in the [configuration reference](configuration.md).

## Policy Files

Each policy file is a YAML file defining checks (rules) grouped by sections and metadata. These rules are executed during the scan, and the results are stored for reporting and compliance auditing.

## Key Features

- **Policy-based scanning**: Support for CIS benchmarks and custom policies
- **Multiple rule types**: File, command, registry, directory, and process checks
- **Conditional evaluation**: Complex logic with `all`, `any`, and `none` conditions
- **Compliance mapping**: Built-in support for CIS, NIST, and other standards
- **Result persistence**: Local database storage with reliable synchronization
- **Dual event system**: Stateful events for synchronization and stateless for real-time alerts

## Document Limits

The manager sends the agent a limit on the number of SCA checks it synchronizes, taken from the manager's
internal option `sca.checks_limit` (default `30000`, `0` for unlimited; see
[Agent module limits](../remoted/configuration.md#agent-module-limits-fim-syscollector-sca)). The SCA module asks
wazuh-agentd for it (`getdoclimits sca`) before its first scan. The agent keeps the full local SCA state but
synchronizes only the first **N** checks, in the order they were stored. A limit of `0` means **unlimited**
synchronization.

Important behavior:
- The limit applies **only** to stateful SCA documents sent to the indexer.
- **Stateless** real-time SCA alerts are still generated for the **full** local state.
- It is a manager internal option, not an agent configuration option.

# Introduction

The **FIM (File Integrity Monitoring)** module runs on the agent, in the `wazuh-syscheckd` daemon, and is configured in the `<syscheck>` section of the agent's `ossec.conf`. It monitors files and directories on every platform, and Windows registry keys and values. Its synchronization mechanism keeps file and registry state persisted and synchronized with the manager even during network interruptions or agent restarts.

The module implements a **dual event system** that provides both real-time alerts and reliable state synchronization. It uses the **Agent Sync Protocol** to persist differences in a local SQLite database and synchronizes them periodically with the manager through a session-based protocol. The manager stores that state in the `wazuh-states-fim-files`, `wazuh-states-fim-registry-keys` and `wazuh-states-fim-registry-values` indices.

FIM persistence supports **stateful synchronization** for complete file/registry metadata including checksums, while maintaining **stateless real-time alerts** for immediate threat detection.

FIM includes **automatic recovery capabilities** to detect and resolve synchronization inconsistencies between agent and manager databases. Recovery is triggered automatically during a periodic synchronization cycle determined by the `integrity_interval` option.

FIM implements **DataClean capabilities** for proper state management when monitored paths are removed from configuration:
- **Complete path removal**: When all directories/registries are removed, FIM sends a DataClean notification to the manager and clears local databases before exiting.
- **Partial path removal**: When some paths are removed, the existing DBSync transaction mechanism automatically detects and removes orphaned entries during the next scan cycle.

## Pages

- [Architecture](architecture.md): event flow, document limits, synchronization, recovery, coordination commands and schema validation
- [API Reference](api-reference.md): the Agent Sync Protocol calls FIM makes and its coordination commands
- [Configuration](configuration.md): every `<syscheck>` option and the `syscheck.*` internal options
- [Database Schema](database-schema.md): the local FIM database and the sync protocol database
- [Windows Registry monitoring](windows-registry-monitoring.md): registry monitoring walkthrough

# Agent Information (agent_info) Module

## Introduction

The **agent_info** module is a core component responsible for collecting, persisting, and synchronizing agent identity and metadata. It acts as a central source of truth for agent information, ensuring that other modules like SCA, Syscollector, and FIM have a consistent and up-to-date view of the agent's state.

The module periodically gathers agent metadata, including its ID, name, version, operating system details, and group memberships. This information is stored in a local SQLite database, allowing the module to detect changes over time and generate events accordingly.

A key feature of the `agent_info` module is its **coordination protocol**. When critical metadata like agent groups change, this module orchestrates a synchronization process across other modules to ensure that configuration changes are applied consistently and reliably.

## Configuration

The module is configured in the `ossec.conf` file within an `<agent_info>` block.

```xml
<agent_info>
  <interval>60</interval>
  <integrity_interval>86400</integrity_interval>
  <synchronization>
    <enabled>yes</enabled>
    <sync_end_delay>1s</sync_end_delay>
    <response_timeout>30s</response_timeout>
    <retries>5</retries>
    <max_eps>10</max_eps>
  </synchronization>
</agent_info>
```

- More information about each configuration option can be found in the [Configuration Reference](configuration.md).

## Key Features

- **Agent Metadata Collection**: Gathers agent ID, name, version, OS information, and group assignments.
- **Change Detection**: Monitors for changes in metadata and agent group membership, generating events when modifications occur.
- **Local Persistence**: Uses an SQLite database to store metadata, enabling stateful comparisons across agent restarts.
- **Module Coordination**: Orchestrates synchronization with other modules (SCA, Syscollector, FIM) to apply configuration changes consistently after a group change.
- **Reliable Synchronization**: Ensures that metadata updates are reliably communicated to the manager.

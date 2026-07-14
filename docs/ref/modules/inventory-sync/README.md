# Introduction

The **Inventory Sync** module is the manager-side state synchronization service for agent state data. It receives FlatBuffer messages from agents over the Router topic `inventory-states`, stores the session payload temporarily in RocksDB, indexes the resulting state documents into `wazuh-states-*`, and acknowledges completion back to the agent.

Inventory Sync currently handles these manager-side flows:

- **Syscollector** inventory states such as system, hardware, packages, hotfixes, processes, ports, interfaces, protocols, networks, users, groups, services, and browser extensions.
- **FIM** state indices for files, registry keys, and registry values.
- **SCA** state documents in `wazuh-states-sca`.
- **Agent metadata and group updates** across already indexed state documents.
- **Vulnerability Scanner orchestration** for `VDFirst` and `VDSync` sessions after inventory data is persisted.

The module implements a **session-based protocol** with full sync, delta sync, integrity-check, metadata, and group-reconciliation modes. It also supports batched inventory payloads, explicit data cleanup requests, checksum-based validation, and retransmission handling for missing chunks.

Inventory Sync runs on the **manager only**. Agents are producers of synchronization messages; the manager owns session state, RocksDB persistence, Indexer operations, and response dispatch.

## Current scope

The current implementation is broader than basic inventory indexing:

- It indexes **syscollector**, **FIM**, and **SCA** state documents.
- It keeps agent metadata and group membership in sync across existing state indices.
- It stores `DataContext` payloads in RocksDB for session consumers without indexing them directly.
- It can trigger the **Vulnerability Scanner** using the same session context when the Start message requests `VDFirst` or `VDSync`.

## Main outputs

Inventory Sync writes or updates documents in these index families:

- `wazuh-states-inventory-*`
- `wazuh-states-fim-*`
- `wazuh-states-sca`

Sessions that enable vulnerability processing can also lead to downstream writes to `wazuh-states-vulnerabilities`, but those documents are produced by the Vulnerability Scanner, not directly by Inventory Sync.

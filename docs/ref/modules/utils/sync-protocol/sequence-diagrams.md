# Sequence Diagrams

This document provides visual representations of the interactions between modules and the Agent Sync Protocol during various synchronization scenarios. Every scenario below sends **one** `FullSession` message and gets back **one** terminal answer — see [Protocol Lifecycle](lifecycle.md) for the message-level detail behind these diagrams.

Participants used throughout:

- **Module** — the internal module (FIM/SCA/Syscollector/agent-info) driving the protocol.
- **ASP** — `AgentSyncProtocol`.
- **Queue** — the SQLite-backed persistent queue.
- **Transport** — `SyncSocketTransport`, which streams the session over the agent's local `queue-sync` socket.
- **AD** — `agentd`'s intake process, which hands the session to `https_client` and relays its HTTPS response back.
- **Manager** — the Wazuh Manager, reached over HTTPS.

## Module Integration Flow

### Initial Setup

```mermaid
sequenceDiagram
    participant Module as Internal Module<br/>(FIM/SCA/Syscollector)
    participant ASP as Agent Sync Protocol
    participant Queue as Persistent Queue<br/>(SQLite)
    participant Transport as SyncSocketTransport

    Module->>ASP: Create instance<br/>(moduleName, dbPath, logger)
    ASP->>Queue: Open/initialize database
    Queue-->>ASP: Database ready
    ASP->>Transport: Default-constructed<br/>(queue-sync socket path)
    ASP-->>Module: Instance created
```

### Data Persistence Flow

```mermaid
sequenceDiagram
    participant Module as Internal Module
    participant ASP as Agent Sync Protocol
    participant Queue as Persistent Queue

    Note over Module: Detect change<br/>(file modified, check completed, etc.)

    Module->>ASP: persistDifference(id, operation, index, data, version, isDataContext)
    ASP->>Queue: Store in SQLite
    Queue-->>ASP: Success
    ASP-->>Module: Return

    Note over Queue: Item persisted,<br/>ready for the next sync cycle
```

## Synchronization Flows

### Successful Delta Synchronization (mixed `DataValue` + `DataContext`)

```mermaid
sequenceDiagram
    participant Module as Internal Module
    participant ASP as Agent Sync Protocol
    participant Queue as Persistent Queue
    participant Transport as SyncSocketTransport
    participant AD as agentd (https_client)
    participant Manager as Wazuh Manager

    Module->>ASP: synchronizeModule(DELTA)
    ASP->>Queue: fetchAndMarkForSync(byteCap)
    Queue-->>ASP: PersistedData[] (DataValue + DataContext mixed)

    ASP->>ASP: Build ONE FullSession<br/>Start + SyncData{values, contexts} + End
    ASP->>Transport: sendSession(session_id, bytes)
    Transport->>AD: Write over queue-sync socket
    AD-->>Transport: Queued (status byte)
    Transport-->>ASP: true

    Note over ASP: Phase = WaitingResponse<br/>Block on condition variable

    AD->>Manager: POST /stateful<br/>(X-Session-Id header, FullSession body)
    Manager->>Manager: Decode SyncData:<br/>values -> upsert/delete indexer docs<br/>contexts -> store, not indexed
    Manager-->>AD: 200 OK, EndAck(status=Ok)
    AD->>ASP: parseResponseBuffer(EndAck)
    ASP->>Queue: Delete synced items
    Queue-->>ASP: Success

    ASP-->>Module: SyncModuleResult{success=true}
```

### Delta Sync Split Into Multiple Blocks

`Mode::DELTA` splits the queue into as many `FullSession`s as needed to stay under `FULLSESSION_MAX_BYTES`; each block is its own independent session with its own session id.

```mermaid
sequenceDiagram
    participant Module as Internal Module
    participant ASP as Agent Sync Protocol
    participant Queue as Persistent Queue
    participant Transport as SyncSocketTransport
    participant Manager as Wazuh Manager

    Module->>ASP: synchronizeModule(DELTA)

    loop Until queue drained or FULLSESSION_MAX_BLOCKS_PER_SYNC reached
        ASP->>Queue: fetchAndMarkForSync(byteCap)
        Queue-->>ASP: Next block of PersistedData
        ASP->>Transport: sendSession(session_id_N, FullSession)
        Transport-->>Manager: (via agentd/https_client)
        Manager-->>ASP: EndAck(status=Ok)
        ASP->>Queue: clearSyncedItems() for this block
    end

    ASP-->>Module: SyncModuleResult{success=true}
```

### Integrity Check Flow (`requiresFullSync`)

```mermaid
sequenceDiagram
    participant Module as Internal Module
    participant ASP as Agent Sync Protocol
    participant Transport as SyncSocketTransport
    participant AD as agentd (https_client)
    participant Manager as Wazuh Manager

    Module->>Module: Calculate checksum for index
    Module->>ASP: requiresFullSync(index, checksum)

    ASP->>ASP: Build ONE FullSession<br/>Start(mode=ModuleCheck) + ChecksumModule{index, checksum} + End
    ASP->>Transport: sendSession(session_id, bytes)
    Transport->>AD: Write over queue-sync socket
    AD->>Manager: POST /stateful

    Manager->>Manager: Compare agent checksum<br/>against indexed documents

    alt Checksum mismatch
        Manager-->>AD: EndAck(status=ChecksumMismatch)
        AD->>ASP: parseResponseBuffer(EndAck)
        ASP-->>Module: true (full sync needed)
        Module->>Module: Schedule full synchronization
    else Checksum match
        Manager-->>AD: EndAck(status=Ok)
        AD->>ASP: parseResponseBuffer(EndAck)
        ASP-->>Module: false (integrity valid)
    end
```

### Metadata/Groups Synchronization Flow

```mermaid
sequenceDiagram
    participant Module as Internal Module
    participant ASP as Agent Sync Protocol
    participant Transport as SyncSocketTransport
    participant AD as agentd (https_client)
    participant Manager as Wazuh Manager

    Module->>ASP: synchronizeMetadataOrGroups(MetadataDelta, indices, globalVersion)

    ASP->>ASP: Build ONE FullSession<br/>Start(mode=MetadataDelta, global_version) + End<br/>(no SessionPayload set)
    ASP->>Transport: sendSession(session_id, bytes)
    Transport->>AD: Write over queue-sync socket
    AD->>Manager: POST /stateful

    Manager->>Manager: Apply metadata/group update

    Manager-->>AD: EndAck(status=Ok)
    AD->>ASP: parseResponseBuffer(EndAck)
    ASP-->>Module: SyncModuleResult{success=true}
```

### Data Clean Notification Flow

```mermaid
sequenceDiagram
    participant Module as Internal Module
    participant ASP as Agent Sync Protocol
    participant Queue as Persistent Queue
    participant Transport as SyncSocketTransport
    participant AD as agentd (https_client)
    participant Manager as Wazuh Manager

    Note over Module: Module disabled or<br/>specific indices removed

    Module->>ASP: notifyDataClean(indices)

    ASP->>ASP: Build ONE FullSession<br/>Start(mode=DELTA, index=[...]) +<br/>Cleans{DataClean per index} + End
    ASP->>Transport: sendSession(session_id, bytes)
    Transport->>AD: Write over queue-sync socket
    AD->>Manager: POST /stateful

    Manager->>Manager: deleteByQuery for each index

    Manager-->>AD: EndAck(status=Ok)
    AD->>ASP: parseResponseBuffer(EndAck)
    ASP->>Queue: clearItemsByIndex() for each index

    ASP-->>Module: true (success)
```

### Full-Replace Recovery Flow (DataClean + DELTA)

There is no in-memory recovery API or `Mode::FULL` anymore (see [Protocol Lifecycle](lifecycle.md#full-replace-recovery-dataclean-then-delta) for why). Recovery is a `notifyDataClean()` call followed by an ordinary persisted-queue `Mode::DELTA` sync of the fresh snapshot:

```mermaid
sequenceDiagram
    participant Module as Internal Module
    participant ASP as Agent Sync Protocol
    participant Queue as Persistent Queue
    participant Transport as SyncSocketTransport
    participant Manager as Wazuh Manager

    Note over Module: Recovery initiated (e.g. checksum mismatch)

    Module->>ASP: notifyDataClean({index})
    ASP->>ASP: Build FullSession<br/>Start(mode=ModuleDelta, index=[index]) + Cleans{DataClean(index)} + End
    ASP->>Transport: sendSession(session_id, bytes)
    Transport-->>Manager: (via agentd/https_client)
    Manager-->>ASP: EndAck(status=Ok)
    ASP-->>Module: true

    loop For each item in the fresh snapshot
        Module->>ASP: persistDifference(id, operation, index, data, version)
        ASP->>Queue: Store in SQLite
    end

    Module->>ASP: synchronizeModule(DELTA)
    ASP->>Queue: fetchAndMarkForSync(byteCap)
    ASP->>ASP: Build FullSession<br/>Start(mode=ModuleDelta, size=N) + SyncData{values} + End
    ASP->>Transport: sendSession(session_id, bytes)
    Transport-->>Manager: (via agentd/https_client)
    Manager-->>ASP: EndAck(status=Ok)
    ASP->>Queue: clearSyncedItems()

    ASP-->>Module: SyncModuleResult{success=true}
```

## Error Handling Scenarios

### Manager Reports Offline / Not Ready

```mermaid
sequenceDiagram
    participant Module as Internal Module
    participant ASP as Agent Sync Protocol
    participant Transport as SyncSocketTransport
    participant Manager as Wazuh Manager

    Module->>ASP: synchronizeModule(DELTA)
    ASP->>Transport: sendSession(session_id, FullSession)
    Transport-->>Manager: (via agentd/https_client)

    Note over Manager: Cannot serve this agent yet<br/>(e.g. right after enrollment)

    Manager-->>ASP: EndAck(status=Offline)
    Note over ASP: lastSyncResult = COMMUNICATION_ERROR<br/>managerNotReady = true

    ASP-->>Module: SyncModuleResult{success=false, managerNotReady=true,<br/>consecutiveFailures=N}
    Note over Module: N below SYNC_MANAGER_NOT_READY_TOLERANCE:<br/>log at INFO/DEBUG.<br/>N at or above it: log at WARNING.
```

### Manager Error Response

```mermaid
sequenceDiagram
    participant Module as Internal Module
    participant ASP as Agent Sync Protocol
    participant Transport as SyncSocketTransport
    participant Manager as Wazuh Manager

    Module->>ASP: synchronizeModule(DELTA)
    ASP->>Transport: sendSession(session_id, FullSession)
    Transport-->>Manager: (via agentd/https_client)

    Manager-->>ASP: EndAck(status=Error)
    Note over ASP: lastSyncResult = PROTOCOL_ERROR<br/>syncFailed = true

    ASP-->>Module: SyncModuleResult{success=false}
    Note over Module: Items stay/return to PENDING,<br/>next periodic cycle retries.
```

### Stop Requested While Waiting for a Response

```mermaid
sequenceDiagram
    participant Module as Internal Module
    participant ASP as Agent Sync Protocol
    participant Transport as SyncSocketTransport

    Module->>ASP: synchronizeModule(DELTA)
    ASP->>Transport: sendSession(session_id, FullSession)
    Note over ASP: Phase = WaitingResponse<br/>Block on condition variable

    Module->>ASP: stop() (called from shutdown path)
    Note over ASP: shouldStop() becomes true<br/>cv notified, wait unblocks

    ASP-->>Module: SyncModuleResult{success=false, stopped=true}
    Note over Module: stopped=true demotes this to<br/>INFO/DEBUG instead of WARNING
```

## Response Handling Flow

### Two Response Paths Into `AgentSyncProtocol`

The manager's verdict can reach the protocol through either of two independent paths, both terminal:

```mermaid
sequenceDiagram
    participant SyncThread as Sync Thread
    participant ResponseThread as Response Thread
    participant ASP as Agent Sync Protocol
    participant AD as agentd (https_client)
    participant Manager as Wazuh Manager

    SyncThread->>ASP: synchronizeModule(DELTA)
    ASP->>ASP: Phase = WaitingResponse
    ASP->>AD: sendSession(session_id, FullSession)
    SyncThread->>ASP: Block on condition variable

    alt FlatBuffer EndAck path
        Manager->>AD: 200 OK, Message{EndAck}
        AD->>ResponseThread: Deliver body
        ResponseThread->>ASP: parseResponseBuffer(data, length)
        ASP->>ASP: Validate phase, apply status
    else HTTPS result-code path
        Manager->>AD: HTTP status code for this request
        AD->>ResponseThread: "HCRESULT:<session>:<code>"
        ResponseThread->>ASP: applyHttpResultCode(code, session)
        ASP->>ASP: Validate phase + session id, apply code
    end

    ASP->>ASP: Set responseReceived/syncFailed,<br/>notify condition variable
    ASP-->>SyncThread: Wake up, read result
    SyncThread->>SyncThread: Delete synced items on success
```

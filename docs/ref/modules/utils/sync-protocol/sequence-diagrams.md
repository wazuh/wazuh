# Sequence Diagrams

This document provides visual representations of the interactions between modules and the Agent Sync Protocol during various synchronization scenarios.

## Module Integration Flow

### Initial Setup and Registration

```mermaid
sequenceDiagram
    participant Module as Internal Module<br/>(FIM/SCA/Inventory)
    participant ASP as Agent Sync Protocol
    participant Queue as Persistent Queue<br/>(SQLite)
    participant MQ as Message Queue

    Module->>ASP: Create instance<br/>(module_name, db_path, mq_funcs)
    ASP->>Queue: Initialize database
    Queue-->>ASP: Database ready
    ASP->>MQ: Setup connection functions
    ASP-->>Module: Instance created
```

### Data Persistence Flow

```mermaid
sequenceDiagram
    participant Module as Internal Module
    participant ASP as Agent Sync Protocol
    participant Queue as Persistent Queue

    Note over Module: Detect change<br/>(file modified, check completed, etc.)

    Module->>ASP: persistDifference(id, operation, index, data)
    ASP->>ASP: Validate parameters
    ASP->>Queue: Store in SQLite
    Queue-->>ASP: Success
    ASP-->>Module: Return

    Note over Queue: Data persisted<br/>Ready for sync
```

## Synchronization Flows

### Successful Delta Synchronization

```mermaid
sequenceDiagram
    participant Module as Internal Module
    participant ASP as Agent Sync Protocol
    participant Queue as Persistent Queue
    participant MQ as Message Queue
    participant AD as Wazuh agentd
    participant Manager as Wazuh Manager

    Module->>ASP: synchronizeModule(DELTA, timeout, retries, maxEps)
    ASP->>Queue: Get pending differences
    Queue-->>ASP: Return data array

    Note over ASP,Manager: Session Establishment Phase
    ASP->>ASP: Build Start message
    ASP->>MQ: Send Start message
    MQ->>AD: Forward Start
    AD->>Manager: Forward Start
    Manager->>Manager: Create session
    Manager->>AD: Send StartAck(session_id)
    AD->>ASP: Forward StartAck
    ASP->>ASP: Store session_id

    Note over ASP,Manager: Data Transfer Phase
    loop For each difference
        ASP->>ASP: Apply EPS throttling
        ASP->>ASP: Build Data message
        ASP->>MQ: Send Data[seq_num]
        MQ->>AD: Forward Data
        AD->>Manager: Forward Data
        Manager->>Manager: Process & store
    end

    Note over ASP,Manager: Session Completion Phase
    ASP->>ASP: Build End message
    ASP->>MQ: Send End(session_id)
    MQ->>AD: Forward End
    AD->>Manager: Forward End
    Manager->>Manager: Validate received data
    Manager->>AD: Send EndAck(success)
    AD->>ASP: Forward EndAck
    ASP->>Queue: Delete data
    Queue-->>ASP: Success

    ASP-->>Module: Return true (success)
```

### Synchronization with Retransmission Request

```mermaid
sequenceDiagram
    participant Module as Internal Module
    participant ASP as Agent Sync Protocol
    participant Queue as Persistent Queue
    participant MQ as Message Queue
    participant AD as Wazuh agentd
    participant Manager as Wazuh Manager

    Module->>ASP: synchronizeModule(DELTA, timeout, retries, maxEps)
    ASP->>Queue: Get pending differences
    Queue-->>ASP: Return data array[1..100]

    Note over ASP,Manager: Session Establishment
    ASP->>MQ: Send Start
    MQ->>AD: Forward Start
    AD->>Manager: Forward Start
    Manager->>AD: Send StartAck(session_id=123)
    AD->>ASP: Forward StartAck

    Note over ASP,Manager: Data Transfer with Loss
    ASP->>MQ: Send Data[1..30]
    MQ->>AD: Forward Data[1..30]
    AD->>Manager: Forward Data[1..30]

    Note over MQ,Manager: Network issue:<br/>Data[31..35] lost
    ASP->>MQ: Send Data[31..35]
    MQ->>AD: Send Data[31..35]
    AD--xManager: Lost in transit

    ASP->>MQ: Send Data[36..100]
    MQ->>AD: Send Data[36..100]
    AD->>Manager: Forward Data[36..100]

    Note over ASP,Manager: Session Completion Phase
    ASP->>MQ: Send End
    MQ->>AD: Forward End
    AD->>Manager: Forward End

    Note over Manager: Detect missing<br/>sequences 31-35
    Manager->>AD: Send ReqRet(ranges=[[31,35]])
    AD->>ASP: Forward ReqRet

    Note over ASP,Manager: Retransmission
    ASP->>ASP: Filter data by ranges
    ASP->>MQ: Resend Data[31..35]
    MQ->>AD: Forward Data[31..35]
    AD->>Manager: Forward Data[31..35]
    Manager->>Manager: Fill gaps

    Manager->>AD: Send EndAck(success)
    AD->>ASP: Forward EndAck
    ASP-->>Module: Return true
```

### Failed Synchronization with Retry

```mermaid
sequenceDiagram
    participant Module as Internal Module
    participant ASP as Agent Sync Protocol
    participant MQ as Message Queue
    participant AD as Wazuh agentd
    participant Manager as Wazuh Manager

    Module->>ASP: synchronizeModule(FULL, timeout=30s, retries=3, maxEps=1000)

    Note over ASP,Manager: Attempt 1
    ASP->>MQ: Send Start
    MQ->>AD: Forward Start
    AD->>Manager: Forward Start
    Note over ASP: Wait 30s
    ASP->>ASP: Timeout waiting for StartAck

    Note over ASP,Manager: Attempt 2
    ASP->>MQ: Send Start
    MQ->>AD: Forward Start
    AD->>Manager: Forward Start
    Note over Manager: Manager busy/overloaded
    Note over ASP: Wait 30s
    ASP->>ASP: Timeout waiting for StartAck

    Note over ASP,Manager: Attempt 3
    ASP->>MQ: Send Start
    MQ->>AD: Forward Start
    AD->>Manager: Forward Start
    Manager->>AD: Send StartAck(session_id=456)
    AD->>ASP: Forward StartAck

    Note over ASP,Manager: Continue with sync...
    ASP->>MQ: Send Data messages
    MQ->>AD: Forward Data
    AD->>Manager: Forward Data
    ASP->>MQ: Send End
    MQ->>AD: Forward End
    AD->>Manager: Forward End
    Manager->>AD: Send EndAck
    AD->>ASP: Forward EndAck

    ASP-->>Module: Return true (success after retries)
```

## Error Handling Scenarios

### Manager Error Response

```mermaid
sequenceDiagram
    participant Module as Internal Module
    participant ASP as Agent Sync Protocol
    participant MQ as Message Queue
    participant AD as Wazuh agentd
    participant Manager as Wazuh Manager

    Module->>ASP: synchronizeModule()
    ASP->>MQ: Send Start
    MQ->>AD: Forward Start
    AD->>Manager: Forward Start

    Note over Manager: Detect invalid<br/>protocol version

    Manager->>AD: Send Error(INVALID_VERSION)
    AD->>ASP: Forward Error

    ASP->>ASP: Set syncFailed flag
    ASP->>ASP: Clear sync state
    ASP-->>Module: Return false (sync failed)

    Note over Module: Handle failure<br/>(log, retry later, etc.)
```

## Response Handling Flow

### Asynchronous Response Processing

```mermaid
sequenceDiagram
    participant Thread1 as Sync Thread
    participant Thread2 as Response Thread
    participant ASP as Agent Sync Protocol
    participant State as Sync State
    participant MQ as Message Queue
    participant AD as Wazuh agentd
    participant Manager as Wazuh Manager

    Thread1->>ASP: synchronizeModule()
    ASP->>State: Set phase = WaitingStartAck
    ASP->>MQ: Send Start
    MQ->>AD: Forward Start
    AD->>Manager: Forward Start

    Thread1->>State: Wait on condition variable

    Note over Thread2: agend Receive Loop
    Manager->>AD: Send StartAck
    AD->>Thread2: Receive StartAck
    Thread2->>ASP: parseResponseBuffer(data)
    ASP->>State: Validate session & phase
    ASP->>State: Set startAckReceived = true
    ASP->>State: Notify condition variable

    State->>Thread1: Wake up
    Thread1->>State: Check startAckReceived
    Thread1->>ASP: Continue with data send
    ASP->>MQ: Send Data
    MQ->>AD: Forward Data
    AD->>Manager: Forward Data
    ASP->>State: Set phase = WaitingEndAck

    Thread1->>State: Wait on condition variable

    Note over Thread2: agend Receive Loop
    Manager->>AD: Send EndtAck
    AD->>Thread2: Receive EndtAck
    Thread2->>ASP: parseResponseBuffer(data)
    ASP->>State: Validate session & phase
    ASP->>State: Set endAckReceived = true
    ASP->>State: Notify condition variable

    State->>Thread1: Wake up
    Thread1->>State: Check endAckReceived
    Thread1->>ASP: Delete sent data
```

### Integrity Check Flow (requiresFullSync)

```mermaid
sequenceDiagram
    participant Module as Internal Module
    participant ASP as Agent Sync Protocol
    participant MQ as Message Queue
    participant AD as Wazuh agentd
    participant Manager as Wazuh Manager

    Module->>Module: Calculate checksum for index
    Module->>ASP: requiresFullSync(index, checksum, timeout, retries, maxEps)

    Note over ASP,Manager: Session Establishment
    ASP->>MQ: Send Start(mode=CHECK)
    MQ->>AD: Forward Start
    AD->>Manager: Forward Start
    Manager->>AD: Send StartAck(session_id)
    AD->>ASP: Forward StartAck

    Note over ASP,Manager: Send Checksum Only
    ASP->>MQ: Send ChecksumModule
    MQ->>AD: Forward ChecksumModule
    AD->>Manager: Forward ChecksumModule

    Note over Manager: Compare checksums

    Note over ASP,Manager: Session Completion
    ASP->>MQ: Send End(session_id)
    MQ->>AD: Forward End
    AD->>Manager: Forward End
    Manager->>Manager: Determine if mismatch

    alt Checksum Mismatch
        Manager->>AD: Send EndAck(status=Error)
        AD->>ASP: Forward EndAck
        ASP-->>Module: Return true (full sync needed)
        Module->>Module: Schedule full synchronization
    else Checksum Match
        Manager->>AD: Send EndAck(status=Ok)
        AD->>ASP: Forward EndAck
        ASP-->>Module: Return false (integrity valid)
        Module->>Module: Continue with delta sync
    end
```

### In-Memory Recovery Flow

```mermaid
sequenceDiagram
    participant Module as Internal Module
    participant ASP as Agent Sync Protocol
    participant Memory as In-Memory Vector
    participant MQ as Message Queue
    participant AD as Wazuh agentd
    participant Manager as Wazuh Manager

    Note over Module: Module recovery initiated

    loop For each recovery item
        Module->>ASP: persistDifferenceInMemory(id, operation, index, data)
        ASP->>Memory: Store in memory vector
        Memory-->>ASP: Success
    end

    Note over Module: All recovery data in memory

    Module->>ASP: synchronizeModule(FULL, timeout, retries, maxEps)

    Note over ASP,Manager: Session Establishment
    ASP->>MQ: Send Start(mode=FULL, size=N)
    MQ->>AD: Forward Start
    AD->>Manager: Forward Start
    Manager->>AD: Send StartAck(session_id)
    AD->>ASP: Forward StartAck

    Note over ASP,Manager: Data Transfer from Memory
    loop For each in-memory item
        ASP->>Memory: Get next item
        Memory-->>ASP: Return data
        ASP->>ASP: Build Data message
        ASP->>MQ: Send Data
        MQ->>AD: Forward Data
        AD->>Manager: Forward Data
    end

    Note over ASP,Manager: Session Completion
    ASP->>MQ: Send End(session_id)
    MQ->>AD: Forward End
    AD->>Manager: Forward End
    Manager->>AD: Send EndAck(success)
    AD->>ASP: Forward EndAck

    ASP-->>Module: Return true (success)
    Module->>ASP: clearInMemoryData()
    ASP->>Memory: Clear all entries
    Memory-->>ASP: Cleared

    Note over Module: Recovery complete
```

### Metadata/Groups Synchronization Flow

```mermaid
sequenceDiagram
    participant Module as Internal Module
    participant ASP as Agent Sync Protocol
    participant MQ as Message Queue
    participant AD as Wazuh agentd
    participant Manager as Wazuh Manager

    Module->>ASP: synchronizeMetadataOrGroups(METADATA_DELTA, timeout, retries, maxEps, globalVersion)

    Note over ASP,Manager: Session Establishment
    ASP->>ASP: Validate mode (METADATA/GROUP)
    ASP->>MQ: Send Start(mode=METADATA_DELTA)
    MQ->>AD: Forward Start
    AD->>Manager: Forward Start
    Manager->>Manager: Prepare to receive metadata
    Manager->>AD: Send StartAck(session_id)
    AD->>ASP: Forward StartAck

    Note over ASP,Manager: No Data Messages Sent

    Note over ASP,Manager: Immediate Session Completion
    ASP->>MQ: Send End(session_id)
    MQ->>AD: Forward End
    AD->>Manager: Forward End

    Note over Manager: Process metadata<br/>based on mode

    Manager->>AD: Send EndAck(success)
    AD->>ASP: Forward EndAck

    ASP-->>Module: Return true (success)

    Note over Module: Metadata synchronized<br/>without data transfer
```

### Data Clean Notification Flow

```mermaid
sequenceDiagram
    participant Module as Internal Module
    participant ASP as Agent Sync Protocol
    participant Queue as Persistent Queue
    participant MQ as Message Queue
    participant AD as Wazuh agentd
    participant Manager as Wazuh Manager

    Note over Module: Module disabled or<br/>specific indices removed

    Module->>ASP: notifyDataClean(indices, timeout, retries, maxEps)
    ASP->>ASP: Validate indices (non-empty)

    Note over ASP: Create PersistedData<br/>for each index

    Note over ASP,Manager: Session Establishment
    ASP->>MQ: Send Start(mode=DELTA, size=N, indices)
    MQ->>AD: Forward Start
    AD->>Manager: Forward Start
    Manager->>Manager: Create session
    Manager->>AD: Send StartAck(session_id)
    AD->>ASP: Forward StartAck
    ASP->>ASP: Store session_id

    Note over ASP,Manager: DataClean Messages Transfer
    loop For each index
        ASP->>ASP: Build DataClean message
        ASP->>MQ: Send DataClean[seq, session, index]
        MQ->>AD: Forward DataClean
        AD->>Manager: Forward DataClean
        Manager->>Manager: Mark index for cleanup
    end

    Note over ASP,Manager: Session Completion
    ASP->>MQ: Send End(session_id)
    MQ->>AD: Forward End
    AD->>Manager: Forward End
    Manager->>Manager: Clean marked indices
    Manager->>AD: Send EndAck(success)
    AD->>ASP: Forward EndAck

    Note over ASP: Success confirmed

    ASP->>Queue: clearItemsByIndex(index) for each
    Queue-->>ASP: Local data cleared

    ASP-->>Module: Return true (success)

    Note over Module: Data clean notification<br/>completed successfully
```

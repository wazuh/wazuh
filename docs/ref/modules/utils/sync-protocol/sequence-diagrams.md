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

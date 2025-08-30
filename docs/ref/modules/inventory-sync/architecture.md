# Architecture

The **Inventory Sync module** implements a **session-based synchronization architecture** designed to ensure reliable transfer of inventory data from Wazuh agents to the Wazuh Indexer.
It leverages a combination of design patterns — **Facade**, **Template Method**, and **Publisher–Subscriber** — to modularize responsibilities, simplify extensibility, and provide scalable synchronization capabilities.

---

## Main Components

### **`inventorySyncFacade.hpp`**

The main orchestration component and entry point for inventory synchronization.
Responsibilities:

* Initializes local RocksDB storage for session-based data persistence.
* Subscribes to Router communication channels for incoming FlatBuffer messages.
* Manages agent session lifecycle, including creation, tracking, and timeouts.
* Coordinates IndexerConnector and ResponseDispatcher interactions.
* Implements the session-based synchronization protocol with unique session IDs.

---

### **`agentSession.hpp`**

Manages synchronization state and lifecycle for each agent.
Responsibilities:

* Tracks session lifecycle (Start → Data → End).
* Stores incoming data with session-prefixed keys in RocksDB.
* Validates integrity and detects gaps in sequences.
* Implements timeout and heartbeat validation.
* Coordinates acknowledgment handling with the ResponseDispatcher.

---

### **`context.hpp`**

Defines metadata for each synchronization session.
Responsibilities:

* Stores synchronization mode (Full or Delta).
* Maintains session ID, agent ID, and module name.
* Provides metadata to IndexerConnector and ResponseDispatcher.

---

### **`responseDispatcher.hpp`**

Handles outbound communication to agents.
Responsibilities:

* Sends acknowledgments upon successful synchronization.
* Reports errors and status updates.
* Routes responses based on session context.

---

## Synchronization Flow

The Inventory Sync protocol operates in **three phases**:

1. **Start Phase**

   * Agent initiates synchronization with a `START` message.
   * A unique session ID is generated.
   * Context is created, and RocksDB storage prepared.

2. **Data Phase**

   * Agent transmits inventory data in chunks.
   * Data is written into RocksDB with session-prefixed keys.
   * FlatBuffer validation ensures message integrity.
   * Both insert (upsert) and delete operations are supported.

3. **End Phase**

   * Agent sends an `END` message.
   * Session data is processed by the IndexerConnector.
   * Bulk indexing/deletion operations are issued to the Indexer.
   * An acknowledgment is sent back, and session data is cleaned up.

---

## High-Level Diagram

```mermaid
flowchart TD

subgraph WazuhManager[" "]
  subgraph WazuhModulesM[" "]
    subgraph InventorySync[" "]
      AgentSessions["Agent Sessions"]
      LocalStorage["RocksDB Storage"]
      WorkersQueue["Workers Queue"] 
      IndexerQueue["Indexer Queue"]
    end
    D@{ shape: braces, label: "Inventory Sync" } --> InventorySync
    IndexerConnector["Indexer Connector"]
    InventorySync -- "Bulk Operations" --> IndexerConnector
  end
  C@{ shape: braces, label: "Wazuh Modules" } --> WazuhModulesM
  Router -- "FlatBuffer Messages" --> InventorySync
  InventorySync -- "ACK / Status" --> Router
end
B@{ shape: braces, label: "Wazuh Manager" } --> WazuhManager
IndexerConnector -- "HTTP Bulk API" --> WazuhIndexer

subgraph WazuhAgent["Wazuh Agent"]
  subgraph WazuhModulesA[" "]
    Syscollector["Syscollector"]
    FIM["FIM Module"]  
  end
  A@{ shape: braces, label: "Wazuh Modules" } --> WazuhModulesA
  Syscollector -- "Inventory States" --> Router
  FIM -- "FIM States" --> Router
end

WazuhIndexer["Wazuh Indexer"]
WazuhDashboard["Wazuh Dashboard"]
WazuhDashboard -- "/wazuh-states-*/_search" --> WazuhIndexer
```

---

## Session Management

The module provides robust **session lifecycle management**:

* **Session Creation**: 64-bit random IDs prevent collisions.
* **Timeout Handling**: Configurable timeout (default: 10s) triggers cleanup.
* **Concurrency Control**: Thread-safe session map with shared/unique locks.
* **Data Persistence**: Session-scoped keys ensure isolation in RocksDB.
* **Error Recovery**: Automatic cleanup on timeouts or errors.

---

## Scalability Features

* **Asynchronous Processing**: Multi-threaded workers handle messages in concurrent way, using a producer-consumer approach.
* **Bulk Operations**: Efficient batching reduces Indexer overhead.
* **Memory Protection**: Temporary RocksDB storage prevents memory bloat.
* **Queue Management**: Configurable worker and Indexer queues enable backpressure control.

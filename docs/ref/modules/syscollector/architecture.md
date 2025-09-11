# Architecture

The **Syscollector module** implements a **dual event architecture** designed to provide both immediate alerting and reliable state synchronization for system inventory monitoring. It combines stateless events with persistent stateful events using the Agent Sync Protocol for guaranteed delivery.

---

## Main Components

### **Database Integration (DBSync)**

The local database component responsible for storing and comparing system inventory states.
Responsibilities:

* DBSync manages the actual SQLite database operations and synchronization
* Provides transaction-based state comparison through callback mechanisms
* Compares current system state with stored state via database transactions
* Triggers transaction callbacks when changes are detected
* Supports atomic database transactions for consistency
* Manages different inventory tables (hardware, OS, packages, processes, etc.)

### **Agent Sync Protocol Integration (C++ Interface)**

Syscollector integrates with the sync protocol through the C++ interface.
Responsibilities:

* Creates and manages sync protocol instance via `initSyncProtocol()`
* Persists differences using `persistDifference()` when changes detected
* Triggers periodic synchronization via `syncModule()`
* Handles manager responses through `parseResponseBuffer()`
* Manages persistent queue for reliable message delivery
* Uses `IAgentSyncProtocol` interface for better C++ integration

### **Transaction Callbacks**

Handle database comparison results and generate appropriate events.
Responsibilities:

* Process database transaction results from DBSync
* Determine change type (create, modify, delete) based on stored state
* Generate both stateless and stateful events for each change
* Handle inventory item hashing for unique identification
* Coordinate event generation and persistence
* Called for all changes detected through database transactions

### **Periodic Scanning Thread**

Dedicated thread that performs system inventory scans at configured intervals.
Responsibilities:

* **`Syscollector::syncLoop()`** - Main scanning thread:
  - Runs periodic inventory collection based on configured interval
  - Triggers scans for enabled inventory types (hardware, OS, packages, etc.)
  - Coordinates with SysInfo provider for data collection
  - Manages scan timing and throttling
* Triggers `updateChanges()` which leads to database transactions and callbacks
* Runs continuously in background thread launched at Syscollector startup

---

## Event Flow Architecture

### Complete Syscollector Event Flow

```
System Inventory Change Detected
         │
         ▼
scanHardware() / scanPackages() / scan*()
         │
         ▼
updateChanges() ──────────────► DBSync Database Operation
         │                           │
         ▼                           ▼
notifyChange() / processEvent() Compare with stored state
         │
         ├─► Generate Stateless Event ─────► reportDiffFunction() ─────► Manager (immediate)
         │
         └─► Generate Stateful Event ──────► persistDiffFunction()
                                                      │
                                                      └─► persistDifference()
                                                                │
                                                                ▼
                                                        Sync Protocol Database
                                                                │
                                                                ▼
                                            Periodic Sync Thread (syncLoop)
                                                                │
                                                                └─► syncModule()
                                                                         │
                                                                         ▼
                                                                      Manager
```

---

## Dual Event System

### Stateless Events

Generated immediately when changes are detected and sent directly to the manager:

```cpp
if (m_reportDiffFunction) {
    m_reportDiffFunction(data.dump());  // Immediate send to manager
}
```

**Characteristics:**
- Sent immediately when changes detected
- Contain essential inventory change information
- No persistence or retry mechanism
- Lost if network is down or agent restarts

### Stateful Events (Synchronization State)

Generated with complete data including checksums and persisted for synchronization:

```cpp
if (m_persistDiffFunction) {
    std::string id = calculateHashId(data, table);
    std::string index = getSyncIndexForTable(table);
    m_persistDiffFunction(id, operation, index, data.dump());
}
```

**Characteristics:**
- Include complete inventory metadata and checksums
- Persisted to sync protocol database
- Survive agent restarts and network failures
- Synchronized periodically with manager
- Use specific sync indexes for each inventory type

---

## Database Transaction Flow

### Transaction Process

Syscollector uses database transactions to ensure consistency between change detection and event generation:

```cpp
auto callback = [this, table](ReturnTypeCallback result, const nlohmann::json& data) {
    processEvent(result, data, table);
};

m_spDBSync->syncRowData(table, values, callback);
```

### Transaction Callback Processing

The `processEvent()` function handles the database response:

1. **Receives database comparison result** from DBSync
2. **Determines change type** (create, modify, delete) based on database state
3. **Generates both event types**:
   - Stateless event for immediate alerts
   - Stateful event for synchronization
4. **Persists stateful event** to sync protocol with appropriate index

---

## Synchronization Architecture

### Periodic Synchronization Thread

Syscollector runs a dedicated synchronization mechanism as part of its main loop:

```cpp
// Function: Syscollector::syncLoop()
void Syscollector::syncLoop(std::unique_lock<std::mutex>& lock) {
    while (!m_stopping) {
        // Wait for sync interval
        m_cv.wait_for(lock, std::chrono::seconds(m_intervalValue));

        // Trigger synchronization of all pending inventory changes
        if (m_spSyncProtocol) {
            bool success = m_spSyncProtocol->synchronizeModule(
                Mode::DELTA,
                std::chrono::seconds(timeout),
                retries,
                maxEps
            );
        }
    }
}
```

### Manager Response Handling

Syscollector processes manager responses through the syscom interface:

```cpp
// Handle inventory sync messages from manager
bool ret = parseResponseBuffer(response_data, response_length);
```

### Inventory Type Synchronization

Each inventory type is synchronized with its specific index:

| Inventory Type | Database Table | Sync Protocol Index |
|----------------|----------------|-------------------|
| Hardware | `dbsync_hwinfo` | `wazuh-states-inventory-hardware` |
| OS | `dbsync_osinfo` | `wazuh-states-inventory-system` |
| Packages | `dbsync_packages` | `wazuh-states-inventory-packages` |
| Processes | `dbsync_processes` | `wazuh-states-inventory-processes` |
| Ports | `dbsync_ports` | `wazuh-states-inventory-ports` |
| Users | `dbsync_users` | `wazuh-states-inventory-users` |
| Groups | `dbsync_groups` | `wazuh-states-inventory-groups` |
| Services | `dbsync_services` | `wazuh-states-inventory-services` |
| Browser Extensions | `dbsync_browser_extensions` | `wazuh-states-inventory-browser-extensions` |
| Hotfixes | `dbsync_hotfixes` | `wazuh-states-inventory-hotfixes` |
| Network Interfaces | `dbsync_network_iface` | `wazuh-states-inventory-interfaces` |
| Network Protocols | `dbsync_network_protocol` | `wazuh-states-inventory-protocols` |
| Network Address | `dbsync_network_address` | `wazuh-states-inventory-networks` |

---

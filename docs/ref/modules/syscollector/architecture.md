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

## Syscollector Disabled Cleanup Flow

### Overview

When the Syscollector module is disabled, the `wm_handle_sys_disabled_and_notify_data_clean()` function executes a cleanup procedure to notify the manager and remove local databases. This ensures the manager's state remains synchronized with the agent's actual inventory monitoring status.

### Execution Trigger

The function is called during module startup in `wm_sys_main()` when `sys->flags.enabled` is false:

```c
if (!sys->flags.enabled) {
    wm_handle_sys_disabled_and_notify_data_clean(sys);
    mtinfo(WM_SYS_LOGTAG, "Module disabled. Exiting...");
    pthread_exit(NULL);
}
```

### Cleanup Flow

```
Module Startup (wm_sys_main)
      │
      ▼
Check sys->flags.enabled
      │
      ▼ (if disabled)
wm_handle_sys_disabled_and_notify_data_clean()
      │
      ├─► Check for database file ────► w_is_file(SYSCOLLECTOR_DB_DISK_PATH)
      │                                           │
      │                                           ├─► File exists
      │                                           │   (proceed with cleanup)
      │                                           │
      │                                           └─► File not exists
      │                                               (skip notification, exit)
      │
Load Syscollector module dynamically
      │
      ▼
Configure Syscollector minimally
      │
      ├─► Initialize sync protocol ──────► syscollector_init_sync()
      │   (module name, DB path, MQ funcs)
      │
      └─► Initialize module ──────────────► syscollector_init()
      │
      │
      ▼
Prepare indices array
      │
      ├─► All 13 inventory indices:
      │   ├─► SYSCOLLECTOR_SYNC_INDEX_SYSTEM
      │   ├─► SYSCOLLECTOR_SYNC_INDEX_HARDWARE
      │   ├─► SYSCOLLECTOR_SYNC_INDEX_HOTFIXES
      │   ├─► SYSCOLLECTOR_SYNC_INDEX_PACKAGES
      │   ├─► SYSCOLLECTOR_SYNC_INDEX_PROCESSES
      │   ├─► SYSCOLLECTOR_SYNC_INDEX_PORTS
      │   ├─► SYSCOLLECTOR_SYNC_INDEX_INTERFACES
      │   ├─► SYSCOLLECTOR_SYNC_INDEX_PROTOCOLS
      │   ├─► SYSCOLLECTOR_SYNC_INDEX_NETWORKS
      │   ├─► SYSCOLLECTOR_SYNC_INDEX_USERS
      │   ├─► SYSCOLLECTOR_SYNC_INDEX_GROUPS
      │   ├─► SYSCOLLECTOR_SYNC_INDEX_SERVICES
      │   └─► SYSCOLLECTOR_SYNC_INDEX_BROWSER_EXTENSIONS
      │
      ▼
Send data clean notification ────────► syscollector_notify_data_clean()
      │                                     │
      │                                     ├─► All 13 indices
      │                                     ├─► Retry on failure
      │                                     │   (wait sync_interval)
      │                                     │
      │                                     └─► Success confirmation
      │
      └─► Delete databases ─────────────► syscollector_delete_database()
          (both sync protocol and DBSync)
```

### Behavior Scenarios

#### Scenario 1: Syscollector Disabled with Existing Database

```
1. Agent starts with Syscollector disabled (sys->flags.enabled = false)
2. Syscollector database file exists at SYSCOLLECTOR_DB_DISK_PATH
3. Load Syscollector module dynamically
4. Initialize sync protocol with MQ functions
5. Initialize Syscollector module with full configuration
6. Prepare all 13 inventory indices
7. Send data clean notification to manager (with infinite retries)
8. Manager removes all 13 indices from agent's state
9. Delete both sync protocol and DBSync databases
10. Exit module startup
```

#### Scenario 2: Syscollector Disabled with No Database

```
1. Agent starts with Syscollector disabled (sys->flags.enabled = false)
2. Syscollector database file does not exist
3. Skip data clean notification (nothing to clean)
4. Exit module startup immediately
```

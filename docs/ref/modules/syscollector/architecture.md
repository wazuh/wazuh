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
  - Respects pause state before initiating scans
* Triggers `updateChanges()` which leads to database transactions and callbacks
* Runs continuously in background thread launched at Syscollector startup

### **Operation State Control**

Syscollector implements atomic state flags to coordinate operations and enable external control:

**State Flags:**
* `m_paused` - Indicates if the module is paused (prevents new operations from starting)
* `m_scanning` - Indicates if a scan operation is currently in progress
* `m_syncing` - Indicates if a synchronization operation is currently in progress

**Coordination Flow:**

```
External Coordination Command (pause)
         │
         ▼
Set m_paused = true
         │
         ▼
Wait for m_scanning = false AND m_syncing = false
         │
         ▼
Operations Complete - Module Paused
         │
         ▼
External Coordination Command (resume)
         │
         ▼
Set m_paused = false
         │
         ▼
Notify Main Loop (m_cv.notify_one())
         │
         ▼
Operations Resume
```

**Operation Protection:**

Before starting scan or sync operations, the module checks the pause state:

```cpp
// Before scan operation
if (!m_paused) {
    m_scanning = true;
    // Perform scan...
    m_scanning = false;
    m_pauseCv.notify_all();  // Notify pause() if waiting
}

// Before sync operation
if (!m_paused) {
    m_syncing = true;
    // Perform sync...
    m_syncing = false;
    m_pauseCv.notify_all();  // Notify pause() if waiting
}
```

This coordination mechanism ensures that:
- Pause commands wait for ongoing operations to complete gracefully
- No new operations start while paused
- Resume commands immediately allow operations to continue
- Module state is consistent and thread-safe

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

---

## Coordination Commands Architecture

The coordination commands provide external control over Syscollector operations, allowing the manager or other components to coordinate module behavior. These commands were added to support centralized coordination of module operations across the agent.

### Command Types

#### Pause/Resume Commands

**Purpose:** Allow temporary suspension of Syscollector operations without stopping the module completely.

**Use Cases:**
- Manager-requested coordination during configuration changes
- Agent reconfiguration that requires stable module state
- Coordination with other modules that need Syscollector to be idle
- Testing and maintenance operations

**Implementation:**

The pause command follows this sequence:

```
Pause Command Received
         │
         ▼
Set m_paused = true (atomic flag)
         │
         ▼
Wait for Current Operations
         │
         ├─► Wait for m_scanning = false
         │   (any ongoing scan completes)
         │
         └─► Wait for m_syncing = false
             (any ongoing sync completes)
         │
         ▼
Both Operations Complete
         │
         ▼
Return Success to Caller
```

The resume command is immediate:

```
Resume Command Received
         │
         ▼
Set m_paused = false (atomic flag)
         │
         ▼
Notify Main Loop (m_cv.notify_one())
         │
         ▼
Module Resumes Normal Operations
```

#### Flush Command

**Purpose:** Force immediate synchronization of pending inventory changes, bypassing the normal sync interval.

**Use Cases:**
- Agent shutdown (ensure all inventory is sent before exit)
- Manager-requested immediate inventory update
- Critical inventory changes that need immediate delivery
- Testing and verification operations

**Implementation:**

```
Flush Command Received
         │
         ▼
Check if Sync Protocol Initialized
         │
         ├─► Not Initialized → Return 0 (nothing to flush)
         │
         └─► Initialized
             │
             ▼
Call synchronizeModule(Mode::DELTA)
             │
             ├─► Sends all pending differences
             ├─► Waits for manager acknowledgment
             └─► Returns sync result
```

The flush operation does not wait for an ongoing sync to complete—it triggers a new sync session immediately.

#### Version Management Commands

**Purpose:** Query and set version numbers for tracking scanning operations and coordination state.

**Use Cases:**
- Coordination protocol needs to track which scan produced inventory data
- Manager needs to verify agent scan completion
- Rolling back to a previous inventory state version
- Marking inventory data with specific scan identifiers

**getMaxVersion() Implementation:**

```
getMaxVersion() Called
         │
         ▼
Initialize maxVersion = 0
         │
         ▼
For Each Syscollector Table:
         │
         ├─► Execute: SELECT MAX(version) FROM table
         │
         ├─► Compare result with maxVersion
         │
         └─► Update maxVersion if higher
         │
         ▼
Return maxVersion
```

**setVersion() Implementation:**

```
setVersion(newVersion) Called
         │
         ▼
For Each Syscollector Table:
         │
         ├─► Execute: SELECT * FROM table
         │
         ├─► For Each Row:
         │   │
         │   ├─► Update row with new version
         │   │
         │   └─► Increment counter
         │
         └─► Continue to next table
         │
         ▼
Return Total Rows Updated
```

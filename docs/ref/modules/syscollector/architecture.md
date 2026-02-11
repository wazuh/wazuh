# Architecture

The **Syscollector module** implements a **dual event architecture** designed to provide both immediate alerting and reliable state synchronization for system inventory monitoring. It combines stateless events with persistent stateful events using the Agent Sync Protocol for guaranteed delivery, with enhanced VD Context routing for vulnerability detection integration.

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

**Note on Vulnerability Detector Separation (v5.0+):**

Starting in version 5.0, the Vulnerability Detector (VD) operates as an independent module with its own sync protocol instance. While Syscollector continues to collect inventory data (packages, OS, hotfixes), VD independently handles vulnerability detection and CVE correlation. This architectural change provides:

* **Independent synchronization**: VD has its own sync protocol instance with separate persistent queue
* **DataContext support**: VD uses DataContext messages for vulnerability data synchronization
* **Decoupled operation**: Syscollector and VD can be configured, started, stopped, and synchronized independently
* **Improved scalability**: Each module can optimize its sync strategy based on its data characteristics

### **VD Context Integration (v5.0+)**

Syscollector integrates with the Vulnerability Detector through a dual database system and context-aware event routing.
Responsibilities:

* **Context Evaluation**: Determines whether inventory data requires VD processing via `is_data_context` parameter
* **Dual Database Management**: Maintains separate databases for regular inventory and VD context data
* **DataContext Event Generation**: Creates specialized events for vulnerability detection when context evaluation triggers
* **VD Sync Protocol Coordination**: Routes DataContext events to VD's independent sync protocol instance
* **Context-Aware Persistence**: Uses `persistDifference()` with context flags to route data appropriately
* **VD Database Operations**: Supports VD-specific operations like `getAllEvents()` and `deleteDataContextBatch()`

**VD Context Event Flow Integration:**

```cpp
// VD table detection based on sync index
bool isVDTable = (index == SYSCOLLECTOR_SYNC_INDEX_SYSTEM ||
                  index == SYSCOLLECTOR_SYNC_INDEX_PACKAGES ||
                  index == SYSCOLLECTOR_SYNC_INDEX_HOTFIXES);

if (isVDTable && m_spSyncProtocolVD) {
    // Route to VD sync protocol
    m_spSyncProtocolVD->persistDifference(id, operation, index, data, version, isDataContext);
} else if (m_spSyncProtocol) {
    // Route to regular sync protocol
    m_spSyncProtocol->persistDifference(id, operation, index, data, version, isDataContext);
}
```

**Key VD Context Features:**
- **VD Table Detection**: Automatic routing based on sync index (system, packages, hotfixes)
- **Dual Sync Protocols**: Separate `m_spSyncProtocolVD` for VD tables vs `m_spSyncProtocol` for regular inventory
- **DataContext Processing**: Post-scan processing via `processVDDataContext()` method
- **Platform-Specific Rules**: `getDataContextTables()` determines context inclusion based on platform and operation
- **VD Context Batch Operations**: Support for `clearAllDataContext()` and context table fetching

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

### **Document Limits**

Syscollector implements an inventory limit mechanism to control the number of synchronized items per inventory type. This feature allows the manager to limit resource consumption by restricting how many items are synced to the indexer.

**Configuration:**
- Document limits are received from the manager during agent handshake
- Limits are applied per inventory index (packages, processes, ports, etc.)
- Value of `0` means unlimited (all items are synchronized)
- Non-zero values enforce a maximum number of synchronized items

**Synchronization Control:**

Each inventory item has a `sync` flag in the database:
- `sync=1`: Item is synchronized and will generate events
- `sync=0`: Item is stored locally but not synchronized

**Limit Enforcement Flow:**

```
Inventory Scan Detects Item
         │
         ▼
Check Document Limit
         │
         ├─► Limit = 0 (unlimited) ──────► Set sync=1 ──────► Generate Event
         │
         └─► Limit > 0 (limited)
                  │
                  ├─► Count < Limit ──────► Set sync=1 ──────► Generate Event
                  │
                  └─► Count >= Limit ─────► Set sync=0 ──────► Store Locally (no event)
```

**Promotion Mechanism:**

When limits increase or items are deleted, pending items (sync=0) are promoted:

```cpp
// Triggered when:
// 1. Document limit increases
// 2. Document limit changes to unlimited
// 3. Synced item is deleted (frees a slot)

promoteUnsyncedItems(index, tableName, availableSlots, reason);
         │
         ├─► Select unsynced items: WHERE sync=0 ORDER BY primary_key ASC
         ├─► Generate INSERT events for selected items
         └─► Update sync flag: sync=0 → sync=1
```

**Ordering Strategy:**
- Items are promoted in deterministic alphabetical order (COLLATE NOCASE)
- Uses primary key fields for stable ordering (e.g., packages ordered by `name, type`)
- Ensures consistent behavior across agent restarts

**Dynamic Limit Updates:**
- Limits can be updated during agent reconnection
- If new limits differ from previous limits and agent auto-restart is enabled, the agent reloads modules
- Limit changes are logged with promotion/demotion details

---

## Event Flow Architecture

### Complete Syscollector Event Flow with VD Context Integration

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
         └─► Generate Stateful Event ──────► persistDifference()
                                                      │
                                                      ▼
                                              VD Table Detection
                                                      │
                                                      ├─► VD Table (OS/Packages/Hotfixes) ──────► VD Sync Protocol
                                                      │
                                                      └─► Regular Table ──────► Regular Sync Protocol Database
                                                                                         │
                                                                                         ▼
                                                                         Periodic Sync Thread (syncLoop)
                                                                                         │
                                                                                         └─► syncModule()
                                                                                                  │
                                                                                                  ▼
                                                                                               Manager
         │
         ▼
Scan Completion
         │
         ▼
processVDDataContext() ──────► getDataContextTables() ──────► Fetch Context Data ──────► VD Sync Protocol
         │                              │                             │
         ├─► clearAllDataContext()      ├─► Platform Rules            └─► DataContext Events
         ├─► fetchPendingItems()        └─► OS → packages
         └─► fetchAllFromTable()              packages → OS + hotfixes (Windows)
                                              hotfixes → OS + packages (Windows)
```

---

## Dual Event System with VD Context Routing

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

### Stateful Events (Synchronization State) with VD Context Routing

Generated with complete data including checksums and persisted for synchronization:

```cpp
if (m_persistDiffFunction) {
    std::string id = calculateHashId(data, table);
    std::string index = getSyncIndexForTable(table);
    m_persistDiffFunction(id, operation, index, data.dump());
}
```

**VD Context Routing for Stateful Events:**

```cpp
// VD table routing based on sync index
bool isVDTable = (index == SYSCOLLECTOR_SYNC_INDEX_SYSTEM ||
                  index == SYSCOLLECTOR_SYNC_INDEX_PACKAGES ||
                  index == SYSCOLLECTOR_SYNC_INDEX_HOTFIXES);

if (isVDTable && m_spSyncProtocolVD) {
    m_spSyncProtocolVD->persistDifference(id, operation, index, data, version, isDataContext);
} else {
    m_spSyncProtocol->persistDifference(id, operation, index, data, version, isDataContext);
}
```

**Characteristics:**
- Include complete inventory metadata and checksums
- Persisted to sync protocol database
- Survive agent restarts and network failures
- Synchronized periodically with manager
- **VD-relevant tables** (OS, packages, hotfixes) are routed to VD sync protocol
- **Regular tables** continue using standard sync protocol
- Use specific sync indexes for each inventory type

### VD DataContext Processing (Post-Scan)

Additional context data generated after scan completion for VD analysis:

Additional context data generated after scan completion for VD analysis:

```cpp
void Syscollector::processVDDataContext() {
    // Clear previous DataContext
    m_spSyncProtocolVD->clearAllDataContext();
    
    // Get pending DataValue items
    std::vector<PersistedData> pendingDataValues = m_spSyncProtocolVD->fetchPendingItems(true);
    
    // Determine context tables needed based on platform rules
    std::vector<std::string> contextTables = getDataContextTables(operation, index);
    
    // Fetch and submit context data
    for (const auto& item : contextItems) {
        m_spSyncProtocolVD->persistDifference(itemId, Operation::MODIFY, contextIndex, item.dump(), 0, true);
    }
}
```

**Characteristics:**
- **Post-scan processing** via `processVDDataContext()` method
- **Platform-specific rules** via `getDataContextTables()` determine context inclusion
- **DataContext flag** (`isDataContext=true`) marks context vs regular data
- **Context data routing** to VD sync protocol for vulnerability analysis
- **Exclusion logic** prevents duplicate data submission

---

## Recovery Flow

The Syscollector module includes automatic recovery to detect and resolve synchronization inconsistencies between the agent and manager:

### Recovery Mechanism

1. **Periodic Integrity Checks**: Each time the `integrity_interval` elapses, Syscollector performs an integrity check for each enabled inventory table
2. **Checksum Calculation**: Agent calculates checksum-of-checksums from each inventory table
3. **Manager Validation**: Checksum is sent to manager via `requiresFullSync()` in Agent Sync Protocol
4. **Comparison**: Manager compares agent checksum with its indexed data
5. **Recovery Trigger**: On checksum mismatch, full recovery is initiated for that specific table
6. **Timestamp Tracking**: `last_sync_time` is stored in `table_metadata` table per inventory type

### Recovery Process

When a checksum mismatch is detected for a table:

1. **Version Increment**: All entries in the table have their version incremented by 1
   - Uses DBSync's `increaseEachEntryVersion()` method
2. **Data Extraction**: All elements are retrieved from the affected table using `getEverySyncElement()`
3. **Memory Preparation**: In-memory sync data is cleared via `clearInMemoryData()`
4. **Stateful Message Rebuild**: Each inventory item is:
   - Converted to ECS format
   - Wrapped in stateful message structure
   - Persisted to sync protocol memory with CREATE operation
5. **Full Synchronization**: A FULL mode synchronization is triggered
   - Sends all data for the affected table to manager
   - Manager replaces its entire state for that index
6. **Timestamp Update**: `last_sync_time` is updated to current timestamp

### Recovery Flow Diagram

```
Main Scanning Loop (syncLoop)
         │
         ▼
Periodic Scan Execution
         │
         ▼
Check if integrity_interval elapsed for each table
         │
         ├─► No  → Skip integrity check for this table
         │
         └─► Yes → Calculate table checksum
                   │
                   ▼
             Send checksum to manager (requiresFullSync)
                   │
                   ├─► Match    → No action needed, update last_sync_time
                   │
                   └─► Mismatch → Perform full recovery for this table
                                  │
                                  ├─► Lock scan mutex (prevent concurrent scans)
                                  ├─► Increase version for all entries
                                  ├─► Load all elements from table
                                  ├─► Clear in-memory sync data
                                  ├─► Rebuild stateful messages
                                  ├─► Trigger FULL synchronization
                                  ├─► Update last_sync_time
                                  └─► Unlock scan mutex
```

### Configuration

Recovery behavior is controlled by the `integrity_interval` parameter:

```xml
<wodle name="syscollector">
    <synchronization>
        <integrity_interval>86400</integrity_interval>  <!-- 24 hours -->
    </synchronization>
</wodle>
```

**Default**: 86400 seconds (24 hours)
**Minimum**: 60 seconds (1 minute)
**Disabled**: Set to 0 to disable integrity checks

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

Each inventory type is synchronized with its specific index, with certain types also supporting VD context routing:

| Inventory Type | Database Table | Sync Protocol Index | VD Context Support |
|----------------|----------------|-------------------|-------------------|
| Hardware | `dbsync_hwinfo` | `wazuh-states-inventory-hardware` | No |
| OS | `dbsync_osinfo` | `wazuh-states-inventory-system` | **Yes** → VD Sync Protocol |
| Packages | `dbsync_packages` | `wazuh-states-inventory-packages` | **Yes** → VD Sync Protocol |
| Processes | `dbsync_processes` | `wazuh-states-inventory-processes` | No |
| Ports | `dbsync_ports` | `wazuh-states-inventory-ports` | No |
| Users | `dbsync_users` | `wazuh-states-inventory-users` | No |
| Groups | `dbsync_groups` | `wazuh-states-inventory-groups` | No |
| Services | `dbsync_services` | `wazuh-states-inventory-services` | No |
| Browser Extensions | `dbsync_browser_extensions` | `wazuh-states-inventory-browser-extensions` | No |
| Hotfixes | `dbsync_hotfixes` | `wazuh-states-inventory-hotfixes` | **Yes** → VD Sync Protocol |
| Network Interfaces | `dbsync_network_iface` | `wazuh-states-inventory-interfaces` | No |
| Network Protocols | `dbsync_network_protocol` | `wazuh-states-inventory-protocols` | No |
| Network Address | `dbsync_network_address` | `wazuh-states-inventory-networks` | No |

> **VD Context Routing**: OS info, packages, and hotfixes data is automatically routed to the VD module's independent sync protocol instance based on table detection logic in the code, while still generating regular stateful events for inventory synchronization.

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

---

## Schema Validation Integration

Syscollector integrates with the [Schema Validator](../utils/schema-validator/README.md) module to ensure all inventory data conforms to the expected Wazuh indexer schema before transmission.

### Purpose

- **Prevent Indexing Errors**: Validate data before it reaches the indexer
- **Prevent Integrity Sync Loops**: Invalid data is removed from local databases to avoid repeated sync attempts
- **Improve Data Quality**: Ensure all indexed data conforms to expected types and structures
- **Provide Detailed Error Reporting**: Specific field paths and validation failures for debugging

### Validation Points

Schema validation occurs at three critical points in the Syscollector lifecycle:

#### 1. During Scans (notifyChange)

When inventory data changes are detected during scans, validation occurs before queuing to the sync protocol:

```cpp
// Validate data against schema before queuing
bool validationPassed = validateSchemaAndLog(statefulToSend, indexIt->second, context);

if (!validationPassed)
{
    // Don't queue invalid message
    m_logFunction(LOG_ERROR, "Discarding invalid Syscollector message (table: " + table + ")");

    // Mark for deferred deletion from DBSync to prevent integrity sync loops
    if (result == INSERTED || result == MODIFIED)
    {
        m_logFunction(LOG_DEBUG, "Marking entry from table " + table + " for deferred deletion");

        // Store the failed item for deletion after transaction completes
        if (m_failedItems)
        {
            m_failedItems->push_back({table, aux});
        }
    }

    shouldQueue = false;
}
```

**Key characteristics:**
- Validation happens inside DBSync callback (cannot delete immediately)
- Failed items are accumulated in `m_failedItems` vector
- Items marked with INSERT or MODIFIED operations are candidates for deletion

#### 2. After Scan Completion (scan)

Failed items are deleted in a single batch transaction after all scans complete:

```cpp
// Delete all items that failed schema validation inside a DBSync transaction
deleteFailedItemsFromDB(failedItems);
```

**Implementation:**
```cpp
void Syscollector::deleteFailedItemsFromDB(
    const std::vector<std::pair<std::string, nlohmann::json>>& failedItems) const
{
    if (failedItems.empty() || !m_spDBSync)
    {
        return;
    }

    try
    {
        // Create a transaction scope
        DBSyncTxn deleteTxn(m_spDBSync->handle(), nlohmann::json::array(), 0, 1,
                           [](ReturnTypeCallback, const nlohmann::json&) {});

        // Execute all deletions within the transaction scope
        for (const auto& [tableName, data] : failedItems)
        {
            m_logFunction(LOG_DEBUG, "Deleting entry from table " + tableName +
                         " due to validation failure");

            auto deleteQuery = DeleteQuery::builder()
                               .table(tableName)
                               .data(data)
                               .rowFilter("")
                               .build();

            m_spDBSync->deleteRows(deleteQuery.query());
        }

        // Finalize transaction to commit changes
        deleteTxn.getDeletedRows([](ReturnTypeCallback, const nlohmann::json&) {});

        m_logFunction(LOG_DEBUG, "Deleted " + std::to_string(failedItems.size()) +
                     " item(s) from DBSync due to validation failure");
    }
    catch (const std::exception& e)
    {
        m_logFunction(LOG_ERROR, "Failed to create DBSync transaction for deletion: " +
                     std::string(e.what()));
    }
}
```

**Key characteristics:**
- Uses DBSync transaction for atomicity
- All deletions committed together
- Prevents integrity sync loops

#### 3. During Recovery (runRecoveryProcess)

When performing integrity recovery, only valid items are synchronized:

```cpp
// Validate stateful event before persisting for recovery
bool validationPassed = validateSchemaAndLog(statefulToSend, index, context);

if (!validationPassed)
{
    m_logFunction(LOG_DEBUG, "Skipping persistence of invalid recovery event");
    shouldPersist = false;
}

if (shouldPersist)
{
    m_spSyncProtocol->persistDifferenceInMemory(
        calculateHashId(item, tableName),
        Operation::CREATE,
        index,
        statefulToSend,
        item["version"].get<uint64_t>()
    );
}
```

**Key characteristics:**
- Validation before in-memory persistence
- Invalid items are skipped (not persisted)
- Prevents synchronizing invalid recovery data

### Helper Functions

Two helper functions encapsulate common validation and deletion patterns:

#### validateSchemaAndLog()

Validates a JSON message against a schema and logs detailed error information:

```cpp
bool Syscollector::validateSchemaAndLog(const std::string& data,
                                        const std::string& index,
                                        const std::string& context) const;
```

**Behavior:**
- Returns `true` if validation passed or validator not initialized
- Returns `false` if validation failed
- Logs detailed error messages with field paths and expected types
- Logs raw event data for debugging

#### deleteFailedItemsFromDB()

Deletes failed items from DBSync in a batch transaction:

```cpp
void Syscollector::deleteFailedItemsFromDB(
    const std::vector<std::pair<std::string, nlohmann::json>>& failedItems) const;
```

**Behavior:**
- Creates DBSync transaction for atomicity
- Deletes all failed items in a single transaction
- Logs number of items deleted
- Handles deletion errors gracefully

### Supported Indices

Syscollector validates data for the following Wazuh indices:

| Table Name | Index Pattern | Description |
|------------|---------------|-------------|
| `dbsync_hwinfo` | `wazuh-states-inventory-hardware` | Hardware information |
| `dbsync_osinfo` | `wazuh-states-inventory-system` | Operating system details |
| `dbsync_netinfo_iface` | `wazuh-states-inventory-network` | Network interfaces |
| `dbsync_netinfo_proto` | `wazuh-states-inventory-network` | Network protocols |
| `dbsync_netinfo_addr` | `wazuh-states-inventory-network` | Network addresses |
| `dbsync_packages` | `wazuh-states-inventory-packages` | Installed packages |
| `dbsync_hotfixes` | `wazuh-states-inventory-hotfixes` | System hotfixes (Windows) |
| `dbsync_ports` | `wazuh-states-inventory-ports` | Open network ports |
| `dbsync_processes` | `wazuh-states-inventory-processes` | Running processes |

### Deferred Deletion Pattern

Syscollector uses a deferred deletion pattern to safely remove invalid entries:

**Flow:**

```
1. Initialize Scan
   │
   ├─► Create failedItems vector
   │
   ├─► Set m_failedItems = &failedItems
   │
   ▼
2. Process Scans
   │
   ├─► For each inventory change:
   │   │
   │   ├─► Validate against schema
   │   │
   │   ├─► If validation fails:
   │   │   │
   │   │   ├─► Log error
   │   │   │
   │   │   └─► Add to failedItems vector
   │   │
   │   └─► If validation passes:
   │       │
   │       └─► Queue to sync protocol
   │
   ▼
3. After All Scans
   │
   ├─► Set m_failedItems = nullptr
   │
   ├─► deleteFailedItemsFromDB(failedItems)
   │   │
   │   ├─► Create DBSync transaction
   │   │
   │   ├─► Delete all failed items
   │   │
   │   └─► Commit transaction
   │
   ▼
4. Complete
```

**Why Deferred?**
- **Avoids nested transactions**: Cannot delete during DBSync callback
- **Improves performance**: Single batch transaction instead of multiple deletes
- **Ensures atomicity**: All deletions committed together or rolled back

### Error Handling

**Initialization:**
```
[INFO] Schema validator initialized successfully from embedded resources
```

**Validation Failure:**
```
[ERROR] Schema validation failed for Syscollector message (table: dbsync_packages, index: wazuh-states-inventory-packages). Errors:
  - Field 'package.version' expected type 'keyword', got 'object'
[ERROR] Raw event that failed validation: {"package":{"version":{"major":1}}}
[ERROR] Discarding invalid Syscollector message (table: dbsync_packages)
[DEBUG] Marking entry from table dbsync_packages for deferred deletion due to validation failure
```

**Batch Deletion:**
```
[DEBUG] Deleted 3 item(s) from DBSync due to validation failure
```

**Graceful Degradation:**

If the schema validator is not initialized:
- Validation is skipped
- Data is processed normally
- A warning is logged on startup:
  ```
  [WARNING] Failed to initialize schema validator. Schema validation will be disabled.
  ```

### Performance Considerations

- **Deferred Deletion**: Batch transaction minimizes database overhead
- **Validation Caching**: Validators are obtained once per scan and reused
- **Early Exit**: Validation happens before queuing (saves sync protocol overhead)
- **Graceful Degradation**: Validation can be disabled without affecting core functionality

### Integration Status

**Integration points:**
- Module initialization (`syscollectorImp.cpp`)
- Scan processing (`syscollectorImp.cpp`)
- Batch deletion (`syscollectorImp.cpp`)
- VD DataContext processing (`syscollectorImp.cpp`)
- Recovery process (`syscollectorImp.cpp`)

### References

- [Schema Validator Overview](../utils/schema-validator/README.md)
- [Schema Validator API Reference](../utils/schema-validator/api-reference.md)
- [Schema Validator Integration Guide](../utils/schema-validator/integration-guide.md)

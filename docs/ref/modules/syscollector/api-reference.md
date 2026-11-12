# API Reference

The Syscollector module integrates with the Agent Sync Protocol through the C++ interface exposed by the `agent_sync_protocol` module.

---

## Agent Sync Protocol C++ Interface

Syscollector uses the sync protocol C++ interface defined in `iagent_sync_protocol.hpp` provided by the `agent_sync_protocol` module.

### Core Interface

#### `IAgentSyncProtocol` Class

The main interface for Agent Sync Protocol operations.

**Include:**
```cpp
#include "iagent_sync_protocol.hpp"
```

### Initialization Methods

#### `initSyncProtocol()`

Initializes the Agent Sync Protocol for Syscollector.

**Signature:**
```cpp
void Syscollector::initSyncProtocol(const std::string& moduleName,
                                    const std::string& syncDbPath,
                                    const std::string& syncDbPathVD,
                                    uint32_t integrityInterval);
```

**Parameters:**
- `moduleName`: Module name (`"syscollector"`). The VD instance uses `moduleName + "_vd"`
- `syncDbPath`: Path to the sync protocol database
- `syncDbPathVD`: Path to the sync protocol database of the VD instance
- `integrityInterval`: Seconds between integrity checks of each table

**Usage Example:**
```cpp
// Initialize sync protocol in Syscollector (called through syscollector_init_sync())
Syscollector::instance().initSyncProtocol("syscollector",
                                          "queue/syscollector/db/syscollector_sync.db",
                                          "queue/syscollector/db/syscollector_vd_sync.db",
                                          integrity_interval);
```

### Synchronization Methods

#### `syncModule()`

Triggers synchronization of all pending inventory differences.

**Signature:**
```cpp
SyncModuleResult Syscollector::syncModule(Mode mode);
```

**Parameters:**
- `mode`: Sync mode

**Returns:**
- `SyncModuleResult` whose `success` field is `true` if synchronization succeeded and `false` otherwise, including when it is skipped because the module is paused, stopping, flushing or running a DataClean

**Usage Example:**
```cpp
// Syscollector sync thread triggers periodic synchronization
bool sync_success = Syscollector::instance().syncModule(Mode::DELTA).success;
```

#### `persistDifference()`

Persists an inventory difference for later synchronization.

**Signature:**
```cpp
void Syscollector::persistDifference(const std::string& id,
                                     Operation operation,
                                     const std::string& index,
                                     const std::string& data,
                                     uint64_t version,
                                     bool isDataContext = false);
```

**Parameters:**
- `id`: Unique identifier (calculated hash of inventory item)
- `operation`: Operation type (`Operation::CREATE`, `Operation::MODIFY`, `Operation::DELETE_`)
- `index`: Sync index name for the inventory type
- `data`: JSON string containing inventory data
- `version`: Version of the data
- `isDataContext`: `true` to queue the item as DataContext instead of DataValue

**Usage Example:**
```cpp
void Syscollector::processEvent(ReturnTypeCallback result,
                                const nlohmann::json& data,
                                const std::string& table) {
    if (m_persistDiffFunction) {
        std::string id = calculateHashId(data, table);
        Operation operation = getOperationFromResult(result);
        std::string index = getIndexForTable(table);
        auto [newData, version] = ecsData(data, table);

        // Persist the difference for synchronization
        persistDifference(id, operation, index, newData.dump(), version);
    }
}
```

#### `parseResponseBuffer()`

Processes FlatBuffer responses from the manager.

**Signature:**
```cpp
bool Syscollector::parseResponseBuffer(const uint8_t* data, size_t length);
```

**Parameters:**
- `data`: Pointer to FlatBuffer-encoded message
- `length`: Size of message in bytes

**Returns:**
- `true` if parsing succeeded
- `false` if parsing failed

**Usage Example:**
```cpp
// Process FlatBuffer responses from manager via syscom
bool success = Syscollector::instance().parseResponseBuffer(response_data,
                                                            response_length);
```

#### `notifyDataClean()`

Notifies the manager that specific inventory indices have been cleaned and should be removed.

**Signature:**
```cpp
bool Syscollector::notifyDataClean(const std::vector<std::string>& indices);
```

**Parameters:**
- `indices`: Vector of index names to clean

**Returns:**
- `true` if notification succeeded
- `false` if notification failed

**Usage Example:**
```cpp
// Notify data clean for disabled inventory components
std::vector<std::string> indices_to_clean = {
    SYSCOLLECTOR_SYNC_INDEX_PACKAGES,
    SYSCOLLECTOR_SYNC_INDEX_PROCESSES,
    SYSCOLLECTOR_SYNC_INDEX_PORTS
};

bool notify_success = Syscollector::instance().notifyDataClean(indices_to_clean);
```

#### `deleteDatabase()`

Deletes both the sync protocol database and the Syscollector DBSync database.

**Signature:**
```cpp
void Syscollector::deleteDatabase();
```

**Description:**

Removes both the Agent Sync Protocol database and the Syscollector inventory database from disk. This method should be called when the Syscollector module is disabled or when a complete cleanup is required. Typically called after successfully notifying the manager with `notifyDataClean()`.

**Databases Deleted:**
- Sync protocol database: Persistent queue and sync state
- DBSync database: Local inventory data (packages, processes, ports, etc.)

**Usage Example:**
```cpp
// Delete databases when Syscollector is disabled
Syscollector::instance().deleteDatabase();
```

---

## Coordination Commands

The coordination commands allow external control of Syscollector operations for coordination with the manager or other modules. `pause()` blocks until the module is idle; `flush()` is **asynchronous**: it only starts the synchronization in a background worker, and the caller polls `is_flush_completed` for the outcome.

### Pause and Resume Operations

#### `pause()`

Pauses the Syscollector module by waiting for ongoing scanning and synchronization operations to complete, then preventing new operations from starting.

**Signature:**
```cpp
bool Syscollector::pause();
```

**Returns:**
- `true` if module was paused successfully
- `false` if pause was interrupted by shutdown

**Description:**

This method sets the pause flag and waits for both scanning (`m_scanning`) and synchronization (`m_syncing`) operations to complete before returning. Once paused, no new scan or sync operations will start until `resume()` is called. This is useful for coordinating module operations during agent reconfigurations or manager-requested pauses.

**Behavior:**
- Sets the internal pause flag (`m_paused = true`)
- Waits for ongoing scan operations to finish
- Waits for ongoing sync operations to finish
- Returns when both operations are complete or if the module is shutting down

**Usage Example:**
```cpp
// Pause Syscollector operations
bool success = Syscollector::instance().pause();
if (success) {
    // Module successfully paused, safe to perform maintenance
} else {
    // Pause interrupted by shutdown
}
```

#### `resume()`

Resumes the Syscollector module after a pause, allowing scanning and synchronization operations to continue.

**Signature:**
```cpp
void Syscollector::resume();
```

**Description:**

Clears the pause flag and notifies the main loop to continue operations. After calling this method, pending scans and synchronizations will resume according to the configured intervals.

**Usage Example:**
```cpp
// Resume Syscollector operations
Syscollector::instance().resume();
```

---

### Synchronization Control

#### `flush()`

Requests an immediate synchronization of the pending inventory differences with the manager. It does **not** wait for it: the synchronization runs in a background worker (`Utils::AsyncFlushController`).

**Signature:**
```cpp
int Syscollector::flush();
```

**Returns:**
- `0` if the flush request was accepted: a background flush was started, or one was already running and is kept
- `-1` if the async flush controller does not exist

A return of `0` does not mean the data reached the manager. Poll `is_flush_completed` for that.

**Description:**

Starts the blocking flush work, `executeFlushSync()`, on a worker thread and returns at once. This bypasses the normal synchronization interval, which is useful when inventory state must be delivered promptly, for example during agent-info's coordination after an agent ID change. A caller that needs the data delivered (for example, before shutdown) must wait until `is_flush_completed` reports `completed`.

**Behavior of the background work (`executeFlushSync()`):**
- If neither the inventory nor the vulnerability-detection sync protocol is initialized, it ends successfully (nothing to flush)
- Otherwise, it waits for any synchronization or recovery already in progress (such as a resend of every table after an agent ID change) and keeps new ones from starting until it is done
- If the module stops while it waits, it ends with an error
- Calls `synchronizeModule()` with `Mode::DELTA` on the inventory sync protocol, which sends at most `agent.sync_max_blocks_per_cycle` blocks and leaves anything else queued for the next cycle
- Synchronizes the vulnerability-detection tables in `Mode::DELTA` (`synchronizeVDTables()`), with `Option::VDFIRST`/`Option::VDSYNC`, which carry the whole queue, or with `Option::SYNC` when VD scanning is disabled
- Ends successfully only if both synchronizations succeed, with an error otherwise

**Usage Example:**
```cpp
// Request a flush (asynchronous - returns before the data is sent)
if (Syscollector::instance().flush() != 0) {
    // Request rejected: no flush controller
}
// Then poll the "is_flush_completed" command until its status is "completed"
```

#### `is_flush_completed` command

Reports the state of the last flush requested with `flush()`. It is a coordination command, sent as a JSON query (`{"command": "is_flush_completed"}`) and answered without blocking.

**Response:**
- `error`: always `0` (`MQ_SUCCESS`)
- `data.module`: `"syscollector"`
- `data.status`: `"in_progress"` while the background flush runs, `"completed"` otherwise
- `data.result` (only with `"completed"`): `"success"` or `"error"`, the outcome of the last flush

If no flush has run yet, the status is `"completed"` with result `"success"`, meaning there is nothing left to wait for.

---

### Version Management

The version management methods allow querying and setting version numbers across all Syscollector inventory tables. These versions are used by the coordination system to track scanning operations and synchronization state.

#### `getMaxVersion()`

Retrieves the maximum version number across all Syscollector inventory tables.

**Signature:**
```cpp
int Syscollector::getMaxVersion();
```

**Returns:**
- The maximum version number found across all tables (≥ 0)
- `-1` if an error occurred (e.g., DBSync not initialized)

**Description:**

Queries all Syscollector tables (hardware, OS, packages, processes, ports, etc.) to find the highest version number. This is useful for determining the current state version before performing coordination operations.

**Tables Queried:**
- `dbsync_hwinfo` (hardware)
- `dbsync_osinfo` (OS)
- `dbsync_packages` (packages)
- `dbsync_processes` (processes)
- `dbsync_ports` (ports)
- `dbsync_network_iface` (network interfaces)
- `dbsync_network_protocol` (network protocols)
- `dbsync_network_address` (network addresses)
- `dbsync_hotfixes` (Windows hotfixes)
- `dbsync_users` (system users)
- `dbsync_groups` (system groups)
- `dbsync_services` (system services)
- `dbsync_browser_extensions` (browser extensions)

**Usage Example:**
```cpp
// Get current maximum version
int currentVersion = Syscollector::instance().getMaxVersion();
if (currentVersion >= 0) {
    // Use version for coordination
} else {
    // Error getting version
}
```

#### `setVersion()`

Sets the version number for all rows across all Syscollector inventory tables.

**Signature:**
```cpp
int Syscollector::setVersion(int version);
```

**Parameters:**
- `version`: The version number to set for all inventory items

**Returns:**
- Total number of rows updated across all tables (≥ 0)
- `-1` if an error occurred (e.g., DBSync not initialized)

**Description:**

Updates the version field for every row in all Syscollector tables. This is used by the coordination system to mark all inventory data with a specific version number, allowing the manager to track which scanning operation produced each piece of inventory data.

**Implementation Details:**
- Reads all existing rows from each table
- Updates each row with the new version number
- Uses database transactions for consistency
- Returns total count of updated rows

**Usage Example:**
```cpp
// Set version 42 for all inventory items
int rowsUpdated = Syscollector::instance().setVersion(42);
if (rowsUpdated >= 0) {
    // Version set successfully for rowsUpdated items
} else {
    // Error setting version
}
```

---

## Operation Types

Syscollector uses the following operation types defined in the Agent Sync Protocol:

```cpp
enum class Operation : int {
    CREATE = OPERATION_CREATE,  // 0: New inventory item
    MODIFY = OPERATION_MODIFY,  // 1: Modified inventory item
    DELETE_ = OPERATION_DELETE, // 2: Deleted inventory item
    NO_OP  = OPERATION_NO_OP    // 3: No operation (internal use)
};
```

---

## Database Integration

Syscollector integrates with DBSync for local database operations:

### Database Initialization

```cpp
// Syscollector initializes database through DBSync
std::unique_ptr<DBSync> dbSync = std::make_unique<DBSync>(
    HostType::AGENT,
    DbEngineType::SQLITE3,
    dbPath,
    getCreateStatement()
);

m_spDBSync = std::move(dbSync);
```

### Database Transaction Operations

Syscollector uses database transactions for state comparison:

```cpp
// Update changes in database and process events
void Syscollector::updateChanges(const std::string& table,
                                const nlohmann::json& values) {
    if (m_spDBSync) {
        // Define callback for database transaction results
        auto callback = [this, table](ReturnTypeCallback result,
                                     const nlohmann::json& data) {
            processEvent(result, data, table);
        };

        // Synchronize data with database
        m_spDBSync->syncRowData(table, values, callback);
    }
}
```

---

## Syscom Integration

Syscollector handles manager responses through the syscom interface:

```cpp
// Process sync protocol messages from manager
if (message.find("syscollector_sync:") == 0) {
    const uint8_t *data = reinterpret_cast<const uint8_t *>(
        message.c_str() + strlen("syscollector_sync:")
    );
    size_t data_len = message.length() - strlen("syscollector_sync:");

    bool ret = Syscollector::instance().parseResponseBuffer(data, data_len);
    if (!ret) {
        // Handle parsing error
    }
}
```

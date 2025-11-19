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
                                    MQ_Functions mqFuncs);
```

**Parameters:**
- `moduleName`: Module name (`"syscollector"`)
- `syncDbPath`: Path to sync protocol database
- `mqFuncs`: Message queue function pointers structure

**Usage Example:**
```cpp
// Initialize sync protocol in Syscollector
MQ_Functions mq_funcs = {
    .start = syscollector_startmq,
    .send_binary = syscollector_send_binary_msg
};

Syscollector::instance().initSyncProtocol("syscollector",
                                          SYSCOLLECTOR_SYNC_PROTOCOL_DB_PATH,
                                          mq_funcs);
```

### Synchronization Methods

#### `syncModule()`

Triggers synchronization of all pending inventory differences.

**Signature:**
```cpp
bool Syscollector::syncModule(Mode mode,
                              std::chrono::seconds timeout,
                              unsigned int retries,
                              size_t maxEps);
```

**Parameters:**
- `mode`: Sync mode
- `timeout`: Response timeout in seconds
- `retries`: Maximum retry attempts
- `maxEps`: Maximum events per second (0 = unlimited)

**Returns:**
- `true` if synchronization succeeded
- `false` if synchronization failed

**Usage Example:**
```cpp
// Syscollector sync thread triggers periodic synchronization
bool sync_success = Syscollector::instance().syncModule(
    MODE_DELTA,                           // sync mode
    std::chrono::seconds(timeout_config), // timeout
    SYSCOLLECTOR_SYNC_RETRIES,            // retries
    max_eps_config);                      // max events/sec
```

#### `persistDifference()`

Persists an inventory difference for later synchronization.

**Signature:**
```cpp
void Syscollector::persistDifference(const std::string& id,
                                     Operation operation,
                                     const std::string& index,
                                     const std::string& data);
```

**Parameters:**
- `id`: Unique identifier (calculated hash of inventory item)
- `operation`: Operation type (`OPERATION_CREATE`, `OPERATION_UPDATE`, `OPERATION_DELETE`)
- `index`: Sync index name for the inventory type
- `data`: JSON string containing inventory data

**Usage Example:**
```cpp
void Syscollector::processEvent(ReturnTypeCallback result,
                                const nlohmann::json& data,
                                const std::string& table) {
    if (m_persistDiffFunction) {
        std::string id = calculateHashId(data, table);
        Operation operation = getOperationFromResult(result);
        std::string index = getIndexForTable(table);

        // Persist the difference for synchronization
        persistDifference(id, operation, index, data.dump());
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
bool Syscollector::notifyDataClean(const std::vector<std::string>& indices,
                                   std::chrono::seconds timeout,
                                   unsigned int retries,
                                   size_t maxEps);
```

**Parameters:**
- `indices`: Vector of index names to clean
- `timeout`: Response timeout duration
- `retries`: Maximum retry attempts
- `maxEps`: Maximum events per second (0 = unlimited)

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

bool notify_success = Syscollector::instance().notifyDataClean(
    indices_to_clean,
    std::chrono::seconds(timeout_config),
    SYSCOLLECTOR_SYNC_RETRIES,
    max_eps_config);
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

The coordination commands allow external control of Syscollector operations for coordination with the manager or other modules.

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

Forces an immediate synchronization of all pending inventory differences with the manager.

**Signature:**
```cpp
int Syscollector::flush();
```

**Returns:**
- `0` if flush completed successfully or if sync protocol is not initialized
- Non-zero value if flush failed

**Description:**

Triggers an immediate synchronization session to send all pending inventory changes to the manager, bypassing the normal synchronization interval. This is useful when immediate delivery of inventory state is required, such as before agent shutdown or after critical inventory changes.

**Behavior:**
- Checks if sync protocol is initialized
- If not initialized, returns `0` (not an error, just nothing to flush)
- If initialized, calls `synchronizeModule()` with `Mode::DELTA`
- Returns result of synchronization operation

**Usage Example:**
```cpp
// Flush pending inventory changes immediately
int result = Syscollector::instance().flush();
if (result == 0) {
    // Flush successful or nothing to flush
} else {
    // Flush failed
}
```

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
enum class Operation {
    CREATE = 0,    // New inventory item
    UPDATE = 1,    // Modified inventory item
    DELETE = 2,    // Deleted inventory item
    NO_OP = 3      // No operation (internal use)
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

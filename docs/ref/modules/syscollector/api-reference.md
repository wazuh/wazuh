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

# API Reference

## Overview

The Agent Sync Protocol exposes APIs through both C++ and C interfaces, allowing modules written in different languages to integrate seamlessly. The protocol manages the complete synchronization lifecycle, from persisting differences to handling manager responses.

## C++ Interface

### Headers

```cpp
#include "agent_sync_protocol.hpp"
#include "iagent_sync_protocol.hpp"
#include "agent_sync_protocol_types.hpp"
```

### Class: `AgentSyncProtocol`

Implements the `IAgentSyncProtocol` interface for synchronization operations.

#### Constructor

```cpp
AgentSyncProtocol(const std::string& moduleName,
                   const std::string& dbPath,
                   MQ_Functions mqFuncs,
                   LoggerFunc logger,
                   std::shared_ptr<IPersistentQueue> queue = nullptr)
```

**Parameters:**
- `moduleName`: Unique identifier for the module (e.g., "FIM", "SCA", "Inventory")
- `dbPath`: Full path to the SQLite database file for persistent storage
- `mqFuncs`: Structure containing message queue function pointers
- `logger`: Callback function for logging messages
- `queue`: Optional custom persistent queue implementation

#### Public Methods

##### `persistDifference()`

```cpp
void persistDifference(const std::string& id,
                      Operation operation,
                      const std::string& index,
                      const std::string& data)
```

Persists a data to the internal queue for later synchronization.

**Parameters:**
- `id`: Unique identifier for the data source (typically a hash of primary keys, e.g., file-path)
- `operation`: Type of operation (`Operation::Create`, `Operation::Update`, `Operation::Delete`)
- `index`: Target index or destination for the data
- `data`: JSON string containing the difference data

**Example:**
```cpp
protocol.persistDifference(
    "abc123def456",
    Operation::Create,
    "fim_events",
    "{\"path\": \"/etc/passwd\", \"hash\": \"...\", \"timestamp\": 1234567890}"
);
```

##### `persistDifferenceInMemory()`

```cpp
void persistDifferenceInMemory(const std::string& id,
                               Operation operation,
                               const std::string& index,
                               const std::string& data)
```

Persists a difference to in-memory vector instead of database. This method is used for recovery scenarios where data should be kept in memory.

**Parameters:**
- `id`: Unique identifier for the data item
- `operation`: Type of operation (`Operation::Create`, `Operation::Update`, `Operation::Delete`)
- `index`: Logical index for the data item
- `data`: Serialized content of the message

##### `synchronizeModule()`

```cpp
bool synchronizeModule(Mode mode,
                      std::chrono::seconds timeout,
                      unsigned int retries,
                      size_t maxEps)
```

Initiates a synchronization session with the manager.

**Parameters:**
- `mode`: Synchronization mode (`Mode::Full` or `Mode::Delta`)
- `timeout`: Maximum time to wait for each response
- `retries`: Number of retry attempts for Start and End messages
- `maxEps`: Maximum events per second (0 = unlimited)

**Returns:** `true` if synchronization completed successfully, `false` otherwise

**Example:**
```cpp
bool success = protocol.synchronizeModule(
    Mode::Delta,
    std::chrono::seconds(30),
    3,
    1000
);
```

##### `requiresFullSync()`

```cpp
bool requiresFullSync(const std::string& index,
                     const std::string& checksum,
                     std::chrono::seconds timeout,
                     unsigned int retries,
                     size_t maxEps)
```

Checks if a module index requires full synchronization by verifying the checksum with the manager.

**Parameters:**
- `index`: The index/table to check
- `checksum`: The calculated checksum for the index
- `timeout`: Maximum time to wait for each response
- `retries`: Number of retry attempts
- `maxEps`: Maximum events per second (0 = unlimited)

**Returns:** `true` if full sync is required (checksum mismatch); `false` if integrity is valid or connection error.

##### `clearInMemoryData()`

```cpp
void clearInMemoryData()
```

Clears the in-memory data queue. This method removes all entries from the in-memory vector used for recovery scenarios.

##### `synchronizeMetadataOrGroups()`

```cpp
bool synchronizeMetadataOrGroups(Mode mode,
                                std::chrono::seconds timeout,
                                unsigned int retries,
                                size_t maxEps,
                                uint64_t globalVersion)
```

Synchronizes metadata or groups with the server without sending data. This method handles the following modes: MetadataDelta, MetadataCheck, GroupDelta, GroupCheck. The sequence is: Start → StartAck → End → EndAck (no Data messages).

**Parameters:**
- `mode`: Synchronization mode (must be `Mode::MetadataDelta`, `Mode::MetadataCheck`, `Mode::GroupDelta`, or `Mode::GroupCheck`)
- `timeout`: Timeout duration for waiting for server responses
- `retries`: Number of retry attempts for each message
- `maxEps`: Maximum events per second (0 = unlimited)
- `globalVersion`: Global version to include in the Start message.

**Returns:** `true` if synchronization completed successfully, `false` otherwise

##### `notifyDataClean()`

```cpp
bool notifyDataClean(const std::vector<std::string>& indices,
                     std::chrono::seconds timeout,
                     unsigned int retries,
                     size_t maxEps)
```

Notifies the manager about data cleaning for specified indices. This method sends DataClean messages for each index in the provided vector. The sequence is: Start → StartAck → DataClean (for each index) → End → EndAck. Upon receiving Ok/PartialOk, it clears the local database and returns true.

**Parameters:**
- `indices`: Vector of index names to clean
- `timeout`: Timeout duration for waiting for server responses
- `retries`: Number of retry attempts for each message
- `maxEps`: Maximum events per second (0 = unlimited)

**Returns:** `true` if notification completed successfully and database was cleared, `false` otherwise

**Example:**
```cpp
std::vector<std::string> indices = {"fim_files", "fim_registry"};
bool success = protocol.notifyDataClean(
    indices,
    std::chrono::seconds(30),
    3,
    1000
);
```

##### `deleteDatabase()`

```cpp
void deleteDatabase()
```

Deletes the database file. This method closes the database connection and removes the database file from disk.

**Example:**
```cpp
protocol.deleteDatabase();
```

##### `parseResponseBuffer()`

```cpp
bool parseResponseBuffer(const uint8_t* data, size_t length)
```

Processes FlatBuffer-encoded responses from the manager.

**Parameters:**
- `data`: Pointer to the FlatBuffer message
- `length`: Size of the message in bytes

**Returns:** `true` if message was successfully parsed and processed

## C Interface

### Headers

```c
#include "agent_sync_protocol_c_interface.h"
#include "agent_sync_protocol_c_interface_types.h"
```

### Functions

#### `asp_create()`

```c
AgentSyncProtocolHandle* asp_create(const char* module,
                                   const char* db_path,
                                   const MQ_Functions* mq_funcs,
                                   asp_logger_t logger)
```

Creates a new Agent Sync Protocol instance.

**Parameters:**
- `module`: Module name string
- `db_path`: Database file path
- `mq_funcs`: Pointer to message queue functions structure
- `logger`: Logging callback function

**Returns:** Opaque handle to the protocol instance, or NULL on failure

#### `asp_destroy()`

```c
void asp_destroy(AgentSyncProtocolHandle* handle)
```

Destroys a protocol instance and releases resources.

**Parameters:**
- `handle`: Protocol handle to destroy

#### `asp_persist_diff()`

```c
void asp_persist_diff(AgentSyncProtocolHandle* handle,
                     const char* id,
                     Operation_t operation,
                     const char* index,
                     const char* data)
```

C wrapper for `persistDifference()`.

**Parameters:**
- `handle`: Protocol handle
- `id`: Data source identifier
- `operation`: Operation type (`OPERATION_CREATE`, `OPERATION_MODIFY`, `OPERATION_DELETE`, `OPERATION_NO_OP`)
- `index`: Target index
- `data`: JSON data string

#### `asp_persist_diff_in_memory()`

```c
void asp_persist_diff_in_memory(AgentSyncProtocolHandle* handle,
                                const char* id,
                                Operation_t operation,
                                const char* index,
                                const char* data)
```

C wrapper for `persistDifferenceInMemory()`. Persists a difference to in-memory vector instead of database.

**Parameters:**
- `handle`: Protocol handle
- `id`: Unique identifier for the data item
- `operation`: Operation type (`OPERATION_CREATE`, `OPERATION_MODIFY`, `OPERATION_DELETE`, `OPERATION_NO_OP`)
- `index`: Logical index for the data item
- `data`: Serialized content of the message

#### `asp_sync_module()`

```c
bool asp_sync_module(AgentSyncProtocolHandle* handle,
                    Mode_t mode,
                    unsigned int sync_timeout,
                    unsigned int sync_retries,
                    size_t max_eps)
```

C wrapper for `synchronizeModule()`.

**Parameters:**
- `handle`: Protocol handle
- `mode`: Sync mode (`MODE_FULL` or `MODE_DELTA`)
- `sync_timeout`: Timeout in seconds
- `sync_retries`: Number of retries
- `max_eps`: Maximum events per second

**Returns:** `true` on success, `false` on failure

#### `asp_requires_full_sync()`

```c
bool asp_requires_full_sync(AgentSyncProtocolHandle* handle,
                            const char* index,
                            const char* checksum,
                            unsigned int sync_timeout,
                            unsigned int sync_retries,
                            size_t max_eps)
```

C wrapper for `requiresFullSync()`. Checks if a module index requires full synchronization.

**Parameters:**
- `handle`: Protocol handle
- `index`: The index/table to check
- `checksum`: The calculated checksum for the index
- `sync_timeout`: Timeout in seconds
- `sync_retries`: Number of retries
- `max_eps`: Maximum events per second

**Returns:** `true` if full sync is required (checksum mismatch); `false` if integrity is valid

#### `asp_clear_in_memory_data()`

```c
void asp_clear_in_memory_data(AgentSyncProtocolHandle* handle)
```

C wrapper for `clearInMemoryData()`. Clears the in-memory data queue.

**Parameters:**
- `handle`: Protocol handle

#### `asp_sync_metadata_or_groups()`

```c
bool asp_sync_metadata_or_groups(AgentSyncProtocolHandle* handle,
                                 Mode_t mode,
                                 unsigned int sync_timeout,
                                 unsigned int sync_retries,
                                 size_t max_eps,
                                 uint64_t global_version)
```

C wrapper for `synchronizeMetadataOrGroups()`. Synchronizes metadata or groups with the server without sending data.

**Parameters:**
- `handle`: Protocol handle
- `mode`: Sync mode (`MODE_METADATA_DELTA`, `MODE_METADATA_CHECK`, `MODE_GROUP_DELTA`, or `MODE_GROUP_CHECK`)
- `sync_timeout`: Timeout in seconds
- `sync_retries`: Number of retries
- `max_eps`: Maximum events per second
- `global_version`: Global version to include in the Start message.

**Returns:** `true` on success, `false` on failure

#### `asp_notify_data_clean()`

```c
bool asp_notify_data_clean(AgentSyncProtocolHandle* handle,
                           const char** indices,
                           size_t indices_count,
                           unsigned int sync_timeout,
                           unsigned int sync_retries,
                           size_t max_eps)
```

C wrapper for `notifyDataClean()`. Notifies the manager about data cleaning for specified indices. This function sends DataClean messages for each index in the provided array. The sequence is: Start → StartAck → DataClean (for each index) → End → EndAck. Upon receiving Ok/PartialOk, it clears the local database and returns true.

**Parameters:**
- `handle`: Protocol handle
- `indices`: Array of index name strings to clean
- `indices_count`: Number of indices in the array
- `sync_timeout`: Timeout in seconds
- `sync_retries`: Number of retries
- `max_eps`: Maximum events per second

**Returns:** `true` if notification completed successfully and database was cleared, `false` otherwise

**Example:**
```c
const char* indices[] = {"fim_files", "fim_registry"};
bool success = asp_notify_data_clean(
    handle,
    indices,
    2,
    30,
    3,
    1000
);
```

#### `asp_delete_database()`

```c
void asp_delete_database(AgentSyncProtocolHandle* handle)
```

C wrapper for `deleteDatabase()`. Deletes the database file. This function closes the database connection and removes the database file from disk.

**Parameters:**
- `handle`: Protocol handle

**Example:**
```c
asp_delete_database(handle);
```

#### `asp_parse_response_buffer()`

```c
bool asp_parse_response_buffer(AgentSyncProtocolHandle* handle,
                              const uint8_t* data,
                              size_t length)
```

C wrapper for `parseResponseBuffer()`.

## Type Definitions

### Enumerations

#### `Operation` / `Operation_t`

```cpp
enum class Operation {
    Create,
    Update,
    Delete
};
```

```c
typedef enum {
    OPERATION_CREATE = 0,
    OPERATION_MODIFY = 1,
    OPERATION_DELETE = 2,
    OPERATION_NO_OP  = 3
} Operation_t;
```

#### `Mode` / `Mode_t`

```cpp
enum class Mode {
    FULL,               // Full synchronization mode
    DELTA,              // Delta synchronization mode
    CHECK,              // Integrity check mode
    METADATA_DELTA,     // Metadata delta synchronization mode
    METADATA_CHECK,     // Metadata integrity check mode
    GROUP_DELTA,        // Group delta synchronization mode
    GROUP_CHECK         // Group integrity check mode
};
```

```c
typedef enum {
    MODE_FULL,
    MODE_DELTA,
    MODE_CHECK,
    MODE_METADATA_DELTA,
    MODE_METADATA_CHECK,
    MODE_GROUP_DELTA,
    MODE_GROUP_CHECK
} Mode_t;
```

### Callback Types

#### Logger Function

```cpp
using LoggerFunc = std::function<void(int level, const std::string& message)>;
```

```c
typedef void (*asp_logger_t)(modules_log_level_t level, const char* message);
```

Where `modules_log_level_t` is an enumeration for logging levels (typically defined in `logging_helper.h`).

#### Message Queue Functions

```c
typedef struct MQ_Functions {
    mq_start_fn start;
    mq_send_binary_fn send_binary;
} MQ_Functions;
```

Where the function pointers are defined as:

```c
typedef int (*mq_start_fn)(const char* key, short type, short attempts);
typedef int (*mq_send_binary_fn)(int queue, const void* message, size_t message_len,
                                 const char* locmsg, char loc);
```

**Function Parameters:**

`mq_start_fn`:
- `key`: The identifier key for the message queue
- `type`: The type of queue or message
- `attempts`: The number of connection attempts
- Returns: 0 on success, non-zero on failure

`mq_send_binary_fn`:
- `queue`: The queue identifier
- `message`: The message payload to send
- `message_len`: The length of the message payload in bytes
- `locmsg`: Additional location/context message (optional)
- `loc`: A character representing the message location or type
- Returns: 0 on success, non-zero on failure

## Error Handling

The protocol uses logging callbacks to report errors. Common error scenarios include:

- **Database errors**: Failed to open/write to SQLite database
- **Queue errors**: Message queue unavailable or full
- **Network errors**: Timeout waiting for manager response
- **Protocol errors**: Invalid message format or unexpected response

Errors are logged with appropriate severity levels:
- `0`: Debug
- `1`: Info
- `2`: Warning
- `3`: Error

## Thread Safety

The Agent Sync Protocol is designed to be thread-safe:

- Multiple threads can call `persistDifference()` concurrently
- Only one synchronization session (`synchronizeModule()`) should be active at a time
- Response parsing (`parseResponseBuffer()`) is synchronized internally

## Memory Management

### C++ Interface
- Uses RAII and smart pointers for automatic memory management
- No manual cleanup required except for destroying the instance

### C Interface
- Caller must explicitly call `asp_destroy()` to release resources
- String parameters are copied internally; caller retains ownership
- Buffer parameters for responses must remain valid during function calls

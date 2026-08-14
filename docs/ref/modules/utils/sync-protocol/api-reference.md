# API Reference

## Overview

The Agent Sync Protocol exposes APIs through both C++ and C interfaces, allowing modules written in different languages to integrate seamlessly. The protocol manages the complete synchronization lifecycle, from persisting differences to handling manager responses. On the wire, a whole session (data and all) crosses as one `FullSession` FlatBuffer message and the manager answers with one `EndAck` — see [Protocol Lifecycle](lifecycle.md) for the message-level detail.

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
                  std::optional<std::string> dbPath,
                  LoggerFunc logger,
                  std::shared_ptr<IPersistentQueue> queue = nullptr,
                  std::shared_ptr<ISyncSessionTransport> syncTransport = nullptr)
```

**Parameters:**
- `moduleName`: Unique identifier for the module (e.g., "fim", "sca", "syscollector")
- `dbPath`: Full path to the SQLite database file for persistent storage, or `std::nullopt` for in-memory-only synchronization
- `logger`: Callback function for logging messages
- `queue`: Optional custom persistent queue implementation (mainly for testing)
- `syncTransport`: Optional custom carrier for whole sessions (mainly for testing); defaults to `SyncSocketTransport`, which streams the session over the agent's local `queue-sync` socket

There is no `timeout`/`retries` constructor parameter: HTTP-level timeout and retry are owned exclusively by the HTTPS transport layer (`statefulTimeoutMs`, `STATEFUL_MAX_ATTEMPTS`). See [Transport-Level Timeout and Retry](lifecycle.md#transport-level-timeout-and-retry).

#### Public Methods

##### `persistDifference()`

```cpp
void persistDifference(const std::string& id,
                       Operation operation,
                       const std::string& index,
                       const std::string& data,
                       uint64_t version,
                       bool isDataContext = false)
```

Persists a data item to the internal SQLite-backed queue for later synchronization.

**Parameters:**
- `id`: Unique identifier for the data source (typically a hash of primary keys, e.g., file-path)
- `operation`: Type of operation (`Operation::CREATE`, `Operation::MODIFY`, `Operation::DELETE_`)
- `index`: Target index or destination for the data
- `data`: JSON string containing the difference data
- `version`: Version of the data
- `isDataContext`: `true` marks the item as a `DataContext` item (vulnerability-detection data, no operation/version semantics on the wire) instead of a regular `DataValue` item. Regular `DataValue` and `DataContext` items can be mixed in the same queue and end up in the same `SyncData` payload of one session.

**Example:**
```cpp
protocol.persistDifference(
    "abc123def456",
    Operation::CREATE,
    "fim_files",
    "{\"path\": \"/etc/passwd\", \"hash\": \"...\", \"timestamp\": 1234567890}",
    1
);
```

##### `synchronizeModule()`

```cpp
SyncModuleResult synchronizeModule(Mode mode, Option option = Option::SYNC)
```

Synchronizes a module's pending data with the manager. `Mode::DELTA` reads from the persistent queue, split into as many `FullSession` messages as needed to stay under the byte cap (`Option::VDFIRST`/`Option::VDSYNC` are exempt from that cap); `Mode::CHECK` is handled by `requiresFullSync()` instead. There is no `Mode::FULL`: a full-replace resync is `notifyDataClean()` followed by an ordinary `Mode::DELTA` sync of the freshly re-persisted snapshot — see [Protocol Lifecycle](lifecycle.md#full-replace-recovery-dataclean-then-delta) for why.

**Parameters:**
- `mode`: Synchronization mode (only `Mode::DELTA` is valid here)
- `option`: Sync option (default `Option::SYNC`; use `Option::VDFIRST` / `Option::VDSYNC` for VD flows)

**Returns:** `SyncModuleResult` with success flag, optional failure reason, stop and manager-not-ready flags, and consecutive failure count

**Example:**
```cpp
SyncModuleResult result = protocol.synchronizeModule(Mode::DELTA);
if (!result.success) {
    // items reset to PENDING; next periodic cycle will retry
}
```

##### `requiresFullSync()`

```cpp
bool requiresFullSync(const std::string& index,
                      const std::string& checksum)
```

Checks if a module index requires full synchronization by sending one `FullSession` carrying a `ChecksumModule` payload and waiting for the manager's `EndAck`.

**Parameters:**
- `index`: The index/table to check
- `checksum`: The calculated checksum for the index

**Returns:** `true` if full sync is required (checksum mismatch, i.e. `EndAck.status != Ok`); `false` if integrity is valid or the transport is not currently reachable

##### `synchronizeMetadataOrGroups()`

```cpp
SyncModuleResult synchronizeMetadataOrGroups(Mode mode,
                                             const std::vector<std::string>& indices,
                                             uint64_t globalVersion)
```

Synchronizes metadata or groups with the manager without sending any data items. Sent as one `FullSession` carrying `Start` and `End` only — `payload` is absent.

**Parameters:**
- `mode`: Synchronization mode (must be `Mode::METADATA_DELTA`, `Mode::METADATA_CHECK`, `Mode::GROUP_DELTA`, or `Mode::GROUP_CHECK`)
- `indices`: Index names that will be updated by the manager
- `globalVersion`: Global version to include in the `Start` message

**Returns:** `SyncModuleResult` with success flag and failure reason if unsuccessful

##### `notifyDataClean()`

```cpp
bool notifyDataClean(const std::vector<std::string>& indices, Option option = Option::SYNC)
```

Notifies the manager about data cleaning for specified indices. Sent as one `FullSession` carrying a `Cleans` payload (one `DataClean` per index). Upon receiving `Ok`, it clears the local database and returns true.

**Parameters:**
- `indices`: Index names to clean
- `option`: Synchronization option (default `Option::SYNC`)

**Returns:** `true` if notification completed successfully and database was cleared, `false` otherwise

**Example:**
```cpp
std::vector<std::string> indices = {"fim_files", "fim_registry"};
bool success = protocol.notifyDataClean(indices);
```

##### `fetchPendingItems()`

```cpp
std::vector<PersistedData> fetchPendingItems(bool onlyDataValues = true)
```

Fetches pending items from the persistent queue without marking them as syncing.

**Parameters:**
- `onlyDataValues`: If `true`, only returns items with `is_data_context = false`

**Returns:** Vector of pending items

##### `clearAllDataContext()`

```cpp
void clearAllDataContext()
```

Clears all `DataContext` items (vulnerability-detection data) from the persistent queue. Should be called before adding new `DataContext` items to prevent inconsistencies.

##### `deleteDatabase()`

```cpp
void deleteDatabase()
```

Deletes the database file. This method closes the database connection and removes the database file from disk.

**Example:**
```cpp
protocol.deleteDatabase();
```

##### `stop()` / `reset()` / `shouldStop()`

```cpp
void stop()
void reset()
bool shouldStop() const
```

`stop()` signals the protocol to abort any ongoing or pending synchronization; call it when the module is shutting down. `reset()` clears the stop flag so the module can restart operations. `shouldStop()` reports whether a stop is currently in effect.

##### `parseResponseBuffer()`

```cpp
bool parseResponseBuffer(const uint8_t* data, size_t length)
```

Processes a response from the manager. Accepts either a FlatBuffer-encoded `Message` wrapping an `EndAck` (the response format used by `SyncSocketTransport`/the on-disk sync path), or the newer `"HCRESULT:<session>:<code>"` string format the HTTPS transport uses to route an HTTP status code back to the originating session (`"HCRESULT:<code>"`, without a session number, is accepted for backward compatibility and skips the session-correlation check).

**Parameters:**
- `data`: Pointer to the response buffer
- `length`: Size of the buffer in bytes

**Returns:** `true` if the message was successfully parsed and processed

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
                                   asp_logger_t logger)
```

Creates a new Agent Sync Protocol instance.

**Parameters:**
- `module`: Module name string (e.g. `"fim"`, `"syscollector"`)
- `db_path`: SQLite database file path for the persistent queue (`NULL` for in-memory only)
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
                     const char* data,
                     uint64_t version)
```

C wrapper for `persistDifference()`, always with `isDataContext = false`.

**Parameters:**
- `handle`: Protocol handle
- `id`: Data source identifier
- `operation`: Operation type (`OPERATION_CREATE`, `OPERATION_MODIFY`, `OPERATION_DELETE`, `OPERATION_NO_OP`)
- `index`: Target index
- `data`: JSON data string
- `version`: Version of the data

#### `asp_sync_module()`

```c
SyncModuleResult_t asp_sync_module(AgentSyncProtocolHandle* handle, Mode_t mode)
```

C wrapper for `synchronizeModule()` with the default `Option_t` (`OPTION_SYNC`).

**Parameters:**
- `handle`: Protocol handle
- `mode`: Sync mode (only `MODE_DELTA` is valid here)

**Returns:** `SyncModuleResult_t` with success flag and optional failure reason string

#### `asp_requires_full_sync()`

```c
bool asp_requires_full_sync(AgentSyncProtocolHandle* handle,
                            const char* index,
                            const char* checksum)
```

C wrapper for `requiresFullSync()`. Checks if a module index requires full synchronization.

**Parameters:**
- `handle`: Protocol handle
- `index`: The index/table to check
- `checksum`: The calculated checksum for the index

**Returns:** `true` if full sync is required (checksum mismatch); `false` if integrity is valid

#### `asp_sync_metadata_or_groups()`

```c
SyncModuleResult_t asp_sync_metadata_or_groups(AgentSyncProtocolHandle* handle,
                                               Mode_t mode,
                                               const char** indices,
                                               size_t indices_count,
                                               uint64_t global_version)
```

C wrapper for `synchronizeMetadataOrGroups()`. Synchronizes metadata or groups with the manager without sending data.

**Parameters:**
- `handle`: Protocol handle
- `mode`: Sync mode (`MODE_METADATA_DELTA`, `MODE_METADATA_CHECK`, `MODE_GROUP_DELTA`, or `MODE_GROUP_CHECK`)
- `indices`: Array of index name strings that will be updated by the manager
- `indices_count`: Number of indices in the array
- `global_version`: Global version to include in the `Start` message

**Returns:** `SyncModuleResult_t` with success flag and failure reason if unsuccessful

#### `asp_notify_data_clean()`

```c
bool asp_notify_data_clean(AgentSyncProtocolHandle* handle,
                           const char** indices,
                           size_t indices_count)
```

C wrapper for `notifyDataClean()` with the default `Option_t` (`OPTION_SYNC`). Notifies the manager about data cleaning for specified indices.

**Parameters:**
- `handle`: Protocol handle
- `indices`: Array of index name strings to clean
- `indices_count`: Number of indices in the array

**Returns:** `true` if notification completed successfully and database was cleared, `false` otherwise

**Example:**
```c
const char* indices[] = {"fim_files", "fim_registry"};
bool success = asp_notify_data_clean(handle, indices, 2);
```

#### `asp_delete_database()`

```c
void asp_delete_database(AgentSyncProtocolHandle* handle)
```

C wrapper for `deleteDatabase()`. Closes the database connection and removes the database file from disk.

**Parameters:**
- `handle`: Protocol handle

**Example:**
```c
asp_delete_database(handle);
```

#### `asp_stop()` / `asp_reset()` / `asp_should_stop()`

```c
void asp_stop(AgentSyncProtocolHandle* handle);
void asp_reset(AgentSyncProtocolHandle* handle);
bool asp_should_stop(const AgentSyncProtocolHandle* handle);
```

C wrappers for `stop()`, `reset()`, and `shouldStop()`.

#### `asp_parse_response_buffer()`

```c
bool asp_parse_response_buffer(AgentSyncProtocolHandle* handle,
                              const uint8_t* data,
                              size_t length)
```

C wrapper for `parseResponseBuffer()`.

#### `asp_set_session_sender()`

```c
void asp_set_session_sender(asp_sync_session_sender_fn sender);
```

Registers the in-process sender that the Windows build of `SyncSocketTransport` uses to hand a session directly to `https_client`, since Windows agents run modules in-process and have no local socket to connect to. A no-op on POSIX, where the real `queue-sync` socket is used instead. Process-global — there is one `sync_protocol` instance per process regardless of how many modules use it. Call with `NULL` to deregister (e.g. when `https_client` is stopping).

**Parameters:**
- `sender`: Function to call for each session, or `NULL` to deregister

## Type Definitions

### Enumerations

#### `Operation` / `Operation_t`

```cpp
enum class Operation : int {
    CREATE = OPERATION_CREATE,
    MODIFY = OPERATION_MODIFY,
    DELETE_ = OPERATION_DELETE, // trailing underscore: DELETE collides with a macro/keyword
    NO_OP = OPERATION_NO_OP     // neutral state, not a synchronized operation
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
enum class Mode : int {
    DELTA          = MODE_DELTA,          // Delta synchronization mode
    CHECK          = MODE_CHECK,          // Integrity check mode
    METADATA_DELTA = MODE_METADATA_DELTA, // Metadata delta synchronization mode
    METADATA_CHECK = MODE_METADATA_CHECK, // Metadata integrity check mode
    GROUP_DELTA    = MODE_GROUP_DELTA,    // Group delta synchronization mode
    GROUP_CHECK    = MODE_GROUP_CHECK     // Group integrity check mode
};
```

```c
typedef enum {
    MODE_DELTA = 0,
    MODE_CHECK = 1,
    MODE_METADATA_DELTA = 2,
    MODE_METADATA_CHECK = 3,
    MODE_GROUP_DELTA = 4,
    MODE_GROUP_CHECK = 5
} Mode_t;
```

There is no `FULL`/`MODE_FULL`: a full-replace resync is `notifyDataClean()` followed by an ordinary `Mode::DELTA` sync — see [Protocol Lifecycle](lifecycle.md#full-replace-recovery-dataclean-then-delta).

#### `Option` / `Option_t`

```cpp
enum class Option : int {
    SYNC    = OPTION_SYNC,     // Standard synchronization option
    VDFIRST = OPTION_VD_FIRST, // Vulnerability-detection-first synchronization option
    VDSYNC  = OPTION_VD_SYNC   // Vulnerability-detection synchronization option
};
```

```c
typedef enum {
    OPTION_SYNC     = 0,
    OPTION_VD_FIRST = 1,
    OPTION_VD_SYNC  = 2,
    OPTION_VD_CLEAN = 3 // not currently mapped on the C++ Option enum
} Option_t;
```

### Result Type

#### `SyncModuleResult` / `SyncModuleResult_t`

```cpp
struct SyncModuleResult {
    bool success{false};
    std::string failureReason;
    bool stopped{false};
    bool managerNotReady{false};
    unsigned int consecutiveFailures{0};
};
```

```c
typedef struct SyncModuleResult_t {
    bool success;
    char failure_reason[SYNC_FAILURE_REASON_MAX_LEN];
    bool stopped;
    bool manager_not_ready;
    unsigned int consecutive_failures;
} SyncModuleResult_t;
```

- `success`: whether the synchronization completed successfully.
- `failureReason`/`failure_reason`: human-readable reason, may be empty.
- `stopped`: `true` if the operation was aborted because `stop()` was called — lets the caller demote an expected shutdown-time failure to INFO/DEBUG instead of WARNING.
- `managerNotReady`/`manager_not_ready`: `true` if the manager did not answer the handshake, or answered `Offline`. Describes what happened, not how serious it is — use it together with `consecutiveFailures` (see `SYNC_MANAGER_NOT_READY_TOLERANCE`) to decide the log level.
- `consecutiveFailures`/`consecutive_failures`: consecutive failed synchronizations for this module, including this one; reset to zero on the first success.

### Callback Types

#### Logger Function

```cpp
using LoggerFunc = std::function<void(modules_log_level_t level, const std::string& message)>;
```

```c
typedef void (*asp_logger_t)(modules_log_level_t level, const char* message);
```

Where `modules_log_level_t` is defined in `logging_helper.h`.

#### Session Sender Function (Windows in-process transport)

```c
typedef bool (*asp_sync_session_sender_fn)(const char* session_id, const uint8_t* buffer, size_t length);
```

Registered via `asp_set_session_sender()` — see above.

### Transport Abstraction

Modules do not usually need to touch this: `AgentSyncProtocol`'s default constructor argument already wires up the real transport. It exists mainly so tests can drive a session without a socket.

```cpp
class ISyncSessionTransport
{
public:
    virtual bool checkStatus() = 0;
    virtual bool sendSession(uint64_t session, const std::vector<uint8_t>& message) = 0;
};
```

`SyncSocketTransport` is the real implementation: it streams one whole `FullSession` message over the agent's local `queue-sync` `AF_UNIX` STREAM socket, which `agentd`'s HTTPS-client intake binds. `sendSession()` reports whether the **agent** took the session, not whether the **manager** accepted it — the manager's verdict arrives asynchronously over the HTTPS response and is routed back through `parseResponseBuffer()`/`applyHttpResultCode()`.

`MQ_Functions`/`mq_start_fn`/`mq_send_binary_fn` are still declared in `agent_sync_protocol_c_interface_types.h` for ABI reasons but are not used by any current code path — the message-queue-based transport they described predates `SyncSocketTransport`/`FullSession`.

## Error Handling

The protocol uses logging callbacks to report errors. Common error scenarios include:

- **Database errors**: Failed to open/write to SQLite database
- **Queue errors**: Persistent queue unavailable
- **Transport errors**: `queue-sync` socket unreachable, or the HTTPS transport reporting a non-OK result
- **Protocol errors**: Invalid message format or unexpected response

## Thread Safety

The Agent Sync Protocol is designed to be thread-safe:

- Multiple threads can call `persistDifference()` concurrently
- Only one synchronization session (`synchronizeModule()`) should be active at a time per instance — a concurrent caller is expected to skip its cycle, since the in-flight sync already drains the shared queue
- Response parsing (`parseResponseBuffer()`) is synchronized internally

## Memory Management

### C++ Interface
- Uses RAII and smart pointers for automatic memory management
- No manual cleanup required except for destroying the instance

### C Interface
- Caller must explicitly call `asp_destroy()` to release resources
- String parameters are copied internally; caller retains ownership
- Buffer parameters for responses must remain valid during function calls

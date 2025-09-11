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
    Full,
    Delta
};
```

```c
typedef enum {
    MODE_FULL,
    MODE_DELTA
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

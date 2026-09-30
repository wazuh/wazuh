# API Reference

The FIM module integrates with the Agent Sync Protocol through the C interface exposed by the `agent_sync_protocol` module.

---

## Agent Sync Protocol C Interface

FIM uses the sync protocol C interface defined in `agent_sync_protocol_c_interface.h` provided by the `agent_sync_protocol` module.

### Core Functions

#### `asp_create()`

Creates and initializes an Agent Sync Protocol handle for FIM.

**Signature:**
```c
AgentSyncProtocolHandle* asp_create(const char* module,
                                   const char* db_path,
                                   asp_logger_t logger);
```

**Parameters:**
- `module`: Module name (`"fim"`)
- `db_path`: Path to sync protocol database (`FIM_SYNC_PROTOCOL_DB_PATH`)
- `logger`: Logging callback function

**Usage Example:**
```c
// FIM initializes sync protocol handle during startup
syscheck.sync_handle = asp_create("fim", FIM_SYNC_PROTOCOL_DB_PATH, loggingFunction);
```

#### `asp_persist_diff()`

Persists a file or registry difference for later synchronization.

**Signature:**
```c
void asp_persist_diff(AgentSyncProtocolHandle* handle,
                      const char* id,
                      Operation_t operation,
                      const char* index,
                      const char* data,
                      uint64_t version);
```

**Parameters:**
- `handle`: Sync protocol handle from `asp_create()`
- `id`: Unique identifier (SHA1 hash of file path)
- `operation`: Operation type (`OPERATION_CREATE`, `OPERATION_MODIFY`, `OPERATION_DELETE`)
- `index`: Sync index name
- `data`: JSON string containing file/registry data
- `version`: Document version

**Usage Example:**
```c
// FIM wraps the call in persist_syscheck_msg() (run_check.c)
asp_persist_diff(syscheck.sync_handle, file_hash, OPERATION_CREATE, FIM_FILES_SYNC_INDEX, json_msg, version);
asp_persist_diff(syscheck.sync_handle, file_hash, OPERATION_MODIFY, FIM_FILES_SYNC_INDEX, json_msg, version);
asp_persist_diff(syscheck.sync_handle, file_hash, OPERATION_DELETE, FIM_FILES_SYNC_INDEX, json_msg, version);
```

#### `asp_sync_module()`

Triggers synchronization of all pending differences.

**Signature:**
```c
SyncModuleResult_t asp_sync_module(AgentSyncProtocolHandle* handle,
                                   Mode_t mode);
```

**Parameters:**
- `handle`: Sync protocol handle
- `mode`: Sync mode (`MODE_DELTA` for FIM)

**Returns:** `SyncModuleResult_t`; see the [sync protocol API reference](../utils/sync-protocol/api-reference.md) for its fields. `success` with `sent_anything == false` means nothing was sent: the queue was empty or another sync was already running.

**Usage Example:**
```c
// FIM integrity thread triggers periodic synchronization
SyncModuleResult_t sync_result = asp_sync_module(syscheck.sync_handle, MODE_DELTA);

if (!sync_result.success) {
    mwarn("FIM synchronization failed: %s", sync_result.failure_reason);
} else if (!sync_result.sent_anything) {
    mdebug1("FIM synchronization: nothing to send.");
}
```

Timeouts and retries belong to the agent's HTTPS transport (`agent.https_stateful_timeout`, `agent.https_stateful_attempts`), not to this call.

#### `asp_parse_response_buffer()`

Processes FlatBuffer responses from the manager.

**Signature:**
```c
bool asp_parse_response_buffer(AgentSyncProtocolHandle* handle,
                               const uint8_t* data,
                               size_t length);
```

**Parameters:**
- `handle`: Sync protocol handle
- `data`: Pointer to FlatBuffer-encoded message
- `length`: Size of message in bytes

**Usage Example:**
```c
// Process FlatBuffer responses from manager
bool success = asp_parse_response_buffer(syscheck.sync_handle,
                                        response_data,
                                        response_length);
```

#### `asp_notify_data_clean()`

Notifies the manager that specific indices have been cleaned and should be removed.

**Signature:**
```c
bool asp_notify_data_clean(AgentSyncProtocolHandle* handle,
                           const char** indices,
                           size_t indices_count);
```

**Parameters:**
- `handle`: Sync protocol handle
- `indices`: Array of index names to clean
- `indices_count`: Number of indices in the array

**Returns:**
- `true`: Notification succeeded
- `false`: Notification failed

**Usage Example:**
```c
// Notify data clean for disabled FIM components
const char* indices_to_clean[] = {
    FIM_FILES_SYNC_INDEX,
    FIM_REGISTRY_KEYS_SYNC_INDEX,
    FIM_REGISTRY_VALUES_SYNC_INDEX
};

bool notify_success = asp_notify_data_clean(syscheck.sync_handle, indices_to_clean, 3);
```

#### `asp_delete_database()`

Deletes the sync protocol database associated with the handle.

**Signature:**
```c
void asp_delete_database(AgentSyncProtocolHandle* handle);
```

**Parameters:**
- `handle`: Sync protocol handle

**Usage Example:**
```c
// Delete sync protocol database when FIM is disabled
asp_delete_database(syscheck.sync_handle);
```

#### `asp_destroy()`

Destroys and cleans up an Agent Sync Protocol handle.

**Signature:**
```c
void asp_destroy(AgentSyncProtocolHandle* handle);
```

**Parameters:**
- `handle`: Sync protocol handle to destroy

---

## Operation Types

FIM uses the following operation types defined in `agent_sync_protocol_c_interface_types.h`:

```c
typedef enum {
    OPERATION_CREATE = 0,    // New file/registry entry
    OPERATION_MODIFY = 1,    // Modified file/registry entry
    OPERATION_DELETE = 2,    // Deleted file/registry entry
    OPERATION_NO_OP = 3     // No operation (internal use)
} Operation_t;
```

---

## Sync Indexes

FIM uses different indexes for different data types:

| Data Type | Index Name | Constant |
|-----------|------------|----------|
| Files | `"wazuh-states-fim-files"` | `FIM_FILES_SYNC_INDEX` |
| Registry Keys | `"wazuh-states-fim-registry-keys"` | `FIM_REGISTRY_KEYS_SYNC_INDEX` |
| Registry Values | `"wazuh-states-fim-registry-values"` | `FIM_REGISTRY_VALUES_SYNC_INDEX` |

---

## FIM Database Integration

FIM integrates with DBSync through the FIMDB wrapper class for local database operations:

### Database Initialization

```c
// FIM initializes database through DB interface (C wrapper)
void DB::init(const int storage,
              std::function<void(modules_log_level_t, const std::string&)> callbackLogWrapper,
              const int fileLimit,
              const int valueLimit) {
    auto dbsyncHandler = std::make_shared<DBSync>(...);
    FIMDB::instance().init(callbackLogWrapper, dbsyncHandler, fileLimit, valueLimit);
}
```

### Database Transaction Operations

FIM uses database transactions for state comparison, not direct database calls:

```c
// Start database transaction for file operations
TXN_HANDLE db_transaction_handle = fim_db_transaction_start(FIMDB_FILE_TXN_TABLE,
                                                            transaction_callback,
                                                            &txn_ctx);

// Transaction callback processes database comparison results
STATIC void transaction_callback(ReturnTypeCallback resultType,
                                const cJSON* result_json,
                                void* user_data) {
    // Database comparison result processed here
    // Events generated based on comparison
    // Validates against the schema, then persist_syscheck_msg() on success
    validate_and_persist_fim_event(stateful_event, file_path_sha1, sync_operation,
                                   FIM_FILES_SYNC_INDEX, document_version,
                                   item_desc, mark_for_deletion,
                                   txn_context->failed_paths, path_copy, sync_flag);
}
```

---

## Syscom Integration

FIM handles manager responses through the syscom interface:

```c
// Process sync protocol messages from manager
if (strncmp(command, FIM_SYNC_HEADER, strlen(FIM_SYNC_HEADER)) == 0) {
    if (syscheck.enable_synchronization) {
        const uint8_t *data = (const uint8_t *)(command + header_len);
        size_t data_len = command_len - header_len;

        bool ret = asp_parse_response_buffer(syscheck.sync_handle, data, data_len);
        if (!ret) {
            // Handle parsing error
        }
    }
}
```

---

## Coordination Commands

The coordination commands allow external control of FIM operations for coordination with the manager or other modules. FIM implements an **asynchronous model with polling** where commands return immediately and separate functions check completion status.

### Pause and Resume Operations

#### `fim_execute_pause()`

Requests the FIM module to pause scanning operations. This is an asynchronous request that returns immediately.

**Signature:**
```c
int fim_execute_pause(void);
```

**Returns:**
- `0` if pause request was accepted or FIM is already paused
- `-1` on error

**Description:**

This function sets an atomic flag (`fim_pause_requested`) to signal FIM threads to pause their operations. The function returns immediately without waiting for operations to complete. Use `fim_execute_is_pause_completed()` to poll the pause status.

**Behavior:**
- Sets `fim_pause_requested` atomic flag to `1`
- Returns immediately (non-blocking)
- FIM threads check this flag and pause when safe
- Idempotent: safe to call multiple times

**Usage Example:**
```c
// Request FIM to pause
int result = fim_execute_pause();
if (result == 0) {
    // Pause request accepted
    // Use fim_execute_is_pause_completed() to check when complete
}
```

#### `fim_execute_is_pause_completed()`

Checks whether the FIM pause operation has completed.

**Signature:**
```c
int fim_execute_is_pause_completed(void);
```

**Returns:**
- `0` if pause is completed (FIM is fully paused)
- `1` if pause is still in progress
- `-1` on error

**Description:**

This function checks atomic flags to determine if FIM has acknowledged the pause request and all scanning operations have stopped. It should be called repeatedly (polling) after `fim_execute_pause()` until it returns `0`.

**Behavior:**
- Reads `fim_pause_requested` and `fim_pausing_is_allowed` atomic flags
- Returns immediately (non-blocking)
- Returns `0` when both conditions are met:
  - Pause was requested (`fim_pause_requested = 1`)
  - FIM acknowledged the pause (`fim_pausing_is_allowed = 1`)

**Usage Example:**
```c
// Request pause
fim_execute_pause();

// Poll until pause completes (with timeout)
int max_attempts = 100;
for (int i = 0; i < max_attempts; i++) {
    int status = fim_execute_is_pause_completed();
    if (status == 0) {
        // Pause completed successfully
        break;
    } else if (status == 1) {
        // Still in progress, wait and retry
        sleep(1);
    } else {
        // Error occurred
        break;
    }
}
```

#### `fim_execute_resume()`

Resumes FIM scanning operations after a pause.

**Signature:**
```c
int fim_execute_resume(void);
```

**Returns:**
- `0` on success
- `-1` on error

**Description:**

This function clears the pause request flag and releases all scan mutexes, allowing FIM threads to resume their operations. The function completes synchronously.

**Behavior:**
- Checks if FIM is actually paused
- Releases all scan mutexes:
  - `fim_realtime_mutex`
  - `fim_scan_mutex`
  - `fim_registry_scan_mutex` (Windows only)
- Clears atomic flags:
  - Sets `fim_pause_requested = 0`
  - Sets `fim_pausing_is_allowed = 0`
- FIM threads resume scanning immediately

**Usage Example:**
```c
// Resume FIM operations
int result = fim_execute_resume();
if (result == 0) {
    // FIM resumed successfully
}
```

---

### Synchronization Control

#### `fim_execute_flush()`

Requests FIM to immediately synchronize all pending file integrity changes with the manager. This is an asynchronous request that returns immediately.

**Signature:**
```c
int fim_execute_flush(void);
```

**Returns:**
- `0` if flush request was accepted or synchronization is disabled
- `-1` on error

**Description:**

This function sets atomic flags to trigger an immediate synchronization of all pending FIM changes, bypassing the normal sync interval. The function returns immediately without waiting for synchronization to complete. Use `fim_execute_is_flush_completed()` to poll the flush status.

**Behavior:**
- Checks if synchronization is enabled
- Checks if a flush is already in progress (idempotent)
- Sets atomic flags:
  - `fim_flush_in_progress = 1`
  - `fim_flush_result = 0` (reset previous result)
- Returns immediately (non-blocking)
- The FIM integrity thread (`fim_run_integrity`) detects the flag and performs the sync

**Usage Example:**
```c
// Request immediate synchronization
int result = fim_execute_flush();
if (result == 0) {
    // Flush request accepted
    // Use fim_execute_is_flush_completed() to check when complete
}
```

#### `fim_execute_is_flush_completed()`

Checks whether the FIM flush operation has completed.

**Signature:**
```c
int fim_execute_is_flush_completed(void);
```

**Returns:**
- `0` if flush completed successfully
- `1` if flush is still in progress
- `-1` if flush completed with error

**Description:**

This function checks atomic flags to determine if the flush operation has finished and retrieves the result. It should be called repeatedly (polling) after `fim_execute_flush()` until it returns `0` or `-1`.

**Behavior:**
- Reads atomic flags:
  - `fim_flush_in_progress` (0 = idle, 1 = active)
  - `fim_flush_result` (0 = success, -1 = error)
- Returns immediately (non-blocking)
- If synchronization is disabled, returns `0` immediately

**Usage Example:**
```c
// Request flush
fim_execute_flush();

// Poll until flush completes (with timeout)
int max_attempts = 60;
for (int i = 0; i < max_attempts; i++) {
    int status = fim_execute_is_flush_completed();
    if (status == 0) {
        // Flush completed successfully
        break;
    } else if (status == 1) {
        // Still in progress, wait and retry
        sleep(1);
    } else {
        // Flush failed
        break;
    }
}
```

---

### Asynchronous Pattern

FIM coordination commands follow an **asynchronous pattern with polling**:

```
1. Call command function (returns immediately)
   ├─► fim_execute_pause() → returns 0
   ├─► fim_execute_flush() → returns 0

2. Poll completion status (loop until done)
   ├─► fim_execute_is_pause_completed() → 1 (in progress)
   ├─► fim_execute_is_flush_completed() → 1 (in progress)
   │
   └─► Wait/sleep between polls

3. Operation completes
   ├─► fim_execute_is_pause_completed() → 0 (success)
   ├─► fim_execute_is_flush_completed() → 0 or -1 (success/error)
```

**Advantages of this pattern:**
- Non-blocking: caller can perform other operations while waiting
- Timeout control: caller decides how long to wait
- Status monitoring: can check progress at any interval
- Thread-safe: uses atomic operations

**Comparison with Syscollector:**
| Feature | FIM | Syscollector |
|---------|-----|--------------|
| Pattern | Asynchronous + polling | Synchronous blocking |
| Pause/Flush | Returns immediately | Waits for completion |
| Status check | Separate `is_completed()` functions | Not needed |
| Implementation | Atomic flags | Condition variables |
| Use case | Legacy C codebase | Modern C++ codebase |

---

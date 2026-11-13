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
                                   asp_logger_t logger,
                                   uint64_t flush_batch_size,
                                   uint64_t flush_interval_ms,
                                   uint64_t wal_autocheckpoint_pages);
```

**Parameters:**
- `module`: Module name (`"fim"`)
- `db_path`: Path to sync protocol database (`FIM_SYNC_PROTOCOL_DB_PATH`)
- `logger`: Logging callback function
- `flush_batch_size`: Persistent queue flush batch size (`syscheck.sync_flush_batch_size`), or `0` to use the built-in default
- `flush_interval_ms`: Persistent queue flush interval in milliseconds (`syscheck.sync_flush_interval_ms`), or `0` to use the built-in default
- `wal_autocheckpoint_pages`: WAL auto-checkpoint threshold in pages (`syscheck.sync_wal_autocheckpoint_pages`), or `0` to keep SQLite's own default (1000 pages)

**Usage Example:**
```c
// FIM initializes sync protocol handle during startup
syscheck.sync_handle = asp_create("fim", FIM_SYNC_PROTOCOL_DB_PATH, loggingFunction,
                                  (uint64_t)syscheck.sync_flush_batch_size,
                                  (uint64_t)syscheck.sync_flush_interval_ms,
                                  (uint64_t)syscheck.sync_wal_autocheckpoint_pages);
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
- `id`: Unique identifier (SHA1 of the file path; for registry rows, SHA1 of `arch:path` for keys and `path:arch:value` for values, with `arch` as a number: `0` for the 32-bit view, `1` for the 64-bit view)
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

if (sync_result.success) {
    minfo(sync_result.sent_anything ? "FIM synchronization finished successfully."
                                    : "FIM synchronization finished: nothing to send.");
} else if (sync_result.stopped || fim_shutdown_process_on()) {
    minfo("FIM synchronization aborted: FIM is stopping.");
} else if (sync_result.awaiting_prerequisite) {
    minfo("FIM synchronization deferred: %s", sync_result.failure_reason);
} else if ((sync_result.manager_not_ready || sync_result.local_transport_unavailable)
           && sync_result.consecutive_failures <= SYNC_MANAGER_NOT_READY_TOLERANCE) {
    minfo("FIM synchronization deferred: %s Will retry next cycle.", sync_result.failure_reason);
} else if (sync_result.manager_not_ready || sync_result.local_transport_unavailable) {
    mwarn("FIM synchronization failed %u times in a row: %s",
          sync_result.consecutive_failures, sync_result.failure_reason);
} else {
    mwarn("FIM synchronization failed%s%s", sync_result.failure_reason[0] != '\0' ? ": " : "", sync_result.failure_reason);
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
// Notify data clean for the indices that still hold entries (up to 3 on Windows, 1 on Linux/Unix).
// Recovery calls it with the single index of the table being resent.
const char* indices_to_clean[] = {
    FIM_FILES_SYNC_INDEX,
    FIM_REGISTRY_KEYS_SYNC_INDEX,
    FIM_REGISTRY_VALUES_SYNC_INDEX
};

bool notify_success = asp_notify_data_clean(syscheck.sync_handle, indices_to_clean, indices_count);
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
- `-1` if FIM is stopping

**Description:**

This function sets an atomic flag (`fim_pause_requested`) to signal FIM threads to pause their operations. The function returns immediately without waiting for operations to complete. Use `fim_execute_is_pause_completed()` to poll the pause status.

**Behavior:**
- Returns `-1` if FIM is stopping
- Sets `fim_pausing_is_allowed` to `0` and `fim_pause_requested` to `1`
- Returns immediately (non-blocking)
- The sync thread skips its regular cycles while the flag is set (it still serves a flush); scans are held off only once `fim_execute_is_pause_completed()` acquires the scan mutexes
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

Tries to complete the pause requested by `fim_execute_pause()`. It does not only read flags: on success it **acquires the FIM scan mutexes** and keeps them until `fim_execute_resume()`.

**Signature:**
```c
int fim_execute_is_pause_completed(void);
```

**Returns:**
- `0` if FIM is paused: this call acquired the scan mutexes, or an earlier call already did
- `0` also when no pause request is active (nothing to wait for; no mutex is taken)
- `1` if a scan mutex is busy; call it again later. The holder can be a scheduled scan, realtime processing, or FIM's own sync thread (`fim_run_integrity()`), which keeps the scan and realtime mutexes during the agent-ID resync and the integrity checks, including their DataClean and checksum round trips to the manager. A long recovery can therefore outlast `agent_info`'s pause polling (30 attempts, 1 second apart)
- `-1` if FIM is stopping; any pause in progress is cancelled and its mutexes released

**Description:**

Call it repeatedly (polling) after `fim_execute_pause()` until it returns `0` or `-1`. It never blocks: it uses `pthread_mutex_trylock()` and releases whatever it took if one lock fails.

**Behavior:**
- If FIM is stopping, releases a pause already acknowledged, clears `fim_pause_requested` and returns `-1`
- If `fim_pausing_is_allowed` is already set, returns `0` (the mutexes are already held)
- If `fim_pause_requested` is not set, returns `0` without taking anything
- Otherwise tries, in order, `fim_scan_mutex`, `fim_realtime_mutex` and, on Windows, `fim_registry_scan_mutex`; if any is busy, releases the ones taken and returns `1`
- With all of them held, checks the stop flag again (returning `-1` after releasing them if a stop arrived meanwhile), sets `fim_pausing_is_allowed` to `1` and returns `0`

**Mutex ownership:** after a `0` that acquired them, the mutexes stay locked until `fim_execute_resume()` releases them, so every successful pause must be followed by `fim_execute_resume()`. If FIM stops before that, the stop path releases them instead.

**Usage Example:**
```c
// Request pause
fim_execute_pause();

// Poll until pause completes (with timeout)
int max_attempts = 100;
for (int i = 0; i < max_attempts; i++) {
    int status = fim_execute_is_pause_completed();
    if (status == 0) {
        // Paused: the scan mutexes are held until fim_execute_resume()
        break;
    } else if (status == 1) {
        // A scan still holds a mutex, wait and retry
        sleep(1);
    } else {
        // -1: FIM is stopping, the pause was cancelled
        break;
    }
}

// ... coordinated work ...

fim_execute_resume();
```

#### `fim_execute_resume()`

Resumes FIM scanning operations after a pause.

**Signature:**
```c
int fim_execute_resume(void);
```

**Returns:**
- `0` always (also when no pause was requested)

**Description:**

This function clears the pause request flag and, if the pause had been acknowledged, releases the scan mutexes, allowing FIM threads to resume their operations. The function completes synchronously.

**Behavior:**
- Returns `0` without doing anything if no pause was requested
- If the pause was acknowledged (`fim_pausing_is_allowed` set), releases the scan mutexes:
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
- `0` if flush request was accepted, a flush is already in progress, or synchronization is disabled
- `-1` if FIM is stopping

**Description:**

This function sets atomic flags to trigger an immediate synchronization of all pending FIM changes, bypassing the normal sync interval. The function returns immediately without waiting for synchronization to complete. Use `fim_execute_is_flush_completed()` to poll the flush status.

**Behavior:**
- Returns `-1` if FIM is stopping
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
- `0` if flush completed successfully (or synchronization is disabled)
- `1` if flush is still in progress
- `-1` if flush completed with error
- `-2` if FIM is stopping; the flush result is not reported

**Description:**

This function checks atomic flags to determine if the flush operation has finished and retrieves the result. It should be called repeatedly (polling) after `fim_execute_flush()` until it returns anything other than `1`: a poller that only stops on `0` or `-1` keeps polling during shutdown (forever, if it has no attempt limit), because every call then returns `-2`.

**Behavior:**
- Reads atomic flags:
  - `fim_flush_in_progress` (0 = idle, 1 = active)
  - `fim_flush_result` (0 = success, -1 = error)
- Returns immediately (non-blocking)
- If FIM is stopping, returns `-2` before reading anything
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
    } else if (status == -2) {
        // FIM is stopping, stop polling
        break;
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
   ├─► fim_execute_is_pause_completed() → 0 (paused, scan mutexes held) or -1 (stopping)
   ├─► fim_execute_is_flush_completed() → 0 or -1 (success/error), -2 (stopping)
```

**Advantages of this pattern:**
- Non-blocking: caller can perform other operations while waiting
- Timeout control: caller decides how long to wait
- Status monitoring: can check progress at any interval
- Thread-safe: uses atomic operations

**Comparison with Syscollector and SCA:**
| Feature | FIM | Syscollector / SCA |
|---------|-----|--------------------|
| Pause | Asynchronous: `fim_execute_pause()` returns at once, `fim_execute_is_pause_completed()` acquires the scan mutexes | Synchronous: `pause()` waits until scans and syncs finish |
| Flush | Asynchronous: the sync thread runs it | Asynchronous: `flush()` starts a worker (`Utils::AsyncFlushController`) and returns |
| Status check | `fim_execute_is_pause_completed()`, `fim_execute_is_flush_completed()` | `is_flush_completed` command (`in_progress` / `completed`); none for pause |
| Implementation | Atomic flags and mutexes | Condition variables and a flush worker thread |

---

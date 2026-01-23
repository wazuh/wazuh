# Architecture

The **FIM module** implements a **dual event architecture** designed to provide both immediate alerting and reliable state synchronization for file integrity monitoring. It combines real-time stateless events with persistent stateful events using the Agent Sync Protocol for guaranteed delivery.

---

## Main Components

### **FIM Database Integration (FIMDB + DBSync)**

The local database component responsible for storing and comparing file/registry states.
Responsibilities:

* FIMDB acts as a wrapper around DBSync for FIM-specific operations
* DBSync manages the actual SQLite database operations and synchronization
* Provides transaction-based state comparison through callback mechanisms
* Compares current file/registry state with stored state via database transactions
* Triggers transaction callbacks when changes are detected
* Supports atomic database transactions for consistency

### **Agent Sync Protocol Integration**

FIM integrates with the sync protocol through C interface functions.
Responsibilities:

* Creates and manages sync protocol handle via `asp_create()`
* Persists differences using `asp_persist_diff()` when changes detected
* Triggers periodic synchronization via `asp_sync_module()`
* Handles manager responses through `asp_parse_response_buffer()`
* Manages persistent queue for reliable message delivery

### **Transaction Callbacks**

Handle database comparison results and generate appropriate events.
Responsibilities:

* Process database transaction results from FIMDB
* Determine change type (add, modify, delete) based on stored state
* Generate both stateless and stateful events for each change
* Handle file path hashing for unique identification
* Coordinate event generation and persistence
* Called for all changes detected through database transactions

### **Realtime Monitoring Threads**

Dedicated threads that monitor filesystem changes in real-time and trigger event processing.
Responsibilities:

* **`fim_run_realtime()`** - Platform-specific realtime monitoring thread:
  - **Linux/Unix**: Uses inotify to watch filesystem events (`INOTIFY_ENABLED`)
  - **Windows**: Uses ReadDirectoryChangesW API (`WIN32`)
  - **Other platforms**: Falls back to polling-based monitoring
* Monitors configured directories for changes (create, modify, delete, move)
* Triggers `fim_checker()` which leads to database transactions and `transaction_callback()`
* Runs continuously in background thread launched at FIM startup
* **Respects pause state** - checks `fim_pause_requested` before processing changes

### **Integrity Scanning Thread**

Dedicated thread that performs periodic full scans and handles synchronization.
Responsibilities:

* **`fim_run_integrity()`** - Main integrity scanning thread:
  - Runs periodic full filesystem scans based on configured interval
  - Manages synchronization with the manager
  - Handles flush requests by checking `fim_flush_in_progress` flag
  - **Respects pause state** - checks `fim_pause_requested` before initiating scans
  - Coordinates with sync protocol for reliable message delivery

### **Operation State Control**

FIM implements atomic state flags to coordinate operations and enable external control. Unlike Syscollector's synchronous model, FIM uses an **asynchronous model with polling**.

**State Flags (Atomic Variables):**
* `fim_pause_requested` - Indicates if a pause has been requested
* `fim_pausing_is_allowed` - Indicates if FIM has acknowledged the pause (operations stopped)
* `fim_flush_in_progress` - Indicates if a flush operation is active
* `fim_flush_result` - Result of the flush operation (0 = success, -1 = error)

**Coordination Flow (Asynchronous):**

```
External Coordination Command (pause)
         │
         ▼
Set fim_pause_requested = 1 (atomic)
         │
         ▼
Return immediately (non-blocking)
         │
         ▼
Caller Polls: fim_execute_is_pause_completed()
         │
         ├─► Returns 1 (in progress) - FIM threads detecting flag
         │
         ├─► FIM threads check fim_pause_requested
         │   └─► Pause at safe points
         │   └─► Set fim_pausing_is_allowed = 1
         │
         ├─► Returns 1 (in progress) - waiting for acknowledgment
         │
         └─► Returns 0 (completed) - both flags set
         │
         ▼
External Coordination Command (resume)
         │
         ▼
Release mutexes and clear flags
         │
         ▼
FIM threads resume operations
```

**Operation Protection:**

Before starting scan operations, FIM threads check the pause state:

```c
// In fim_run_integrity (periodic scanning)
if (atomic_int_get(&syscheck.fim_pause_requested)) {
    // Set acknowledgment flag
    atomic_int_set(&syscheck.fim_pausing_is_allowed, 1);

    // Wait on mutex (blocking until resume)
    w_mutex_lock(&syscheck.fim_scan_mutex);
    w_mutex_unlock(&syscheck.fim_scan_mutex);

    // Clear acknowledgment flag
    atomic_int_set(&syscheck.fim_pausing_is_allowed, 0);
}

// Check flush request
if (atomic_int_get(&fim_flush_in_progress)) {
    // Perform synchronization immediately
    bool result = asp_sync_module(...);

    // Update result and clear in-progress flag
    atomic_int_set(&fim_flush_result, result ? 0 : -1);
    atomic_int_set(&fim_flush_in_progress, 0);
}

// Proceed with normal scanning
perform_integrity_scan();
```

---

## Event Flow Architecture

### Complete FIM Event Flow

```
File/Registry Change Detected
         │
         ▼
 fim_checker() / registry checking
         │
         ▼
 fim_db_transaction_start() ──► FIMDB Database Operation
         │                           │
         ▼                           ▼
 transaction_callback()      Compare with stored state
         │
         ├─► Generate Stateless Event ─────► send_syscheck_msg() ─────► Manager (immediate)
         │
         └─► Generate Stateful Event ──────► persist_syscheck_msg()
                                                      │
                                                      └─► asp_persist_diff()
                                                                │
                                                                ▼
                                                        Persistent Database
                                                                │
                                                                ▼
                                            Periodic Sync Thread (fim_run_integrity)
                                                                │
                                                                └─► asp_sync_module()
                                                                         │
                                                                         ▼
                                                                     Manager
```

---

## Dual Event System

### Stateless Events (Real-time Alerts)

Generated immediately when changes are detected and sent directly to the manager:

```c
if (notify_scan != 0 && txn_context->event->report_event) {
    send_syscheck_msg(stateless_event);  // Immediate send to manager
}
```

**Characteristics:**
- Sent immediately when changes detected
- Contain essential alert information
- No persistence or retry mechanism
- Lost if network is down or agent restarts

### Stateful Events (Synchronization State)

Generated with complete data including checksums and persisted for synchronization:

```c
persist_syscheck_msg(file_path_sha1, sync_operation, FIM_FILES_SYNC_INDEX, stateful_event);
```

**Characteristics:**
- Include complete checksums and metadata
- Persisted to sync protocol database
- Survive agent restarts and network failures
- Synchronized periodically with manager

---

## Database Transaction Flow

### Transaction Process

FIM uses database transactions to ensure consistency between change detection and event generation:

```c
TXN_HANDLE db_transaction_handle = fim_db_transaction_start(FIMDB_FILE_TXN_TABLE,
                                                            transaction_callback,
                                                            &txn_ctx);
```

### Transaction Callback Processing

The `transaction_callback()` function handles the database response:

1. **Receives database comparison result** from FIMDB
2. **Determines change type** (add, modify, delete) based on database state
3. **Generates both event types**:
   - Stateless event for immediate alerts
   - Stateful event for synchronization
4. **Persists stateful event** to sync protocol

#### **Central Event Processing Hub**

**Most FIM events flow through `transaction_callback()`**, including:
- File modifications detected by realtime monitoring
- New file creation events
- File attribute changes (permissions, ownership, etc.)
- Registry key and value changes (Windows)
- Scheduled scan results comparing current vs. stored state

#### **File Deletion Exception**

**File deletions are handled differently** and may bypass `transaction_callback()` in some scenarios:

- **Standard deletions**: Use `fim_db_transaction_deleted_rows()` which calls `transaction_callback()`
- **Bulk cleanup**: At scan completion, `fim_db_transaction_deleted_rows()` processes all files that weren't found during the scan
- **Special case**: Some deletion events may be processed through alternative paths depending on detection method

**Implementation**:
```c
// At end of file scan - handles files deleted since last scan
fim_db_transaction_deleted_rows(db_transaction_handle, transaction_callback, &txn_ctx);
```

---

## FIM Disabled Cleanup Flow

### Overview

When FIM (syscheck) is disabled, the `handle_fim_disabled()` function executes a cleanup procedure to notify the manager and remove local databases. This ensures the manager's state remains synchronized with the agent's actual monitoring status.

### Execution Trigger

The function is called during agent startup in `start_daemon()` when `syscheck.disabled` is true:

```c
if (syscheck.disabled) {
    handle_fim_disabled();
    minfo("Syscheck is disabled. Exiting.");
    return;
}
```

### Cleanup Flow

```
Agent Startup
      │
      ▼
Check syscheck.disabled
      │
      ▼ (if disabled)
handle_fim_disabled()
      │
      ├─► Check file entries count ──────► fim_db_get_count_file_entry()
      │                                           │
      │                                           ▼
      │                                    Add FIM_FILES_SYNC_INDEX
      │
      ├─► Check registry keys count ─────► fim_db_get_count_registry_key()
      │   (Windows only)                          │
      │                                           ▼
      │                                    Add FIM_REGISTRY_KEYS_SYNC_INDEX
      │
      ├─► Check registry values count ───► fim_db_get_count_registry_data()
      │   (Windows only)                          │
      │                                           ▼
      │                                    Add FIM_REGISTRY_VALUES_SYNC_INDEX
      │
      ▼
Prepare indices array
      │
      ▼ (if indices_count > 0)
Send data clean notification ──────► asp_notify_data_clean()
      │                                     │
      │                                     ▼
      │                              Retry on failure
      │                              (wait sync_interval)
      │                                     │
      │                                     ▼
      │                              Success confirmation
      │
      ├─► Delete sync protocol DB ────► asp_delete_database()
      │
      └─► Delete FIM database ────────► fim_db_close_and_delete_database()
```

### Implementation Details

#### Step 1: Database Entry Count Check

The function queries the FIM database to determine which indices contain data:

```c
int files_count = fim_db_get_count_file_entry();
if (files_count > 0) {
    indices[indices_count++] = FIM_FILES_SYNC_INDEX;
}

#ifdef WIN32
int registry_keys_count = fim_db_get_count_registry_key();
int registry_values_count = fim_db_get_count_registry_data();

if (registry_keys_count > 0) {
    indices[indices_count++] = FIM_REGISTRY_KEYS_SYNC_INDEX;
}
if (registry_values_count > 0) {
    indices[indices_count++] = FIM_REGISTRY_VALUES_SYNC_INDEX;
}
#endif
```

**Indices checked:**
- `FIM_FILES_SYNC_INDEX` (`"wazuh-states-fim-files"`) - File monitoring data
- `FIM_REGISTRY_KEYS_SYNC_INDEX` (`"wazuh-states-fim-registry-keys"`) - Registry keys (Windows)
- `FIM_REGISTRY_VALUES_SYNC_INDEX` (`"wazuh-states-fim-registry-values"`) - Registry values (Windows)

#### Step 2: Data Clean Notification

If any indices contain data, the agent notifies the manager to remove them from its state:

```c
if (indices_count > 0) {
    minfo("Syscheck is disabled, FIM database has entries. Proceeding with data clean notification.");

    bool ret = false;
    while (!ret) {
        ret = asp_notify_data_clean(syscheck.sync_handle, indices, indices_count,
                                    syscheck.sync_response_timeout, FIM_SYNC_RETRIES,
                                    syscheck.sync_max_eps);
        if (!ret) {
            // Wait sync_interval before retry
            for (uint32_t i = 0; i < syscheck.sync_interval; i++) {
                sleep(1);
            }
        }
    }
}
```

**Retry Logic:**
- Continues retrying until successful
- Waits `syscheck.sync_interval` seconds between retries
- Uses configured timeout and max events per second limits

#### Step 3: Database Cleanup

After successful notification (or if no data exists), both databases are deleted:

```c
asp_delete_database(syscheck.sync_handle);      // Delete sync protocol database
fim_db_close_and_delete_database();             // Delete FIM database
```

### Behavior Scenarios

#### Scenario 1: FIM Disabled with Existing Data

```
1. Agent starts with syscheck.disabled = true
2. FIM database contains 150 file entries and 50 registry keys
3. Indices array: [FIM_FILES_SYNC_INDEX, FIM_REGISTRY_KEYS_SYNC_INDEX]
4. Send data clean notification to manager (with retries if needed)
5. Manager removes indices from agent's state
6. Delete sync protocol database
7. Delete FIM database
8. Exit FIM module
```

#### Scenario 2: FIM Disabled with Empty Database

```
1. Agent starts with syscheck.disabled = true
2. FIM database is empty (counts = 0)
3. Skip data clean notification
4. Delete sync protocol database
5. Delete FIM database
6. Exit FIM module
```

---

## DataClean: All Paths Removed

When syscheck is enabled but all monitored paths have been removed from configuration, FIM triggers a DataClean process at startup via `handle_all_paths_removed()`. This notifies the manager to clear stale data and deletes local databases.

**Trigger:** `fim_has_configured_paths()` returns false (checked after the disabled check in `start_daemon()`)

**Process:**
1. Check if database has data (`fim_has_data_in_database()`) - exit early if empty
2. Send `asp_notify_data_clean()` for indices with data (with retry on failure)
3. Delete sync protocol and FIM databases
4. Exit module

**Note:** Wildcards that don't expand to any paths are treated as "no paths configured."

---

## Partial Path Removal

When some (but not all) paths are removed, the DBSync transaction mechanism handles cleanup during the next scan:

1. `fim_db_transaction_start()` marks all DB entries
2. Scan touches only entries under currently configured paths
3. `fim_db_transaction_deleted_rows()` identifies untouched entries as orphaned
4. `handle_orphaned_delete()` generates minimal delete events for files under removed paths
5. Events synced to manager via `persist_syscheck_msg()`

**Note:** For orphaned deletes, `transaction_callback()` cannot use the normal event generation path since `fim_configuration_directory()` returns NULL for removed paths. The `handle_orphaned_delete()` function creates minimal events with just the path, checksum, and version from the database.

---

## Synchronization Architecture

### Periodic Synchronization Thread

FIM runs a dedicated thread for inventory synchronization:

```c
// Function: fim_run_integrity()
void * fim_run_integrity(__attribute__((unused)) void * args) {
    while (FOREVER()) {
        mdebug1("Running inventory synchronization.");

        // Trigger synchronization of all pending FIM changes
        asp_sync_module(syscheck.sync_handle, MODE_DELTA,
                       syscheck.sync_response_timeout, FIM_SYNC_RETRIES,
                       syscheck.sync_max_eps);

        sleep(syscheck.sync_interval);
    }
}
```

### Manager Response Handling

FIM processes manager responses through the syscom interface:

```c
// Handle FIM sync messages from manager
bool ret = asp_parse_response_buffer(syscheck.sync_handle, data, data_len);
```

---

## Recovery Architecture

### Overview

FIM implements an automatic recovery mechanism to detect and resolve database synchronization inconsistencies between agent and manager. The recovery system ensures long-term data consistency by periodically validating synchronization state and triggering full resynchronization when mismatches are detected.

* **`fim_run_integrity()`** - Integrity monitoring thread.
* Attempts DELTA synchronizations for each table every `syscheck.sync_interval`.
* Each time `syscheck.integrity_interval` elapses, it performs the integrity validation and full recovery process in case of a checksum mismatch between the agent and the manager's tables.
* Runs continuously in background thread launched at FIM startup

### Recovery Trigger Flow

Recovery operations are integrated into the periodic synchronization cycle:

```
Synchronization Cycle (every sync_interval)
         │
         ▼
Run Delta Sync ──► asp_sync_module(MODE_DELTA)
         │
         └─►  Failure? ──► Skip Recovery, Wait for Next Cycle
         │
         └─►  Success? ──► Continue to Recovery Check
                                    │
                                    ▼
                          For Each Table (file_entry, registry_key, registry_data):
                                    │
                                    └─► Check if integrity_interval elapsed
                                            │
                                            └─► Yes?
                                                 │
                                                 ▼
                                        Calculate Table Checksum
                                                 │
                                                 ▼
                                        Compare with Manager Checksum
                                            │
                                            ├─► Match? ──► Update last_sync_time, Done
                                            │
                                            └─► Mismatch? ──► Trigger Recovery
                                                                 │
                                                                 ▼
                                                         Load Entire Table into Memory
                                                                     │
                                                                     ▼
                                                         Persist All Entries (MODE_FULL)
                                                                     │
                                                                     ▼
                                                         Full Sync with Manager
    ```

---

## Coordination Commands Architecture

The coordination commands provide external control over FIM operations, allowing the manager or other components to coordinate module behavior. FIM implements an **asynchronous model with polling** where commands return immediately and callers poll for completion status.

### Command Types

#### Pause/Resume Commands

**Purpose:** Allow temporary suspension of FIM scanning operations without stopping the module completely.

**Implementation:**

The pause command follows this **asynchronous sequence**:

```
Pause Command Received (fim_execute_pause)
         │
         ▼
Set fim_pause_requested = 1 (atomic)
         │
         ▼
Return 0 immediately (non-blocking)
         │
         ▼
Caller Polls Status (fim_execute_is_pause_completed)
         │
         ├─► Returns 1: In progress
         │   │
         │   ├─► FIM threads detect fim_pause_requested
         │   │
         │   ├─► Threads pause at safe points
         │   │   └─► Set fim_pausing_is_allowed = 1
         │   │   └─► Wait on scan mutexes
         │   │
         │   └─► Caller waits and polls again
         │
         └─► Returns 0: Completed (both flags set)
```

The resume command is **synchronous**:

```
Resume Command Received (fim_execute_resume)
         │
         ▼
Check if FIM is paused
         │
         ├─► Not paused → Return (idempotent)
         │
         └─► Paused → Continue
                 │
                 ▼
         Release all mutexes:
                 │
                 ├─► fim_realtime_mutex
                 ├─► fim_scan_mutex
                 └─► fim_registry_scan_mutex (Windows)
                 │
                 ▼
         Clear atomic flags:
                 │
                 ├─► fim_pause_requested = 0
                 └─► fim_pausing_is_allowed = 0
                 │
                 ▼
         FIM threads immediately resume
```

#### Flush Command

**Purpose:** Force immediate synchronization of pending file integrity changes, bypassing the normal sync interval.

**Implementation:**

```
Flush Command Received (fim_execute_flush)
         │
         ▼
Check if Sync Enabled
         │
         ├─► Disabled → Return 0 (nothing to flush)
         │
         └─► Enabled → Continue
                 │
                 ▼
         Check if flush already in progress
                 │
                 ├─► In progress → Return 0 (idempotent)
                 │
                 └─► Not in progress → Continue
                         │
                         ▼
                 Reset result and set flags (atomic):
                         │
                         ├─► fim_flush_result = 0
                         └─► fim_flush_in_progress = 1
                         │
                         ▼
                 Return 0 immediately (non-blocking)
                         │
                         ▼
         FIM Integrity Thread Detects Flag
                         │
                         ▼
         Call asp_sync_module(MODE_DELTA)
                         │
                         ├─► Sends all pending differences
                         ├─► Waits for manager acknowledgment
                         └─► Gets sync result
                         │
                         ▼
         Update atomic flags:
                         │
                         ├─► fim_flush_result = result ? 0 : -1
                         └─► fim_flush_in_progress = 0
                         │
                         ▼
         Caller Polls Status (fim_execute_is_flush_completed)
                         │
                         ├─► Returns 1: In progress
                         ├─► Returns 0: Success
                         └─► Returns -1: Error
```

### Thread Safety

All coordination commands are thread-safe:

- **Atomic operations** (`atomic_int_get`, `atomic_int_set`) ensure consistent flag reads/writes
- **Mutexes** coordinate between command handlers and FIM threads
- **Lock-free polling** allows non-blocking status checks
- **Idempotent operations** allow safe retries

---

## Schema Validation Integration

FIM integrates with the [Schema Validator](../utils/schema-validator/README.md) module to ensure all events conform to the expected Wazuh indexer schema before transmission.

### Purpose

- **Prevent Indexing Errors**: Validate file/registry events before they reach the indexer
- **Prevent Integrity Sync Loops**: Invalid events are removed from local databases to avoid repeated sync attempts
- **Improve Data Quality**: Ensure all indexed data conforms to expected types and structures
- **Provide Detailed Error Reporting**: Specific field paths and validation failures for debugging

### Validation Points

Schema validation occurs at two critical points in the FIM lifecycle:

#### 1. During Event Processing (fim_process_event)

When file or registry changes are detected, validation occurs before sending to the sync protocol:

```c
// Validate and handle stateful message
validation_passed = fim_validate_and_handle_stateful(
    stateful_event,
    fim_index,
    context,
    failed_list,
    failed_item_data
);

if (validation_passed)
{
    // Send valid event to sync protocol
    fim_send_sync(stateful_event, operation, index);
}
```

**Key characteristics:**
- Validation before sync protocol transmission
- Failed items are accumulated in `failed_list`
- Item data is marked for deferred deletion

#### 2. During Recovery (fim_recovery_process)

When performing integrity recovery, only valid items are synchronized:

```c
if (schema_validator_is_initialized())
{
    char* errorMessage = NULL;

    if (!schema_validator_validate(index, stateful_event_str, &errorMessage))
    {
        // Validation failed - log but don't persist
        if (errorMessage)
        {
            mdebug2("Schema validation failed for FIM recovery message (index: %s). Error: %s",
                   index, errorMessage);
            mdebug2("Raw recovery event that failed validation: %s", stateful_event_str);
            free(errorMessage);
        }
        validation_passed = false;
    }
}

if (validation_passed)
{
    // Persist for recovery
    asp_persist_diff_in_memory(sync_handle, id, operation, index, data, version);
}
```

**Key characteristics:**
- Validation before in-memory persistence
- Invalid items are skipped (not persisted)
- Prevents synchronizing invalid recovery data

### C API Functions

FIM uses the C wrapper API for schema validation:

#### schema_validator_initialize()

Initialize the schema validator factory during FIM startup:

```c
if (!schema_validator_is_initialized())
{
    if (schema_validator_initialize())
    {
        minfo("Schema validator initialized successfully from embedded resources");
    }
    else
    {
        mwarn("Failed to initialize schema validator. Schema validation will be disabled.");
    }
}
```

#### schema_validator_is_initialized()

Check if the validator is ready:

```c
if (schema_validator_is_initialized())
{
    // Proceed with validation
}
```

#### schema_validator_validate()

Validate a JSON message:

```c
char* errorMessage = NULL;
const char* index = "wazuh-states-fim-file";
const char* message = "{\"file\":{\"path\":\"/etc/passwd\"}}";

if (!schema_validator_validate(index, message, &errorMessage))
{
    // Validation failed
    if (errorMessage)
    {
        merror("Validation failed: %s", errorMessage);
        free(errorMessage);  // Caller must free
    }

    // Delete from database
    delete_from_database(data);
}
```

### Deferred Deletion Pattern

FIM uses a deferred deletion pattern to safely remove invalid entries:

**Flow:**

```
1. Start Event Processing
   │
   ├─► Create failed_list (OSList)
   │
   ▼
2. Process Events
   │
   ├─► For each file/registry event:
   │   │
   │   ├─► Validate against schema
   │   │
   │   ├─► If validation fails:
   │   │   │
   │   │   ├─► Log error
   │   │   │
   │   │   └─► Add to failed_list
   │   │
   │   └─► If validation passes:
   │       │
   │       └─► Send to sync protocol
   │
   ▼
3. After All Events
   │
   ├─► fim_delete_failed_items(failed_list)
   │   │
   │   ├─► For each failed item:
   │   │   │
   │   │   └─► fim_db_remove_path()
   │   │
   │   └─► Log deletion count
   │
   ├─► OSList_Destroy(failed_list)
   │
   ▼
4. Complete
```

**Why Deferred?**
- **Avoids nested transactions**: Cannot delete during database callbacks
- **Improves performance**: Batch deletion instead of multiple deletes
- **Better error recovery**: Failures don't affect validation process

### Supported Schemas

FIM validates data for the following Wazuh indices:

| Event Type | Index Pattern | Description |
|------------|---------------|-------------|
| File events | `wazuh-states-fim-file` | File creation, modification, deletion |
| Registry events | `wazuh-states-fim-registry` | Registry key/value changes (Windows) |

#### File Event Structure

- `file.*`: File attributes (path, size, permissions, ownership, timestamps)
- `file.hash.*`: File checksums (md5, sha1, sha256)
- `event.*`: Event metadata (action, type, category)
- `agent.*`: Agent information
- `host.*`: Host information

#### Registry Event Structure

- `registry.*`: Registry key/value information (path, value_name, value_type, value_data)
- `registry.hash.*`: Registry checksums
- `event.*`: Event metadata
- `agent.*`: Agent information
- `host.*`: Host information

### Error Handling

**Initialization:**
```
INFO: Schema validator initialized successfully from embedded resources
```

**Validation Failure (File):**
```
DEBUG2: Schema validation failed for FIM message (file: /etc/passwd, index: wazuh-states-fim-file). Error: Field 'file.size' expected type 'long', got 'string'
DEBUG2: Raw event that failed validation: {"file":{"path":"/etc/passwd","size":"1024"}}
DEBUG: Discarding invalid FIM message (file: /etc/passwd)
DEBUG: Marking FIM entry for deferred deletion due to validation failure
```

**Validation Failure (Registry):**
```
DEBUG2: Schema validation failed for FIM message (registry: HKEY_LOCAL_MACHINE\Software\Test, index: wazuh-states-fim-registry). Error: Field 'registry.value_type' expected type 'keyword', got 'integer'
DEBUG2: Raw event that failed validation: {"registry":{"path":"HKEY_LOCAL_MACHINE\\Software\\Test","value_type":1}}
DEBUG: Discarding invalid FIM message (registry: HKEY_LOCAL_MACHINE\Software\Test)
```

**Batch Deletion:**
```
DEBUG: Deleted 3 FIM item(s) from database due to validation failure
```

**Graceful Degradation:**

If the schema validator is not initialized:
- Validation is skipped
- Events are processed normally
- A warning is logged on startup:
  ```
  WARN: Failed to initialize schema validator. Schema validation will be disabled.
  ```

### Memory Management

**Important:** The C API requires manual memory management for error messages:

```c
char* errorMessage = NULL;

if (!schema_validator_validate(index, message, &errorMessage))
{
    if (errorMessage)
    {
        // Use error message
        merror("Validation error: %s", errorMessage);

        // MUST free the error message
        free(errorMessage);
    }
}
```

**Do not forget to free the error message** - memory leak will occur otherwise.

### Integration with FIM Database

FIM's database integration with schema validation:

```
┌─────────────────────────────────────┐
│     File System Monitoring         │
│  (inotify/fanotify/FIM eBPF)       │
└─────────────┬───────────────────────┘
              │
              ▼
┌─────────────────────────────────────┐
│      Event Generation               │
│  (calculate checksums, diffs)       │
└─────────────┬───────────────────────┘
              │
              ▼
┌─────────────────────────────────────┐
│   Schema Validation                 │◄──── Schema Validator Module
│   (schema_validator_validate)       │
└─────────────┬───────────────────────┘
              │
         Valid │ Invalid
              ▼     ▼
┌──────────────────────────────┐
│  FIM Database (FIMDB)        │
│  - Valid events stored       │
│  - Invalid events marked     │
└──────────┬───────────────────┘
           │
           ▼
┌──────────────────────────────┐
│  Batch Deletion              │
│  (fim_delete_failed_items)   │
└──────────┬───────────────────┘
           │
           ▼
┌──────────────────────────────┐
│  Agent Sync Protocol         │
│  (Send to Manager)           │
└──────────────────────────────┘
```

### Performance Considerations

- **Deferred Deletion**: Batch deletion minimizes database overhead
- **Validation Caching**: Validator initialization is done once
- **Early Exit**: Validation happens before sync protocol (saves queuing overhead)
- **Real-time Impact**: Validation adds ~0.1-1ms per event (minimal impact on real-time monitoring)
- **Graceful Degradation**: Validation can be disabled without affecting monitoring

### Integration Status

**Integration points:**
- Module initialization (`syscheck.c`)
- Event processing (`run_check.c`)
- Recovery process (`recovery.c`)
- File monitoring (`file.c`)
- Registry monitoring (`registry.c`)

### Real-time Monitoring Impact

Schema validation is designed to have minimal impact on real-time file monitoring:

| Monitoring Mode | Validation Impact |
|----------------|------------------|
| inotify/fanotify | < 1ms per event |
| FIM eBPF | < 0.5ms per event |
| Scheduled scans | Negligible (batch processing) |
| Who-data | < 1ms per event |

### Troubleshooting

#### Validation Always Fails

**Symptom:** All events fail validation

**Possible Causes:**
1. Schema mismatch between agent and manager
2. Incorrect data format from file system monitoring
3. Schema validator not properly initialized

**Solution:**
```c
// Check initialization
if (!schema_validator_is_initialized())
{
    mwarn("Schema validator not initialized");
}

// Check for specific validation errors
char* errorMessage = NULL;
if (!schema_validator_validate(index, message, &errorMessage))
{
    if (errorMessage)
    {
        merror("Validation error: %s", errorMessage);
        merror("Raw message: %s", message);
        free(errorMessage);
    }
}
```

#### Memory Leaks

**Symptom:** Increasing memory usage over time

**Possible Cause:** Not freeing error messages

**Solution:**
```c
// Always free error messages
char* errorMessage = NULL;
if (!schema_validator_validate(index, message, &errorMessage))
{
    if (errorMessage)
    {
        // Use error message
        free(errorMessage);  // MUST free
    }
}
```

### References

- [Schema Validator Overview](../utils/schema-validator/README.md)
- [Schema Validator API Reference](../utils/schema-validator/api-reference.md)
- [Schema Validator Integration Guide](../utils/schema-validator/integration-guide.md)

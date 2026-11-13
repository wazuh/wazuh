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
  - **Other platforms**: Realtime is unsupported; the thread logs a warning if a directory requests it and exits
* Monitors configured directories for changes (create, modify, delete, move)
* Triggers `fim_checker()` which leads to database transactions and `transaction_callback()`
* Runs continuously in background thread launched at FIM startup
* **Respects pause state** - the inotify loop reads the inotify descriptor under `fim_realtime_mutex`, so it is held off while a completed pause owns that mutex

### **Integrity Scanning Thread**

Dedicated thread that performs the periodic synchronization and the integrity/recovery checks. It is started only when `synchronization` is enabled. The scheduled filesystem scan runs in the daemon's main loop (`start_daemon()`), not in this thread.
Responsibilities:

* **`fim_run_integrity()`** - Synchronization and integrity thread:
  - Waits `syscheck.sync_interval` seconds between cycles (the first cycle runs without delay on a first start)
  - Runs one `asp_sync_module(MODE_DELTA)` per cycle for the whole module
  - Handles flush requests by checking the `fim_flush_in_progress` flag
  - **Respects pause state** - skips the cycle while `fim_pause_requested` is set, except for a pending flush, which it serves without taking the scan mutexes
  - Runs the agent-ID resync and the integrity/recovery checks under the scan mutexes (see [Recovery Architecture](#recovery-architecture))

### **Operation State Control**

FIM implements atomic state flags to coordinate operations and enable external control. Unlike Syscollector's synchronous model, FIM uses an **asynchronous model with polling**.

**State Flags (Atomic Variables):**
* `fim_pause_requested` - Indicates if a pause has been requested
* `fim_pausing_is_allowed` - Indicates that a pause was acknowledged: `fim_execute_is_pause_completed()` holds the scan mutexes
* `fim_flush_in_progress` - Indicates if a flush operation is active
* `fim_flush_result` - Result of the flush operation (0 = success, -1 = error)

**Coordination Flow (Asynchronous):**

```
External Coordination Command (pause)
         │
         ▼
Set fim_pausing_is_allowed = 0, fim_pause_requested = 1 (atomic)
         │
         ▼
Return immediately (non-blocking)
         │
         ▼
Caller Polls: fim_execute_is_pause_completed()
         │
         ├─► trylock fim_scan_mutex, fim_realtime_mutex
         │   (and fim_registry_scan_mutex on Windows)
         │
         ├─► Any mutex busy (scan, realtime, or the sync thread's
         │   resync/integrity checks) ──► release those taken, Returns 1
         │
         ├─► All acquired ──► Set fim_pausing_is_allowed = 1, Returns 0
         │   (the mutexes stay held until resume)
         │
         └─► FIM stopping ──► release any held pause, Returns -1
         │
         ▼
External Coordination Command (resume)
         │
         ▼
Release the mutexes (if acknowledged) and clear both flags
         │
         ▼
FIM threads resume operations
```

**Operation Protection:**

The sync thread checks the pause flag on every cycle; scans and realtime processing are held off only by the mutexes that a completed pause owns:

```c
// In fim_run_integrity, once per cycle
int pause_requested = atomic_int_get(&syscheck.fim_pause_requested);

if (pause_requested && !flush_request_detected) {
    mdebug2("FIM is paused, skipping sync iteration");
    continue;
}

if (pause_requested && flush_request_detected) {
    // Paused with a pending flush: sync without taking the scan mutexes
    SyncModuleResult_t sync_result = asp_sync_module(syscheck.sync_handle, MODE_DELTA);

    atomic_int_set(&fim_flush_result, sync_result.success ? 0 : -1);
    atomic_int_set(&fim_flush_in_progress, 0);
} else {
    // Normal cycle: asp_sync_module(), then (with the scan mutexes held)
    // fim_resync_on_agent_id_change() and fim_recovery_run_integrity_checks()
}
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
persist_syscheck_msg(file_path_sha1, sync_operation, FIM_FILES_SYNC_INDEX, stateful_event, document_version);
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
- Registry key and value changes (Windows), through `registry_key_transaction_callback()` and `registry_value_transaction_callback()`, which follow the same pattern
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

## Document Limits

FIM implements a synchronization limit mechanism to control the number of files/registry entries synchronized to the indexer while maintaining unlimited local monitoring.

### Purpose

Document limits allow agents to:
- **Track unlimited files/registry entries locally** for complete monitoring coverage
- **Synchronize only a subset** to the indexer to manage resource usage
- **Continue generating stateless events** for all changes regardless of sync status
- **Prioritize by arrival** while the limit is being filled: a new item gets `sync=1` only while the synced count is below the limit

### Synchronization Control

Each monitored item has a `sync` flag in the database:
- `sync=1`: Item is synchronized and will be sent to the indexer
- `sync=0`: Item is stored locally but not synchronized

All items generate **stateless events** regardless of their sync status. Only items with `sync=1` are added to the **persistent sync queue** for indexer synchronization.

### Limit Enforcement Flow

```
File/Registry Change Detected
         │
         ▼
Transaction Callback Processing
         │
         ├─► Limit = 0 (unlimited) ──────► Set sync=1 ──────► Queue for Sync
         │
         └─► Limit > 0 (limited)
                  │
                  ├─► Total synced < Limit ──────► Set sync=1 ──────► Queue for Sync
                  │
                  └─► Total synced >= Limit ─────► Set sync=0 ──────► Store Locally (no sync)
```

### State Transition Handling

The implementation uses a **deferred update mechanism** to prevent race conditions during database transactions:

#### INSERT Operations
```cpp
// During transaction callback (before commit)
if (current_sync_count < sync_limit) {
    add_pending_sync_item(pending_items, document_json, 1);  // Mark for sync=1
    current_sync_count++;
} else {
    add_pending_sync_item(pending_items, document_json, 0);  // Mark for sync=0
}

// After transaction commits
process_pending_sync_updates(table_name, pending_items);
```

#### MODIFY Operations
```cpp
// If document currently has sync=0 but slots available
if (old_sync == 0 && current_sync_count < sync_limit) {
    add_pending_sync_item(pending_items, document_json, 1);  // Promote to sync=1
    current_sync_count++;
}
// If already sync=1, stays sync=1
```

#### DELETE Operations
```cpp
// If deleted document had sync=1
if (old_sync == 1) {
    current_sync_count--;
}
```

### Promotion and Demotion on Limit Changes

FIM fetches the sync limit from agentd once, when it starts (agent start or restart). If it differs from the one the documents were synced with, FIM automatically adjusts which documents are synchronized based on the limit change.

#### Limit Change Detection (During Initialization)

**Process:**
1. Count currently synced documents: `synced_docs = fim_db_count_synced_docs(table_name)`
2. Receive the new limit from agentd
3. Compare and adjust:
   - **Limit increased** (`synced_docs < new_limit`): Promote the first non-synced documents in a fixed order (see Ordering Strategy)
   - **Limit decreased** (`synced_docs > new_limit`): Demote the first synced documents in a fixed order (see Ordering Strategy)
   - **Special case**: `limit = 0` means unlimited, promote all documents

### Ordering Strategy

When a startup limit change promotes documents, the candidates are selected in a fixed order (not insertion order): by path, then architecture and value where the table has them, then version, as in the queries below; during normal operation a new item is synced only while the synced count is below the limit:

**File Table:**
```sql
SELECT * FROM file_entry WHERE sync = 0 ORDER BY path, version LIMIT N
```

**Registry Key Table (Windows):**
```sql
SELECT * FROM registry_key WHERE sync = 0 ORDER BY path, architecture, version LIMIT N
```

**Registry Value Table (Windows):**
```sql
SELECT * FROM registry_data WHERE sync = 0 ORDER BY path, architecture, value, version LIMIT N
```

This fixed ordering ensures **deterministic and consistent** selection across agent restarts. It follows the key columns but not always their declared order: `registry_key`'s primary key is `(architecture, path)`, while the query sorts by `path, architecture`.

### Configuration

The sync limit is fetched from agentd at startup (FIM retries once per second until agentd answers) and stored globally:

```c
extern int synced_docs_files;           // Current count of synced files
extern int synced_docs_registry_keys;    // Current count of synced registry keys (Windows)
extern int synced_docs_registry_values;  // Current count of synced registry values (Windows)
```

**Behavior:**
- **`sync_limit = 0`** (default): Unlimited synchronization - all items have `sync=1`
- **`sync_limit > 0`**: Items inserted while the synced count is below N get `sync=1`; the rest are stored with `sync=0`

### Recovery with Limits

During recovery operations, only items with `sync=1` are synchronized:

```c
bool fim_recovery_persist_table_and_resync(char* table_name, AgentSyncProtocolHandle* handle,
                                           const OSList* directories_list, const char* retry_note) {
    // Increase version for all entries
    fim_db_increase_each_entry_version(table_name);

    // Get only synced entries
    cJSON* items = fim_db_get_every_element(table_name, "WHERE sync=1");

    // Clear the manager's index for this table
    asp_notify_data_clean(handle, clean_indices, 1);

    // Build, validate and queue the stateful events for synced items only
    // (rows no longer covered by the configuration are skipped)
    cJSON_ArrayForEach(item, items) {
        asp_persist_diff(handle, hashed_id, OPERATION_CREATE, index, stateful_event_str, document_version);
    }

    // Nothing is sent here: the caller sends the queued rows after releasing the scan mutexes,
    // with fim_recovery_sync_recovered_tables()
    return true;
}
```

### Startup Initialization

On module startup, FIM calculates the current count of synced documents:

```cpp
// Called during fim_initialize()
synced_docs_files = fim_db_count_synced_docs(FIMDB_FILE_TABLE_NAME);

#ifdef WIN32
synced_docs_registry_keys = fim_db_count_synced_docs(FIMDB_REGISTRY_KEY_TABLENAME);
synced_docs_registry_values = fim_db_count_synced_docs(FIMDB_REGISTRY_VALUE_TABLENAME);
#endif
```

### Deferred Update Mechanism

To prevent race conditions during database transactions, sync flag updates occur **after** transaction commits:

1. **During Transaction Callback**: Calculate sync flags, add items to pending list
2. **After Transaction Commits**: Execute `process_pending_sync_updates()` to update database

```cpp
// Transaction callback adds to pending list
add_pending_sync_item(pending_items, document_json, sync_value);

// After transaction completes
process_pending_sync_updates(table_name, pending_items);
    └─► Updates sync flag in database for each pending item
```

This ensures the document version doesn't increment unnecessarily during sync flag updates.

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

    // send_data_clean_with_retry() in run_check.c
    bool dataCleanSent = false;
    while (!dataCleanSent && !fim_shutdown_process_on()) {
        w_rwlock_rdlock(&fim_sync_handle_rwlock);
        if (syscheck.sync_handle) {
            dataCleanSent = asp_notify_data_clean(syscheck.sync_handle, indices, indices_count);
        }
        w_rwlock_unlock(&fim_sync_handle_rwlock);
        if (!dataCleanSent) {
            // Wait sync_interval before retry, checking for shutdown every second
            for (uint32_t i = 0; i < syscheck.sync_interval && !fim_shutdown_process_on(); i++) {
                sleep(1);
            }
        }
    }
}
```

**Retry Logic:**
- Continues retrying until it succeeds or FIM shuts down
- Waits `syscheck.sync_interval` seconds between retries

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
        SyncModuleResult_t sync_result = asp_sync_module(syscheck.sync_handle, MODE_DELTA);
        if (!sync_result.success) {
            // Logged by severity; see the asp_sync_module() example in api-reference.md
        }

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
* Runs one DELTA synchronization (all tables share the same queue) every `syscheck.sync_interval`.
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
         └─►  Success? ──► Lock fim_scan_mutex, fim_realtime_mutex
                           (and fim_registry_scan_mutex on Windows;
                            retried every second, abandoned on shutdown)
                                    │
                                    ▼
                          Agent ID changed since the last sync?
                          (fim_resync_on_agent_id_change)
                                    │
                                    └─► Yes? ──► DataClean + queue every table not yet
                                                 resent under the new ID, then record the ID
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
                                            ├─► Match? ──► Done
                                            │
                                            ├─► Not checked (check failed)? ──► Reported in one
                                            │     warning, retried in the next integrity_interval
                                            │
                                            └─► Mismatch? ──► Trigger Recovery
                                                                 │
                                                                 ▼
                                                         Load Table Rows with sync=1
                                                                     │
                                                                     ▼
                                                         Clear Manager Index (DataClean)
                                                                     │
                                                                     ▼
                                                         Queue the Entries (sent after the unlock)

After every table is checked (last_sync_time is updated whatever the outcome,
unless a shutdown interrupted the pass):
         │
         ▼
Unlock the mutexes
         │
         ▼
Any table recovered? ──► One Delta Sync for all of them ──► asp_sync_module(MODE_DELTA)
                         (regular agent.sync_max_blocks_per_cycle limit; whatever is
                          left is sent by the next cycles and the log says so)
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
FIM stopping? ──► Return -1
         │
         ▼
Already requested? ──► Return 0 (idempotent)
         │
         ▼
Set fim_pausing_is_allowed = 0, fim_pause_requested = 1 (atomic)
         │
         ▼
Return 0 immediately (non-blocking)
         │
         ▼
Caller Polls Status (fim_execute_is_pause_completed)
         │
         ├─► FIM stopping: release any held pause ──► Returns -1
         │
         ├─► fim_pausing_is_allowed already set ──► Returns 0
         │
         ├─► No pause requested ──► Returns 0 (nothing is taken)
         │
         ├─► trylock fim_scan_mutex, fim_realtime_mutex
         │   (and fim_registry_scan_mutex on Windows)
         │   │
         │   ├─► Any busy: release those taken ──► Returns 1 (caller polls again)
         │   │
         │   └─► All acquired: set fim_pausing_is_allowed = 1 ──► Returns 0
         │       (the mutexes stay held until resume or shutdown)
```

The resume command is **synchronous**:

```
Resume Command Received (fim_execute_resume)
         │
         ▼
Check if a pause was requested
         │
         ├─► Not requested → Return 0 (idempotent)
         │
         └─► Requested → Continue
                 │
                 ▼
         Release the mutexes (only if the pause was acknowledged):
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
FIM stopping? ──► Return -1
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
                         ├─► Returns 0: Success (also when synchronization is disabled)
                         ├─► Returns -1: Error
                         └─► Returns -2: FIM is stopping (no result reported)
```

### Thread Safety

All coordination commands are thread-safe:

- **Atomic operations** (`atomic_int_get`, `atomic_int_set`) ensure consistent flag reads/writes
- **Mutexes** coordinate between command handlers and FIM threads
- **Non-blocking polling**: status checks never wait; `fim_execute_is_pause_completed()` uses `pthread_mutex_trylock()` and returns 1 when a mutex is busy
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

#### 1. During Event Processing (the file and registry transaction callbacks)

When file or registry changes are detected, validation occurs before sending to the sync protocol:

```c
// Validate the stateful event and, if it passes, persist it
validation_passed = validate_and_persist_fim_event(
    stateful_event,
    file_path_sha1,
    sync_operation,
    FIM_FILES_SYNC_INDEX,
    document_version,
    item_desc,
    mark_for_deletion,
    txn_context->failed_paths,
    path_copy,
    sync_flag
);
```

`validate_and_persist_fim_event()` validates only when synchronization is enabled and the schema validator is initialized. On success, and only if `sync_flag` is `1`, it calls `persist_syscheck_msg()`. A validation failure that is observed while FIM is shutting down is ignored (logged at debug level, nothing is persisted or deleted), because the validator's state may already be torn down.

**Key characteristics:**
- Validation before sync protocol transmission
- Failed items are accumulated in `failed_list`
- Item data is marked for deferred deletion

#### 2. During Recovery (fim_recovery_persist_table_and_resync)

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
            merror("Schema validation failed for recovery event (table: %s, id: %s, index: %s). Errors: %s",
                   table_name, id_str, index, errorMessage);
            os_free(errorMessage);
        }

        merror("Raw recovery event that failed validation: %s", stateful_event_str);
        mdebug1("Skipping persistence of invalid recovery event for %s", id_str);
        validation_passed = false;
    }
}

if (validation_passed)
{
    // Persist for recovery (into the sync protocol's persistent queue, same as any other delta item)
    asp_persist_diff(handle, hashed_id, OPERATION_CREATE, index, stateful_event_str, document_version);
}
```

**Key characteristics:**
- Validation before persistence
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
        mdebug1("Schema validator initialized successfully from embedded resources");
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
const char* index = "wazuh-states-fim-files";
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
   ├─► cleanup_failed_fim_files() / cleanup_failed_registry_keys() /
   │   cleanup_failed_registry_values()
   │   │
   │   └─► For each failed item:
   │       │
   │       ├─► Log "Deleting <item> from DBSync due to validation failure"
   │       │
   │       └─► fim_db_file_delete() / fim_db_registry_key_delete() /
   │           fim_db_registry_value_delete()
   │
   ├─► OSList_Destroy(failed_list)
   │
   ▼
4. Complete
```

**Why Deferred?**
- **Avoids nested transactions**: Cannot delete during database callbacks; the deletes run after the transaction, one per item
- **Better error recovery**: Failures don't affect validation process

### Supported Schemas

FIM validates data for the following Wazuh indices:

| Event Type | Index Pattern | Description |
|------------|---------------|-------------|
| File events | `wazuh-states-fim-files` | File creation, modification, deletion |
| Registry key events | `wazuh-states-fim-registry-keys` | Registry key changes (Windows) |
| Registry value events | `wazuh-states-fim-registry-values` | Registry value changes (Windows) |

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
DEBUG: Schema validator initialized successfully from embedded resources
```

**Validation Failure** (`validate_and_persist_fim_event()` in `run_check.c`; `<item>` is `file <path>`, `registry key <path>` or `registry value <path>:<value>`):
```
ERROR: Schema validation failed for <item> (index: <index>). Errors: <validator errors, one per line>
ERROR: Raw event that failed validation: <event JSON>
DEBUG: Skipping persistence of invalid event for <item>
DEBUG: Marking <item> for deletion from DBSync due to validation failure
```

The validator errors use the format in the [schema validator API reference](../utils/schema-validator/api-reference.md), for example `file.size: Expected integer, got string with value: "1024"`.

**Deferred Deletion** (one line per item):
```
DEBUG: Deleting <path> from DBSync due to validation failure
DEBUG: Deleting registry key <path> from DBSync due to validation failure
DEBUG: Deleting registry value <path>:<value> from DBSync due to validation failure
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
│  Deferred Deletion           │
│  (cleanup_failed_*)          │
└──────────┬───────────────────┘
           │
           ▼
┌──────────────────────────────┐
│  Agent Sync Protocol         │
│  (Send to Manager)           │
└──────────────────────────────┘
```

### Performance Considerations

- **Deferred Deletion**: Invalid entries are deleted after the transaction, not inside the database callback
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

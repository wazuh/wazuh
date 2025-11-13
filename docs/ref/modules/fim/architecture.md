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

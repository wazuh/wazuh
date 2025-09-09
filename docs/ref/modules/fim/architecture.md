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

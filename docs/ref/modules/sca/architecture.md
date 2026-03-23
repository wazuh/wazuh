# Architecture

The **SCA module** implements a security configuration assessment system that evaluates system compliance against security policies. The module loads these policies from YAML files, executes security checks, and synchronizes results with the manager.

---

## Main Components

### **SCA Implementation (sca_impl)**

The central C++ implementation (`SecurityConfigurationAssessment` class) that coordinates SCA operations.

**Key responsibilities:**
* Manages the main scanning loop
* Coordinates policy loading and execution
* Handles configuration setup and lifecycle management
* Integrates with DBSync for local data persistence
* Manages Agent Sync Protocol for manager communication

### **Policy Loader (`SCAPolicyLoader`)**

Handles loading and parsing of YAML policy files.

**Key responsibilities:**
* Loads policies from configured file paths
* Parses YAML policy structure using the configured YAML-to-JSON callback function
* Validates policy metadata and check definitions
* Creates policy objects for execution
* Stores policy data in the database via DBSync

### **Rule Evaluators**

Individual evaluators for different rule types found in policy checks.

**Available evaluators:**
* **File Rule Evaluator**: Checks file existence, permissions, and content
* **Command Rule Evaluator**: Executes system commands and evaluates output
* **Registry Rule Evaluator**: Checks Windows registry keys and values
* **Directory Rule Evaluator**: Validates directory properties
* **Process Rule Evaluator**: Checks for running processes

Each evaluator processes specific rule syntax and returns pass/fail results.

### **Event Handler (`SCAEventHandler`)**

Manages the generation and delivery of SCA events.

**Key responsibilities:**
* Generates events when policy or check states change
* Handles both stateless (immediate) and stateful (persistent) message delivery
* Calls configured push functions to send events to the message queue
* Reports policy and check deltas during synchronization

### **Database Integration (DBSync)**

Uses the shared DBSync component for local SQLite database operations.

**Key responsibilities:**
* Stores policy metadata in the `sca_policy` table
* Maintains check results in the `sca_check` table
* Provides database abstraction layer for SCA data
* Handles database schema creation and management

### **Agent Sync Protocol**

Integrates with Wazuh's Agent Sync Protocol for reliable manager communication.

**Key responsibilities:**
* Persists SCA data changes for synchronization with the manager
* Handles periodic synchronization requests from the manager
* Manages the sync database and message queues
* Processes synchronization responses from the manager

---

## Data Flow

### **Initialization Flow**
1. `wm_sca_main()` loads the SCA dynamic library and sets up callbacks
2. `sca_start()` initializes the SCA implementation with configuration
3. `SecurityConfigurationAssessment::Setup` callbacks and other configuration values.
4. Agent Sync Protocol handle is created if synchronization is enabled
5. `SecurityConfigurationAssessment::Run ` Starts the execution flow

### **Scan Execution Flow**
1. `SecurityConfigurationAssessment::Run()` executes the main loop
2. `SCAPolicyLoader` loads enabled policies from YAML files
3. For each policy, checks are executed using appropriate rule evaluators
4. `SCAEventHandler` compares results with stored state
5. Changed results trigger event generation via configured push functions

### **Synchronization Flow**
1. Stateful events are persisted via Agent Sync Protocol
2. Periodic synchronization sends accumulated changes to manager
3. Manager responses are parsed and processed
4. Database state is updated through DBSync

### **Recovery Flow**
The SCA module includes automatic recovery to detect and resolve synchronization inconsistencies:

1. Each time `integrity_interval` elapses, an integrity check is performed
2. Agent calculates checksum-of-checksums from the `sca_check` table
3. Checksum is sent to manager via `requiresFullSync()` in Agent Sync Protocol
4. Manager compares agent checksum with its indexed data
5. On mismatch, full recovery is triggered:
   - All checks are loaded from local database
   - Stateful messages are rebuilt in the indexer-required format
   - Full synchronization sends all data to manager
6. `last_integrity_check` timestamp is stored in `sca_metadata` table

```
Sync Thread (wm_sca_sync_module)
         │
         ▼
   DELTA Sync
         │
         ▼
Check if integrity_interval elapsed
         │
         ├─► No  → Skip integrity check
         │
         └─► Yes → Calculate table checksum
                   │
                   ▼
             Send checksum to manager
                   │
                   ├─► Match    → No action needed
                   │
                   └─► Mismatch → Perform full recovery
                                  │
                                  ├─► Load all checks from DB
                                  ├─► Clear in-memory sync data
                                  ├─► Rebuild stateful messages
                                  └─► Trigger FULL synchronization
```

---

## Threading Model

The SCA module operates with the following threads:

* **Main Thread** (`wm_sca_main`): Runs the SCA implementation and handles policy execution
* **Sync Thread** (`wm_sca_sync_module`): Handles periodic synchronization with the manager (when enabled)

---

## SCA Disabled Cleanup Flow

### Overview

When the SCA module is disabled, the `wm_handle_sca_disable_and_notify_data_clean()` function executes a cleanup procedure to notify the manager and remove local databases. This ensures the manager's state remains synchronized with the agent's actual module status.

### Execution Trigger

The function is called during module startup in `wm_sca_main()` when `data->enabled` is false:

```c
if (data->enabled) {
    minfo("SCA module enabled.");
} else {
    wm_handle_sca_disable_and_notify_data_clean();
    minfo("SCA module disabled. Exiting.");
    pthread_exit(NULL);
}
```

### Cleanup Flow

```
Module Startup (wm_sca_main)
      │
      ▼
Check data->enabled
      │
      ▼ (if disabled)
wm_handle_sca_disable_and_notify_data_clean()
      │
      ├─► Check for SCA database file ───► w_is_file(SCA_DB_DISK_PATH)
      │                                           │
      │                                           ├─► File exists
      │                                           │   (proceed with cleanup)
      │                                           │
      │                                           └─► File not exists
      │                                               (skip notification, exit)
      │
Load SCA module dynamically
      │
      ▼
Configure SCA module minimally
      │
      ├─► Set logging callback ─────────► sca_set_log_function(sca_log_callback)
      │
      ├─► Set sync parameters ──────────► sca_set_sync_parameters()
      │   (module name, DB path, MQ funcs)
      │
      └─► Initialize module ─────────────► sca_init()
      │
      ▼
Send data clean notification ────────► sca_notify_data_clean()
      │                                     │
      │                                     ├─► indices: [SCA_SYNC_INDEX]
      │                                     ├─► Retry on failure
      │                                     │   (wait sca_sync_interval)
      │                                     │
      │                                     └─► Success confirmation
      │
      └─► Delete databases ─────────► sca_delete_database()
```

### Behavior Scenarios

#### Scenario 1: SCA Disabled with Existing Database

```
1. Agent starts with SCA module disabled (enabled = false)
2. SCA database file exists at SCA_DB_DISK_PATH
3. Load SCA module dynamically
4. Configure logging and sync parameters
5. Initialize SCA module structures
6. Send data clean notification to manager (with infinite retries)
7. Manager removes SCA_SYNC_INDEX from agent's state
8. Delete sync protocol database
9. Exit module startup
```

#### Scenario 2: SCA Disabled with No Database

```
1. Agent starts with SCA module disabled (enabled = false)
2. SCA database file does not exist
3. Skip data clean notification (nothing to clean)
4. Exit module startup immediately
```

---

## Policy Removal Cleanup Flow

When all SCA policies are removed from configuration while the module remains enabled, the module detects this at startup or during runtime and initiates a cleanup process.

### Behavior

| Scenario | Action |
|----------|--------|
| **All policies removed** | DataClean sent to manager → DB tables cleared → module exits |
| **Partial removal** | DBSync generates delete events → module continues with remaining policies |

### Flow

```
Policy Loading
      │
      ▼
No enabled policies found?
      │
      ├─► No  → Continue normal scanning
      │
      └─► Yes → Check if DB has existing data
                │
                ├─► No data  → Exit (nothing to clean)
                │
                └─► Has data → Send DataClean notification
                              │
                              ├─► Clear sca_policy table
                              ├─► Clear sca_check table
                              └─► Exit module
```

---

## Coordination Commands Architecture

The coordination commands provide external control over SCA operations, allowing the agent-info to coordinate module behavior. SCA implements a **synchronous blocking model** using C++ threading primitives, similar to Syscollector.

### Command Types

#### Pause/Resume Commands

**Purpose:** Allow temporary suspension of SCA scanning operations without stopping the module completely.

**Implementation:**

The pause command follows this **synchronous sequence**:

```
Pause Command Received
         │
         ▼
Set m_paused = true (atomic flag)
         │
         ▼
Wait for Current Operations
         │
         ├─► Wait for m_scanInProgress = false
         │   (any ongoing scan completes)
         │
         └─► Wait for m_syncInProgress = false
             (any ongoing sync completes)
         │
         ▼
Both Operations Complete
         │
         ▼
Return to Caller (blocking complete)
```

The resume command:

```
Resume Command Received
         │
         ▼
Set m_paused = false (atomic flag)
         │
         ▼
Notify Main Loop (m_cv.notify_one())
         │
         ▼
SCA Resumes Normal Operations
```

#### Flush Command

**Purpose:** Force immediate synchronization of pending SCA check results, bypassing the normal sync interval.

**Implementation:**

```
Flush Command Received
         │
         ▼
Check if Sync Protocol Initialized
         │
         ├─► Not Initialized → Return 0 (nothing to flush)
         │
         └─► Initialized
             │
             ▼
Call synchronizeModule(Mode::DELTA)
             │
             ├─► Waits for manager acknowledgment
             └─► Returns sync result
```

#### Version Management Commands

**Purpose:** Query and set version numbers for tracking SCA scanning operations and coordination state.

**getMaxVersion() Implementation:**

```
getMaxVersion() Called
         │
         ▼
Execute SQL Query
         │
         └─► SELECT MAX(version) FROM sca_check
         │
         ▼
Return Maximum Version (or 0 if empty, -1 on error)
```

**setVersion() Implementation:**

```
setVersion(newVersion) Called
         │
         ▼
Start Database Transaction
         │
         ├─► For Each Row in sca_check Table:
         │   │
         │   ├─► Retrieve all columns
         │   │
         │   ├─► Update version = newVersion
         │   │
         │   └─► Continue to next row
         │
         ▼
Commit Transaction
         │
         ▼
Return 0 (success) or -1 (error)
```

---

## Event Types

### Stateful Events
- Persisted via Agent Sync Protocol for reliable delivery
- Synchronized with manager during periodic sync sessions
- Include check and policy data with operation types (CREATE, MODIFY, DELETE)

### Stateless Events
- Sent immediately through the message queue system
- Used for real-time SCA alerts and notifications
- No local persistence or retry mechanism

---

## Schema Validation Integration

SCA integrates with the [Schema Validator](../utils/schema-validator/README.md) module to ensure all security check results conform to the expected Wazuh indexer schema before transmission.

### Purpose

- **Prevent Indexing Errors**: Validate check results before they reach the indexer
- **Prevent Integrity Sync Loops**: Invalid checks are removed from local databases to avoid repeated sync attempts
- **Improve Data Quality**: Ensure all indexed data conforms to expected types and structures
- **Provide Detailed Error Reporting**: Specific field paths and validation failures for debugging

### Validation Points

Schema validation occurs at three critical points in the SCA lifecycle:

#### 1. During Policy Delta Reporting (ReportPoliciesDelta)

When policies or checks are modified, validation occurs before sending to the sync protocol:

```cpp
const bool validationPassed = ValidateAndHandleStatefulMessage(
    processedStatefulEvent,
    "policy/check event",
    checkDataForDelete,
    &failedChecks
);

if (validationPassed)
{
    PushStateful(processedStatefulEvent, operation, version);
}
```

**Key characteristics:**
- Validation before stateful event transmission
- Failed checks are accumulated in `failedChecks` vector
- Check data is marked for deferred deletion

#### 2. During Check Result Reporting (ReportCheckResult)

When individual check results are reported:

```cpp
const bool validationPassed = ValidateAndHandleStatefulMessage(
    stateful,
    "checkId: " + checkId,
    dataForDelete,
    &failedChecks
);

if (validationPassed)
{
    PushStateful(stateful, operation, version);
}

// Delete checks that failed schema validation (batch delete with transaction)
DeleteFailedChecksFromDB(failedChecks);
```

**Key characteristics:**
- Validation per check result
- Failed checks accumulated
- Batch deletion after all checks processed

#### 3. During Recovery (performRecovery)

When performing integrity recovery, only valid items are synchronized:

```cpp
auto validationResult = validator->validate(statefulMessage.dump());

if (!validationResult.isValid)
{
    // Log validation errors
    std::string errorMsg = "Schema validation failed for SCA recovery message (policy: " +
                           policyId + ", check: " + checkId + ", index: " +
                           std::string(SCA_SYNC_INDEX) + "). Errors: ";

    for (const auto& error : validationResult.errors)
    {
        errorMsg += "  - " + error;
    }

    LoggingHelper::getInstance().log(LOG_ERROR, errorMsg);
    LoggingHelper::getInstance().log(LOG_ERROR, "Raw recovery event that failed validation: " +
                                     statefulMessage.dump());
    LoggingHelper::getInstance().log(LOG_DEBUG, "Skipping persistence of invalid recovery event");
    shouldPersist = false;
}
```

**Key characteristics:**
- Validation before in-memory persistence
- Invalid items are skipped (not persisted)
- Prevents synchronizing invalid recovery data

### Helper Functions

The SCA Event Handler provides two helper functions:

#### ValidateAndHandleStatefulMessage()

Validates a stateful SCA message and marks it for deletion if validation fails:

```cpp
bool ValidateAndHandleStatefulMessage(const nlohmann::json& statefulEvent,
                                      const std::string& context,
                                      const nlohmann::json& checkData,
                                      std::vector<nlohmann::json>* failedChecks) const;
```

**Behavior:**
- Returns `true` if validation passed or validator not initialized
- Returns `false` if validation failed
- Logs detailed error messages with field paths and expected types
- Logs raw event data for debugging
- Accumulates failed checks in `failedChecks` vector for deferred deletion

#### DeleteFailedChecksFromDB()

Deletes failed checks from DBSync in a batch transaction:

```cpp
void DeleteFailedChecksFromDB(const std::vector<nlohmann::json>& failedChecks) const;
```

**Implementation:**
```cpp
void SCAEventHandler::DeleteFailedChecksFromDB(
    const std::vector<nlohmann::json>& failedChecks) const
{
    if (failedChecks.empty() || !m_dBSync)
    {
        return;
    }

    try
    {
        DBSyncTxn deleteTxn(m_dBSync->handle(), nlohmann::json::array(), 0, 1,
                           [](ReturnTypeCallback, const nlohmann::json&) {});

        for (const auto& failedCheck : failedChecks)
        {
            auto deleteQuery = DeleteQuery::builder()
                               .table("sca_check")
                               .data(failedCheck)
                               .build();

            m_dBSync->deleteRows(deleteQuery.query());
        }

        deleteTxn.getDeletedRows([](ReturnTypeCallback, const nlohmann::json&) {});

        LoggingHelper::getInstance().log(LOG_DEBUG, "Deleted " +
                                         std::to_string(failedChecks.size()) +
                                         " SCA check(s) from DBSync due to validation failure");
    }
    catch (const std::exception& e)
    {
        LoggingHelper::getInstance().log(LOG_ERROR, "Failed to delete from DBSync: " +
                                         std::string(e.what()));
    }
}
```

**Behavior:**
- Creates DBSync transaction for atomicity
- Deletes all failed checks in a single transaction
- Logs number of checks deleted
- Handles deletion errors gracefully

### Deferred Deletion Pattern

SCA uses a deferred deletion pattern to safely remove invalid checks:

**Flow:**

```
1. Start Event Processing
   │
   ├─► Create failedChecks vector
   │
   ▼
2. Process Events
   │
   ├─► For each policy/check event:
   │   │
   │   ├─► Validate against schema
   │   │
   │   ├─► If validation fails:
   │   │   │
   │   │   ├─► Log error
   │   │   │
   │   │   └─► Add to failedChecks vector
   │   │
   │   └─► If validation passes:
   │       │
   │       └─► Push to stateful queue
   │
   ▼
3. After All Events
   │
   ├─► DeleteFailedChecksFromDB(failedChecks)
   │   │
   │   ├─► Create DBSync transaction
   │   │
   │   ├─► Delete all failed checks
   │   │
   │   └─► Commit transaction
   │
   ▼
4. Complete
```

**Why Deferred?**
- **Clean separation**: Validation and deletion are separate concerns
- **Improves performance**: Single batch transaction instead of multiple deletes
- **Ensures atomicity**: All deletions committed together or rolled back
- **Better error recovery**: Transaction rollback on any failure

### Supported Schema

SCA validates data against the `wazuh-states-sca` index:

**Schema Structure:**
- `check.*`: Check details (id, name, description, result, etc.)
- `policy.*`: Policy metadata (id, name, file, references)
- `state.*`: State information (modified_at, document_version)
- `checksum.*`: Integrity checksum

### Check Not Found in DB

When a check result is reported but the check is not found in the database, SCA logs a debug message:

```cpp
LoggingHelper::getInstance().log(LOG_DEBUG,
    "Check " + checkId + " not found in DB (may have been deleted due to validation failure), skipping report");
```

**Previous Behavior:** Logged as `LOG_WARNING` without explanation

**New Behavior:**
- Changed to `LOG_DEBUG` level (expected behavior, not an error)
- More specific message indicating probable cause
- Prevents log flooding when checks are deleted due to validation failures

**Occurs when:**
- A check fails validation and is deleted from the database
- A check result report is later attempted for that check
- The check has been legitimately removed

### Error Handling

**Initialization:**
```
[INFO] Schema validator initialized successfully from embedded resources
```

**Validation Failure:**
```
[ERROR] Schema validation failed for SCA message (checkId: cis_rhel7_1.1.1, index: wazuh-states-sca). Errors:
  - Field 'check.result' expected type 'keyword', got 'integer'
[ERROR] Raw event that failed validation: {"check":{"id":"cis_rhel7_1.1.1","result":1}}
[DEBUG] Marking SCA check for deferred deletion due to validation failure
```

**Batch Deletion:**
```
[DEBUG] Deleted 2 SCA check(s) from DBSync due to validation failure
```

**Check Not Found:**
```
[DEBUG] Check cis_rhel7_1.1.1 not found in DB (may have been deleted due to validation failure), skipping report
```

**Graceful Degradation:**

If the schema validator is not initialized:
- Validation is skipped
- Checks are processed normally
- A warning is logged on startup

### Performance Considerations

- **Deferred Deletion**: Batch transaction minimizes database overhead
- **Validation Caching**: Validator is obtained once and reused
- **Early Exit**: Validation happens before queuing (saves sync protocol overhead)
- **Graceful Degradation**: Validation can be disabled without affecting core functionality

### Integration Status

**Integration points:**
- Module initialization (`sca_impl.cpp`)
- Policy delta reporting (`sca_event_handler.cpp`)
- Check result reporting (`sca_event_handler.cpp`)
- Recovery process (`sca_impl.cpp`)

### Database Schema

#### sca_check Table

Stores individual security checks:
- `id`: Check ID (primary key)
- `policy_id`: Foreign key to sca_policy
- `name`: Check name
- `description`: Check description
- `result`: Check result (Passed, Failed, Not applicable, Not run)
- `reason`: Reason for result (optional)
- `version`: Document version for synchronization

### References

- [Schema Validator Overview](../utils/schema-validator/README.md)
- [Schema Validator API Reference](../utils/schema-validator/api-reference.md)
- [Schema Validator Integration Guide](../utils/schema-validator/integration-guide.md)

# API Reference

The SCA module provides C and C++ APIs for interaction with other Wazuh components and supports database synchronization through the Agent Sync Protocol.

---

## Internal APIs

### Core Module Functions

#### `wm_sca_main()`
Main entry point for the SCA module.

```c
#ifdef WIN32
DWORD WINAPI wm_sca_main(void *arg);
#else
void* wm_sca_main(wm_sca_t *data);
#endif
```

**Description:**

Initializes the SCA module, loads the SCA dynamic library, sets up callback functions, and starts the module.

---

#### `wm_sca_start()`
Starts the SCA module with the given configuration.

```c
static int wm_sca_start(wm_sca_t *sca);
```

**Description:**

Initializes message queues, sets synchronization parameters, launches the SCA synchronization thread if enabled, finally it starts the SCA module through a pointer to the C++ implementation.

---

## SCA C/C++ Library Interface

#### `sca_start()`
Starts the SCA assessment process.

```c
EXPORTED void sca_start(const struct wm_sca_t* sca_config);
```

**Description:**

Serves as a bridge between the C and C++ code. Initializes and runs the Security Configuration Assessment with the provided configuration.

---

#### `sca_stop()`

Stops the SCA assessment process.

```c
EXPORTED void sca_stop();
```

**Description:**

Serves as a bridge between the C and C++ code. Gracefully stops the running SCA assessment and cleans up resources.

---

#### `sca_set_wm_exec()`

Sets the command execution callback function. Certain SCA policy rules require commands to be executed, this callback sets a function that receives the command to be executed with its arguments and returns the output and exitcode of execution.

```c
EXPORTED void sca_set_wm_exec(wm_exec_callback_t wm_exec_callback);
```

**Callback Signature:**
```c
typedef int (*wm_exec_callback_t)(char* command, char** output, int* exitcode, int secs, const char* add_path);
```

---

#### `sca_set_log_function()`

Sets the logging callback function. This is required to see log output from the module.

```c
EXPORTED void sca_set_log_function(log_callback_t log_callback);
```

**Callback Signature:**
```c
typedef void (*log_callback_t)(const modules_log_level_t level, const char* log, const char* tag);
```

---

#### `sca_set_push_functions()`

Sets the message pushing functions for stateless and stateful messages.

```c
EXPORTED void sca_set_push_functions(push_stateless_func stateless_func, push_stateful_func stateful_func);
```

**Parameters:**

- `stateless_func`: Function for sending stateless messages
- `stateful_func`: Function for sending stateful messages

**Function Signatures:**

```c
typedef int (*push_stateless_func)(const char* message);
typedef int (*push_stateful_func)(const char* id, Operation_t operation, const char* index, const char* message, uint64_t version);
```

---

## Database and Synchronization Interface

#### `sca_set_sync_parameters()`
Sets synchronization protocol parameters.

```c
EXPORTED void sca_set_sync_parameters(const char* module_name, const char* sync_db_path, unsigned int integrity_interval);
```

---

#### `sca_sync_module()`

Triggers synchronization with the manager.

```c
EXPORTED bool sca_sync_module(Mode_t mode);
```

---

#### `sca_persist_diff()`

Persists a difference for synchronization.

```c
EXPORTED void sca_persist_diff(const char* id, Operation_t operation, const char* index, const char* data, uint64_t version);
```

---

#### `sca_parse_response()`

Parses synchronization response from manager.

```c
EXPORTED bool sca_parse_response(const unsigned char* data, size_t length);
```

---

#### `sca_notify_data_clean()`

Notifies the manager that specific indices have been cleaned and should be removed.

```c
EXPORTED bool sca_notify_data_clean(const char** indices, size_t indices_count);
```

**Parameters:**
- `indices`: Array of index names to clean
- `indices_count`: Number of indices in the array

**Returns:**
- `true`: Notification succeeded
- `false`: Notification failed

**Description:**

Sends a data clean notification to the manager, informing it that the given SCA indices should be removed from the agent's state. `wazuh-modulesd` calls it when the SCA module is disabled. When all policies are removed from the configuration, the module sends the same notification internally.

**Usage Example:**
```c
// Notify data clean for the SCA index
const char* indices[] = {SCA_SYNC_INDEX};

bool notify_success = sca_notify_data_clean(indices, 1);
```

---

#### `sca_delete_database()`

Deletes the SCA synchronization database.

```c
EXPORTED void sca_delete_database();
```

**Description:**

Removes the SCA synchronization database file from disk. This function is called when the SCA module is disabled or when a complete cleanup is required. Should typically be called after successfully notifying the manager with `sca_notify_data_clean()`.

**Usage Example:**
```c
// Delete SCA sync database when module is disabled
sca_delete_database();
```

---

## YAML Processing

#### `sca_set_yaml_to_cjson_func()`

Sets the YAML to cJSON conversion function. This function will be used to parse the policy yaml files and return them as cJSON objects.

```c
EXPORTED void sca_set_yaml_to_cjson_func(yaml_to_cjson_func yaml_func);
```

**Function Signature:**
```c
typedef struct cJSON* (*yaml_to_cjson_func)(const char* yaml_path);
```

---

## Message Communication Protocol

### Message Queue Interface

The SCA module communicates through Wazuh's message queue system rather than direct API calls.

#### Message Queue Functions

#### `wm_sca_send_stateless()`
Sends stateless messages for immediate alerts.

```c
static int wm_sca_send_stateless(const char* message);
```

**Description:**
Sends real-time SCA alerts through the message queue system using `SendMSGPredicated()`.

---

#### `wm_sca_persist_stateful()`
Persists stateful messages for reliable delivery.

```c
static int wm_sca_persist_stateful(const char* id, Operation_t operation, const char* index, const char* message, uint64_t version);
```

**Description:**
Stores messages for synchronization with manager using the Agent Sync Protocol.

---

## C++ Implementation Classes

### SecurityConfigurationAssessment Class

The core C++ implementation provides the following methods:

#### `Setup()`
Configures the SCA module parameters.

```cpp
void Setup(bool enabled,
           bool scanOnStart,
           std::chrono::seconds scanInterval,
           const int commandsTimeout,
           const bool remoteEnabled,
           const std::vector<sca::PolicyData>& policies,
           const YamlToJsonFunc& yamlToJsonFunc = nullptr);
```

#### `Run()`

Reloads the policies files. Executes the main SCA scanning loop. Reports check results.

```cpp
void Run();
```

#### `Stop()`

Gracefully stops the SCA scanning process.

```cpp
void Stop();
```

#### Synchronization Methods

```cpp
void initSyncProtocol(const std::string& moduleName, const std::string& syncDbPath, std::chrono::seconds integrityInterval);
bool syncModule(Mode mode);
void persistDifference(const std::string& id, Operation operation, const std::string& index, const std::string& data, uint64_t version);
bool parseResponseBuffer(const uint8_t* data, size_t length);
bool notifyDataClean(const std::vector<std::string>& indices);
void deleteDatabase();
```

---

## Coordination Commands

The coordination commands allow external control of SCA operations for coordination with the manager or other modules. `pause()` blocks until the module is idle; `flush()` is **asynchronous**: it only starts the synchronization in a background worker, and the caller polls `is_flush_completed` for the outcome.

### Pause and Resume Operations

#### `pause()`

Pauses the SCA module by waiting for ongoing scanning and synchronization operations to complete, then preventing new operations from starting.

**Signature:**
```cpp
void SecurityConfigurationAssessment::pause();
```

**Description:**

This method sets the pause flag and waits for both scanning (`m_scanInProgress`) and synchronization (`m_syncInProgress`) operations to complete before returning. Once paused, no new scan or sync operations will start until `resume()` is called.

**Behavior:**
- Sets the internal pause flag (`m_paused = true`)
- Waits for ongoing scan operations to finish
- Waits for ongoing sync operations to finish
- Blocks until both operations are complete or if the module is shutting down
- Returns when operations complete

**Thread Safety:**
- Uses condition variable (`m_pauseCv`) with mutex (`m_pauseMutex`)
- Atomic flag (`m_paused`) ensures thread-safe state checks
- Blocks calling thread until pause conditions are met

**Usage Example:**
```cpp
// Pause SCA operations (synchronous - blocks until complete)
sca_instance.pause();
// Module is now fully paused, safe to perform maintenance
```

---

#### `resume()`

Resumes the SCA module after a pause, allowing scanning and synchronization operations to continue.

**Signature:**
```cpp
void SecurityConfigurationAssessment::resume();
```

**Description:**

Clears the pause flag and notifies the main loop to continue operations. After calling this method, pending scans and synchronizations will resume according to the configured intervals.

**Behavior:**
- Clears the pause flag (`m_paused = false`)
- Notifies the main loop via condition variable (`m_cv.notify_one()`)
- Operations resume immediately
- Returns without waiting

**Usage Example:**
```cpp
// Resume SCA operations (immediate)
sca_instance.resume();
// Module resumes scanning immediately
```

---

### Synchronization Control

#### `flush()`

Requests an immediate synchronization of the pending SCA check results with the manager. It does **not** wait for it: the synchronization runs in a background worker (`Utils::AsyncFlushController`).

**Signature:**
```cpp
int SecurityConfigurationAssessment::flush();
```

**Returns:**
- `0` if the flush request was accepted: a background flush was started, or one was already running and is kept
- `-1` if the async flush controller does not exist

A return of `0` does not mean the data reached the manager. Poll `is_flush_completed` for that.

**Description:**

Starts the blocking flush work, `executeFlushSync()`, on a worker thread and returns at once. This bypasses the normal synchronization interval, which is useful when SCA state must be delivered promptly, for example during agent-info's coordination after an agent ID change. A caller that needs the data delivered (for example, before shutdown) must wait until `is_flush_completed` reports `completed`.

**Behavior of the background work (`executeFlushSync()`):**
- If the sync protocol is not initialized, it ends successfully (nothing to flush)
- Otherwise, it waits for any SCA synchronization or integrity-recovery DataClean already in progress (such as a full resend after an agent ID change) and keeps new ones from starting until it is done
- If the module stops while it waits, it ends with an error
- Calls `synchronizeModule()` with `Mode::DELTA`, which sends at most `agent.sync_max_blocks_per_cycle` blocks; anything left stays queued for the next cycle
- Ends successfully if the synchronization succeeds, with an error otherwise

**Usage Example:**
```cpp
// Request a flush (asynchronous - returns before the data is sent)
if (sca_instance.flush() != 0) {
    // Request rejected: no flush controller
}
// Then poll the "is_flush_completed" command until its status is "completed"
```

#### `is_flush_completed` command

Reports the state of the last flush requested with `flush()`. It is a coordination command, sent as a JSON query (`{"command": "is_flush_completed"}`) and answered without blocking.

**Response:**
- `error`: always `0`
- `data.module`: `"sca"`
- `data.status`: `"in_progress"` while the background flush runs, `"completed"` otherwise
- `data.result` (only with `"completed"`): `"success"` or `"error"`, the outcome of the last flush

If no flush has run yet, the status is `"completed"` with result `"success"`, meaning there is nothing left to wait for.

---

### Version Management

The version management methods allow querying and setting version numbers for all SCA check results.

#### `getMaxVersion()`

Retrieves the maximum version number from the SCA check results table.

**Signature:**
```cpp
int SecurityConfigurationAssessment::getMaxVersion();
```

**Returns:**
- The maximum version number found in the `sca_check` table (≥ 0)
- `-1` if an error occurred (e.g., database not initialized)
- `0` if the table is empty

**Description:**

Queries the `sca_check` table to find the highest version number. This is useful for determining the current state version before performing coordination operations.

**Implementation Details:**
- Executes SQL query: `SELECT MAX(version) FROM sca_check`
- Returns the maximum version value found
- Thread-safe database access

**Usage Example:**
```cpp
// Get current maximum version
int currentVersion = sca_instance.getMaxVersion();
if (currentVersion >= 0) {
    // Use version for coordination
} else {
    // Error getting version
}
```

---

#### `setVersion()`

Sets the version number for all rows in the SCA check results table.

**Signature:**
```cpp
int SecurityConfigurationAssessment::setVersion(int version);
```

**Parameters:**
- `version`: The version number to set for all check results

**Returns:**
- `0` on success
- `-1` if an error occurred (e.g., database not initialized)

**Description:**

Updates the version field for every row in the `sca_check` table using a transaction-based approach. This is used by the coordination system to mark all check results with a specific version number.

**Implementation Details:**
- Uses database transaction for atomicity
- Retrieves all columns from each row in `sca_check` table
- Updates each row with the new version number
- Commits transaction upon completion
- Rollback on error

**Usage Example:**
```cpp
// Set version 42 for all check results
int result = sca_instance.setVersion(42);
if (result == 0) {
    // Version set successfully
} else {
    // Error setting version
}
```

---

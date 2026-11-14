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

Initializes the SCA module, loads the SCA dynamic library, sets up callback functions and the synchronization parameters, creates the SCA instance with `sca_init()`, waits until wazuh-agentd answers the `getdoclimits sca` query to set the sync limit with `sca_set_sync_limit()`, and starts the module. When the module is disabled, it only runs the data clean notification (see [SCA Disabled Cleanup Flow](architecture.md#sca-disabled-cleanup-flow)).

---

#### `wm_sca_start()`
Starts the SCA module with the given configuration.

```c
static int wm_sca_start(wm_sca_t *sca);
```

**Description:**

Opens the message queue, launches the SCA synchronization thread if synchronization is enabled, and runs the SCA module through a pointer to the C++ implementation. When the module returns, it joins the synchronization thread and releases the module resources with `sca_release_resources()`.

---

## SCA C/C++ Library Interface

#### `sca_init()`
Creates the SCA instance and its sync protocol.

```c
EXPORTED void sca_init();
```

**Description:**

Opens the SCA database (`queue/sca/db/sca.db`) and creates the sync protocol with the parameters set by `sca_set_sync_parameters()`, whether or not synchronization is enabled. It does nothing if the instance already exists. Errors are logged.

---

#### `sca_start()`
Starts the SCA assessment process.

```c
EXPORTED void sca_start(const struct wm_sca_t* sca_config);
```

**Description:**

Serves as a bridge between the C and C++ code. Calls `init()`, `setup()` with the provided configuration and `run()` on the SCA instance. It blocks until the module stops.

---

#### `sca_stop()`

Stops the SCA assessment process.

```c
EXPORTED void sca_stop();
```

**Description:**

Serves as a bridge between the C and C++ code. Signals the running SCA assessment to stop, stops the sync protocol and any running flush, and returns. It does not release the databases: that is done by `sca_release_resources()`.

---

#### `sca_release_resources()`

Releases the SCA resources.

```c
EXPORTED void sca_release_resources();
```

**Description:**

Closes the SCA database and the sync protocol connection. It must be called only after the synchronization thread and the SCA run loop have exited; `wm_sca_main()` calls it on the module thread before returning.

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

#### `sca_set_sync_limit()`

Sets the maximum number of checks synchronized with the manager.

```c
EXPORTED void sca_set_sync_limit(uint64_t syncLimit);
```

`0` means unlimited. `wm_sca_main()` obtains the value from wazuh-agentd (`getdoclimits sca`).

---

#### `sca_sync_module()`

Triggers synchronization with the manager.

```c
EXPORTED bool sca_sync_module(Mode_t mode);
```

**Description:**

The `mode` argument is ignored: the call always synchronizes with `Mode::DELTA`. The synchronization only runs while the module is paused (between the `pause` and `resume` commands, as the synchronization thread does); otherwise it is skipped and returns `false`. It also returns `false` while another synchronization, a flush or a recovery is in progress. The first synchronization of an installation, and the first one after the agent ID changes, sends the whole local state (DataClean followed by the checks) instead of a delta.

**Returns:** `true` if the synchronization succeeded (including when there was nothing to send), `false` otherwise.

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

Removes both the sync protocol database (`queue/sca/db/sca_sync.db`) and the SCA database (`queue/sca/db/sca.db`) from disk. This function is called when the SCA module is disabled or when a complete cleanup is required. Should typically be called after successfully notifying the manager with `sca_notify_data_clean()`.

**Usage Example:**
```c
// Delete SCA sync database when module is disabled
sca_delete_database();
```

---

## Query Function

#### `sca_query()`

Handles a JSON coordination command.

```c
EXPORTED size_t sca_query(const char* query, char** output);
```

**Description:**

Parses `query`, executes the command (see [Coordination Commands](#coordination-commands)) and stores the JSON response in `*output`, allocated with `strdup()` (the caller frees it). Returns the length of the response, or `0` if `query` or `output` is `NULL`. If the instance does not exist, the response is a `MQ_ERR_MODULE_NOT_RUNNING` error.

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

Stops the SCA scanning process: it runs `quiesce()` (signals the scanning loop, the sync protocol and the policies to stop, and waits for a running flush) and then `releaseResources()` (closes the databases and the sync protocol). `sca_stop()` only runs `quiesce()`.

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

### Query Commands

SCA answers JSON queries of the form `{"command": "<name>", "parameters": {...}}` through `sca_query()`. Every response has `error` (`0` on success) and `message`; `data` carries `module: "sca"` and `action` (the command name) unless noted.

| Command | Parameters | Response `data` and errors |
|---------|------------|----------------------------|
| `pause` | none | Blocks until idle (see `pause()`). |
| `resume` | none | Returns at once. |
| `flush` | none | Starts the asynchronous flush. `error` is `1` if the request was rejected. |
| `is_flush_completed` | none | `status` (`in_progress` or `completed`) and, when completed, `result`. `data` has `module` but no `action`. |
| `get_version` | none | `version`. `error` is `3` if it cannot be read. |
| `set_version` | `version` (number, `>= 0`) | `version`. `error` is `3` for a missing or negative `version`, `2` if the update fails. |
| `get_first_sync_completed` | none | `first_sync_completed` (`1` or `0`). `error` is `2` if it cannot be read. When synchronization is disabled, `wm_sca_query_handler` answers `1`. |
| `get_identity_changed` | none | `identity_changed` (`1` if the agent ID differs from the one last synchronized, `0` if not or if none was recorded, `-1` if it cannot be told) and `resync_attempts` (full resends started since the module came up). |
| `get_scan_completed` | none | `scan_completed` (`1` once a full scan iteration has completed since startup; only maintained until the first synchronization completes). |
| `check_integrity` | none | `recovery_performed` and, when a recovery ran, `recovery_success`. Does nothing until `integrity_interval` has elapsed; it is deferred while a flush or DataClean is running. `error` is `1` if the checksum could not be computed or checked, or the recovery failed. |

An unknown command returns `error` `1` with `data.command` set to the received command. A request without a string `command` returns `error` `3`; JSON that cannot be parsed, or an exception while running the command, returns `error` `98`; an exception outside the command handler returns `error` `99`.

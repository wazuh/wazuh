# API Reference

The `agent_info` module exposes a C-style API for integration with `wazuh-modulesd` and uses a C++ implementation for its core logic. It also relies on a query-based API to coordinate with other modules.

---

## C API Reference

These functions are exported from the `agent_info` shared library and serve as the primary entry points for the module.

### `agent_info_start()`

Main entry point that initializes and starts the module.

```c
void agent_info_start(const struct wm_agent_info_t* agent_info_config);
```

**Description:**
Makes sure the `AgentInfoImpl` instance (and `agent_info.db`) exists, reusing the one already built by `agent_info_task_registry_init()` or `agent_info_ensure_database()`. It then creates the sync protocol (an instance without a queue database) with the module name stored by `agent_info_init_sync_protocol()` and runs `AgentInfoImpl::start()` with the configured `interval` and `integrity_interval`. The call blocks until the module stops.

---

### `agent_info_stop()`

Stops the module and cleans up resources.

```c
void agent_info_stop();
```

**Description:**
Signals the main loop to stop and stops any in-flight synchronization, then returns. It does not release resources and does not destroy the instance: the `DBSync` and sync protocol handles are closed by `agent_info_release_resources()` and the object is destroyed by `agent_info_cleanup()`.

---

### `agent_info_release_resources()`

Closes the module's database and sync protocol connections while keeping the instance alive.

```c
void agent_info_release_resources();
```

**Description:**
Called by `wazuh-modulesd` on the module thread once the run loop has returned. It is idempotent. The instance is kept because other threads (sync response dispatch, `/control` task queries) only null-check it before use; resources are released under the mutexes those threads take. If the run loop is still active, it logs a warning and skips the release.

---

### `agent_info_cleanup()`

Destroys the `AgentInfoImpl` instance.

```c
void agent_info_cleanup();
```

---

### Callback-Setter Functions

These functions are used by `wazuh-modulesd` to provide the necessary callbacks for logging, reporting, and inter-module communication.

```c
// Sets the logging callback function.
void agent_info_set_log_function(log_callback_t log_callback);

// Sets the stateless event reporting callback.
void agent_info_set_report_function(report_callback_t report_callback);

// Sets the function for querying other modules.
void agent_info_set_query_module_function(query_module_callback_t query_module_callback);

// Sets the predicate that reports whether a shutdown is in progress. It is used to log
// expected shutdown-time failures at a lower level.
void agent_info_set_is_shutting_down_function(is_shutting_down_callback_t is_shutting_down_callback);

// Sets the function that queries agentd (`gethandshake`) for fresh cluster_name and agent_groups.
void agent_info_set_query_handshake_function(query_handshake_callback_t callback);
```

---

### Synchronization Functions

These functions integrate `agent_info` with the Agent Sync Protocol managed by `wazuh-modulesd`.

#### `agent_info_init_sync_protocol()`
Stores the module name used to create the synchronization protocol. The protocol itself is created later, inside `agent_info_start()`, and has no queue database (it only sends metadata, groups and integrity checks). `wazuh-modulesd` calls this function before `agent_info_start()`.

```c
void agent_info_init_sync_protocol(const char* module_name);
```

---

#### `agent_info_parse_response()`
Parses a synchronization response buffer received from the manager.

```c
bool agent_info_parse_response(const uint8_t* data, size_t data_len);
```
**Returns:**
`true` if parsing was successful, `false` otherwise (including when the instance or the sync protocol does not exist).

---

### Handshake Data Functions

The cluster name and agent groups come from the handshake with the manager. `wazuh-modulesd` reads them from agentd and stores them with these functions.

```c
void agent_info_set_cluster_name(const char* cluster_name);   // copied internally (max 255 chars)
const char* agent_info_get_cluster_name(void);                // empty string if not set
void agent_info_set_agent_groups(const char* agent_groups);   // CSV, copied internally
const char* agent_info_get_agent_groups(void);                // empty string if not set
void agent_info_clear_agent_groups(void);                     // called after the groups are consumed once
```

---

### Task Registry Functions

The `tasks` table remembers the `/control` task IDs already handled.

```c
void agent_info_task_registry_init(uint32_t max_entries, uint32_t ttl_seconds);
int agent_info_task_check_and_record(const char* task_id);
```

- `agent_info_task_registry_init()` makes sure `agent_info.db` exists and sets the bounds. Cleanup is not triggered by this call: it runs once per cycle inside `AgentInfoImpl::start()`.
- `agent_info_task_check_and_record()` returns `1` if `task_id` is new (now recorded), `0` if it is a duplicate, and `-1` on error (including a null or empty ID, or `agent_info.db` not yet available).

---

### Vulnerability Detection Feed Offset Functions

These functions persist the VD feed offset reported by the manager in the `vd_feed_state` table.

```c
int agent_info_vd_offset_observe(uint64_t offset, int* out_changed, int* out_pending, uint64_t* out_pending_offset);
int agent_info_vd_offset_clear_pending(uint64_t offset);
int agent_info_vd_offset_get_state(int* out_has_offset, uint64_t* out_offset, int* out_pending, uint64_t* out_pending_offset);
```

- `agent_info_vd_offset_observe()` is monotonic: an offset not newer than the stored one leaves the stored record unchanged (the stored offset is republished to the metadata provider, and the stored `pending`/`pending_offset` are returned). When the offset advances it is stored, and a re-scan is marked pending only if Syscollector's first VD synchronization has already completed. Returns `0` on success, `-1` if `agent_info.db` is not available. All `out_*` pointers are optional.
- `agent_info_vd_offset_clear_pending()` clears the pending flag only if it is still pending for exactly `offset`. Returns `1` if cleared, `0` if not (stale or nothing pending), `-1` on error.
- `agent_info_vd_offset_get_state()` returns `0` on success and `-1` on error.

### `agent_info_ensure_database()`

Constructs the instance and `agent_info.db` without starting the processing loop. It is idempotent.

```c
void agent_info_ensure_database(void);
```

---

## C++ Implementation (`AgentInfoImpl`)

The core logic is encapsulated within the `AgentInfoImpl` class.

### `start()`
Starts the main processing loop of the module.

```cpp
void start(int interval, int integrityInterval = 86400, const std::function<bool()>& shouldContinue = nullptr);
```
**Description:**
Loads the sync flags from `db_metadata`, then, once per cycle, calls `populateAgentMetadata`, runs the delta synchronization for each table whose flag is set, runs the integrity check for each table whose `integrityInterval` has elapsed (only if no delta sync is pending for it), prunes the `tasks` table, and waits `interval` seconds.

- The first run (`is_first_run` / `is_first_groups_run` still `1`) only records the baseline: the sync flag is reset without synchronizing.
- Before the first cycle it waits 5 seconds for the other modules to start, but only if a delta synchronization could run in that cycle (that is, when either first-run flag is already cleared).
- The loop ends when `stop()` is called or a shutdown is in progress.

---

### `stop()`
Signals the module to stop.

```cpp
void stop();
```
**Description:**
Sets the stop flag, wakes the sleeping loop and stops the sync protocol so an in-flight synchronization returns. It does not close anything: `releaseResources()` closes the `DBSync` connection and destroys the sync protocol, and runs on the module thread once the loop has returned. It is idempotent and also runs from the destructor.

---

### `releaseResources()`
Closes the `DBSync` connection and the sync protocol.

```cpp
void releaseResources();
```

---

### `initSyncProtocol()`
Initializes the `AgentSyncProtocol` instance for manager communication.

```cpp
void initSyncProtocol(const std::string& moduleName);
```
---

### `parseResponseBuffer()`
The C++ implementation for parsing synchronization response buffers.

```cpp
bool parseResponseBuffer(const uint8_t* data, size_t length);
```
**Description:**
Delegates the call to the `AgentSyncProtocol` instance to process a response from the manager.

---

### `processEvent()`
The callback function invoked by `DBSync` when a change is detected in the database.

```cpp
void processEvent(ReturnTypeCallback result, const nlohmann::json& data, const std::string& table);
```
**Description:**
Converts the data to ECS format and reports a stateless event through the report callback. It does not set sync flags: `populateAgentMetadata()` sets them from what `updateChanges()` detected.

- The event is `{"module": "agent_info", "type": <table>, "data": {<ECS fields>, "event": {"type": "created"|"modified"|"deleted", "created": <ISO 8601>, "changed_fields": [...]}}}`. `changed_fields` is present only for modifications.
- A modification of `agent_metadata` that changes only OS fields (`host_architecture`, `host_hostname`, `host_os_name`, `host_os_type`, `host_os_platform`, `host_os_version`) does not generate an event.
- Flag routing: a change in any `agent_metadata` field other than `cluster_name` sets the metadata flag (version = max + 1). A change in `agent_groups`, or a `cluster_name` change alone, sets the groups flag (version = max).

---

## Module Coordination API (Query-Based)

The `agent_info` module acts as a coordinator, sending JSON-based commands to other modules (`FIM`, `SCA`, `Syscollector`) via the `query_module_callback_t` function. Every command carries a `parameters` object (empty when the command has none). A query is retried up to 3 times, 1 second apart; an error that means the module is unavailable (disabled, not found, not running) is not retried and the module is skipped.

### Commands

| Command                | Parameters                | Description                                                                                               |
| ---------------------- | ------------------------- | --------------------------------------------------------------------------------------------------------- |
| `pause`                | (none)                    | Requests the target module to pause its operations and file scanning.                                     |
| `flush`                | (none)                    | Requests the module to flush any pending events or data to ensure a clean state before synchronization.   |
| `get_version`          | (none)                    | Asks the module for its current database synchronization version.                                         |
| `set_version`          | `{"version": <number>}`   | Instructs the module to set its internal synchronization version to the provided value.                   |
| `resume`               | (none)                    | Requests the module to resume its normal operations after coordination is complete.                       |
| `get_first_sync_completed` | (none)                | Asks SCA or Syscollector whether their first synchronization has completed (`data.first_sync_completed`). While it has not, coordination is deferred. |
| `is_pause_completed`   | (none)                    | **(FIM only)** Polls the FIM module to check if its asynchronous pause operation has finished.            |
| `is_flush_completed`   | (none)                    | Polls the module (FIM, SCA or Syscollector) to check if its asynchronous flush operation has finished.    |

### Command Sequence

For each coordination cycle, `agent_info` sends the commands in this order:

1. `pause` to each module in the order FIM, SCA, Syscollector. For FIM it then polls `is_pause_completed` (up to 30 times, 1 second apart). If FIM (which reports it in its `is_pause_completed` answer), SCA or Syscollector (`get_first_sync_completed`) has not completed its first synchronization, the paused modules are resumed and the cycle is deferred: the sync flag is kept and the cycle is retried on the next interval.
2. `get_version` on every paused module, then `set_version` with the new version (maximum + 1 for a metadata change, maximum for a groups change).
3. `flush` on every paused module.
4. `resume` on every paused module.
5. `is_flush_completed` polled on each module every 10 seconds until it reports `completed`. If any flush fails, the synchronization is not sent and the cycle is retried on the next interval.
6. The change is synchronized with the manager, together with the indices of the coordinated modules.

If no module could be paused (FIM, SCA and Syscollector all disabled or not running), the cycle ends as successful without sending anything to the manager, and the sync flag is cleared: that metadata or groups change is not sent by the delta path.

### Commands Served by `agent_info`

`agent_info` also answers JSON queries addressed to the module `agent-info` (through `wazuh-modulesd`'s query socket, or in-process on Windows). Parameters are top-level keys of the request, not a `parameters` object (for example `{"command": "task_check_and_record", "task_id": "..."}`). Responses use the `{"error": <code>, "data": {...}}` envelope.

| Command                  | Parameters                | Response `data`                                                            |
| ------------------------ | ------------------------- | -------------------------------------------------------------------------- |
| `task_check_and_record`  | `task_id` (non-empty string) | `{"new": true\|false}`                                                    |
| `vd_offset_observe`      | `offset` (number)         | `{"changed": bool, "pending": bool, "pending_offset": N}`                  |
| `vd_offset_clear_pending`| `offset` (number)         | `{"cleared": bool}`                                                        |
| `vd_offset_get_state`    | (none)                    | `{"has_offset": bool, "offset": N, "pending": bool, "pending_offset": N}`  |

Invalid JSON or parameters return the corresponding error code; an unknown command returns `MQ_ERR_UNKNOWN_COMMAND` with the command echoed in `data.command`.

### Example JSON Command

A `set_version` command sent to the `sca` module would look like this:
```json
{
  "command": "set_version",
  "parameters": {
    "version": 12345
  }
}
```

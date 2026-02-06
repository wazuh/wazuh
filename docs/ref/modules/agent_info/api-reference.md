# API Reference

The `agent_info` module exposes a C-style API for integration with `wazuh-manager-modulesd` and uses a C++ implementation for its core logic. It also relies on a query-based API to coordinate with other modules.

---

## C API Reference

These functions are exported from the `agent_info` shared library and serve as the primary entry points for the module.

### `agent_info_start()`

Main entry point that initializes and starts the module.

```c
void agent_info_start(const struct wm_agent_info_t* agent_info_config);
```

**Description:**
Creates the `AgentInfoImpl` instance, sets synchronization parameters from the configuration, initializes the sync protocol, and starts the main processing loop.

---

### `agent_info_stop()`

Stops the module and cleans up resources.

```c
void agent_info_stop();
```

**Description:**
Stops the main loop in `AgentInfoImpl`, resets the `DBSync` and `AgentSyncProtocol` instances, and destroys the `AgentInfoImpl` object.

---

### Callback-Setter Functions

These functions are used by `wazuh-manager-modulesd` to provide the necessary callbacks for logging, reporting, and inter-module communication.

```c
// Sets the logging callback function.
void agent_info_set_log_function(log_callback_t log_callback);

// Sets the stateless event reporting callback.
void agent_info_set_report_function(report_callback_t report_callback);

// Sets the function for querying other modules.
void agent_info_set_query_module_function(query_module_callback_t query_module_callback);
```

---

### Synchronization Functions

These functions integrate `agent_info` with the Agent Sync Protocol managed by `wazuh-manager-modulesd`.

#### `agent_info_init_sync_protocol()`
Initializes the synchronization protocol handle. This function is called by `wazuh-manager-modulesd` before `agent_info_start` to provide the necessary message queue functions.

```c
void agent_info_init_sync_protocol(const char* module_name, const MQ_Functions* mq_funcs);
```

---

#### `agent_info_parse_response()`
Parses a synchronization response buffer received from the manager.

```c
bool agent_info_parse_response(const uint8_t* data, size_t data_len);
```
**Returns:**
`true` if parsing was successful, `false` otherwise.

---

## C++ Implementation (`AgentInfoImpl`)

The core logic is encapsulated within the `AgentInfoImpl` class.

### `start()`
Starts the main processing loop of the module.

```cpp
void start(int interval, int integrityInterval, std::function<bool()> shouldContinue = nullptr);
```
**Description:**
Periodically calls `populateAgentMetadata` to gather data, triggers delta or integrity synchronization when needed, and waits for the next cycle.

---

### `stop()`
Stops the module's execution.

```cpp
void stop();
```

---

### `initSyncProtocol()`
Initializes the `AgentSyncProtocol` instance for manager communication.

```cpp
void initSyncProtocol(const std::string& moduleName, const MQ_Functions& mqFuncs);
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

### `setSyncParameters()`
Configures the parameters for the synchronization protocol.

```cpp
void setSyncParameters(uint32_t syncEndDelay, uint32_t timeout, uint32_t retries, long maxEps);
```
---

### `processEvent()`
The callback function invoked by `DBSync` when a change is detected in the database.

```cpp
void processEvent(ReturnTypeCallback result, const nlohmann::json& data, const std::string& table);
```
**Description:**
Generates a stateless event, converts the data to ECS format, and sets the appropriate flag (`m_shouldSyncMetadata` or `m_shouldSyncGroups`) to trigger the module coordination process.

---

## Module Coordination API (Query-Based)

The `agent_info` module acts as a coordinator, sending JSON-based commands to other modules (`FIM`, `SCA`, `Syscollector`) via the `query_module_callback_t` function.

### Commands

| Command                | Parameters                | Description                                                                                               |
| ---------------------- | ------------------------- | --------------------------------------------------------------------------------------------------------- |
| `pause`                | (none)                    | Requests the target module to pause its operations and file scanning.                                     |
| `flush`                | (none)                    | Requests the module to flush any pending events or data to ensure a clean state before synchronization.   |
| `get_version`          | (none)                    | Asks the module for its current database synchronization version.                                         |
| `set_version`          | `{"version": <number>}`   | Instructs the module to set its internal synchronization version to the provided value.                   |
| `resume`               | (none)                    | Requests the module to resume its normal operations after coordination is complete.                       |
| `is_pause_completed`   | (none)                    | **(FIM only)** Polls the FIM module to check if its asynchronous pause operation has finished.            |
| `is_flush_completed`   | (none)                    | **(FIM only)** Polls the FIM module to check if its asynchronous flush operation has finished.            |

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

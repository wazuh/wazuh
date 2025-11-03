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
typedef int (*push_stateful_func)(const char* id, Operation_t operation, const char* index, const char* message);
```

---

## Database and Synchronization Interface

#### `sca_set_sync_parameters()`
Sets synchronization protocol parameters.

```c
EXPORTED void sca_set_sync_parameters(const char* module_name, const char* sync_db_path, const MQ_Functions* mq_funcs);
```

---

#### `sca_sync_module()`

Triggers synchronization with the manager.

```c
EXPORTED bool sca_sync_module(Mode_t mode, unsigned int timeout, unsigned int retries, unsigned int max_eps);
```

---

#### `sca_persist_diff()`

Persists a difference for synchronization.

```c
EXPORTED void sca_persist_diff(const char* id, Operation_t operation, const char* index, const char* data);
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
EXPORTED bool sca_notify_data_clean(const char** indices, size_t indices_count, unsigned int timeout, unsigned int retries, size_t max_eps);
```

**Parameters:**
- `indices`: Array of index names to clean
- `indices_count`: Number of indices in the array
- `timeout`: Timeout value in seconds for the notification operation
- `retries`: Number of retry attempts on failure
- `max_eps`: Maximum events per second during the notification

**Returns:**
- `true`: Notification succeeded
- `false`: Notification failed

**Description:**

Sends a data clean notification to the manager, informing it that specific SCA indices should be removed from the agent's state. This is typically used when the SCA module is disabled or when specific policies are removed.

**Usage Example:**
```c
// Notify data clean for SCA policies
const char* indices_to_clean[] = {
    "wazuh-states-sca-policy1",
    "wazuh-states-sca-policy2"
};

bool notify_success = sca_notify_data_clean(indices_to_clean, 2,
                                           sca_config->sync_response_timeout,
                                           SCA_SYNC_RETRIES,
                                           sca_config->sync_max_eps);
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
static int wm_sca_persist_stateful(const char* id, Operation_t operation, const char* index, const char* message);
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
           std::time_t scanInterval,
           const int commandsTimeout,
           const bool remoteEnabled,
           const std::vector<sca::PolicyData>& policies,
           const YamlToJsonFunc& yamlToJsonFunc);
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
void initSyncProtocol(const std::string& moduleName, const std::string& syncDbPath, MQ_Functions mqFuncs);
bool syncModule(Mode mode, std::chrono::seconds timeout, unsigned int retries, size_t maxEps);
void persistDifference(const std::string& id, Operation operation, const std::string& index, const std::string& data);
bool parseResponseBuffer(const uint8_t* data, size_t length);
bool notifyDataClean(const std::vector<std::string>& indices, std::chrono::seconds timeout, unsigned int retries, size_t maxEps);
void deleteDatabase();
```

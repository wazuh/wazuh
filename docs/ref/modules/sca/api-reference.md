# API Reference

The SCA module provides internal C APIs for interaction with other Wazuh components and supports database synchronization through the Agent Sync Protocol.

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

**Parameters:**
- `arg`/`data`: Pointer to SCA configuration structure (`wm_sca_t`)

**Returns:**
- Platform-specific: `DWORD` on Windows, `void*` on Unix
- `NULL`/`0` on normal termination

**Description:**
Initializes the SCA module, loads the SCA dynamic library, sets up callback functions, and starts the scanning process.

---

#### `wm_sca_start()`
Starts the SCA module with the given configuration.

```c
static int wm_sca_start(wm_sca_t *sca);
```

**Parameters:**
- `sca`: SCA module configuration

**Returns:**
- `0` on success
- `-1` on error

**Description:**
Initializes message queues, sets synchronization parameters, and launches the SCA synchronization thread if enabled.

---

#### `wm_sca_destroy()`
Cleans up SCA module resources.

```c
void wm_sca_destroy(wm_sca_t *data);
```

**Parameters:**
- `data`: SCA module data to destroy

**Description:**
Stops the SCA module and frees allocated resources.

---

## SCA Library Interface

#### `sca_start()`
Starts the SCA assessment process.

```c
EXPORTED void sca_start(const struct wm_sca_t* sca_config);
```

**Parameters:**
- `sca_config`: Pointer to SCA configuration structure

**Description:**
Initializes and runs the Security Configuration Assessment with the provided configuration.

---

#### `sca_stop()`
Stops the SCA assessment process.

```c
EXPORTED void sca_stop();
```

**Description:**
Gracefully stops the running SCA assessment and cleans up resources.

---

#### `sca_set_wm_exec()`
Sets the command execution callback function.

```c
EXPORTED void sca_set_wm_exec(wm_exec_callback_t wm_exec_callback);
```

**Parameters:**
- `wm_exec_callback`: Function pointer for executing commands

**Callback Signature:**
```c
typedef int (*wm_exec_callback_t)(char* command, char** output, int* exitcode, int secs, const char* add_path);
```

---

#### `sca_set_log_function()`
Sets the logging callback function.

```c
EXPORTED void sca_set_log_function(log_callback_t log_callback);
```

**Parameters:**
- `log_callback`: Function pointer for logging

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

**Parameters:**
- `module_name`: Module identifier (typically "sca")
- `sync_db_path`: Path to synchronization database
- `mq_funcs`: Message queue function pointers

**MQ_Functions Structure:**
```c
typedef struct {
    int (*start)(const char* key, short type, short attempts);
    int (*send_binary)(int queue, const void* message, size_t message_len, const char* locmsg, char loc);
} MQ_Functions;
```

---

#### `sca_sync_module()`
Triggers synchronization with the manager.

```c
EXPORTED bool sca_sync_module(Mode_t mode, unsigned int timeout, unsigned int retries, unsigned int max_eps);
```

**Parameters:**
- `mode`: Synchronization mode (`MODE_FULL` or `MODE_DELTA`)
- `timeout`: Response timeout in seconds
- `retries`: Number of retry attempts
- `max_eps`: Maximum events per second

**Returns:**
- `true` on successful synchronization
- `false` on failure

---

#### `sca_persist_diff()`
Persists a difference for synchronization.

```c
EXPORTED void sca_persist_diff(const char* id, Operation_t operation, const char* index, const char* data);
```

**Parameters:**
- `id`: Unique identifier for the change
- `operation`: Operation type (`OPERATION_CREATE`, `OPERATION_MODIFY`, `OPERATION_DELETE`)
- `index`: Index or category identifier
- `data`: JSON data representing the change

---

#### `sca_parse_response()`
Parses synchronization response from manager.

```c
EXPORTED bool sca_parse_response(const unsigned char* data, size_t length);
```

**Parameters:**
- `data`: Response data buffer
- `length`: Size of data buffer

**Returns:**
- `true` if response was parsed successfully
- `false` on parsing error

---

## YAML Processing

#### `sca_set_yaml_to_cjson_func()`
Sets the YAML to cJSON conversion function.

```c
EXPORTED void sca_set_yaml_to_cjson_func(yaml_to_cjson_func yaml_func);
```

**Parameters:**
- `yaml_func`: Function pointer for YAML to cJSON conversion

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

**Parameters:**
- `message`: JSON-formatted message string

**Returns:**
- `0` on success
- `-1` on error

**Description:**
Sends real-time SCA alerts through the message queue system using `SendMSGPredicated()`.

---

#### `wm_sca_persist_stateful()`
Persists stateful messages for reliable delivery.

```c
static int wm_sca_persist_stateful(const char* id, Operation_t operation, const char* index, const char* message);
```

**Parameters:**
- `id`: Unique message identifier
- `operation`: Operation type (CREATE, MODIFY, DELETE)
- `index`: Message index or category
- `message`: JSON-formatted message content

**Returns:**
- `0` on success
- `-1` on error

**Description:**
Stores messages for synchronization with manager using the Agent Sync Protocol.

---

## Configuration Dump

#### `wm_sca_dump()`
Returns current SCA module configuration as JSON.

```c
cJSON *wm_sca_dump(const wm_sca_t * data);
```

**Parameters:**
- `data`: SCA module configuration

**Returns:**
- `cJSON*`: JSON object containing configuration

**Sample Output:**
```json
{
    "sca": {
        "enabled": "yes",
        "scan_on_start": "yes",
        "max_eps": 50,
        "policies": [
            "policy1.yml",
            "policy2.yml"
        ],
        "synchronization": {
            "enabled": "yes",
            "interval": 300,
            "max_eps": 10,
            "response_timeout": 30
        }
    }
}
```

---

## Synchronization Protocol

#### Synchronization Message Handling

#### `wm_sca_sync_message()`
Handles incoming synchronization messages from manager.

```c
int wm_sca_sync_message(const char *command, size_t command_len);
```

**Parameters:**
- `command`: Raw synchronization command data
- `command_len`: Length of command data

**Returns:**
- `0` on success
- `-1` on error

**Description:**
Processes synchronization responses from the manager by parsing the data and updating local state.

---

## Database Schema

The SCA module uses a SQLite database with the following schema:

**Policy Table:**
```sql
CREATE TABLE IF NOT EXISTS sca_policy (
    id TEXT PRIMARY KEY,
    name TEXT,
    file TEXT,
    description TEXT,
    refs TEXT
);
```

**Check Table:**
```sql
CREATE TABLE IF NOT EXISTS sca_check (
    checksum TEXT NOT NULL,
    id TEXT PRIMARY KEY,
    policy_id TEXT REFERENCES sca_policy(id),
    name TEXT,
    description TEXT,
    rationale TEXT,
    remediation TEXT,
    refs TEXT,
    result TEXT DEFAULT 'Not run',
    reason TEXT,
    condition TEXT,
    compliance TEXT,
    rules TEXT,
    regex_type TEXT DEFAULT 'pcre2'
);
```

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
Executes the main SCA scanning loop.

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
```

---

## Type Definitions

### Core Module Structures

#### wm_sca_t Structure
Main SCA module configuration structure.

```c
typedef struct wm_sca_t {
    int enabled;                        // Module enabled flag
    int scan_on_start;                  // Scan on startup flag
    int max_eps;                        // Maximum events per second
    wm_sca_policy_t** policies;         // Array of policy configurations
    int remote_commands:1;              // Remote commands enabled flag
    int commands_timeout;               // Command execution timeout
    sched_scan_config scan_config;      // Scan scheduling configuration
    wm_sca_db_sync_flags_t sync;       // Synchronization settings
} wm_sca_t;
```

#### wm_sca_policy_t Structure
Individual policy configuration.

```c
typedef struct wm_sca_policy_t {
    unsigned int enabled:1;             // Policy enabled flag
    unsigned int remote:1;              // Remote policy flag
    char *policy_path;                  // Path to policy file
    char *policy_id;                    // Unique policy identifier
    char *policy_regex_type;            // Regex engine type (e.g., "pcre2")
} wm_sca_policy_t;
```

#### wm_sca_db_sync_flags_t Structure
Database synchronization configuration.

```c
typedef struct wm_sca_db_sync_flags_t {
    unsigned int enable_synchronization:1;  // Enable database synchronization
    uint32_t sync_interval;                 // Synchronization interval in seconds
    uint32_t sync_response_timeout;         // Response timeout in seconds
    long sync_max_eps;                      // Maximum events per second for sync
} wm_sca_db_sync_flags_t;
```

### Module Framework Structures

#### wm_context Structure
Module context definition for integration with Wazuh module system.

```c
typedef struct wm_context {
    const char *name;                           // Name for module
    wm_routine start;                           // Main function pointer
    void (*destroy)(void *);                    // Configuration destructor
    cJSON *(* dump)(const void *);              // Dump current configuration
    int (* sync)(const char*, size_t);          // Sync message handler
    void (*stop)(void *);                       // Module destructor
    size_t (*query)(void *, char *, char **);   // Run a query
} wm_context;
```

#### wmodule Structure
Main module structure.

```c
typedef struct wmodule {
    pthread_t thread;                   // Thread ID
    const wm_context *context;          // Context (common structure)
    char *tag;                          // Module tag
    void *data;                         // Data (module-dependent structure)
    struct wmodule *next;               // Pointer to next module
} wmodule;
```

### Agent Sync Protocol Types

#### Operation_t Enumeration
Defines modification operation types.

```c
typedef enum {
    OPERATION_CREATE = 0,   // Create a new record
    OPERATION_MODIFY = 1,   // Modify an existing record
    OPERATION_DELETE = 2,   // Delete a record
    OPERATION_NO_OP  = 3    // No operation (neutral state)
} Operation_t;
```

#### Mode_t Enumeration
Defines synchronization mode types.

```c
typedef enum {
    MODE_FULL  = 0,  // Full synchronization
    MODE_DELTA = 1   // Delta synchronization
} Mode_t;
```

#### MQ_Functions Structure
Message queue function pointers.

```c
typedef struct MQ_Functions {
    mq_start_fn start;                  // Callback to start a message queue
    mq_send_binary_fn send_binary;      // Callback to send a message
} MQ_Functions;
```

Where the function pointer types are:

```c
typedef int (*mq_start_fn)(const char* key, short type, short attempts);
typedef int (*mq_send_binary_fn)(int queue, const void* message, size_t message_len, const char* locmsg, char loc);
```

### Callback Function Types

#### Logging Callback
```c
typedef void (*log_callback_t)(const modules_log_level_t level, const char* log, const char* tag);
```

#### Command Execution Callback
```c
typedef int (*wm_exec_callback_t)(char* command, char** output, int* exitcode, int secs, const char* add_path);
```

#### Message Push Callbacks
```c
typedef int (*push_stateless_func)(const char* message);
typedef int (*push_stateful_func)(const char* id, Operation_t operation, const char* index, const char* message);
```

#### YAML Processing Callback
```c
typedef struct cJSON* (*yaml_to_cjson_func)(const char* yaml_path);
```

#### Agent Sync Protocol Logger
```c
typedef void (*asp_logger_t)(modules_log_level_t level, const char* log);
```

---

## Constants and Definitions

### Module Constants

```c
#define SCA_WM_NAME "sca"
#define SCA_SYNC_PROTOCOL_DB_PATH "queue/sca/db/sca_sync.db"
#define SCA_SYNC_RETRIES 3
#define SCA_DB_DISK_PATH "queue/sca/db/sca.db"
```

### Operation Types

```c
typedef enum {
    OPERATION_CREATE,
    OPERATION_MODIFY, 
    OPERATION_DELETE
} Operation_t;
```

### Synchronization Modes

```c
typedef enum {
    MODE_FULL,
    MODE_DELTA
} Mode_t;
```

### Logging Types

#### modules_log_level_t Enumeration
Logging level definitions (from logging_helper.h).

```c
typedef enum {
    LOG_DEBUG,
    LOG_INFO,
    LOG_WARNING,
    LOG_ERROR
} modules_log_level_t;
```

---

## Thread Management

### Synchronization Thread

The SCA module creates a separate thread for database synchronization when enabled:

```c
#ifdef WIN32
static DWORD WINAPI wm_sca_sync_module(__attribute__((unused)) void * args);
#else
static void * wm_sca_sync_module(__attribute__((unused)) void * args);
#endif
```

This thread runs continuously, performing synchronization at configured intervals using the Agent Sync Protocol.

---

## Logging Integration

All errors are logged through the Wazuh logging system using the configured log callback:

```c
static void sca_log_callback(const modules_log_level_t level, const char* log, const char* tag);
```

---

## Module Context

### WM_SCA_CONTEXT

The SCA module registers with the Wazuh module system using:

```c
const wm_context WM_SCA_CONTEXT = {
    .name = SCA_WM_NAME,
    .start = (wm_routine)wm_sca_main,
    .destroy = (void(*)(void *))wm_sca_destroy,
    .dump = (cJSON * (*)(const void *))wm_sca_dump,
    .sync = (int(*)(const char*, size_t))wm_sca_sync_message,
    .stop = NULL,
    .query = NULL,
};
```

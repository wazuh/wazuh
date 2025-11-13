# API Reference

The FIM module integrates with the Agent Sync Protocol through the C interface exposed by the `agent_sync_protocol` module.

---

## Agent Sync Protocol C Interface

FIM uses the sync protocol C interface defined in `agent_sync_protocol_c_interface.h` provided by the `agent_sync_protocol` module.

### Core Functions

#### `asp_create()`

Creates and initializes an Agent Sync Protocol handle for FIM.

**Signature:**
```c
AgentSyncProtocolHandle* asp_create(const char* module,
                                   const char* db_path,
                                   const MQ_Functions* mq_funcs,
                                   asp_logger_t logger);
```

**Parameters:**
- `module`: Module name (`"fim"`)
- `db_path`: Path to sync protocol database (`FIM_SYNC_PROTOCOL_DB_PATH`)
- `mq_funcs`: Message queue function pointers
- `logger`: Logging callback function

**Usage Example:**
```c
// FIM initializes sync protocol handle during startup
MQ_Functions mq_funcs = {
    .start = fim_startmq,
    .send_binary = fim_send_binary_msg
};

AgentSyncProtocolHandle* sync_handle = asp_create("fim",
                                                  FIM_SYNC_PROTOCOL_DB_PATH,
                                                  &mq_funcs,
                                                  loggingFunction);
```

#### `asp_persist_diff()`

Persists a file or registry difference for later synchronization.

**Signature:**
```c
void asp_persist_diff(AgentSyncProtocolHandle* handle,
                      const char* id,
                      Operation_t operation,
                      const char* index,
                      const char* data);
```

**Parameters:**
- `handle`: Sync protocol handle from `asp_create()`
- `id`: Unique identifier (SHA1 hash of file path)
- `operation`: Operation type (`OPERATION_CREATE`, `OPERATION_UPDATE`, `OPERATION_DELETE`)
- `index`: Sync index name
- `data`: JSON string containing file/registry data

**Usage Example:**
```c
void persist_syscheck_msg(const char *id, Operation_t operation,
                         const char *index, const cJSON* msg) {
    if (syscheck.enable_synchronization) {
        char* json_msg = cJSON_PrintUnformatted(msg);
        asp_persist_diff(syscheck.sync_handle, id, operation, index, json_msg);
        os_free(json_msg);
    }
}

// Example calls for different operations:
persist_syscheck_msg(file_hash, OPERATION_CREATE, FIM_FILES_SYNC_INDEX, file_json);
persist_syscheck_msg(file_hash, OPERATION_UPDATE, FIM_FILES_SYNC_INDEX, file_json);
persist_syscheck_msg(file_hash, OPERATION_DELETE, FIM_FILES_SYNC_INDEX, file_json);
```

#### `asp_sync_module()`

Triggers synchronization of all pending differences.

**Signature:**
```c
bool asp_sync_module(AgentSyncProtocolHandle* handle,
                     Mode_t mode,
                     unsigned int sync_timeout,
                     unsigned int sync_retries,
                     size_t max_eps);
```

**Parameters:**
- `handle`: Sync protocol handle
- `mode`: Sync mode (`MODE_DELTA` for FIM)
- `sync_timeout`: Response timeout in seconds
- `sync_retries`: Maximum retry attempts
- `max_eps`: Maximum events per second (0 = unlimited)

**Usage Example:**
```c
// FIM integrity thread triggers periodic synchronization
bool sync_success = asp_sync_module(syscheck.sync_handle,
                                   MODE_DELTA,                    // sync mode
                                   syscheck.sync_response_timeout, // timeout
                                   FIM_SYNC_RETRIES,              // retries
                                   syscheck.sync_max_eps);        // max events/sec
```

#### `asp_parse_response_buffer()`

Processes FlatBuffer responses from the manager.

**Signature:**
```c
bool asp_parse_response_buffer(AgentSyncProtocolHandle* handle,
                               const uint8_t* data,
                               size_t length);
```

**Parameters:**
- `handle`: Sync protocol handle
- `data`: Pointer to FlatBuffer-encoded message
- `length`: Size of message in bytes

**Usage Example:**
```c
// Process FlatBuffer responses from manager
bool success = asp_parse_response_buffer(syscheck.sync_handle,
                                        response_data,
                                        response_length);
```

#### `asp_notify_data_clean()`

Notifies the manager that specific indices have been cleaned and should be removed.

**Signature:**
```c
bool asp_notify_data_clean(AgentSyncProtocolHandle* handle,
                           const char** indices,
                           size_t indices_count,
                           unsigned int sync_timeout,
                           unsigned int retries,
                           size_t max_eps);
```

**Parameters:**
- `handle`: Sync protocol handle
- `indices`: Array of index names to clean
- `indices_count`: Number of indices in the array
- `sync_timeout`: Response timeout in seconds
- `retries`: Maximum retry attempts
- `max_eps`: Maximum events per second (0 = unlimited)

**Returns:**
- `true`: Notification succeeded
- `false`: Notification failed

**Usage Example:**
```c
// Notify data clean for disabled FIM components
const char* indices_to_clean[] = {
    FIM_FILES_SYNC_INDEX,
    FIM_REGISTRY_KEYS_SYNC_INDEX,
    FIM_REGISTRY_VALUES_SYNC_INDEX
};

bool notify_success = asp_notify_data_clean(syscheck.sync_handle,
                                           indices_to_clean,
                                           3,
                                           syscheck.sync_response_timeout,
                                           FIM_SYNC_RETRIES,
                                           syscheck.sync_max_eps);
```

#### `asp_delete_database()`

Deletes the sync protocol database associated with the handle.

**Signature:**
```c
void asp_delete_database(AgentSyncProtocolHandle* handle);
```

**Parameters:**
- `handle`: Sync protocol handle

**Usage Example:**
```c
// Delete sync protocol database when FIM is disabled
asp_delete_database(syscheck.sync_handle);
```

#### `asp_destroy()`

Destroys and cleans up an Agent Sync Protocol handle.

**Signature:**
```c
void asp_destroy(AgentSyncProtocolHandle* handle);
```

**Parameters:**
- `handle`: Sync protocol handle to destroy

---

## Operation Types

FIM uses the following operation types defined in `agent_sync_protocol_c_interface_types.h`:

```c
typedef enum {
    OPERATION_CREATE = 0,    // New file/registry entry
    OPERATION_UPDATE = 1,    // Modified file/registry entry
    OPERATION_DELETE = 2,    // Deleted file/registry entry
    OPERATION_NO_OP = 3     // No operation (internal use)
} Operation_t;
```

---

## Sync Indexes

FIM uses different indexes for different data types:

| Data Type | Index Name | Constant |
|-----------|------------|----------|
| Files | `"wazuh-states-fim-files"` | `FIM_FILES_SYNC_INDEX` |
| Registry Keys | `"wazuh-states-fim-registry-keys"` | `FIM_REGISTRY_KEYS_SYNC_INDEX` |
| Registry Values | `"wazuh-states-fim-registry-values"` | `FIM_REGISTRY_VALUES_SYNC_INDEX` |

---

## FIM Database Integration

FIM integrates with DBSync through the FIMDB wrapper class for local database operations:

### Database Initialization

```c
// FIM initializes database through DB interface (C wrapper)
void DB::init(const int storage,
              std::function<void(modules_log_level_t, const std::string&)> callbackLogWrapper,
              const int fileLimit,
              const int valueLimit) {
    auto dbsyncHandler = std::make_shared<DBSync>(...);
    FIMDB::instance().init(callbackLogWrapper, dbsyncHandler, fileLimit, valueLimit);
}
```

### Database Transaction Operations

FIM uses database transactions for state comparison, not direct database calls:

```c
// Start database transaction for file operations
TXN_HANDLE db_transaction_handle = fim_db_transaction_start(FIMDB_FILE_TXN_TABLE,
                                                            transaction_callback,
                                                            &txn_ctx);

// Transaction callback processes database comparison results
STATIC void transaction_callback(ReturnTypeCallback resultType,
                                const cJSON* result_json,
                                void* user_data) {
    // Database comparison result processed here
    // Events generated based on comparison
    persist_syscheck_msg(file_path_sha1, sync_operation,
                        FIM_FILES_SYNC_INDEX, stateful_event);
}
```

---

## Syscom Integration

FIM handles manager responses through the syscom interface:

```c
// Process sync protocol messages from manager
if (strncmp(command, FIM_SYNC_HEADER, strlen(FIM_SYNC_HEADER)) == 0) {
    if (syscheck.enable_synchronization) {
        const uint8_t *data = (const uint8_t *)(command + header_len);
        size_t data_len = command_len - header_len;

        bool ret = asp_parse_response_buffer(syscheck.sync_handle, data, data_len);
        if (!ret) {
            // Handle parsing error
        }
    }
}
```

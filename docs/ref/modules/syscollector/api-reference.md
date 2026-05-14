# API Reference

This document describes the internal interfaces for the Syscollector module in Wazuh.

## Wazuh Module Interface (C)

The main C interface is defined in `src/wazuh_modules/wm_syscollector.h` and implements the standard Wazuh module interface.

### Module Functions

#### `wm_syscollector_read()`

Reads and parses Syscollector configuration from XML.

**Function Signature:**
```c
int wm_syscollector_read(const OS_XML *xml, XML_NODE node, wmodule *module);
```

**Parameters:**
- `xml`: XML parser context
- `node`: XML node to parse
- `module`: Module structure to populate

**Returns:**
- `0`: Success
- `-1`: Configuration error

#### `wm_sys_main()`

Main thread function for the Syscollector module.

**Function Signature:**
```c
void* wm_sys_main(wm_sys_t *sys);
```

**Parameters:**
- `sys`: Syscollector configuration structure

**Returns:**
- `NULL`: Thread termination

#### `wm_sys_destroy()`

Cleanup function called when module is destroyed.

**Function Signature:**
```c
void wm_sys_destroy(wm_sys_t *sys);
```

### Configuration Structure

```c
typedef struct wm_sys_t {
    unsigned int interval;                  // Time interval between cycles (seconds)
    wm_sys_flags_t flags;                   // Flag bitfield
    wm_sys_state_t state;                   // Running state
    wm_sys_db_sync_flags_t sync;            // Database synchronization value
} wm_sys_t;
```

### State Structure

```c
typedef struct wm_sys_state_t {
    time_t next_time;                       // Absolute time for next scan
} wm_sys_state_t;
```

### Database Synchronization Structure

```c
typedef struct wm_sys_db_sync_flags_t {
    long sync_max_eps;                      // Maximum events per second for synchronization messages
} wm_sys_db_sync_flags_t;
```

### Flags Structure

```c
typedef struct wm_sys_flags_t {
    unsigned int enabled:1;                 // Main switch
    unsigned int scan_on_start:1;           // Scan always on start
    unsigned int hwinfo:1;                  // Hardware inventory
    unsigned int netinfo:1;                 // Network inventory
    unsigned int osinfo:1;                  // OS inventory
    unsigned int programinfo:1;             // Installed packages inventory
    unsigned int hotfixinfo:1;              // Windows hotfixes installed
    unsigned int portsinfo:1;               // Opened ports inventory
    unsigned int allports:1;                // Scan only listening ports or all
    unsigned int procinfo:1;                // Running processes inventory
    unsigned int running:1;                 // The module is running
    unsigned int groups:1;                  // Groups inventory
    unsigned int users:1;                   // Users inventory
    unsigned int services:1;                // Services inventory
    unsigned int browser_extensions:1;      // Browser extensions inventory
} wm_sys_flags_t;
```

## Internal Implementation

The syscollector module uses dynamic library loading to access platform-specific functionality.

### Dynamic Library Loading

The syscollector module loads the dynamic library at runtime and accesses the following functions:

```c
// Main syscollector functions loaded from dynamic library
void syscollector_start(const unsigned int interval,
                       send_data_callback_t callbackDiff,
                       send_data_callback_t callbackSync,
                       log_callback_t callbackLog,
                       const char* dbPath,
                       const char* normalizerConfigPath,
                       const char* normalizerType,
                       const bool scanOnStart,
                       const bool hardware,
                       const bool os,
                       const bool network,
                       const bool packages,
                       const bool ports,
                       const bool portsAll,
                       const bool processes,
                       const bool hotfixes,
                       const bool groups,
                       const bool users,
                       const bool services,
                       const bool browserExtensions);

void syscollector_stop();

int syscollector_sync_message(const char* data);
```

### Callback Type Definitions

```c
// Callback types used by syscollector
typedef void (*send_data_callback_t)(const void* buffer);
typedef void (*log_callback_t)(const modules_log_level_t level, const char* log, const char* tag);

// Function pointer types for dynamic loading
typedef void (*syscollector_start_func)(const unsigned int interval,
                                       send_data_callback_t callbackDiff,
                                       send_data_callback_t callbackSync,
                                       log_callback_t callbackLog,
                                       const char* dbPath,
                                       const char* normalizerConfigPath,
                                       const char* normalizerType,
                                       const bool scanOnStart,
                                       const bool hardware,
                                       const bool os,
                                       const bool network,
                                       const bool packages,
                                       const bool ports,
                                       const bool portsAll,
                                       const bool processes,
                                       const bool hotfixes,
                                       const bool groups,
                                       const bool users,
                                       const bool services,
                                       const bool browserExtensions);

typedef void (*syscollector_stop_func)();
typedef int (*syscollector_sync_message_func)(const char* data);
```

### Database Integration

The module integrates with the agent's local database through dynamic loading:

```c
// Database operations through wdb interface
void dbsync_initialize(const char* db_path);
void dbsync_add_table_relationship(const char* table_name, 
                                  const char* table_schema);
int dbsync_sync_row(const char* table_name, 
                   const char* json_event);
void dbsync_teardown();
```

## Configuration Interface

### XML Configuration Elements

```xml
<wodle name="syscollector">
    <!-- Basic settings -->
    <disabled>no</disabled>
    <interval>1h</interval>
    <scan_on_start>yes</scan_on_start>
    
    <!-- Inventory categories -->
    <hardware>yes</hardware>
    <os>yes</os>
    <network>yes</network>
    <packages>yes</packages>
    <processes>yes</processes>
    <ports all="no">yes</ports>
    <hotfixes>yes</hotfixes>
    
    <!-- New inventory categories -->
    <users>yes</users>
    <groups>yes</groups>
    <services>yes</services>
    <browser_extensions>yes</browser_extensions>
    
    <!-- Synchronization settings -->
    <synchronization>
        <max_eps>10</max_eps>
    </synchronization>
</wodle>
```

### Configuration Parsing

The main configuration parsing is handled by `wm_syscollector_read()` in `/src/config/wmodules-syscollector.c`. The function parses XML nodes and sets the appropriate flags and values in the configuration structure:

```c
// Main configuration parser
int wm_syscollector_read(const OS_XML *xml, XML_NODE node, wmodule *module);

// Helper function for synchronization section
static void parse_synchronization_section(wm_sys_t *syscollector, XML_NODE node);
```

## Integration with Wazuh Components

### Message Queue Integration

```c
// Queue creation and message sending
int StartMQ(const char *path, short int type);
int SendMSG(int queue, const char *message, const char *locmsg, char loc);
```

### Router Integration

```c
// Router communication
int router_provider_send(const char* message, size_t message_size);
```

### Database Integration

```c
// Wazuh DB operations
wdb_t* wdb_open_agent(int agent_id, const char *name);
int wdb_exec(sqlite3 *db, const char *sql);
void wdb_close(wdb_t *wdb);
```

## Event Format and Processing

### Event Structure

Syscollector events use Wazuh's custom inventory format:

```json
{
  "agent": {
    "id": "001",
    "name": "agent-name"
  },
  "manager": {
    "name": "wazuh-manager"
  },
  "data": {
    "scan_time": "2023-10-15 14:30:00",
    "checksum": "a1b2c3d4e5f6",
    "item_id": "unique-identifier",
    // Component-specific fields with prefixes:
    // - program.* (packages)
    // - process.* (processes) 
    // - port.* (ports)
    // - netinfo.iface.* (network interfaces)
    // - netinfo.proto.* (network protocols)
    // - hotfix (direct field for Windows updates)
  }
}
```

### Event Field Mappings

The module generates events with these field prefixes based on the decoder mappings:

| Category | Field Prefix | Example Fields |
|----------|-------------|----------------|
| **Hardware** | `hardware.*` | `hardware.serial`, `hardware.cpu_name`, `hardware.ram_total` |
| **Operating System** | `os.*` | `os.hostname`, `os.name`, `os.version`, `os.architecture` |
| **Packages** | `program.*` | `program.name`, `program.version`, `program.vendor` |
| **Processes** | `process.*` | `process.pid`, `process.name`, `process.cmd` |
| **Ports** | `port.*` | `port.protocol`, `port.local_ip`, `port.local_port` |
| **Network Interfaces** | `netinfo.iface.*` | `netinfo.iface.name`, `netinfo.iface.state` |
| **Network Protocols** | `netinfo.proto.*` | `netinfo.proto.iface`, `netinfo.proto.gateway` |
| **Network Addresses** | `netinfo.addr.*` | `netinfo.addr.iface`, `netinfo.addr.address` |
| **Users** | `user.*` | `user.user_name`, `user.user_home`, `user.user_shell` |
| **Groups** | `group.*` | `group.group_name`, `group.group_description` |
| **Services** | `service.*` | `service.service_name`, `service.service_state` |
| **Browser Extensions** | `browser.*` | `browser.browser_name`, `browser.package_name` |
| **Hotfixes** | (direct field) | `hotfix` |

**Note**: These field mappings are defined in `src/analysisd/decoders/syscollector.c` and determine how database fields are transformed into event fields for processing.

## Error Handling and Logging

### Logging Macros

```c
// Standard Wazuh logging
mtinfo(WM_SYSCOLLECTOR_LOGTAG, "Info: %s", message);
mtwarn(WM_SYSCOLLECTOR_LOGTAG, "Warning: %s", message);
mterror(WM_SYSCOLLECTOR_LOGTAG, "Error: %s", message);
mtdebug1(WM_SYSCOLLECTOR_LOGTAG, "Debug: %s", message);
mtdebug2(WM_SYSCOLLECTOR_LOGTAG, "Verbose: %s", message);
```

### Error Conditions

```c
// Library loading failures
if (!(syscollector_module = so_get_module_handle("syscollector"))) {
    mterror(WM_SYS_LOGTAG, "Failed to load syscollector library");
    return NULL;
}

// Function pointer loading failures
if (!(syscollector_start_ptr = so_get_function_sym(syscollector_module, "syscollector_start"))) {
    mterror(WM_SYS_LOGTAG, "Failed to load syscollector_start function");
    return NULL;
}

// Configuration validation
if (sys->interval < 60) {
    mterror(WM_SYS_LOGTAG, "Invalid interval: %u (minimum is 60 seconds)", sys->interval);
    return -1;
}
```

## Module Lifecycle

### Initialization Sequence

1. **Configuration Parsing**: `wm_sys_read()` parses XML configuration
2. **Library Loading**: Dynamic libraries are loaded
3. **Database Setup**: Local database is initialized
4. **Thread Creation**: Main module thread is started
5. **Synchronization Setup**: Communication with manager is established

### Main Loop

```c
void* wm_sys_main(wm_sys_t *sys) {
    if (sys->flags.running) {
        // Already running
        return 0;
    }

    sys->flags.running = true;

    // Initialize mutexes and condition variables
    w_cond_init(&sys_stop_condition, NULL);
    w_mutex_init(&sys_stop_mutex, NULL);
    w_mutex_init(&sys_reconnect_mutex, NULL);

    if (!sys->flags.enabled) {
        mtinfo(WM_SYS_LOGTAG, "Module disabled. Exiting...");
        pthread_exit(NULL);
    }

    // Connect to message queue
    queue_fd = StartMQ(DEFAULTQUEUE, WRITE, INFINITE_OPENQ_ATTEMPTS);
    if (queue_fd < 0) {
        mterror(WM_SYS_LOGTAG, "Can't connect to queue.");
        pthread_exit(NULL);
    }

    // Load dynamic library and function pointers
    if (syscollector_module = so_get_module_handle("syscollector"), syscollector_module) {
        syscollector_start_ptr = so_get_function_sym(syscollector_module, "syscollector_start");
        syscollector_stop_ptr = so_get_function_sym(syscollector_module, "syscollector_stop");
        syscollector_sync_message_ptr = so_get_function_sym(syscollector_module, "syscollector_sync_message");

        if (syscollector_start_ptr) {
            // Start syscollector with current configuration
            syscollector_start_ptr(
                sys->interval,
                wm_sys_send_message_diff,
                wm_sys_send_message_sync,
                wm_sys_log_callback,
                queue,
                norm_config_path,
                norm_type,
                sys->flags.scan_on_start,
                sys->flags.hwinfo,
                sys->flags.osinfo,
                sys->flags.netinfo,
                sys->flags.programinfo,
                sys->flags.portsinfo,
                sys->flags.allports,
                sys->flags.procinfo,
                sys->flags.hotfixinfo,
                sys->flags.groups,
                sys->flags.users,
                sys->flags.services,
                sys->flags.browser_extensions
            );
        }
    }
    
    return NULL;
}
```

### Cleanup

```c
void wm_sys_destroy(wm_sys_t *sys) {
    if (sys) {
        if (sys->queue) {
            os_free(sys->queue);
        }
        os_free(sys);
    }
}
```

## Thread Safety and Synchronization

### Threading Model

- **Main Thread**: Configuration and module management
- **Scanner Thread**: Periodic inventory collection
- **Sync Thread**: Manager synchronization
- **Database Thread**: Local database operations

### Synchronization Primitives

```c
// Module-level synchronization
static pthread_mutex_t sys_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t sys_cond = PTHREAD_COND_INITIALIZER;

// Thread-safe operations
w_mutex_lock(&sys_mutex);
// Critical section
w_mutex_unlock(&sys_mutex);
```

## Dependencies

### Required System Libraries

- **libsqlite3**: Database operations
- **libcjson**: JSON processing
- **libpthread**: Threading support

### Wazuh Dependencies

- **libwazuhext**: Extended Wazuh functionality
- **libwazuhshared**: Shared utilities
- **librouter**: Message routing
- **libwazuhdb**: Database interface

### Dynamic Libraries

The module loads these libraries at runtime:

- **libsyscollector**: Core inventory collection
- **libsysinfo**: System information provider
- **libdbsync**: Database synchronization
- **librsync**: Remote synchronization protocol

## Debugging and Troubleshooting

### Debug Configuration

Enable debug logging in `ossec.conf`:

```xml
<ossec_config>
    <global>
        <logall>yes</logall>
        <logall_json>yes</logall_json>
    </global>
</ossec_config>
```

### Debug Commands

```bash
# View syscollector logs
grep syscollector /var/ossec/logs/ossec.log

# Check library loading
ldd /var/ossec/bin/wazuh-agentd | grep syscollector

# Monitor database operations
sqlite3 /var/ossec/queue/db/000.db ".tables"

# Test module configuration
/var/ossec/bin/wazuh-agentd -t
```

### Common Issues

1. **Library Loading Failures**: Check library paths and dependencies
2. **Database Corruption**: Remove database file and restart agent
3. **Sync Failures**: Verify network connectivity to manager
4. **High Resource Usage**: Adjust scan intervals and component selection

**Note**: This module does not expose a public API for external applications. All functionality is accessed through the Wazuh agent configuration system.
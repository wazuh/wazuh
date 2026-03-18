# Control Module Architecture

## Overview

The Control Module (`wm_control`) is a lightweight module within `wazuh-modulesd` that provides manager control operations. It implements a Unix domain socket server that accepts control commands and executes system-level operations.

This module is enabled in manager builds (`TARGET=manager`) on Unix-like systems.

## Component Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                          wazuh-modulesd                             │
│                                                                     │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │                      wm_control Module                        │  │
│  │                                                               │  │
│  │  ┌──────────────────────┐      ┌───────────────────────┐      │  │
│  │  │   Socket             │      │   Command Dispatcher  │      │  │
│  │  │   Listener           │─────▶│   wm_control_dispatch │      │  │
│  │  │   process_control()  │      └───────────┬───────────┘      │  │
│  │  └──────────────────────┘                  │                  │  │
│  │                                            │                  │  │
│  │                                            │                  │  │
│  │                                            │                  │  │
│  │                                 ┌──────────▼─────────┐        │  │
│  │                                 │ Restart/Reload     │        │  │
│  │                                 │ wm_control_execute │        │  │
│  │                                 │ _action()          │        │  │
│  │                                 └────────────────────┘        │  │
│  └───────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
         │                                           ▲
         │ fork + execv                              │ socket connect
         ▼                                           │
┌──────────────────────┐                  ┌─────────────────────┐
│  systemctl/          │                  │   API / Framework   │
│  wazuh-control       │                  │   Clients           │
└──────────────────────┘                  └─────────────────────┘
```

## Core Components

### 1. Socket Listener (`process_control()`)

The socket listener is the main entry point for control commands.

**Functionality**:
- Binds to Unix domain socket: `/var/ossec/queue/sockets/control`
- Listens for incoming connections (SOCK_STREAM)
- Accepts connections and reads commands
- Dispatches commands to handler
- Sends responses back to client

**Implementation Details**:
```c
// Socket creation with specific permissions
int sock = OS_BindUnixDomainWithPerms(
    CONTROL_SOCK,        // "queue/sockets/control"
    SOCK_STREAM,         // Stream socket
    OS_MAXSTR,           // Max connections
    getuid(),            // Owner UID
    wm_getGroupID(),     // Wazuh group GID
    0660                 // Permissions: rw-rw----
);
```

**Main Loop**:
1. `select()` on socket for incoming connections
2. `accept()` new client connection
3. `OS_RecvUnix()` read command from client
4. `wm_control_dispatch()` process command
5. `OS_SendUnix()` send response to client
6. Close client connection

### 2. Command Dispatcher (`wm_control_dispatch()`)

Routes incoming commands to appropriate handlers.

**Command Routing**:
```c
size_t wm_control_dispatch(char *command, char **output) {
    // Parse command and arguments
    char *args = strchr(command, ' ');
    if (args) {
        *args = '\0';
        args++;
    }

    if (strcmp(command, "restart") == 0) {
        return wm_control_execute_action("restart", output);
    }
    else if (strcmp(command, "reload") == 0) {
        return wm_control_execute_action("reload", output);
    }
    else {
        mterror(WM_CONTROL_LOGTAG, "Unknown command: '%s'", command);
        os_strdup("Err", *output);
        return strlen(*output);
    }
}
```

### 3. Action Executor (`wm_control_execute_action()`)

Executes restart/reload operations via system commands.

**Process Flow**:

```
┌─────────────────────────────────────────────┐
│  wm_control_execute_action("restart")       │
└─────────────────┬───────────────────────────┘
                  │
                  ▼
         ┌────────────────┐
         │ Check systemd? │
         └───┬────────┬───┘
             │        │
      Yes ◄──┘        └──► No
       │                   │
       ▼                   ▼
┌─────────────┐    ┌──────────────────┐
│ systemctl   │    │ wazuh-control    │
│ restart     │    │ restart          │
│ wazuh-      │    │                  │
│ manager     │    │                  │
└─────────────┘    └──────────────────┘
```

**Systemd Detection**:
```c
static bool wm_control_check_systemd() {
    // Check if systemd directory exists
    if (access("/run/systemd/system", F_OK) != 0) {
        return false;
    }

    // Check if PID 1 is systemd
    FILE *fp = fopen("/proc/1/comm", "r");
    if (fp) {
        char init_name[256];
        if (fgets(init_name, sizeof(init_name), fp)) {
            init_name[strcspn(init_name, "\n")] = 0;
            if (strcmp(init_name, "systemd") == 0) {
                fclose(fp);
                return true;
            }
        }
        fclose(fp);
    }
    return false;
}
```

**Fork and Execute**:
```c
switch (fork()) {
    case -1:  // Fork failed
        return error;

    case 0:   // Child process
        // For reload: wait for service active
        if (reload && systemd) {
            wm_control_wait_for_service_active();
        }

        // Execute command
        execv("/usr/bin/systemctl", ["systemctl", action, "wazuh-manager"]);
        _exit(1);

    default:  // Parent process
        return "ok ";  // Return immediately
}
```

**Key Design Decision**: The parent process returns `"ok "` immediately after forking, without waiting for the child to complete. This is intentional to prevent socket timeout issues during restart operations.

### 4. Reload Safety Mechanism

For reload operations with systemd, the module ensures the service is ready:

```c
static bool wm_control_wait_for_service_active() {
    const int timeout = 60;  // seconds

    while (elapsed < timeout) {
        // Check service state
        FILE *fp = popen("systemctl is-active wazuh-manager", "r");
        char state[256];
        fgets(state, sizeof(state), fp);

        if (strcmp(state, "active") == 0) {
            return true;  // Ready for reload
        }

        if (strcmp(state, "inactive") == 0 || strcmp(state, "failed") == 0) {
            return false;  // Cannot reload
        }

        sleep(1);
        elapsed++;
    }

    return false;  // Timeout
}
```

### 5. Unknown Command Handling

`wm_control` only accepts `restart` and `reload`.
Any other command:

1. Is logged as an error (`Unknown command`)
2. Returns `Err` to the client

## Data Flow

### Restart Request Flow

```
1. API/Framework
   └─► socket.connect("/var/ossec/queue/sockets/control")

2. API/Framework
   └─► socket.send("restart")

3. wm_control Module
   └─► wm_control_dispatch("restart", &output)
       └─► wm_control_execute_action("restart", &output)
           ├─► Check systemd available?
           ├─► fork()
           │   └─► Child: execv("systemctl restart wazuh-manager")
           └─► Parent: return "ok "

4. API/Framework
   └─► socket.recv() → "ok "

5. API/Framework
   └─► socket.close()
```

## Thread Model

**Main Thread**: Module initialization (`wm_control_main()`)
- Calls `process_control()` to start socket server
- Never returns (runs forever)

**Socket Server**: Single-threaded event loop (`process_control()`)
- Uses `select()` for socket events
- Handles one connection at a time
- Synchronous processing (no concurrency)

**Action Execution**: Fork-based process isolation
- Parent process returns immediately
- Child process executes system command
- No inter-process synchronization needed

## Error Handling

**Socket Errors**:
- Bind failure: Log error and exit thread
- Accept failure: Log and continue (skip connection)
- Receive failure: Log and close connection
- Send failure: Log and close connection

**Fork Errors**:
- Fork failure: Return error response to client
- Execv failure: Child logs error and exits with code 1

**Systemd Errors**:
- Service not active: Log error and abort reload
- Timeout waiting for active: Log error and return failure

## Security Model

**Access Control**:
- Socket permissions: `0660` (owner and group only)
- Socket group: Wazuh group (for API/framework access)
- No authentication required (filesystem permissions provide security)

**Privilege Model**:
- Module runs as root (within modulesd)
- Can execute privileged commands (systemctl, wazuh-control)
- No privilege escalation needed

**Attack Surface**:
- Local socket only (no network exposure)
- Simple command protocol (minimal parsing)
- Limited command set (restart, reload)
- No arbitrary command execution

## Performance Characteristics

**Socket Performance**:
- Single-threaded (no concurrency overhead)
- Synchronous processing (one request at a time)
- Minimal latency (Unix socket, no network)

**Restart Performance**:
- Non-blocking (returns immediately)
- Fork overhead: ~1-2ms
- Actual restart time: 5-10 seconds (depends on services)

**Resource Usage**:
- Memory: Minimal (runs within modulesd)
- CPU: Idle when no requests
- File Descriptors: 1 (control socket)

## Future Enhancements

Potential improvements for future versions:

1. **Restart Lock**: Migrate lock_restart functionality from execd
2. **Status Tracking**: Return actual restart completion status
3. **Async Notifications**: Notify when restart completes
4. **Health Checks**: Pre-restart validation
5. **Rollback Support**: Automatic rollback on failed restart

## See Also

- [Control Module README](README.md) - Module overview
- [wazuh-modulesd](../modulesd/) - Host daemon documentation
- [Manager Installation](../../getting-started/installation.md) - Manager setup and systemctl

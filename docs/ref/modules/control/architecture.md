# Control Module Architecture

## Overview

The Control Module provides control operations for both the Wazuh manager and agents. It implements Unix domain socket servers that accept control commands and execute system-level operations.

The entire Unix-side implementation lives in a single file, `wm_control.c`, compiled differently per build target:

- **Manager build** (`TARGET=manager`): `process_control()` runs directly in the main thread.
- **Agent build** (`CLIENT` defined, Unix): `process_control()` is spawned as a worker thread within `wazuh-modulesd`.

On **Windows agents**, `control_dispatch()` in `client-agent/src/control.c` handles control commands in-process (no separate socket listener thread).

## Component Architecture

### Manager Side

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

### Agent Side (Unix)

On Unix agents, `wm_control.c` is compiled with `CLIENT` defined. `wm_control_main()` spawns `process_control()` as a thread. The socket listener and dispatcher are identical to the manager side; only the service name passed to `wm_control_execute_action()` differs (`"wazuh-agent"` instead of `"wazuh-manager"`).

Incoming control commands from the manager arrive via `wazuh-agentd`'s `request.c`, which forwards `"control"` target messages to the `CONTROL_SOCK` Unix socket.

```
┌──────────────────────────────────────────────────────────────┐
│            wazuh-modulesd (agent, CLIENT build)              │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐  │
│  │              wm_control Module (CLIENT build)          │  │
│  │                                                        │  │
│  │  ┌───────────────┐      ┌──────────────────────────┐   │  │
│  │  │   Socket      │      │   Command Dispatcher     │   │  │
│  │  │   Listener    │─────▶│   wm_control_dispatch()  │   │  │
│  │  │   process_    │      └──────────┬───────────────┘   │  │
│  │  │   control()   │                 │                   │  │
│  │  └───────────────┘                 ▼                   │  │
│  │                     ┌──────────────────────┐           │  │
│  │                     │ wm_control_execute   │           │  │
│  │                     │ _action("wazuh-agent")│           │  │
│  │                     └──────────────────────┘           │  │
│  └────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
         │                                           ▲
         │ fork + execv                              │ CONTROL_SOCK
         ▼                                           │ (forwarded by agentd/request.c)
┌──────────────────────┐                  ┌──────────────────────┐
│  systemctl/          │                  │  wazuh-remoted /     │
│  wazuh-control       │                  │  API / Framework     │
└──────────────────────┘                  └──────────────────────┘
```

### Agent Side (Windows)

On Windows, there is no separate socket listener. `wazuh-agentd`'s `request.c` calls `control_dispatch()` directly in-process when it receives a `"control"` target message.

```
┌──────────────────────────────────────────────────────────────┐
│            wazuh-agentd (Windows)                            │
│                                                              │
│  request.c                                                   │
│  └─► control_dispatch()  (client-agent/src/control.c)        │
│       └─► control_run_detached()                             │
│            ├─► GetModuleFileNameA()                          │
│            ├─► CreateProcessA("wazuh-agent.exe              │
│            │       service-restart", DETACHED_PROCESS)       │
│            └─► return "ok " immediately                      │
└──────────────────────────────────────────────────────────────┘
                                           ▲
                                           │ via wazuh-remoted
                                           │
                                ┌──────────────────────┐
                                │  API / Framework     │
                                └──────────────────────┘
```

## Core Components

### 1. Socket Listener (`process_control()`)

The socket listener is the main entry point for control commands on Unix (both manager and agent builds).

**Socket Path** (both manager and agent): `CONTROL_SOCK = "queue/sockets/control"`, resolved relative to `WAZUH_HOME`.

- Default manager path: `/var/wazuh-manager/queue/sockets/control`
- Default agent path: `/var/ossec/queue/sockets/control`

**Functionality**:
- Binds to the Unix domain socket
- Listens for incoming connections (SOCK_STREAM)
- Accepts connections and reads commands
- Dispatches commands to `wm_control_dispatch()`
- Sends responses back to client

**Implementation Details**:
```c
// Socket creation with specific permissions (same for manager and agent)
int sock = OS_BindUnixDomainWithPerms(
    CONTROL_SOCK,        // "queue/sockets/control" (resolved relative to WAZUH_HOME)
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
3. `OS_RecvSecureTCP()` read command from client
4. `wm_control_dispatch()` process command
5. `OS_SendSecureTCP()` send response to client
6. Close client connection

### 2. Command Dispatcher (`wm_control_dispatch()`)

The same `wm_control_dispatch()` function handles both manager and agent builds. The service name passed to `wm_control_execute_action()` is determined at compile time via `#ifdef CLIENT`.

```c
size_t wm_control_dispatch(char *command, char **output) {
#ifdef CLIENT
    const char *service = "wazuh-agent";
#else
    const char *service = "wazuh-manager";
#endif

    if (strcmp(command, "restart") == 0) {
        return wm_control_execute_action("restart", service, output);
    }
    else if (strcmp(command, "reload") == 0) {
        return wm_control_execute_action("reload", service, output);
    }
    else {
        mterror(WM_CONTROL_LOGTAG, "Unknown command: '%s'", command);
        os_strdup("Err", *output);
        return strlen(*output);
    }
}
```

#### Windows: `control_dispatch()`

On Windows, `control_dispatch()` in `client-agent/src/control.c` handles the equivalent routing. Unknown commands return `"err Unrecognized command"` (not `"Err"`):

```c
size_t control_dispatch(char *command, char **output) {
    if (strcmp(command, "restart") == 0) {
        return control_run_detached("restart", output);
    } else if (strcmp(command, "reload") == 0) {
        return control_run_detached("reload", output);
    } else {
        os_strdup("err Unrecognized command", *output);
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
│ <service>   │    │                  │
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
            wm_control_wait_for_service_active(service);
        }

        // Execute command
        execv("/usr/bin/systemctl", ["systemctl", action, service]);
        _exit(1);

    default:  // Parent process
        return "ok ";  // Return immediately
}
```

**Key Design Decision**: The parent process returns `"ok "` immediately after forking, without waiting for the child to complete. This is intentional to prevent socket timeout issues during restart operations.

### 4. Reload Safety Mechanism

For reload operations with systemd, the module ensures the service is ready:

```c
static bool wm_control_wait_for_service_active(const char *service) {
    const int timeout = 60;  // seconds

    while (elapsed < timeout) {
        // Check service state
        FILE *fp = popen("systemctl is-active <service>", "r");
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

`wm_control_dispatch()` (Unix, both manager and agent) only accepts `restart` and `reload`. Any other command is logged as an error and returns `"Err"` to the client.

`control_dispatch()` (Windows) returns `"err Unrecognized command"` for unknown commands (no log entry).

## Data Flow

### Manager Restart Request Flow

```
1. API/Framework
   └─► socket.connect("$WAZUH_HOME/queue/sockets/control")

2. API/Framework
   └─► socket.send("restart")

3. wm_control (manager build)
   └─► wm_control_dispatch("restart", &output)
       └─► wm_control_execute_action("restart", "wazuh-manager", &output)
           ├─► Check systemd available?
           ├─► fork()
           │   └─► Child: execv("systemctl restart wazuh-manager")
           └─► Parent: return "ok "

4. API/Framework
   └─► socket.recv() → "ok "

5. API/Framework
   └─► socket.close()
```

### Remote Agent Restart/Reload Request Flow (Unix)

```
1. API/Framework
   └─► WazuhSocket(REMOTED_SOCKET).send("{agent_id} control restart")

2. wazuh-remoted
   └─► Forwards message to target agent

3. wazuh-agentd (request.c, agent side)
   └─► Receives "control" target
       └─► Forwards to CONTROL_SOCK Unix socket

4. wm_control thread (CLIENT build, in wazuh-modulesd)
   └─► process_control() receives command
       └─► wm_control_dispatch("restart", &output)
           └─► wm_control_execute_action("restart", "wazuh-agent", &output)
               ├─► Check systemd available?
               ├─► fork()
               │   └─► Child: execv("systemctl restart wazuh-agent")
               └─► Parent: return "ok "

5. Response propagated back to API/Framework
```

### Remote Agent Restart/Reload Request Flow (Windows)

```
1. API/Framework
   └─► WazuhSocket(REMOTED_SOCKET).send("{agent_id} control restart")

2. wazuh-remoted
   └─► Forwards message to target agent

3. wazuh-agentd (request.c, Windows)
   └─► Receives "control" target
       └─► Calls control_dispatch("restart", &output) in-process
           └─► control_run_detached("restart", &output)
               ├─► GetModuleFileNameA() — resolves wazuh-agent.exe path
               ├─► CreateProcessA("wazuh-agent.exe service-restart",
               │       DETACHED_PROCESS | CREATE_NO_WINDOW)
               │   └─► Detached child:
               │         sleep(1s)              ← waits for "ok" to reach remoted
               │         os_stop_service()      ← stops WazuhSvc
               │         os_start_service()     ← starts WazuhSvc
               │         exit(0)
               ├─► CloseHandle() — parent releases child handles
               └─► return "ok " immediately

4. Response propagated back to API/Framework (before WazuhSvc stops)
```

## Thread Model

### Manager

**Main Thread**: Module initialization (`wm_control_main()`)
- Calls `process_control()` directly (blocking)
- Never returns (runs forever)

**Socket Server**: Single-threaded event loop (`process_control()`)
- Uses `select()` for socket events
- Handles one connection at a time

### Agent (Unix)

**wm_control_main()**: Spawns `process_control()` as a thread (`w_create_thread()`) and returns.

**Socket Server Thread**: Same single-threaded event loop as the manager side.

### Agent (Windows)

No dedicated thread. `control_dispatch()` is called synchronously from the request handler thread in `wazuh-agentd`.

**Action Execution**: Fork-based process isolation (Unix) or detached process (Windows)
- Parent/caller returns immediately
- Child/detached process executes system command

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

## Migration from wazuh-execd

### Previous Architecture (v4.x)

**Component**: `wazuh-execd` daemon
- **Socket**: `/var/ossec/queue/sockets/com`
- **Commands**: restart, reload, getconfig, check-manager-configuration, unmerge, uncompress, lock_restart
- **Agent restart/reload**: Via Active Response scripts (`restart.sh`, `restart-wazuh.exe`)
- **Responsibilities**:
  - Active Response execution
  - Configuration serving
  - File operations
  - Manager control

### Current Architecture (v5.0)

**Manager**: `wm_control` (within modulesd, manager build)
- **Socket**: `$WAZUH_HOME/queue/sockets/control`
- **Commands**: restart, reload
- **Service name**: `wazuh-manager`

**Agent Unix**: `wm_control` (within modulesd, `CLIENT` build, thread)
- **Socket**: `$WAZUH_HOME/queue/sockets/control`
- **Commands**: restart, reload (dispatched by `wm_control_dispatch()`)
- **Service name**: `wazuh-agent`

**Agent Windows**: `control_dispatch()` (within `wazuh-agentd`, in-process)
- Handles restart/reload via `control_run_detached()`, which spawns a detached copy of `wazuh-agent.exe service-restart`. The detached process runs outside WazuhSvc, waits 1 second for the `"ok"` response to reach remoted, then calls `os_stop_service()` / `os_start_service()` and exits

### Changes

| Feature               | v4.x (execd)   | v5.0 (wm_control) | Notes                               |
| --------------------- | -------------- | ----------------- | ----------------------------------- |
| Manager restart       | ✓ wcom socket  | ✓ control socket  | Migrated                            |
| Manager reload        | ✓ wcom socket  | ✓ control socket  | Migrated                            |
| Get primary IP        | ✓ wcom socket  | ✗ Removed         | No longer handled by control socket |
| Configuration serving | ✓ wcom socket  | ✗ File-based      | Changed approach                    |
| Config validation     | ✓ wcom socket  | ✗ File-based      | Changed approach                    |
| File unmerge          | ✓ wcom socket  | ✗ Removed         | Deprecated                          |
| File uncompress       | ✓ wcom socket  | ✗ Removed         | Deprecated                          |
| Restart locking       | ✓ wcom socket  | ✗ Not migrated    | TBD                                 |
| Active Response       | ✓ execd daemon | ✗ Agents only     | Intentional removal                 |

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

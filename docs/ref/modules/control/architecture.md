# Control Module Architecture

## Overview

The Control Module accepts `restart` and `reload` on a local Unix socket and has the service carry
them out. The Unix-side implementation lives in one file, `src/wazuh_modules/src/wm_control.c`,
compiled differently per build target:

- **Manager** (`TARGET=manager`, Linux): the socket listener runs in the module's own thread in
  `wazuh-manager-modulesd`, and the action is executed by the setuid helper
  `wazuh-manager-service-control` (`src/util/manager_service_control/main.c`).
- **Unix agent** (`CLIENT` defined): the module thread spawns the listener as a further thread in the
  agent's `wazuh-modulesd`, which runs `systemctl` or `bin/wazuh-control` itself (macOS: a request
  flag for the launcher).

On **Windows agents**, `control_dispatch()` in `src/client-agent/src/control.c` handles the same two
commands in-process inside `wazuh-agentd` (no socket listener).

For the socket protocol, responses, error codes and the helper's usage, see the
[module overview](README.md).

## Component Architecture

### Manager Side

```text
┌──────────────────────────────────────────────────────────────────────┐
│ wazuh-manager-modulesd  (runs as wazuh-manager)                      │
│                                                                      │
│  wm_control thread                                                   │
│  process_control()  ──►  wm_control_dispatch()  ──►                  │
│  control.sock (0660)       restart | reload      wm_control_execute_ │
│  SO_PEERCRED: root or      anything else: Err    action()            │
│  wazuh-manager only                               │                  │
└───────────────────────────────────────────────────┼──────────────────┘
         ▲                                          │ fork + execl, status pipe on fd 3
         │ connect, "restart"/"reload"              ▼                  waits ≤ 5 s for '1'
┌────────────────────┐              ┌──────────────────────────────────────┐
│ wazuh-manager-apid │              │ wazuh-manager-service-control        │
│ (framework:        │              │ (setuid root, 4750)                  │
│  manager_restart / │              │ validate caller and paths → write '1'│
│  manager_reload)   │              │ → become root → exec:                │
└────────────────────┘              │   systemctl <action>                 │
                                    │     wazuh-manager.service            │
                                    │   or bin/wazuh-manager-control       │
                                    │     <action>                         │
                                    └──────────────────────────────────────┘
```

### Agent Side (Unix)

On Unix agents, `wm_control.c` is compiled with `CLIENT` defined. `wm_control_main()` spawns
`process_control()` as a thread. The dispatcher passes the service name `"wazuh-agent"` to
`wm_control_execute_action()`, which, on Linux and the BSDs, forks and in the child runs:

- with systemd as PID 1 (`/run/systemd/system` exists and `/proc/1/comm` is `systemd`):
  `systemctl <action> wazuh-agent`. For `reload` it first polls `systemctl is-active wazuh-agent`
  once a second for up to 60 seconds; if the unit is `inactive` or `failed`, or never becomes
  `active`, it falls back to `bin/wazuh-control reload`;
- without systemd: `bin/wazuh-control <action>`.

The parent answers `ok ` immediately after `fork()`.

On **macOS** the module does not run `wazuh-control` itself: forking it from `wazuh-modulesd` would
make modulesd the TCC "responsible process" of the respawned daemons. It writes the action to
`var/run/wazuh-control.request.tmp`, renames it to `var/run/wazuh-control.request`, and the
`Wazuh-launcher` loop in `src/init/darwin-init.sh` runs `wazuh-control <action>`. A failure to write
the flag is answered `err Cannot write control flag`.

Commands from the manager arrive as `agent_restart` / `agent_reload` tasks. `wazuh-agentd`'s
`bridge_on_task()` (`src/client-agent/src/https_client_bridge.c`) runs `restartAgent()` /
`reloadAgent()` (`src/client-agent/src/reload_agent.c`) on a worker thread; on Unix they connect to
`CONTROL_SOCK` (retrying up to 30 times, one second apart, while modulesd is not up), send the command
with the length-prefixed framing and close the connection without reading the answer.

```text
┌──────────────────────────────┐   CONTROL_SOCK         ┌──────────────────────────────┐
│ wazuh-agentd                 │   "restart"/"reload"   │ wazuh-modulesd (agent)       │
│ bridge_on_task()             │ ─────────────────────► │ wm_control: process_control()│
│  └─► restartAgent() /        │                        │  └─► wm_control_dispatch()   │
│      reloadAgent()           │                        │       └─► fork + execvp:     │
└──────────────────────────────┘                        │  systemctl <action>          │
          ▲                                             │    wazuh-agent               │
          │ POST /control (task poll)                   │  or bin/wazuh-control        │
┌──────────────────────────────┐                        │    <action>                  │
│ wazuh-manager-remoted        │                        └──────────────────────────────┘
└──────────────────────────────┘
```

### Agent Side (Windows)

On Windows there is no socket listener. `controlAgent()` in `reload_agent.c` calls
`control_dispatch()` directly and checks its answer.

```text
┌──────────────────────────────────────────────────────────────┐
│ wazuh-agentd (Windows)                                       │
│                                                              │
│  restartAgent() / reloadAgent()   (reload_agent.c)           │
│  └─► control_dispatch()  (client-agent/src/control.c)        │
│       └─► control_run_detached()                             │
│            ├─► GetModuleFileNameA()                          │
│            ├─► CreateProcessA("wazuh-agent.exe               │
│            │       service-restart",                         │
│            │       CREATE_NO_WINDOW | DETACHED_PROCESS)      │
│            └─► return "ok " immediately                      │
└──────────────────────────────────────────────────────────────┘
```

`reload` is a full stop and start of the service as well. Failures are answered
`err GetModuleFileName failed`, `err command line too long` or `err CreateProcess failed`.

## Core Components

### 1. Socket Listener (`process_control()`)

**Socket path**: `CONTROL_SOCK`, relative to the installation directory: `queue/sockets/control.sock`
on the manager, `queue/sockets/control` on the agent.

```c
sock = OS_BindUnixDomainWithPerms(CONTROL_SOCK, SOCK_STREAM, OS_MAXSTR,
                                  getuid(), wm_getGroupID(), 0660);
```

**Main loop**:
1. `wm_select_interruptible()` on the socket, until shutdown is requested
2. `accept()` a client
3. Manager only: check the peer with `SO_PEERCRED`; a peer whose uid is neither `0` nor modulesd's own
   is closed
4. Read the command: `OS_RecvUnix()` on the manager (raw bytes), `OS_RecvSecureTCP()` on the agent
   (length-prefixed)
5. `wm_control_dispatch()`
6. Send the answer (`OS_SendUnix()` / `OS_SendSecureTCP()`) and close the connection

### 2. Command Dispatcher (`wm_control_dispatch()`)

The same function serves both builds; only two details differ:

| | Manager | Agent |
|---|---|---|
| Service name passed on | `wazuh-manager` | `wazuh-agent` |
| Text after the first space | rejected: `err Unexpected arguments` | ignored |

`restart` and `reload` go to `wm_control_execute_action()`; anything else is logged
(`Unknown command: '<command>'`) and answered `Err`.

### 3. Manager Action Executor

On a Linux manager, `wm_control_execute_action()`:

1. creates a pipe and forks;
2. in the child, moves the pipe's write end to file descriptor 3 and `execl()`s
   `bin/wazuh-manager-service-control <action>`;
3. in the parent, `poll()`s the read end for up to 5000 ms for one byte:
   - `'1'`: answers `ok accepted` and leaves the child to a detached reaper thread;
   - anything else (timeout, early exit): kills the child if it timed out, reaps it, logs
     `Privileged service control rejected or could not execute '<action>'` and answers
     `err Service control rejected action`.

### 4. wazuh-manager-service-control

The helper writes the acceptance byte only after every check has passed, and executes the action only
after writing it:

1. Standard descriptors 0–2 are reopened on `/dev/null` if they arrive closed.
2. Exactly one argument, `restart` or `reload` (`-h` prints the usage).
3. Caller: the real uid is `0` or that of `wazuh-manager` (`WAZUH_RUNTIME_USER`, set in
   `src/util/CMakeLists.txt`), and the effective uid is `0`.
4. Install paths derived from `/proc/self/exe` (`<home>/bin/wazuh-manager-service-control`): the
   executable (which must still be setuid), `<home>`, `<home>/bin`, `<home>/bin/wazuh-manager-control`
   and, if present, `<home>/bin/.process_list` must be owned by root and not group- or
   world-writable; `/usr/bin/systemctl` too when systemd is running.
5. Environment cleared to `PATH=/usr/sbin:/usr/bin:/sbin:/bin` and `LANG=C`; umask `0077`; every
   inherited descriptor above 3 closed.
6. `'1'` written to descriptor 3, which is then closed.
7. Real, effective and saved uid and gid set to `0`, supplementary groups dropped, then the action is
   executed as shown in the [README](README.md#wazuh-manager-service-control).

The `bin/.process_list` check matters because `wazuh-manager-control` sources that file
(`wazuh-manager-control enable debug` writes to it) and the helper runs `wazuh-manager-control` as
root.

## Data Flow

### Manager Restart Request Flow

```text
1. wazuh-manager-apid (PUT /cluster/restart → manager_restart())
   └─► connect queue/sockets/control.sock, send "restart"

2. wm_control (manager build)
   └─► SO_PEERCRED check
   └─► wm_control_dispatch("restart")
       └─► wm_control_execute_action("restart", "wazuh-manager")
           ├─► pipe() + fork()
           │   └─► child: execl("bin/wazuh-manager-service-control", "restart")
           │        ├─► checks pass → write '1' to fd 3
           │        └─► exec /usr/bin/systemctl restart wazuh-manager.service
           │            (or bin/wazuh-manager-control restart)
           └─► parent: '1' read within 5 s → "ok accepted"

3. wazuh-manager-apid
   └─► answer starts with "ok" → "Restart request sent"
```

### Remote Agent Restart/Reload Request Flow

```text
1. Server API → framework (restart_agents() / reload_agents())
   └─► create_restart_tasks() / create_reload_tasks(): ONE request per chunk of up to 500 agents
       ├─► POST /v1/tasks/bulk on queue/sockets/task-http.sock (HTTP over UDS)
       │       {"tasks": [{"agent_id": "001", "task_type": "agent_restart",
       │                   "create_time": 1234567890, "payload": {}}, ...]}
       └─► Receive: {"results": [{"agent_id": "001", "task_id": "...",
                                  "created": true}, ...]}

2. Task Manager
   └─► Stores every task in ONE database transaction, status pending

3. Agent (HTTPS polling)
   └─► POST /control to wazuh-manager-remoted
       └─► Task Manager hands out the pending tasks and marks them delivered

4. wazuh-agentd
   └─► bridge_on_task() → worker thread → restartAgent() / reloadAgent()
       ├─► Unix: send "restart" to CONTROL_SOCK → wm_control (agent build)
       │         └─► systemctl restart wazuh-agent  (or bin/wazuh-control restart)
       └─► Windows: control_dispatch("restart") → detached "wazuh-agent.exe service-restart"
                    (sleeps 1 s, stops and starts the service)

5. No result is reported back to the manager (fire-and-forget)
```

A pending task the agent never fetches expires after `task-manager.task_ttl`.

## Thread Model

Every module of modulesd runs in its own thread; `main.c` starts the `control` module **before**
waiting on the startup gate and before any other module, because agentd's reloads that resolve that
gate go through the control socket.

- **Manager**: `wm_control_main()` runs `process_control()` in the module thread. One connection at a
  time; a detached thread per accepted action reaps the helper.
- **Agent (Unix)**: `wm_control_main()` spawns `process_control()` as a separate thread
  (`w_create_thread()`) and returns. One connection at a time; the forked child is not waited for.
- **Agent (Windows)**: no dedicated thread; `control_dispatch()` runs on agentd's worker thread for the
  task.

## Error Handling

| Failure | Behaviour |
|---------|-----------|
| Bind | `Unable to bind to socket '<path>': ...` logged; the listener returns and the socket stays absent (API error `1901`) |
| `select()` | `At process_control(): select(): ...` and modulesd exits |
| `accept()` | logged (unless `EINTR`), next connection |
| Receive error, empty or oversized message | logged, no answer sent |
| Manager: helper refuses or times out | `Privileged service control rejected or could not execute '<action>'`; answer `err Service control rejected action` |
| Agent: fork | `Cannot fork for <action>`; answer `err Cannot fork` |
| Agent: `execvp()` in the child | `Error executing <action> command (<bin>): ...`; child exits `1` (the client already has `ok `) |
| Agent: unit not active for a systemd reload | `Service wazuh-agent is in state '<state>', systemctl cannot reload` or `... is not active after waiting 60 seconds`, then the `wazuh-control` fallback |

## Security Model

- **Socket**: mode `0660`, owned by the daemon user and the Wazuh group; local only.
- **Manager peer check**: only `root` and `wazuh-manager` may issue commands, whatever the socket
  permissions allow.
- **Privilege**: manager modulesd runs as `wazuh-manager` and cannot restart the service itself; the
  setuid helper is the single privileged step, accepts only the two fixed actions, never takes a path
  or command from its caller, and refuses to run from a tampered installation (step 4 above).
- **Fixed command set**: `restart` and `reload` only; no argument reaches a command line.

## Migration from wazuh-execd

**4.x**: manager and agent restart/reload were `wazuh-execd` commands on `/var/ossec/queue/sockets/com`
(`restart`, `reload`, alongside the configuration and file commands), and agents were restarted
through Active Response scripts (`restart.sh`, `restart-wazuh.exe`).

**5.x**:

| Function | Where it is now |
|----------|-----------------|
| Manager restart / reload | `wm_control` on `queue/sockets/control.sock`, executed by `wazuh-manager-service-control` |
| Agent restart / reload | `agent_restart` / `agent_reload` tasks → `wm_control` (`queue/sockets/control`) on Unix, `control_dispatch()` on Windows; no Active Response script |
| `getconfig`, `getallconfig`, `check-manager-configuration`, `unmerge`, `uncompress`, `lock_restart` | Unchanged on the **agent**: `wazuh-execd`'s `com` socket (`src/os_execd/src/wcom.c`). `lock_restart -1` is sent before a WPK upgrade, by `wazuh-agentd` on a 5.x agent and by `wazuh-manager-remoted`'s legacy push on an older one. `wazuh-execd` is not a manager daemon; the manager's daemons answer `getconfig` on their own sockets |
| Active Response | Agents only |

## See Also

- [Control Module README](README.md) - Protocol, responses, errors and the helper's usage
- [Task Manager](../task_manager/README.md) - Storage and delivery of `agent_restart` / `agent_reload` tasks
- [Modules index](../README.md) - wazuh-manager-modulesd / wazuh-modulesd (no dedicated page)

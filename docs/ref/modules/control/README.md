# Control Module (wm_control)

The **Control Module** provides control operations for both the Wazuh manager and agents, handling restart and reload requests through a Unix domain socket interface. It is implemented in a single source file (`wm_control.c`) that compiles differently depending on the build target:

- **Manager build** (`TARGET=manager`): `process_control()` runs directly in the main thread, binding to the manager control socket. Commands are dispatched to `wm_control_dispatch()` with `"wazuh-manager"` as the service name.
- **Agent build** (`CLIENT` defined, Unix): `process_control()` is spawned as a thread within `wazuh-modulesd`, binding to the agent control socket. Commands are dispatched to `wm_control_dispatch()` with `"wazuh-agent"` as the service name.

On **Windows agents**, the equivalent logic is implemented in `control_dispatch()` within `client-agent/src/control.c`. The Windows path is called directly in-process by `request.c` rather than via a separate socket listener.

## Key Features

- **Manager Restart/Reload**: Graceful manager restart or config reload via systemctl or wazuh-control
- **Remote Agent Restart/Reload**: Manager can send restart/reload commands to individual agents via the control channel
- **Systemd Integration**: Automatic detection and use of systemd when available
- **Socket-Based Control**: Unix domain socket for inter-process communication
- **Cross-Platform Agent Support**: Unix (`wm_control` with `CLIENT` defined) and Windows (`control_dispatch`) implementations
- **Strict Command Validation**: Unknown commands are rejected with an error response

## Overview

The control module serves as the control plane for operational commands. It:

1. **Manager**: Listens on `$WAZUH_HOME/queue/sockets/control` (default: `/var/wazuh-manager/queue/sockets/control`)
2. **Agent (Unix)**: Listens on `$WAZUH_HOME/queue/sockets/control` (default: `/var/ossec/queue/sockets/control`)
3. **Receives control commands** from the API, framework, or remoted
4. **Executes system operations** (restart/reload) via systemctl or wazuh-control
5. **Returns operation status** to the caller

Manager-side is enabled for manager builds (`TARGET=manager`) on Unix-like systems.
Agent-side (Unix) is the same `wm_control.c` compiled with `CLIENT` defined; Windows agents use `control_dispatch()` in `client-agent`.

## Socket Interface

**Socket Type**: Unix domain stream socket (`SOCK_STREAM`)
**Protocol**: Simple text-based command protocol

| Component | Socket Path |
|-----------|-------------|
| Manager | `$WAZUH_HOME/queue/sockets/control` (default: `/var/wazuh-manager/queue/sockets/control`) |
| Agent (Unix) | `$WAZUH_HOME/queue/sockets/control` (default: `/var/ossec/queue/sockets/control`) |

### Manager-Side Commands

| Command | Description | Response |
|---------|-------------|----------|
| `restart` | Restart the Wazuh manager | `ok ` (immediate) |
| `reload` | Reload manager configuration | `ok ` (immediate) |
| *(other)* | Any unrecognized command | `Err` |

### Agent-Side Commands (Unix: `wm_control_dispatch` / Windows: `control_dispatch`)

| Command | Description | Response |
|---------|-------------|----------|
| `restart` | Restart the Wazuh agent | `ok ` (immediate) |
| `reload` | Reload agent configuration | `ok ` (immediate) |
| *(other)* | Any unrecognized command | `Err` (Unix) / `err Unrecognized command` (Windows) |

## How It Works

### Manager Control

1. **Request Received**: Client (API/framework) sends command to the manager control socket
2. **Systemd Detection**: Module checks if systemd is available
3. **Command Selection**:
   - **With systemd**: `systemctl restart/reload wazuh-manager`
   - **Without systemd**: `bin/wazuh-control restart/reload`
4. **Fork and Execute**: Spawns child process to execute command
5. **Immediate Response**: Returns success immediately (non-blocking)

### Remote Agent Control (Task-Based - v5.0+)

**For agents running version 5.0.0 or higher**, restart and reload operations use the **Task Manager** instead of direct control messages:

1. **API Request**: Client calls `PUT /agents/{agent_id}/restart` or `PUT /agents/{agent_id}/reload`
2. **Framework**: Creates a task via Task Manager socket (`/queue/tasks/task`)
   - Task type: `agent_restart` or `agent_reload`
   - Payload: `{}`
   - Task stored in Task Manager database with status `pending`
3. **Agent Polling**: Agent polls Task Manager for pending tasks via HTTPS
4. **Task Retrieval**: Agent receives task from manager
5. **Agent Dispatch**: Agent's `request.c` forwards to control socket (Unix) or calls `control_dispatch()` (Windows)
6. **Execution**: The agent runs restart/reload via systemctl or wazuh-control
7. **Fire-and-Forget**: No status reported back to manager (task marked as `delivered` locally)

**Key Differences from Legacy Approach**:
- **Asynchronous**: API returns immediately after task creation
- **No status tracking**: Fire-and-forget model, no upgrade-style result queries
- **Batch operations**: Multiple agents can be restarted/reloaded efficiently
- **Version check**: API validates agent version ≥ 5.0.0 before creating tasks

**Framework Code**:
- Task creation: `framework/wazuh/core/agent_tasks.py::core_restart_agents()` / `core_reload_agents()`
- High-level API: `framework/wazuh/agent.py::restart_agents()` / `reload_agents()`

### Systemd Detection

The module detects systemd by checking:
- Existence of `/run/systemd/system` directory
- PID 1 process name is `systemd` (read from `/proc/1/comm`)

### Reload Safety

For reload operations with systemd, the module:
1. Waits for service to be in "active" state (up to 60 seconds)
2. Ensures service is not "inactive" or "failed"
3. Executes reload only when service is ready

## Integration Points

### API Usage

The Wazuh RESTful API uses the control channel for:
- `PUT /cluster/restart` — Manager restart
- `PUT /agents/restart` / `PUT /agents/{agent_id}/restart` — Agent restart (requires agent v5.0.0+)
- `PUT /agents/reload` / `PUT /agents/{agent_id}/reload` — Agent reload (requires agent v5.0.0+)
- `PUT /agents/group/{group_id}/reload` — Reload agents in a group

**Framework Code**:
- Manager: `framework/wazuh/core/cluster/utils.py::manager_restart()`
- Agents: `framework/wazuh/core/agent_tasks.py::core_restart_agents()` / `core_reload_agents()`

### Agent Version Requirement

Agent restart and reload via the API require the target agent to be running **version 5.0.0 or higher**. Agents on older versions will return error `1761`.

### Communication Examples

**Manager Control (Direct Socket)**:
```python
import socket

def send_control_command(command):
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect('/var/wazuh-manager/queue/sockets/control')
    sock.send(command.encode())
    response = sock.recv(1024).decode().strip()
    sock.close()
    return response

result = send_control_command('restart')  # Returns: "ok "
```

**Agent Control (Task Manager - v5.0+)**:
```python
from wazuh.core.agent_tasks import core_restart_agents
import time

# Create restart tasks for agents
agent_ids = ['001', '002', '003']
request_time = int(time.time())
result = core_restart_agents(agents_chunk=agent_ids, request_time=request_time)

# Result format: {"data": [{"agent": "001", "error": 0, "message": "..."}, ...]}
```

## Related Modules

- **wazuh-manager-modulesd / wazuh-modulesd**: Host daemon for `wm_control` (manager and agent Unix builds, respectively)
- **wazuh-manager-remoted**: Forwards control messages from manager to agents
- **wazuh-agentd**: Routes incoming `"control"` requests — forwards to control socket (Unix) or calls `control_dispatch()` directly (Windows)
- **wazuh-manager-apid**: Calls control socket/framework for restart and reload API endpoints

## Architecture Changes

**Previous Architecture (v4.x)**:
- Control functionality in `wazuh-execd` daemon
- Socket: `/var/ossec/queue/sockets/com`
- Agent restart/reload triggered via Active Response scripts (`restart.sh`, `restart-wazuh.exe`)

**Current Architecture (v5.0)**:
- Manager control in `wm_control` (within modulesd); socket: `$WAZUH_HOME/queue/sockets/control`
- Agent control (Unix): same `wm_control.c` compiled with `CLIENT`, running as a thread in `wazuh-modulesd`; socket: `$WAZUH_HOME/queue/sockets/control`
- Agent control (Windows): `control_dispatch()` in `client-agent`, called in-process by `request.c`
- Agent restart/reload via direct control channel — no Active Response scripts required
- `wcom_restart()` and `wcom_reload()` removed from `wazuh-execd`

## Security Considerations

- **Socket Permissions**: The control socket is created with `0660` permissions
- **Group Access**: Socket owned by wazuh group for API/framework access
- **No Authentication**: Local Unix socket provides implicit authentication via filesystem permissions
- **Immediate Response**: Operations return immediately before completion to prevent timeout issues

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture](architecture.md) | Technical architecture and implementation details |

## See Also

- [Manager Installation](../../getting-started/installation.md) - Manager installation and systemctl usage
- [Server API Reference](../server-api/api-reference.md) - API endpoints that use the control channel
- [RBAC](../rbac/index.html) - `agent:reload` and `agent:restart` RBAC actions

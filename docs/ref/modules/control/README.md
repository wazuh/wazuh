# Control Module (wm_control / wm_agent_control)

The **Control Module** provides control operations for both the Wazuh manager and agents, handling restart and reload requests through a Unix domain socket interface. It consists of two complementary components:

- **`wm_control`** — runs within `wazuh-modulesd` on the **manager**, handling manager-level restart/reload.
- **`wm_agent_control`** — runs within `wazuh-modulesd` on **agents** (Unix-like systems), handling agent-level restart/reload commands received from the manager via the remoted socket.

On **Windows agents**, the equivalent logic is implemented in `control_dispatch()` within `client-agent`.

## Key Features

- **Manager Restart/Reload**: Graceful manager restart or config reload via systemctl or wazuh-control
- **Remote Agent Restart/Reload**: Manager can send restart/reload commands to individual agents via the control channel
- **Systemd Integration**: Automatic detection and use of systemd when available
- **Socket-Based Control**: Unix domain socket for inter-process communication
- **Cross-Platform Agent Support**: Unix (`wm_agent_control`) and Windows (`control_dispatch`) implementations
- **Strict Command Validation**: Unknown commands are rejected with `Err`

## Overview

The control module serves as the control plane for operational commands. It:

1. **Manager**: Listens on `/var/wazuh-manager/queue/sockets/control`
2. **Agent**: Listens on `/var/ossec/queue/sockets/control`
3. **Receives control commands** from the API, framework, or remoted
4. **Executes system operations** (restart/reload) via systemctl or wazuh-control
5. **Returns operation status** to the caller

Manager-side (`wm_control`) is enabled for manager builds (`TARGET=manager`) on Unix-like systems.
Agent-side (`wm_agent_control`) is enabled for agent builds on Unix-like systems; Windows agents use `control_dispatch()`.

## Socket Interface

**Socket Type**: Unix domain stream socket (`SOCK_STREAM`)
**Protocol**: Simple text-based command protocol

| Component | Socket Path |
|-----------|-------------|
| Manager (`wm_control`) | `/var/wazuh-manager/queue/sockets/control` |
| Agent Unix (`wm_agent_control`) | `/var/ossec/queue/sockets/control` |

### Manager-Side Commands (`wm_control`)

| Command | Description | Response |
|---------|-------------|----------|
| `restart` | Restart the Wazuh manager | `ok ` (immediate) |
| `reload` | Reload manager configuration | `ok ` (immediate) |
| *(other)* | Any unrecognized command | `Err` |

### Agent-Side Commands (`wm_agent_control` / `control_dispatch`)

| Command | Description | Response |
|---------|-------------|----------|
| `restart` | Restart the Wazuh agent | `ok ` (immediate) |
| `reload` | Reload agent configuration | `ok ` (immediate) |
| *(other)* | Any unrecognized command | `Err` |

## How It Works

### Manager Control (wm_control)

1. **Request Received**: Client (API/framework) sends command to the manager control socket
2. **Systemd Detection**: Module checks if systemd is available
3. **Command Selection**:
   - **With systemd**: `systemctl restart/reload wazuh-manager`
   - **Without systemd**: `bin/wazuh-control restart/reload`
4. **Fork and Execute**: Spawns child process to execute command
5. **Immediate Response**: Returns success immediately (non-blocking)

### Remote Agent Control (wm_agent_control)

1. **API Request**: Client calls `PUT /agents/{agent_id}/restart` or reload equivalent
2. **Framework**: Sends `"{agent_id} control restart"` or `"{agent_id} control reload"` to the remoted socket
3. **Remoted**: Forwards the control message to the target agent
4. **Agent Dispatch**: The agent's request handler routes the `control` socket message to `wm_agentcontrol_dispatch()`
5. **Execution**: The agent runs restart/reload via systemctl or wazuh-control (Unix) or service API (Windows)

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
- `PUT /manager/restart` — Manager restart
- `PUT /agents/restart` / `PUT /agents/{agent_id}/restart` — Agent restart (requires agent v5.0.0+)
- `PUT /agents/reload` / `PUT /agents/{agent_id}/reload` — Agent reload (requires agent v5.0.0+)
- `PUT /agents/group/{group_id}/reload` — Reload agents in a group
- `PUT /agents/node/{node_id}/reload` — Reload agents on a cluster node

**Framework Code**:
- Manager: `framework/wazuh/core/cluster/utils.py::manager_restart()`
- Agents: `framework/wazuh/core/agent.py::send_restart_command()` / `send_reload_command()`

### Agent Version Requirement

Agent restart and reload via the API require the target agent to be running **version 5.0.0 or higher**. Agents on older versions will return error `1761`.

### Socket Communication Example

```python
# Manager-side: send control command directly
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

```python
# Agent-side: framework sends via remoted socket
# Format: "{agent_id} control {command}"
# e.g.: "002 control restart"
```

## Related Modules

- **wazuh-modulesd**: Host daemon for wm_control and wm_agent_control
- **wazuh-remoted**: Forwards control messages from manager to agents
- **wazuh-agentd**: Routes incoming control socket messages to wm_agentcontrol_dispatch()
- **wazuh-apid**: Calls control socket/framework for restart and reload API endpoints

## Architecture Changes

**Previous Architecture (v4.x)**:
- Control functionality in `wazuh-execd` daemon
- Socket: `/var/ossec/queue/sockets/com`
- Agent restart/reload triggered via Active Response scripts (`restart.sh`, `restart-wazuh.exe`)

**Current Architecture (v5.0)**:
- Manager control in `wm_control` module (within modulesd); socket: `/var/wazuh-manager/queue/sockets/control`
- Agent control in `wm_agent_control` module (Unix) and `control_dispatch()` (Windows); socket: `/var/ossec/queue/sockets/control`
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
- [RBAC](../rbac/README.md) - `agent:reload` and `agent:restart` RBAC actions

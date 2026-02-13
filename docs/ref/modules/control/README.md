# Control Module (wm_control)

The **Control Module** (`wm_control`) provides manager control operations for the Wazuh server, handling restart and reload requests through a Unix domain socket interface. This module runs within `wazuh-modulesd` and replaces the control functionality previously handled by `wazuh-execd`.

## Key Features

- **Manager Restart**: Graceful manager restart via systemctl or wazuh-control
- **Manager Reload**: Configuration reload without full restart
- **Primary IP Detection**: Retrieves the manager's primary network interface IP
- **Systemd Integration**: Automatic detection and use of systemd when available
- **Socket-Based Control**: Unix domain socket for inter-process communication

## Overview

The control module serves as the manager's control plane for operational commands. It:

1. **Listens on control socket** (`/var/ossec/queue/sockets/control`)
2. **Receives control commands** from API, framework, or other components
3. **Executes system operations** (restart/reload) via systemctl or wazuh-control
4. **Returns operation status** to the caller

## Socket Interface

**Socket Path**: `/var/ossec/queue/sockets/control`
**Socket Type**: Unix domain stream socket (SOCK_STREAM)
**Protocol**: Simple text-based command protocol

### Supported Commands

| Command | Description | Response |
|---------|-------------|----------|
| `restart` | Restart the Wazuh manager | `ok ` (immediate) |
| `reload` | Reload manager configuration | `ok ` (immediate) |
| `getip` | Get primary network interface IP | IP address string |
| *(other)* | Any unrecognized command | IP address (backward compatibility) |

## How It Works

### Restart/Reload Process

1. **Request Received**: Client sends command to control socket
2. **Systemd Detection**: Module checks if systemd is available
3. **Command Selection**:
   - **With systemd**: `systemctl restart/reload wazuh-manager`
   - **Without systemd**: `/var/ossec/bin/wazuh-control restart/reload`
4. **Fork and Execute**: Spawns child process to execute command
5. **Immediate Response**: Returns success immediately (non-blocking)

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

The Wazuh RESTful API uses the control socket for:
- `PUT /manager/restart` - Manager restart endpoint
- Cluster restart coordination

**Framework Code**: `framework/wazuh/core/cluster/utils.py::manager_restart()`

### Socket Communication Example

```python
import socket

def send_control_command(command):
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect('/var/ossec/queue/sockets/control')
    sock.send(command.encode())
    response = sock.recv(1024).decode().strip()
    sock.close()
    return response

# Restart manager
result = send_control_command('restart')  # Returns: "ok "
```

## Related Modules

- **wazuh-modulesd**: Host daemon for control module
- **wazuh-apid**: Calls control socket for manager restart API
- **Framework**: Python framework uses control socket for restart operations

## Architecture Changes

**Previous Architecture (v4.x)**:
- Control functionality in `wazuh-execd` daemon
- Socket: `/var/ossec/queue/sockets/com`
- Multiple commands: restart, reload, getconfig, unmerge, uncompress, etc.

**Current Architecture (v5.0)**:
- Control functionality in `wm_control` module (within modulesd)
- Socket: `/var/ossec/queue/sockets/control`
- Focused commands: restart, reload, getip
- Configuration reading now done directly from file (no socket needed)

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
- [API Documentation](../../../api/) - API endpoints that use control socket

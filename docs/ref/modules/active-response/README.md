# Active Response

The **Active Response** module enables automated response actions triggered by security events detected by the Wazuh manager. When specific rules are triggered, the manager can execute scripts on agents to block IPs, disable accounts, or perform other security-relevant actions.

Active Response is implemented through `wazuh-execd`, which receives commands from the manager, executes response scripts on the agent, and manages response lifecycle including timeouts for stateful responses.

## Key Features

- **IP Blocking**: Block malicious IPs using various firewall mechanisms (iptables, firewalld, pf, ipfw, npf, netsh, etc.)
- **Account Management**: Disable user accounts in response to suspicious activity
- **Stateful/Stateless Responses**: Support for temporary (stateful) or permanent (stateless) actions
- **Multi-Platform**: Cross-platform support for Linux, macOS, and Windows
- **Deduplication**: Prevents duplicate executions of the same response
- **Timeout Management**: Automatic reversion of stateful responses after configured duration
- **Metadata-Driven**: Uses WCS-compatible metadata format (no `ar.conf` dependency)

## Overview

Active Response operates in a manager-agent communication model:

1. **Event Detection**: Manager's analysis engine detects events matching specific rules
2. **Command Generation**: Manager generates an Active Response command with WCS metadata
3. **Agent Execution**: Agent's `wazuh-execd` receives the command and executes the appropriate script
4. **Lifecycle Management**: For stateful responses, execd manages timeouts and automatic reversion

```
┌─────────────┐         ┌──────────────┐         ┌─────────────┐
│   Manager   │ ──────> │ wazuh-execd  │ ──────> │  AR Script  │
│  (Analysis) │  JSON   │   (Agent)    │  stdin  │ (block-ip)  │
└─────────────┘         └──────────────┘         └─────────────┘
                               │                         │
                               │ Timeout Management      │ Firewall
                               └─────────────────────────┘
```

## Command Protocol

Active Response uses a JSON-based protocol with **enable/disable** commands:

### Enable Command

Activates a response action (e.g., block an IP):

```json
{
  "wazuh": {
    "active_response": {
      "name": "block-ip",
      "executable": "block-ip",
      "location": "defined-agent",
      "agent_id": "001",
      "type": "stateless"
    },
    "agent": {
      "id": "001",
      "name": "test-agent"
    }
  },
  "source": {
    "ip": "192.168.1.100"
  },
  "user": {
    "name": "username"
  },
  "command": "enable"
}
```

### Disable Command

Reverts a response action (e.g., unblock an IP):

```json
{
  "wazuh": {
    "active_response": {
      "name": "block-ip",
      "executable": "block-ip",
      "location": "defined-agent",
      "agent_id": "001",
      "type": "stateful",
      "stateful_timeout": 600
    },
    "agent": {
      "id": "001",
      "name": "test-agent"
    }
  },
  "source": {
    "ip": "192.168.1.100"
  },
  "user": {
    "name": "username"
  },
  "command": "disable"
}
```

## Response Types

### Stateful Responses

Stateful responses are **temporary** actions that automatically revert after a configured timeout:

- **Enable**: Blocks the IP/disables the account
- **Disable**: Automatically sent by execd after timeout expires
- **Use Cases**: Temporary IP blocks, temporary account lockouts

Example: Block IP for 600 seconds, then automatically unblock.

### Stateless Responses

Stateless responses are **permanent** actions that do not automatically revert:

- **Enable**: Applies the action
- **No Disable**: No automatic reversion
- **Use Cases**: Permanent bans, notification systems

Example: Add IP to permanent blocklist.

## Available Executables

Active Response provides the following executables:

### IP Blocking (Cross-Platform)

- **block-ip** (Unix/Linux): Blocks IPs using iptables, firewalld, pf, ipfw, npf, route, or hosts.deny
- **block-ip** (macOS): Blocks IPs using pf or hosts.deny
- **block-ip** (Windows): Blocks IPs using netsh or route

### Account Management

- **disable-account** (Unix/Linux): Disables user accounts using `passwd -l`

### Platform-Specific Details

See [Executables Reference](executables.md) for detailed information about each executable, including:
- Supported platforms
- Firewall methods and fallback order
- Input/output formats
- Platform-specific behaviors

## WCS Metadata Format

Active Response uses a **metadata-driven approach** where all execution metadata is embedded in the JSON command:

```json
{
  "wazuh": {
    "active_response": {
      "name": "block-ip",
      "executable": "block-ip",
      "type": "stateful",
      "stateful_timeout": 600
    }
  },
  "source": {
    "ip": "192.168.1.100"
  },
  "command": "enable"
}
```

**Benefits**:
- **No ar.conf needed**: Executable name, type, and timeout are embedded in the `wazuh.active_response` object
- **WCS Compatibility**: Field names aligned with Wazuh Cloud Standards
- **Simplified Configuration**: Reduces agent-side configuration complexity
- **Centralized Metadata**: All execution parameters controlled by manager

## Deduplication Mechanism

Active Response includes a deduplication system to prevent redundant executions:

1. **Keys Generation**: Extracts unique identifiers (e.g., source IP, username) from the alert
2. **Keys Verification**: Sends keys to execd for duplicate checking
3. **Response Check**: Execd responds with:
   - `continue`: Proceed with execution (no duplicate found)
   - `abort`: Skip execution (duplicate already active)

This prevents multiple concurrent blocks of the same IP or account.

## Integration Points

### Configuration

Active Response is configured from the Wazuh dashboard.

### Agent Execution

The agent's `wazuh-execd` daemon:
1. Listens for commands from the manager
2. Validates the JSON structure and command
3. Executes the appropriate script with JSON input via stdin
4. Manages timeout-based reversions for stateful responses

### Separation from Control Operations

**Important**: Agent restart and reload operations are **not** part of Active Response. These control operations are handled by the [Control Module (wm_control)](../control/README.md), which provides a dedicated control channel for operational commands.

**Architecture**:
- **Active Response (execd)**: Security response actions (block IP with enable/disable commands, disable account)
- **Control Module (wm_control)**: Operational control commands (restart, reload)
- Clear separation between security responses and operational control

## Security Considerations

- **Privilege Requirements**: Most Active Response scripts require elevated privileges (root/Administrator)
- **Input Validation**: All scripts validate JSON input structure before execution
- **Command Whitelisting**: Only `enable` and `disable` commands are accepted
- **Firewall Safety**: IP blocking scripts use safe methods and validate IP addresses
- **Logging**: All operations logged to `/var/ossec/logs/active-responses.log`

## Logging

Active Response operations are logged to:
- **Linux/macOS**: `/var/ossec/logs/active-responses.log`
- **Windows**: `C:\Program Files (x86)\ossec-agent\active-response\active-responses.log`

Log format:
```
2026-03-31 15:30:45 block-ip: Starting
2026-03-31 15:30:45 block-ip: {"wazuh":{"active_response":{...}},"source":{...},"command":"enable"}
2026-03-31 15:30:46 block-ip: INFO - firewalld - success - IP 192.168.1.100 blocked successfully
2026-03-31 15:30:46 block-ip: Ended
```

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture](architecture.md) | Technical architecture, implementation details, and protocol specifications |
| [Executables Reference](executables.md) | Complete inventory of Active Response executables with platform details |

## See Also

- [Control Module](../control/README.md) - Agent restart/reload operations
- [Remoted](../remoted/README.md) - Manager-agent communication layer
- [Server API Reference](../server-api/api-reference.md) - API endpoints for triggering responses

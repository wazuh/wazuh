# Active Response Executables Reference

This document provides a complete inventory of all Active Response executables available in Wazuh 5.0, including their purpose, supported platforms, input requirements, and implementation details.

## Overview

Wazuh provides **5 Active Response executables** covering IP blocking and account management across multiple platforms. Each executable is compiled from platform-specific C source code optimized for the target operating system.

## Executable Inventory

### 1. block-ip (Unix/Linux)

**Source**: `src/active-response/src/block-ip-unix.c`

**Purpose**: Blocks or unblocks IP addresses using various firewall mechanisms on Unix and Linux systems.

**Supported Platforms**:
- Amazon Linux
- Ubuntu
- RedHat
- CentOS
- CentOS Stream
- Debian
- Fedora
- openSUSE Leap
- SLES
- Oracle Linux
- AlmaLinux
- Rocky Linux

**Type**: Stateful (supports timeout-based reversion)

**Firewall Methods** (tried in order):

| Priority | Method | Tool | Command Example |
|----------|--------|------|-----------------|
| 1 | firewalld | `firewall-cmd` | `firewall-cmd --add-rich-rule='rule family="ipv4" source address="192.168.1.100" reject'` |
| 2 | iptables | `iptables` / `ip6tables` | `iptables -I INPUT -s 192.168.1.100 -j DROP` |
| 3 | pf | `pfctl` | `pfctl -t wazuh_fwtable -T add 192.168.1.100` |
| 4 | ipfw | `ipfw` | `ipfw table 00001 add 192.168.1.100` |
| 5 | npf | `npfctl` | `npfctl table wazuh_blacklist add 192.168.1.100` |
| 6 | route | `route` | `route add 192.168.1.100 reject` |
| 7 | hosts.deny | edit file | `ALL: 192.168.1.100` (appended to `/etc/hosts.deny`) |

**Input Fields**:
```json
{
  "wazuh": {
    "active_response": {
      "name": "block-ip",
      "executable": "block-ip",
      "type": "stateless"
    }
  },
  "source": {
    "ip": "192.168.1.100"
  },
  "command": "enable" | "disable"
}
```

**Platform-Specific Behavior**:
- **Linux**: Prefers firewalld or iptables, falls back to route/hosts.deny

**Return Codes**:
- `0`: Success (IP blocked/unblocked)
- `1`: Failure (invalid input or all methods failed)

**Logging**: All operations logged to `/var/ossec/logs/active-responses.log`

---

### 2. block-ip (macOS)

**Source**: `src/active-response/src/block-ip-macos.c`

**Purpose**: Blocks or unblocks IP addresses using macOS-specific firewall mechanisms.

**Supported Platforms**:
- macOS 10.10+

**Type**: Stateful (supports timeout-based reversion)

**Firewall Methods** (tried in order):

| Priority | Method | Tool | Command Example |
|----------|--------|------|-----------------|
| 1 | pf | `pfctl` | `pfctl -t wazuh_fwtable -T add 192.168.1.100` |
| 2 | hosts.deny | edit file | `ALL: 192.168.1.100` (appended to `/etc/hosts.deny`) |

**Input Fields**:
```json
{
  "wazuh": {
    "active_response": {
      "name": "block-ip",
      "executable": "block-ip",
      "type": "stateless"
    }
  },
  "source": {
    "ip": "192.168.1.100"
  },
  "command": "enable" | "disable"
}
```

**macOS-Specific Details**:
- **PF Table**: Uses table name `wazuh_fwtable`
- **Connection Killing**: When blocking, also kills existing connections: `pfctl -k 192.168.1.100`
- **Anchor Configuration**: Requires PF anchor `wazuh_anchor` to be configured in `/etc/pf.conf`
- **Permissions**: Requires root privileges

**Example pf.conf setup**:
```
# /etc/pf.conf
anchor "wazuh_anchor"
load anchor "wazuh_anchor" from "/etc/pf.anchors/wazuh_anchor"
```

**Example anchor file**:
```
# /etc/pf.anchors/wazuh_anchor
table <wazuh_fwtable> persist
block in quick from <wazuh_fwtable>
```

**Return Codes**:
- `0`: Success (IP blocked/unblocked)
- `1`: Failure (invalid input or all methods failed)

**Logging**: All operations logged to `/var/ossec/logs/active-responses.log`

---

### 3. block-ip (Windows)

**Source**: `src/active-response/src/block-ip-windows.c`

**Purpose**: Blocks or unblocks IP addresses using Windows firewall mechanisms.

**Supported Platforms**:
- Windows 7+
- Windows Server 2008 R2+

**Type**: Stateful (supports timeout-based reversion)

**Firewall Methods** (tried in order):

| Priority | Method | Tool | Command Example |
|----------|--------|------|-----------------|
| 1 | netsh | `netsh.exe` | `netsh advfirewall firewall add rule name="Wazuh AR: 192.168.1.100" dir=in action=block remoteip=192.168.1.100` |
| 2 | route | `route.exe` | `route add 192.168.1.100 mask 255.255.255.255 <gateway> metric 1` |

**Input Fields**:
```json
{
  "wazuh": {
    "active_response": {
      "name": "block-ip",
      "executable": "block-ip",
      "type": "stateless"
    }
  },
  "source": {
    "ip": "192.168.1.100"
  },
  "command": "enable" | "disable"
}
```

**Windows-Specific Details**:
- **Firewall Rules**: Creates named rules: `"Wazuh AR: <IP>"`
- **Rule Direction**: Inbound blocking only (`dir=in`)
- **Route Fallback**: Adds blackhole route if netsh fails
- **Gateway Detection**: Uses `ipconfig` to find default gateway for route method
- **IPv6 Support**: Automatically detects IPv6 addresses and uses appropriate commands
- **Permissions**: Requires Administrator privileges

**Removal**:
- Enable: `netsh advfirewall firewall delete rule name="Wazuh AR: 192.168.1.100"`
- Route: `route delete 192.168.1.100`

**Return Codes**:
- `0`: Success (IP blocked/unblocked)
- `1`: Failure (invalid input or all methods failed)

**Logging**: All operations logged to `C:\Program Files (x86)\ossec-agent\active-response\active-responses.log`

---

### 4. disable-account (Unix/Linux)

**Source**: `src/active-response/src/disable-account.c`

**Purpose**: Disables or re-enables user accounts on Unix/Linux systems.

**Supported Platforms**:
- Amazon Linux
- Ubuntu
- RedHat
- CentOS
- CentOS Stream
- Debian
- Fedora
- openSUSE Leap
- SLES
- Oracle Linux
- AlmaLinux
- Rocky Linux

**Type**: Stateful (supports timeout-based reversion)

**Implementation**:

| Platform | Enable (Disable Account) | Disable (Re-enable Account) |
|----------|--------------------------|---------------------------|
| Linux | `passwd -l <username>` | `passwd -u <username>` |

**Input Fields**:
```json
{
  "wazuh": {
    "active_response": {
      "name": "disable-account",
      "executable": "disable-account",
      "type": "stateless"
    }
  },
  "user": {
    "name": "suspicious_user"
  },
  "command": "enable" | "disable"
}
```

**Behavior**:
- **Enable Command**: Locks/disables the user account
- **Disable Command**: Unlocks/re-enables the user account
- **Deduplication**: Uses username as key to prevent duplicate locks
- **Safety**: Validates username exists before attempting to lock/unlock

**Limitations**:
- **Existing Sessions**: Does not terminate existing user sessions
- **Root Account**: Should not be used on root/administrator accounts
- **System Accounts**: May fail on system accounts with special configurations

**Return Codes**:
- `0`: Success (account disabled/re-enabled)
- `1`: Failure (invalid input, command not found, or operation failed)

**Logging**: All operations logged to `/var/ossec/logs/active-responses.log`

---

## Agent Restart and Reload

Agent restart and reload operations are **not** implemented as Active Response executables. These control operations are handled by the [Control Module (wm_control)](../control/README.md).

**Control Operations**:
- Agent restart via `PUT /agents/{agent_id}/restart` API endpoint
- Agent reload via `PUT /agents/{agent_id}/reload` API endpoint
- Handled through dedicated control channel, not Active Response

**See**: [Control Module Documentation](../control/README.md) for details on agent control operations.

---

## Common Features

All Active Response executables share the following characteristics:

### JSON Input

All executables read JSON from **stdin** with this structure:

```json
{
  "wazuh": {
    "active_response": {
      "name": "string",
      "executable": "string",
      "type": "stateless" | "stateful",
      "stateful_timeout": integer
    },
    "agent": {
      "id": "string",
      "name": "string"
    }
  },
  "source": {
    "ip": "string",
    "port": integer,
    "address": "string"
  },
  "user": {
    "name": "string"
  },
  "command": "enable" | "disable"
}
```

### Deduplication

All executables implement key-based deduplication:

1. Extract unique keys (IP address, username, etc.)
2. Send keys to execd via stdout:
   ```json
   {
     "command": "check_keys",
     "parameters": {
       "keys": ["192.168.1.100"]
     }
   }
   ```
3. Wait for execd response:
   - `{"command": "continue"}` → Proceed with execution
   - `{"command": "abort"}` → Exit without action (duplicate)

### Logging

All executables log to `active-responses.log` with this format:

```
<timestamp> <executable>: <level> - <method> - <status> - <message>
```

Examples:
```
2026-03-31 15:30:45 block-ip: INFO - iptables - success - IP 192.168.1.100 blocked successfully
2026-03-31 15:35:50 block-ip: INFO - iptables - success - IP 192.168.1.100 unblocked successfully
2026-03-31 15:40:12 disable-account: INFO - usermod - success - Account 'baduser' disabled successfully
```

### Error Handling

All executables implement graceful error handling:
- **Invalid JSON**: Log error, exit with code 1
- **Missing Fields**: Log error, exit with code 1
- **Command Failure**: Try next method (for block-ip), or exit with code 1
- **All Methods Failed**: Log all attempts, exit with code 1

### Platform Detection

All executables automatically detect:
- **IP Version**: IPv4 vs IPv6 (for block-ip)
- **Available Tools**: Check which firewall tools are installed
- **Operating System**: Adjust commands based on platform

---

## Custom Active Response Scripts

Users can create custom Active Response scripts following these guidelines:

### Requirements

1. **Executable**: Script must have execute permissions
2. **Location**: Place in `/var/ossec/active-response/bin/`
3. **JSON Input**: Read JSON from stdin
4. **Commands**: Support both `add` and `delete` commands
5. **Exit Codes**: Return 0 on success, 1 on failure
6. **Logging**: Write to `/var/ossec/logs/active-responses.log`

### Example: Custom Email Alert Script

```bash
#!/bin/bash
# custom-email-alert.sh

INPUT=$(</dev/stdin)
COMMAND=$(echo "$INPUT" | jq -r '.command')
SRCIP=$(echo "$INPUT" | jq -r '.parameters.alert.source.ip')

LOG_FILE="/var/ossec/logs/active-responses.log"
echo "$(date) custom-email-alert: Received command: $COMMAND for IP: $SRCIP" >> "$LOG_FILE"

if [ "$COMMAND" = "enable" ]; then
    echo "Alert: Suspicious activity from $SRCIP" | mail -s "Wazuh Alert" admin@example.com
    echo "$(date) custom-email-alert: Email sent for IP: $SRCIP" >> "$LOG_FILE"
fi

exit 0
```

### Best Practices

- **Validate Input**: Check JSON structure and required fields
- **Implement Deduplication**: For stateful scripts, use the keys protocol
- **Log Everything**: Detailed logging aids troubleshooting
- **Test Thoroughly**: Test both enable and disable commands
- **Handle Errors**: Gracefully handle missing tools or failed commands
- **Use Absolute Paths**: Don't rely on PATH environment variable
- **Check Privileges**: Verify script has necessary permissions
- **Document**: Include comments explaining behavior

---

## Testing Active Response Scripts

### Manual Testing

Test AR scripts directly:

```bash
# Test enable command
echo '{"wazuh":{"active_response":{"name":"block-ip","executable":"block-ip","type":"stateless"}},"source":{"ip":"192.168.1.100"},"command":"enable"}' | \
  /var/ossec/active-response/bin/block-ip

# Test disable command
echo '{"wazuh":{"active_response":{"name":"block-ip","executable":"block-ip","type":"stateless"}},"source":{"ip":"192.168.1.100"},"command":"disable"}' | \
  /var/ossec/active-response/bin/block-ip
```

### Verify Firewall Changes

**Linux (iptables)**:
```bash
iptables -L INPUT -n | grep 192.168.1.100
```

**Linux (firewalld)**:
```bash
firewall-cmd --list-rich-rules | grep 192.168.1.100
```

**macOS (pf)**:
```bash
pfctl -t wazuh_fwtable -T show
```

**Windows (netsh)**:
```powershell
netsh advfirewall firewall show rule name="Wazuh AR: 192.168.1.100"
```

### Check Logs

```bash
tail -f /var/ossec/logs/active-responses.log
```

---

## Performance Considerations

### Execution Time

| Executable | Platform | Typical Execution Time |
|------------|----------|------------------------|
| block-ip | Linux (iptables) | ~50ms |
| block-ip | Linux (firewalld) | ~200ms |
| block-ip | macOS (pf) | ~100ms |
| block-ip | Windows (netsh) | ~150ms |
| disable-account | Unix/Linux | ~100ms |

### Resource Usage

- **CPU**: Minimal (< 1% per execution)
- **Memory**: ~2-5 MB per process
- **Disk I/O**: Minimal (log writes only, except hosts.deny method)

### Scalability

- **Concurrent Executions**: Limited by execd (single-threaded)
- **Maximum AR Table Size**: 256 entries (configurable)
- **Firewall Rule Limits**: Depends on platform:
  - iptables: ~10,000 rules before performance degradation
  - pf: ~100,000 table entries
  - netsh: ~1,000 rules before performance degradation

---

## See Also

- [Active Response README](README.md) - Module overview and features
- [Architecture](architecture.md) - Technical implementation details
- [Control Module](../control/README.md) - Agent restart/reload (separated in v5.0)

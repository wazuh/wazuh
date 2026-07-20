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

1. **Executable**: Script must have execute permissions (chmod 750)
2. **Location**: Place in `/var/ossec/active-response/bin/` (without file extension)
3. **Ownership**: Set owner to `root:wazuh`
4. **Shebang**: Include proper shebang line (e.g., `#!/bin/bash` or `#!/usr/bin/python3`)
5. **JSON Input**: Read JSON from stdin using `read -r` (bash) or `sys.stdin` (Python)
6. **Commands**: Support both `enable` and `disable` commands
7. **Exit Codes**: Return 0 on success, 1 on failure
8. **Logging**: Write to `/var/ossec/logs/active-responses.log`

### Example 1: Stateful Bash Script (FIM Response)

This example demonstrates a complete stateful Active Response script for FIM events:

```bash
#!/bin/bash
# Custom Active Response for FIM events
# Save as: /var/ossec/active-response/bin/custom-fim-response

# Log file path
LOG_FILE="/var/ossec/logs/active-responses.log"

# Function to write log messages
log_message() {
    local timestamp=$(date '+%Y/%m/%d %H:%M:%S')
    echo "$timestamp $(basename $0): $1" >> "$LOG_FILE"
}

# Function to send keys for stateful deduplication
send_keys() {
    local keys=$1
    local script_name=$(basename "$0")

    # Build keys message
    local keys_msg="{\"version\":1,\"origin\":{\"name\":\"$script_name\",\"module\":\"active-response\"},\"command\":\"check_keys\",\"parameters\":{\"keys\":[$keys]}}"

    log_message "Sending keys: $keys_msg"
    echo "$keys_msg"

    # Read response from execd
    read -r response
    log_message "Received response: $response"

    # Check if we should continue or abort
    local cmd=$(echo "$response" | jq -r '.command // empty')
    if [ "$cmd" = "abort" ]; then
        log_message "Duplicate detected, aborting execution"
        exit 0
    elif [ "$cmd" = "continue" ]; then
        log_message "Continuing execution"
        return 0
    else
        log_message "Invalid response from execd: $response"
        exit 1
    fi
}

log_message "Starting script"

# CRITICAL: Use 'read -r' to read ONE line, NOT '$(</dev/stdin)'
# Using $(</dev/stdin) causes deadlock with execd
read -r INPUT
log_message "Received input (${#INPUT} bytes)"

# Parse JSON fields
COMMAND=$(echo "$INPUT" | jq -r '.command // empty')
AR_TYPE=$(echo "$INPUT" | jq -r '.wazuh.active_response.type // empty')
FILE_PATH=$(echo "$INPUT" | jq -r '.file.path // empty')

log_message "Command: $COMMAND, Type: $AR_TYPE, File: $FILE_PATH"

# Validate command
if [ -z "$COMMAND" ]; then
    log_message "ERROR: No command found in input"
    exit 1
fi

case "$COMMAND" in
    enable)
        log_message "Executing enable command"

        # For stateful responses, implement keys protocol
        if [ "$AR_TYPE" = "stateful" ]; then
            KEYS="\"$FILE_PATH\""
            send_keys "$KEYS"
        fi

        # Execute your custom action here
        log_message "ACTION: Processing file $FILE_PATH"
        # Example: Quarantine file, send alert, create backup, etc.

        log_message "Enable command completed successfully"
        ;;

    disable)
        log_message "Executing disable command"

        # Revert the action
        log_message "ACTION: Reverting action for file $FILE_PATH"
        # Example: Remove backup, restore file, etc.

        log_message "Disable command completed successfully"
        ;;

    *)
        log_message "ERROR: Invalid command '$COMMAND'"
        exit 1
        ;;
esac

log_message "Script finished successfully"
exit 0
```

### Example 2: Python Script

This example uses a custom Python script:

```python
#!/usr/bin/python3
# Save as: /var/ossec/active-response/bin/custom-ar

import os
import sys
import json
import datetime
from pathlib import PureWindowsPath, PurePosixPath
import platform

if os.name == 'nt':
    LOG_FILE = "C:\\Program Files (x86)\\ossec-agent\\active-response\\active-responses.log"
elif platform.system() == 'Darwin':
    LOG_FILE = "/Library/Ossec/logs/active-responses.log"
else:
    LOG_FILE = "/var/ossec/logs/active-responses.log"

ENABLE_COMMAND = 0
DISABLE_COMMAND = 1
CONTINUE_COMMAND = 2
ABORT_COMMAND = 3

OS_SUCCESS = 0
OS_INVALID = -1

class message:
    def __init__(self):
        self.alert = ""
        self.command = 0


def write_debug_file(ar_name, msg):
    with open(LOG_FILE, mode="a") as log_file:
        ar_name_posix = str(PurePosixPath(PureWindowsPath(ar_name[ar_name.find("active-response"):])))
        log_file.write(str(datetime.datetime.now().strftime('%Y/%m/%d %H:%M:%S')) + " " + ar_name_posix + ": " + msg +"\n")


def setup_and_check_message(argv):

    # get alert from stdin
    input_str = ""
    for line in sys.stdin:
        input_str = line
        break

    write_debug_file(argv[0], input_str)

    try:
        data = json.loads(input_str)
    except ValueError:
        write_debug_file(argv[0], 'Decoding JSON has failed, invalid input format')
        message.command = OS_INVALID
        return message

    message.alert = data

    command = data.get("command")

    if command == "enable":
        message.command = ENABLE_COMMAND
    elif command == "disable":
        message.command = DISABLE_COMMAND
    else:
        message.command = OS_INVALID
        write_debug_file(argv[0], 'Not valid command: ' + command)

    return message


def send_keys_and_check_message(argv, keys):

    # build and send message with keys
    keys_msg = json.dumps({"version": 1,"origin":{"name": argv[0],"module":"active-response"},"command":"check_keys","parameters":{"keys":keys}})

    write_debug_file(argv[0], keys_msg)

    print(keys_msg)
    sys.stdout.flush()

    # read the response of previous message
    input_str = ""
    while True:
        line = sys.stdin.readline()
        if line:
            input_str = line
            break

    write_debug_file(argv[0], input_str)

    try:
        data = json.loads(input_str)
    except ValueError:
        write_debug_file(argv[0], 'Decoding JSON has failed, invalid input format')
        return message

    action = data.get("command")

    if "continue" == action:
        ret = CONTINUE_COMMAND
    elif "abort" == action:
        ret = ABORT_COMMAND
    else:
        ret = OS_INVALID
        write_debug_file(argv[0], "Invalid value of 'command'")

    return ret


def main(argv):

    write_debug_file(argv[0], "Started")

    # validate json and get command
    msg = setup_and_check_message(argv)

    if msg.command < 0:
        sys.exit(OS_INVALID)

    if msg.command == ENABLE_COMMAND:

        """ Start Custom Key
        At this point, it is necessary to select the keys from the alert and add them into the keys array.
        """

        alert = msg.alert

        rule_id = alert.get("rule", {}).get("id", "unknown")
        keys = [rule_id]

        """ End Custom Key """

        action = send_keys_and_check_message(argv, keys)

        # if necessary, abort execution
        if action != CONTINUE_COMMAND:

            if action == ABORT_COMMAND:
                write_debug_file(argv[0], "Aborted")
                sys.exit(OS_SUCCESS)
            else:
                write_debug_file(argv[0], "Invalid command")
                sys.exit(OS_INVALID)

        """ Start Custom Action Enable """

        # Replace this section with your custom action
        with open("ar-test-result.txt", mode="a") as test_file:
            test_file.write("Active response triggered by rule ID: <" + str(keys) + ">\n")

        """ End Custom Action Enable """

    elif msg.command == DISABLE_COMMAND:

        """ Start Custom Action Disable """

        # Replace this section with your disable action
        try:
            os.remove("ar-test-result.txt")
        except FileNotFoundError:
            write_debug_file(argv[0], "File not found, nothing to remove")

        """ End Custom Action Disable """

    else:
        write_debug_file(argv[0], "Invalid command")

    write_debug_file(argv[0], "Ended")

    sys.exit(OS_SUCCESS)


if __name__ == "__main__":
    main(sys.argv)
```

**Customization Guide**:

1. **Custom Keys (Line 124-129)**: Define which fields uniquely identify your alert
   ```python
   # Example: Use IP and username as keys
   source_ip = alert.get("source", {}).get("ip", "unknown")
   username = alert.get("user", {}).get("name", "unknown")
   keys = [rule_id, source_ip, username]
   ```

2. **Enable Action (Line 145-149)**: Replace with your custom action
   ```python
   # Example: Add firewall rule, lock account, etc.
   subprocess.run(["iptables", "-I", "INPUT", "-s", source_ip, "-j", "DROP"])
   ```

3. **Disable Action (Line 155-161)**: Implement reversion logic
   ```python
   # Example: Remove firewall rule, unlock account, etc.
   subprocess.run(["iptables", "-D", "INPUT", "-s", source_ip, "-j", "DROP"])
   ```

### Installation

```bash
# Bash script (Example 1)
sudo cp custom-fim-response.sh /var/ossec/active-response/bin/custom-fim-response
sudo chmod 750 /var/ossec/active-response/bin/custom-fim-response
sudo chown root:wazuh /var/ossec/active-response/bin/custom-fim-response

# Python script (Example 2)
sudo cp custom-ar.py /var/ossec/active-response/bin/custom-ar
sudo chmod 750 /var/ossec/active-response/bin/custom-ar
sudo chown root:wazuh /var/ossec/active-response/bin/custom-ar
```

### Best Practices

- **⚠️ stdin Reading**: ALWAYS use `read -r INPUT` in bash (never `$(</dev/stdin)` - causes deadlock)
- **Python stdin**: Use `for line in sys.stdin: input_str = line; break` or `sys.stdin.readline()`
- **No File Extension**: Save scripts without extension in `/var/ossec/active-response/bin/`
- **Path Processing**: Use `PurePosixPath(PureWindowsPath())` for cross-platform path handling
- **Validate Input**: Check JSON structure and required fields before processing
- **Implement Deduplication**: For stateful scripts, always use the keys protocol
- **WCS Fields**: Access fields using Wazuh Common Schema (`rule.id`, `source.ip`, `user.name`, `file.path`)
- **Log Everything**: Detailed logging to `active-responses.log` aids troubleshooting
- **Test Thoroughly**: Test both enable and disable commands with real alerts
- **Handle Errors**: Gracefully handle missing fields, invalid JSON, and failed operations
- **Use Absolute Paths**: Don't rely on PATH environment variable for external commands
- **Check Privileges**: Verify script has necessary permissions (root/wazuh ownership)
- **Python3**: Ensure Python 3 is installed on all agents before deployment
- **Dependencies**: Document any required libraries or external tools (e.g., `jq` for bash)

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

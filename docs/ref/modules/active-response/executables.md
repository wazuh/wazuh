# Active Response Executables Reference

The Active Response executables shipped with the Wazuh agent: what each does on each platform, what
it reads from its input and what it logs, and how to write your own.

## Overview

Wazuh provides two Active Response executables, **`block-ip`** and **`disable-account`**.
`block-ip` has a platform-specific implementation for Unix/Linux, macOS and Windows, so the
inventory below lists four source variants; a given installation ships the ones built for its
platform (`disable-account` is not built on Windows). The installer places them in
`active-response/bin/` under the agent's installation directory, owned `root:wazuh` with mode
`0750`.

All of them read the message described in [JSON protocol](architecture.md#json-protocol) from
stdin, accept `enable` and `disable`, and on `enable` send `wazuh-execd` a `check_keys` line before
acting. Whether a response is reverted depends on the channel's `type`, not on the executable: each
one handles both commands.

## Executable Inventory

### 1. block-ip (Unix/Linux)

**Source**: `src/active-response/src/block-ip-unix.c`

**Purpose**: Blocks or unblocks `source.ip` on Linux, FreeBSD, OpenBSD and NetBSD. The method chain
is chosen when the binary is built for its operating system.

**Keys**: the IP address.

**Methods** (tried in order; a method that is unavailable or fails passes to the next):

| Platform | Chain |
|---|---|
| Linux | firewalld → iptables → hosts.deny → route |
| FreeBSD | ipfw → pf → hosts.deny → route |
| OpenBSD | pf → hosts.deny → route |
| NetBSD | npf → hosts.deny → route |

| Method | Block (enable) | Unblock (disable) | Preconditions |
|---|---|---|---|
| firewalld | `firewall-cmd --add-rich-rule "rule family=ipv4 source address=192.168.1.100 drop"` (`ipv6` for an IPv6 address) | `--remove-rich-rule` with the same rule | `firewall-cmd` found and `systemctl is-active firewalld` answers `active`; retried up to 4 times with a growing pause |
| iptables | `iptables -I INPUT -s 192.168.1.100 -j DROP` and the same on `FORWARD` (`ip6tables` for IPv6) | `-D` instead of `-I` | `iptables` / `ip6tables` found |
| ipfw | `ipfw -q table 00001 add 192.168.1.100`; creates rules `00001` denying traffic from and to `table(00001)` when `ipfw show` lacks them | `ipfw -q table 00001 delete 192.168.1.100` | `ipfw` found |
| pf | `pfctl -t wazuh_fwtable -T add 192.168.1.100`, then `pfctl -k 192.168.1.100` | `pfctl -t wazuh_fwtable -T delete 192.168.1.100` | `pfctl` found, `/dev/pf` present, `pfctl -s info` reports `Status: Enabled` |
| npf | `npfctl table wazuh_blacklist add 192.168.1.100` | `npfctl table wazuh_blacklist del 192.168.1.100` | `npfctl` found, `npfctl show` reports filtering active and a `wazuh_blacklist` table |
| hosts.deny | appends `ALL:192.168.1.100` to `/etc/hosts.deny`; FreeBSD appends `ALL : 192.168.1.100 : deny` to `/etc/hosts.allow`; a file that already names the address is left as it is | removes every line containing the address | the file exists |
| route | Linux: `route add 192.168.1.100 reject`; BSD: `route -q add 192.168.1.100 127.0.0.1 -blackhole` | Linux: `route del 192.168.1.100 reject`; FreeBSD: `route -q delete 192.168.1.100 127.0.0.1 -blackhole`; OpenBSD/NetBSD: `route -q delete 192.168.1.100` | `route` found |

The `pf`, `npf` and `wazuh_blacklist` tables and their block rules are not created by `block-ip`;
`ipfw`'s are. firewalld, iptables and hosts.deny take a lock directory under `active-response/bin/`
(`block-ip-lock`, `block-ip-hostsdeny-lock`) so two runs do not edit the firewall at once.

**Input validation**: after the key exchange, `source.ip` must parse as a numeric IPv4 or IPv6
address (`getaddrinfo` without name resolution), otherwise `Invalid IP address: '<value>'`.

**Logging**: `logs/active-responses.log` under the agent's installation directory.

---

### 2. block-ip (macOS)

**Source**: `src/active-response/src/block-ip-macos.c`

**Purpose**: Blocks or unblocks `source.ip` using macOS-specific mechanisms.

**Keys**: the IP address.

**Methods** (tried in order):

| Priority | Method | Tool | Command Example |
|----------|--------|------|-----------------|
| 1 | pf | `pfctl` | `pfctl -t wazuh_fwtable -T add 192.168.1.100` |
| 2 | hosts.deny | edit file | `ALL:192.168.1.100` (appended to `/etc/hosts.deny`) |
| 3 | route | `route` | IPv4: `route -q add 192.168.1.100 127.0.0.1 -blackhole` · IPv6: `route -q add -inet6 2001:db8::1 ::1 -blackhole` |

**macOS-Specific Details**:
- **PF Table**: Uses table name `wazuh_fwtable`
- **Connection Killing**: When blocking, also kills existing connections: `pfctl -k 192.168.1.100`. Best effort: a failure here is not reported.
- **Table Precondition**: The `wazuh_fwtable` table and its block rules are a one-time setup owned by the administrator, the same way `wazuh_blacklist` is for `npf` on NetBSD. `block-ip` does not use a PF anchor file, never edits `/etc/pf.conf` and never reloads the packet filter ruleset: if the table is absent it declines and the next method in the chain is tried. The macOS package does not apply or announce it — `install.sh`'s notice runs at package build time, not on the endpoint — so it has to be applied by hand.
- **Fallback**: Falls back to `hosts.deny`, then to a `route` blackhole if `pf` is unavailable, not enabled or missing its table — the same no-configuration-needed fallback the Unix/Linux chain has, so a stock macOS install (pf disabled, no `/etc/hosts.deny`) still blocks the address
- **Unblocking**: Each method declines when the address is not the one it holds (`pf` reports `0/1 addresses deleted.`, `hosts.deny` finds no matching line), so the unblock walks the chain until it reaches the method that actually applied the block. Without this a block applied by `route` would never be lifted once `pf` or `hosts.deny` became available.
- **route results**: `route` exits 0 whatever happens, so the result is read from its stderr; `File exists` on a block and `not in table` on an unblock count as success.
- **Permissions**: Requires root privileges

**Example pf.conf setup** (added by the administrator, then `sudo pfctl -f /etc/pf.conf`):
```
# /etc/pf.conf
table <wazuh_fwtable> persist
block in quick from <wazuh_fwtable> to any
block out quick from any to <wazuh_fwtable>
```

**Input validation**: same as the Unix/Linux binary.

**Logging**: `/Library/Ossec/logs/active-responses.log`

---

### 3. block-ip (Windows)

**Source**: `src/active-response/src/block-ip-windows.c`

**Purpose**: Blocks or unblocks `source.ip` using Windows firewall mechanisms. Installed as
`active-response\bin\block-ip.exe`; a channel `executable` of `block-ip` finds it, because
`wazuh-execd` appends `.exe` to a name without a `.`.

**Keys**: the IP address.

**Methods** (ENABLE tries them in order; DISABLE removes **both** — see Removal below):

| Priority | Method | Tool | Command Example |
|----------|--------|------|-----------------|
| 1 | netsh | `netsh.exe` | `netsh advfirewall firewall add rule name="WAZUH ACTIVE RESPONSE BLOCKED IP" interface=any dir=in action=block remoteip=192.168.1.100/32` (plus a matching `dir=out` rule) |
| 2 | route | `route.exe` | `route -p ADD 192.168.1.100 MASK 255.255.255.255 0.0.0.0 IF 1` (blackhole via the loopback interface) |

The `remoteip` prefix matches the address family: `/32` for IPv4 and `/128` for IPv6.

**Windows-Specific Details**:
- **Firewall Rules**: Creates rules named `"WAZUH ACTIVE RESPONSE BLOCKED IP"` — one inbound (`dir=in`) and one outbound (`dir=out`) for bidirectional blocking. A failed outbound rule is logged and does not fail the block.
- **Effective firewall-state detection**: On **ENABLE only**, netsh is used only if the Windows Firewall is *effectively* enabled. The state is read directly from the registry `EnableFirewall` DWORD (locale-independent), evaluated per profile (Domain/Standard/Public):
  - The GPO policy value (`HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\<profile>`) wins if present;
  - otherwise the local SharedAccess value (`HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\<profile>`);
  - otherwise, an **absent** value defaults to **enabled** (the Windows default).

  If any profile is effectively enabled, netsh is used; if the firewall is effectively off, netsh is skipped and the chain defers to the `route` fallback (adding a rule that would sit dormant is avoided). This check is **not** applied on DISABLE, so an unblock always attempts to remove the rule.
- **Route Fallback (best-effort)**: When netsh is unavailable, or the firewall is effectively off, the target is **blackholed through the loopback interface** (`route -p ADD <IP> MASK 255.255.255.255 0.0.0.0 IF 1`) so the host discards packets destined to it. A `0.0.0.0 IF 1` gateway stays in the active routing table; a `127.0.0.1` gateway is only saved to the persistent store and never becomes active, so it would not block anything. This is **best-effort**: the /32 host route is more specific than the on-link subnet route and wins, so it drops egress to the target (including a host on a directly-connected subnet) and breaks the reverse path of inbound sessions, but it does **not** filter inbound packets the way a firewall rule does. Because `route.exe` exits 0 even when it rejects the route, the route is verified against the active routing table after the add (`GetBestRoute`); if it did not take, the method reports a failure. **Windows Firewall (netsh) remains the preferred, bidirectional blocking mechanism.**
- **IPv4-only fallback**: The `route` fallback applies to **IPv4 targets only**; IPv6 targets are skipped (netsh already covers IPv6).
- **Input validation**: `source.ip` must consist only of the characters of a numeric IPv4 address, or of hex digits, `:` and `.` for IPv6, 2 to 45 characters long, so nothing else reaches the netsh or route command line.
- **Permissions**: Requires Administrator privileges

**Removal**:

DISABLE is **not** a fallback chain — because a block may have been applied by *either* netsh (firewall on) *or* the null-route (firewall off), unblock unconditionally attempts to remove **both**, each best-effort (a missing rule/route is the expected, non-failure case):
- netsh: `netsh advfirewall firewall delete rule name="WAZUH ACTIVE RESPONSE BLOCKED IP" remoteip=192.168.1.100/32`; for an IPv6 address the `/128` rule and then a `/32` rule, the prefix older agents wrote for IPv6
- route: `route DELETE 192.168.1.100`

The unblock logs `IP <ip> successfully unblocked` if **either** removal took effect; if nothing matched, a warning is logged (the IP may already be unblocked). It exits `0` in both cases.

**Logging**: `C:\Program Files (x86)\ossec-agent\active-response\active-responses.log`

---

### 4. disable-account (Linux, macOS)

**Source**: `src/active-response/src/disable-account.c`

**Purpose**: Locks or unlocks the local account named in `user.name`.

**Keys**: the user name.

**Implementation**:

| Platform | Enable (lock the account) | Disable (unlock the account) |
|----------|--------------------------|---------------------------|
| Linux | `passwd -l -- <username>` | `passwd -u -- <username>` |
| macOS | `pwpolicy -u <username> -disableuser` | `pwpolicy -u <username> -enableuser` |

On any other system (the binary is also built on the BSDs) it logs `Invalid system: '<name>'` and
exits with failure.

**Input validation**: `user.name` must be 1 to 256 characters from `A-Z`, `a-z`, `0-9`, `.`, `_`,
`-` and `$`, must not start with `-`, and must not be `root`; otherwise `Cannot read 'user.name'
from data or invalid username format`. The name is not checked against the account database: an
account that does not exist makes `passwd` or `pwpolicy` fail, which is logged as
`Command '<path>' failed to disable the account '<username>' (exit code <n>): <first output line>`.

**Limitations**:
- **Existing Sessions**: Locking the account does not end the user's existing sessions
- **Local accounts only**: a name qualified with `@realm` is rejected

**Logging**: `logs/active-responses.log` under the agent's installation directory.

---

## Agent Restart and Reload

Agent restart and reload operations are **not** implemented as Active Response executables. These control operations are handled by the [Control Module (wm_control)](../control/README.md).

**Control Operations**:
- Agent restart via `PUT /agents/{agent_id}/restart` API endpoint
- Agent reload via `PUT /agents/{agent_id}/reload` API endpoint
- Handled through dedicated `agent_restart` / `agent_reload` tasks, not Active Response

**See**: [Control Module Documentation](../control/README.md) for details on agent control operations.

---

## Common Features

### Input and keys

The message format, the `check_keys` line and execd's `continue` / `abort` answer are specified in
[JSON protocol](architecture.md#json-protocol); how execd uses the keys is in
[Deduplication and timeouts](architecture.md#deduplication-and-timeouts). The keys are exchanged on
`enable` only.

### Logging

Every executable appends to `active-responses.log`, one line per message:

```
<YYYY/MM/DD HH:MM:SS> <path>: <message>
```

`<path>` is the executable as execd started it (`active-response/bin/block-ip`). A `block-ip` run
logs `Starting`, the input line, the `check_keys` line and execd's answer, then one line per method
in the form `[<LEVEL>] Method=<method> Action=<action> Details=<details>`, and `Ended`:

```
2026/03/31 15:30:45 active-response/bin/block-ip: Starting
2026/03/31 15:30:45 active-response/bin/block-ip: {"source":{"ip":"192.168.1.100"},"wazuh":{"active_response":{...}},"command":"enable"}
2026/03/31 15:30:45 active-response/bin/block-ip: {"version":1,"origin":{"name":"block-ip","module":"active-response"},"command":"check_keys","parameters":{"keys":["192.168.1.100"]}}
2026/03/31 15:30:45 active-response/bin/block-ip: {"source":{"ip":"192.168.1.100"},"wazuh":{"active_response":{...}},"command":"continue"}
2026/03/31 15:30:45 active-response/bin/block-ip: [INFO] Method=firewalld Action=start Details=Attempting method: firewalld (lock=yes)
2026/03/31 15:30:46 active-response/bin/block-ip: [INFO] Method=firewalld Action=success Details=IP 192.168.1.100 successfully blocked
2026/03/31 15:30:46 active-response/bin/block-ip: Ended
```

### Error Handling

| Situation | Log line | Exit |
|---|---|---|
| No input, or input that is not JSON with a string `command` and a `wazuh` object | `Cannot read input from stdin` / `Invalid input format` | failure |
| `command` other than `enable` / `disable` | `Invalid value of 'command'` | failure |
| Missing field | `Cannot read 'source.ip' from data` / `Cannot read 'user.name' from data or invalid username format` | failure |
| execd answers `abort` | `Aborted` | success |
| A `block-ip` method unavailable or failing | `[WARNING] Method=<m> Action=<a> …` with `<a>` `skipped`, `failed` or `invalid_state`, then the next method | — |
| Every `block-ip` method failed | `WARNING: All <n> firewall methods failed or unavailable (<u> unavailable, <e> execution errors)` | failure |

Success is exit status `0`; failure is `OS_INVALID` (`-1`, exit status 255 on Unix), which
`wazuh-execd` logs as `Active response command '<path>' reported failure (exit code <n>).`

---

## Custom Active Response Scripts

Users can create custom Active Response scripts following these guidelines:

### Requirements

1. **Location**: Place the file in `active-response/bin/` under the agent's installation directory; its file name is the channel's `executable`, exactly (on Windows, `.exe` is appended when the name has no `.`)
2. **Executable**: Owner `root:wazuh`, mode `0750`, with a proper shebang line (e.g. `#!/bin/bash` or `#!/usr/bin/python3`) on Unix
3. **JSON Input**: Read **one line** from stdin using `read -r` (bash) or `sys.stdin.readline()` (Python)
4. **Keys**: On `enable`, write one `check_keys` line on stdout and read execd's answer as a second line; without it a stateful response is never reverted
5. **Commands**: Support both `enable` and `disable`
6. **Exit Codes**: Return 0 on success, non-zero on failure
7. **Logging**: Write to `logs/active-responses.log`
8. **Run time**: Bound your own run time: execd waits for the script to exit and runs one at a time

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
    input_str = sys.stdin.readline()

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
        write_debug_file(argv[0], 'Not valid command: ' + str(command))

    return message


def send_keys_and_check_message(argv, keys):

    # build and send message with keys
    keys_msg = json.dumps({"version": 1,"origin":{"name": os.path.basename(argv[0]),"module":"active-response"},"command":"check_keys","parameters":{"keys":keys}})

    write_debug_file(argv[0], keys_msg)

    print(keys_msg)
    sys.stdout.flush()

    # read the response of previous message
    input_str = sys.stdin.readline()

    write_debug_file(argv[0], input_str)

    try:
        data = json.loads(input_str)
    except ValueError:
        write_debug_file(argv[0], 'Decoding JSON has failed, invalid input format')
        return OS_INVALID

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

        source_ip = alert.get("source", {}).get("ip", "unknown")
        keys = [source_ip]

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
            test_file.write("Active response triggered for: <" + str(keys) + ">\n")

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

`ar-test-result.txt` is relative to the working directory, which execd sets to the agent's
installation directory.

**Customization Guide**:

1. **Custom Keys** (between `Start Custom Key` and `End Custom Key`): define which fields identify
   the action; execd treats two responses with the same keys as the same action
   ```python
   # Example: Use IP and username as keys
   source_ip = alert.get("source", {}).get("ip", "unknown")
   username = alert.get("user", {}).get("name", "unknown")
   keys = [source_ip, username]
   ```

2. **Enable Action** (`Start Custom Action Enable`): replace with your custom action
   ```python
   # Example: Add firewall rule, lock account, etc.
   subprocess.run(["iptables", "-I", "INPUT", "-s", source_ip, "-j", "DROP"])
   ```

3. **Disable Action** (`Start Custom Action Disable`): implement the reversion
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

- **⚠️ stdin Reading**: ALWAYS read one line (`read -r INPUT` in bash, `sys.stdin.readline()` in Python), never to end of file (`$(</dev/stdin)`): execd keeps stdin open while it waits for your `check_keys` line, so reading to EOF deadlocks
- **Path Processing**: Use `PurePosixPath(PureWindowsPath())` for cross-platform path handling
- **Validate Input**: Check JSON structure and required fields before processing
- **Implement Deduplication**: For stateful scripts, always send the keys
- **Field paths**: Read fields at the paths the monitored event uses (`source.ip`, `user.name`, `file.path`, …) and the response metadata under `wazuh.active_response`
- **Log Everything**: Detailed logging to `active-responses.log` aids troubleshooting
- **Test Thoroughly**: Test both enable and disable commands with real alerts
- **Handle Errors**: Gracefully handle missing fields, invalid JSON, and failed operations
- **Use Absolute Paths**: Don't rely on PATH environment variable for external commands
- **Python3**: Ensure Python 3 is installed on all agents before deployment
- **Dependencies**: Document any required libraries or external tools (e.g., `jq` for bash)

---

## Testing Active Response Scripts

### Manual Testing

Run an executable as execd would, from the installation directory. An `enable` reads two lines —
the message, then execd's answer to its `check_keys` line — so give it both:

```bash
cd /var/ossec

# Test enable command
printf '%s\n' \
  '{"wazuh":{"active_response":{"name":"block-ip","executable":"block-ip","type":"stateless"}},"source":{"ip":"192.168.1.100"},"command":"enable"}' \
  '{"wazuh":{"active_response":{"name":"block-ip","executable":"block-ip","type":"stateless"}},"source":{"ip":"192.168.1.100"},"command":"continue"}' \
  | active-response/bin/block-ip

# Test disable command (one line: no key exchange on disable)
echo '{"wazuh":{"active_response":{"name":"block-ip","executable":"block-ip","type":"stateless"}},"source":{"ip":"192.168.1.100"},"command":"disable"}' | \
  active-response/bin/block-ip
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
netsh advfirewall firewall show rule name="WAZUH ACTIVE RESPONSE BLOCKED IP"
```

### Check Logs

```bash
tail -f /var/ossec/logs/active-responses.log
```

---

## See Also

- [Active Response README](README.md) - Module overview and features
- [Architecture](architecture.md) - Technical implementation details
- [Control Module](../control/README.md) - Agent restart/reload (separated in v5.0)

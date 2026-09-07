# Active Response Architecture

## Overview

Active Response is implemented through `wazuh-execd`, a daemon running on agents, that receives and executes security response commands. The architecture follows a message-driven model where JSON commands are sent from the manager to agents, parsed, validated, and executed with proper lifecycle management.

## Component Architecture

### Manager Side (v5.0)

The manager does not decide when a response fires. That decision is made in the Wazuh Indexer: an
Alerting monitor evaluates indexed events, and a trigger whose action targets a notification channel
of the Active Response type writes one document per matching event into the
`wazuh-active-responses` data stream. The manager's part is to turn each of those documents into an
agent task.

```mermaid
sequenceDiagram
    autonumber
    participant AL as Indexer Alerting<br/>monitor + trigger
    participant NO as Indexer Notifications<br/>Active Response channel
    participant DS as wazuh-active-responses<br/>data stream
    participant CD as wazuh-manager-clusterd<br/>ActiveResponseFetchTask, every node
    participant TM as Task Manager<br/>queue/sockets/task-http.sock
    participant RM as wazuh-manager-remoted<br/>POST /control
    participant AG as agent<br/>wazuh-execd

    AL->>NO: matching event (index, document id)
    NO->>NO: copy the event's `wazuh` object; add `wazuh.active_response` from the channel, `event`, `@timestamp`
    NO->>DS: index (op_type=create)
    loop every active_response_polling seconds, on every node
        CD->>DS: search after the bookmark, sorted by [@timestamp, _id], bounded at now
        DS-->>CD: page (up to 1000 documents)
        CD->>CD: validate against AR_SCHEMA, discard what fails
        CD->>DS: mget the referenced events (event.index, event.doc_id)
        CD->>CD: merge event and response into the payload, resolve target agents
        CD->>TM: POST /v1/tasks {agent_id, task_type: active_response, payload, source_id: _id}
        CD->>CD: write queue/cluster/ar_bookmark.json once per page
    end
    AG->>RM: POST /control (notify)
    RM->>TM: POST /v1/tasks/pending
    TM-->>RM: [{task_id, task_type, payload}]
    RM-->>AG: pending tasks in the response
    AG->>AG: hand the payload to wazuh-execd, run wazuh.active_response.executable
```

Where each step lives:

| Steps | Component | Source |
|---|---|---|
| 1-3 | Indexer Alerting and Notifications plugins | `wazuh/wazuh-indexer-notifications` (`SendMessageActionHelper.sendActiveResponseMessage`); the stream template and retention policy are in `wazuh/wazuh-indexer-plugins` |
| 4-10 | `ActiveResponseFetchTask` in `wazuh-manager-clusterd`, started by the master and by every worker | [active_response.py](../../../../framework/wazuh/core/indexer/active_response.py), [master.py](../../../../framework/wazuh/core/cluster/master.py), [worker.py](../../../../framework/wazuh/core/cluster/worker.py) |
| 11-14 | Task Manager and remoted | [Task Manager](../task_manager/README.md), [remoted architecture](../remoted/architecture.md) |
| 15 | `wazuh-execd` on the agent | the rest of this page |

The manager's part in detail — the document contract, the read, the cursor and every message it
logs — is in [Manager-side ingestion](#manager-side-ingestion).

### Agent Side

```
┌─────────────────────────────────────────────────────────────────────┐
│                        wazuh-agentd                                 │
│                                                                     │
│  Receives encrypted messages from manager                          │
└────────────────────────────────┬────────────────────────────────────┘
                                 │
                                 │ Decrypts and forwards
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│                        wazuh-execd                                  │
│                                                                     │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │                    Command Receiver                           │  │
│  │  ┌──────────────┐      ┌─────────────────┐                    │  │
│  │  │ Message      │      │ JSON Parser     │                    │  │
│  │  │ Queue        │─────▶│ & Validator     │                    │  │
│  │  └──────────────┘      └────────┬────────┘                    │  │
│  └──────────────────────────────────┼───────────────────────────┘  │
│                                     │                               │
│  ┌──────────────────────────────────▼───────────────────────────┐  │
│  │                  Execution Engine                            │  │
│  │  ┌─────────────┐   ┌──────────────┐   ┌─────────────────┐   │  │
│  │  │Deduplication│   │   Process     │   │    Timeout      │   │  │
│  │  │   System    │──▶│   Executor    │──▶│   Management    │   │  │
│  │  └─────────────┘   └──────────────┘   └─────────────────┘   │  │
│  └───────────────────────────────────────────────────────────────┘  │
└────────────────────────────────┬────────────────────────────────────┘
                                 │
                                 │ fork + exec
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    AR Script (block-ip, etc.)                       │
│                                                                     │
│  Receives JSON via stdin, parses, executes firewall commands       │
└────────────────────────────────┬────────────────────────────────────┘
                                 │
                                 ▼
                          ┌──────────────┐
                          │   Firewall   │
                          │   Commands   │
                          └──────────────┘
```

## Message Flow

### Enable (Block) Command Flow (v5.0+ Task-Based)

1. **Trigger**: an Alerting monitor in the Wazuh Indexer matches an event; its Active Response channel writes one response document to `wazuh-active-responses`
2. **Ingestion**: `wazuh-manager-clusterd` reads the document on its next polling cycle, validates it, merges the referenced event into the payload and resolves the target agents (see [Manager-side ingestion](#manager-side-ingestion))
3. **Task Creation**: clusterd creates one Task Manager task per target agent:
   - Task type: `active_response`
   - Payload: the response document merged with the event it references
   - Deterministic task id, so every cluster node creates the same task
   - Status: `pending`, stored in the Task Manager database
4. **Agent Polling**: Agent polls `/control` HTTPS endpoint for pending tasks
5. **Task Retrieval**: Task Manager returns AR task to agent
6. **Agent Reception**: Agent's `wazuh-agentd` receives the AR task
7. **Execd Processing**: `wazuh-execd` validates and queues the command
8. **Deduplication Check**: Executes key verification to prevent duplicates
9. **Script Execution**: Forks and executes the AR script (e.g., `block-ip`)
10. **Script Input**: Script receives JSON via stdin
11. **Script Parsing**: Script extracts `source.ip` from JSON
12. **Firewall Action**: Script executes firewall commands to block the IP
13. **Timeout Registration**: If stateful, execd registers the timeout for automatic reversion
14. **Task Acknowledgment**: Task marked as `delivered` in Task Manager (fire-and-forget)

### Disable (Unblock) Command Flow

1. **Timeout Expiry**: Execd's timeout manager detects expired stateful response
2. **Command Modification**: Execd modifies the original JSON, changing `"command": "enable"` to `"command": "disable"`
3. **Script Re-Execution**: Forks and executes the same AR script
4. **Script Input**: Script receives modified JSON via stdin
5. **Firewall Reversion**: Script executes firewall commands to unblock the IP
6. **Cleanup**: Execd removes the entry from the active response list

## Deduplication System

The deduplication mechanism prevents redundant executions of the same response:

### Keys Protocol

1. **Keys Extraction**: AR script extracts unique identifiers (keys) from the alert:
   ```c
   keys[0] = srcip;  // e.g., "192.168.1.100"
   keys[1] = NULL;
   ```

2. **Keys Message**: Script sends keys to execd for verification:
   ```json
   {
     "version": 1,
     "origin": {
       "name": "block-ip",
       "module": "active-response"
     },
     "command": "check_keys",
     "parameters": {
       "keys": ["192.168.1.100"]
     }
   }
   ```

3. **Execd Response**: Execd checks if keys are already in the active responses table:
   - **Not Found**: `{"command": "continue"}` → Script proceeds
   - **Found**: `{"command": "abort"}` → Script exits without executing

4. **Registration**: If continuing, execd adds keys to the active responses table

### Active Responses Table

Execd maintains an in-memory table of active responses:

```c
typedef struct _active_response {
    char *keys[MAX_AR_KEYS];     // Unique identifiers (e.g., IP addresses)
    char *command;                // Original JSON command
    int timeout;                  // Timeout in seconds (0 = stateless)
    time_t time_added;            // Timestamp when added
    struct _active_response *next;
} active_response;
```

**Table Operations**:
- **Add**: When `check_keys` returns `continue`, add entry to table
- **Lookup**: On `check_keys` request, search table for matching keys
- **Remove**: When timeout expires or disable completes, remove entry

## Timeout Management

For stateful responses, execd implements a timeout system:

### Timeout Registration

When a stateful AR executes:
1. Execd receives `"command": "enable"` with embedded timeout metadata
2. Creates active response entry with timeout value
3. Records `time_added` timestamp
4. Continues with execution

### Timeout Monitoring

Execd runs a timeout checker thread:
1. Periodically scans the active responses table (every 60 seconds)
2. For each entry, calculates elapsed time: `current_time - time_added`
3. If elapsed time >= timeout:
   - Modifies the original JSON command to `"command": "disable"`
   - Re-executes the AR script with modified command
   - Removes entry from table

### Timeout Example

```
T=0s    : IP 192.168.1.100 blocked (timeout=600s)
          - Execd adds to table: {keys=["192.168.1.100"], timeout=600, time_added=T0}
          - Script executes: iptables -I INPUT -s 192.168.1.100 -j DROP

T=300s  : Timeout checker runs, elapsed=300s < 600s → No action

T=600s  : Timeout checker runs, elapsed=600s >= 600s
          - Execd modifies command to "disable"
          - Script executes: iptables -D INPUT -s 192.168.1.100 -j DROP
          - Execd removes from table
```

## JSON Protocol Specification

### Message Structure

All Active Response messages follow this structure:

```json
{
  "wazuh": {
    "active_response": {
      "name": "string",
      "executable": "string",
      "location": "string",
      "agent_id": "string",
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
  "command": "enable" | "disable" | "continue" | "abort"
}
```

### Command Types

| Command | Direction | Purpose |
|---------|-----------|---------|
| `enable` | Manager → Agent | Activate response action |
| `disable` | Manager → Agent or Execd (timeout) | Revert response action |
| `check_keys` | Script → Execd | Request deduplication check |
| `continue` | Execd → Script | Proceed with execution |
| `abort` | Execd → Script | Skip execution (duplicate) |

### Field Mapping (WCS Compatibility)

Active Response uses WCS-compatible field names:

| Field | Description |
|-------|-------------|
| `source.ip` | Source IP address |
| `user.name` | Target username |
| `rule.level` | Rule severity level |
| `rule.id` | Rule identifier |

## Script Implementation

### Standard AR Script Structure

All Active Response scripts follow this pattern:

```c
int main(int argc, char **argv) {
    int action;
    cJSON *input_json = NULL;

    // 1. Parse JSON input and determine action (enable/disable)
    action = setup_and_check_message(argv, &input_json);
    if (action != ADD_COMMAND && action != DELETE_COMMAND) {
        return OS_INVALID;
    }

    // 2. Extract parameters (e.g., source IP)
    const char *srcip = get_srcip_from_json(input_json);
    if (!srcip) {
        return OS_INVALID;
    }

    // 3. For ADD: Send keys for deduplication check
    if (action == ADD_COMMAND) {
        char **keys = NULL;
        os_calloc(2, sizeof(char *), keys);
        os_strdup(srcip, keys[0]);
        keys[1] = NULL;

        int action2 = send_keys_and_check_message(argv, keys);
        if (action2 == ABORT_COMMAND) {
            // Duplicate found, exit without executing
            return OS_SUCCESS;
        }
    }

    // 4. Execute the actual response (block/unblock IP)
    if (action == ADD_COMMAND) {
        block_ip(srcip);
    } else {
        unblock_ip(srcip);
    }

    return OS_SUCCESS;
}
```

### Helper Functions

Active Response scripts use shared helper functions from `active_responses.c`:

| Function | Purpose |
|----------|---------|
| `setup_and_check_message()` | Parse JSON from stdin, extract command |
| `get_srcip_from_json()` | Extract source IP from JSON |
| `get_username_from_json()` | Extract username from JSON |
| `send_keys_and_check_message()` | Send keys to execd, check for abort |
| `write_debug_file()` | Write debug logs to active-responses.log |

## Metadata-Driven Execution

Active Response uses a metadata-driven approach where all execution metadata is embedded in the JSON message:

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
- No configuration file needed on agents (no `ar.conf`)
- Centralized metadata management
- Simplified agent deployment
- WCS compatibility

### Execd Implementation

`ExecdRun()` function in `os_execd/src/execd.c` extracts metadata directly from the JSON message:

```c
// Extract metadata directly from JSON
exec_cmd = cJSON_GetObjectItem(json_root, "executable")->valuestring;
timeout = cJSON_GetObjectItem(json_root, "timeout")->valueint;
```

This approach eliminates the need for configuration lookups and reduces agent-side complexity.

## Process Lifecycle

### Fork and Execute

When execd executes an AR script:

1. **Fork Process**: `fork()` creates child process
2. **Setup Pipes**: Create stdin pipe for JSON input
3. **Write JSON**: Parent writes JSON to stdin pipe
4. **Execute Script**: `execvp()` replaces child with AR script
5. **Read Output**: Parent optionally reads stdout for continue/abort responses
6. **Wait**: Parent calls `waitpid()` to collect child exit status

### Exit Status Handling

AR scripts return:
- `0` (OS_SUCCESS): Operation completed successfully
- `1` (OS_INVALID): Invalid input or operation failed

Execd logs script exit status but does not propagate errors to the manager.

## Platform-Specific Considerations

### Unix/Linux

- **Process Model**: Fork/exec model
- **Privileges**: Requires root for most operations
- **Sockets**: Unix domain sockets for inter-process communication
- **Logs**: `/var/ossec/logs/active-responses.log`

### macOS

- **Firewall**: Prefers `pfctl` (Packet Filter)
- **Fallback**: `hosts.deny` for non-root scenarios
- **Privileges**: Requires root for firewall operations

### Windows

- **Process Model**: CreateProcess API
- **Privileges**: Requires Administrator
- **Firewall**: `netsh advfirewall` (preferred), `route` (fallback)
- **Logs**: `C:\Program Files (x86)\ossec-agent\active-response\active-responses.log`

## Security Considerations

### Input Validation

All AR scripts validate:
- JSON structure correctness
- Command field presence and valid values (`enable`/`disable` only)
- Required parameters (source IP, username, etc.)
- IP address format validation

### Command Whitelisting

Only the following commands are accepted:
- `enable` - Activate response
- `disable` - Revert response
- `continue` - Proceed with execution (execd → script)
- `abort` - Skip execution (execd → script)

Any other command value results in immediate rejection.

### Privilege Separation

- **Execd**: Runs as root/Administrator (required for script execution)
- **Scripts**: Inherit privileges from execd
- **Logging**: Logs written with appropriate permissions (0640)

### Firewall Safety

IP blocking scripts implement safety measures:
- **IP Validation**: Reject invalid IP formats
- **Duplicate Prevention**: Deduplication system prevents redundant blocks
- **Graceful Fallback**: Try multiple firewall methods before failing
- **Reversion Guarantee**: Timeout system ensures blocks are eventually removed

## Performance Characteristics

### Throughput

- **Message Processing**: ~1000 messages/second (single-threaded)
- **Execution Overhead**: ~50ms per AR script execution (fork/exec)
- **Deduplication Lookup**: O(n) linear search over active responses table

### Memory Usage

- **Active Responses Table**: ~500 bytes per entry
- **Maximum Entries**: Configurable (default: 256 simultaneous responses)
- **JSON Parsing**: Temporary allocations freed after processing

### Scalability

- **Single-Threaded**: Execd processes messages sequentially
- **Blocking Operations**: Fork/exec blocks during script execution
- **Timeout Checker**: Runs every 60 seconds in separate thread

## Troubleshooting

### Common Issues

**AR script not executing**:
- Check execd is running: `ps aux | grep execd`
- Verify script permissions: `ls -la /var/ossec/active-response/bin/`
- Review logs: `tail -f /var/ossec/logs/active-responses.log`

**Firewall commands failing**:
- Verify root/Administrator privileges
- Check firewall tool availability: `which iptables` / `which firewalld-cmd`
- Test manually: `/var/ossec/active-response/bin/block-ip < test.json`

**Duplicate not detected**:
- Verify keys are correctly extracted in script
- Check execd deduplication logs
- Ensure same keys are used for enable/disable

## See Also

- [Active Response README](README.md) - Module overview and usage
- [Executables Reference](executables.md) - Detailed executable inventory
- [Control Module](../control/index.html) - Agent restart/reload (separated in v5.0)

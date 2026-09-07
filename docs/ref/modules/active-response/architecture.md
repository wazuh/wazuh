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
        DS-->>CD: page (up to active_response_page_size documents)
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

## Manager-side ingestion

Everything in this section is `ActiveResponseFetchTask` and its helpers in
[active_response.py](../../../../framework/wazuh/core/indexer/active_response.py). It runs inside
`wazuh-manager-clusterd` on **every** node, master and workers alike, and logs to `logs/cluster.log`
under the `[Active Response]` tag. The one-paragraph summary is flow 4 of the
[server architecture](../../architecture.md).

### The document

The notification channel writes one document per matching event. It copies the event's `wazuh`
object verbatim, so whatever the monitored index carries under `wazuh` travels with the response,
and adds three things of its own:

| Field | Written by the channel as | The manager uses it for |
|---|---|---|
| `@timestamp` | the instant the document was written | read order and cursor, the task's `create_time`, and the age that bounds the visibility hold |
| `event.index`, `event.doc_id` | the monitored index and the matching document's `_id` | fetching the event whose fields are merged into the payload the agent receives |
| `wazuh.active_response.*` | the channel configuration: `name`, `executable`, `extra_arguments`, `type` (`stateful` or `stateless`), `stateful_timeout`, `location`, `agent_id` | what to run, and on which agents |
| `wazuh.agent.id` | copied from the event, when the event has it | the target when `location` is `local` |
| `wazuh.agent.version` | copied from the event, when the event has it | documents whose version matches `v[0-4]\..*` are never read: an agent below 5.0 has no delivery path |

`location` decides the target agents:

| `location` | Target | Needs |
|---|---|---|
| `local` | the agent the event came from | `wazuh.agent.id` in the document, i.e. in the monitored event |
| `defined-agent` | one fixed agent | `wazuh.active_response.agent_id` |
| `all` | every registered agent | nothing; an empty fleet dispatches nothing |

`AR_SCHEMA` is the first thing a document meets, and it states the contract above: `event.index`
and `event.doc_id` as non-empty strings; `wazuh.active_response` with `executable`,
`extra_arguments`, `location`, `name` and `type`, typed and enumerated as above and with no unknown
keys; `stateful_timeout` when `type` is `stateful`; a non-empty `agent_id` when `location` is
`defined-agent`; and a non-empty `wazuh.agent.id` when `location` is `local`. A document that fails
it is discarded there, once, with its `_id` in the WARNING. What the schema cannot reach is the
*referenced* event, whose shape is only known after the `mget`; that is why dispatch still guards
against a document raising on its own shape.

The indexer's own template (`dynamic: strict`) rejects unknown field names and nothing else: it
cannot express that a field is required, an enum or a conditional, and the manager reads `_source`
verbatim. Validation therefore happens here, and a document the schema accepts can still turn out
unusable further down.

### The read

Each cycle runs one `search` on `wazuh-active-responses*`:

- sorted by `[@timestamp, _id]` ascending, `search_after` the bookmark, up to
  `active_response_page_size` documents (1000 by default);
- bounded above by the node's clock (`@timestamp <= now`), so a document stamped in the future is
  not read until its time comes and cannot move the cursor past everything created before it;
- on the very first run of a node, bounded below by that instant (`only_events_after`), so a fresh
  install does not replay the stream's history;
- excluding documents whose `wazuh.agent.version` matches `v[0-4]\..*`.

Every document on the page is validated against `AR_SCHEMA`. The survivors have their events
fetched with one `mget` per referenced index, and the payload handed to the Task Manager is the
event merged over the response document, except under `wazuh`, where the response's keys win.

### The cursor

The bookmark is a **high-water mark of what was read**, not of what was delivered. It is written
once per page, after the page is processed, to `queue/cluster/ar_bookmark.json`:

```json
{"sort": [1788797763932, "AbCd…"], "sort_fields": ["@timestamp", "_id"], "only_events_after": 1788790000000}
```

Two things follow, and both are deliberate:

- **A document that can never succeed does not stop the others.** Failing the schema, an unusable
  `event` reference, an event still missing after the grace window, an unparseable `@timestamp`, a
  refusal from the Task Manager, or raising on its own shape at dispatch are all terminal for that
  one document: it is discarded, reported at `WARNING` or `ERROR` with its `_id`, and the page still
  advances past it. A lost response is lost: delivery guarantees are the Task Manager's, not the
  cursor's.
- **The page is held, and read again next cycle, in exactly two cases.** A Task Manager that cannot
  be reached, because nothing was decided about any document and so nothing may be skipped; and a
  referenced event that is not visible yet: the event is written to another index by another
  pipeline, so for up to `active_response_event_grace` seconds (120 by default) after the
  response's `@timestamp` the cursor stops short of it. Past that age the reference is taken as broken and the document is
  discarded. While a page is held, the documents on it are dispatched again on the next cycle; the
  deterministic task id makes that harmless.

On load, a bookmark whose `@timestamp` is ahead of the node's clock is capped at the present and
saved, with a `WARNING`: such a cursor would otherwise read zero hits until wall-clock time caught
up.

**Recovery.** Deleting `ar_bookmark.json` restarts the read from the moment of deletion: on the next
cycle `only_events_after` is stamped anew and every document older than that instant is never read.
Documents already in the stream that must not be dispatched are removed from the stream itself. A
`WARNING` that repeats every cycle for the same `_id` means the page is being held, one of the two
cases above; an `ERROR … Error during active response processing` that repeats every cycle means an
exception escaped the poller and the cursor is not moving, which is a defect in the poller rather
than in the data.

### The cluster

Every node runs the same poller against the same stream with its own bookmark. Nothing is owned:
with stateless HTTPS an agent may talk to any node, so there is no agent-to-node assignment to
filter by and no leader. The N tasks the N nodes create for one document collapse into one row
because the Task Manager derives the task id from `source_id` (the document's `_id`), the agent,
the type and `create_time`; see [Task Manager](../task_manager/README.md). The corollary is that
every node reads every document: a document that stalls a cycle stalls it fleet-wide, at once.

### Settings

All three live in `intervals.common` of `framework/wazuh/core/cluster/cluster.json`, an internal
file that is replaced on upgrade. A missing key falls back to its default with a `WARNING`, and so
does a value out of range.

| Key | Default | Meaning | Trade-off |
|---|---|---|---|
| `active_response_polling` | `30` | Seconds between two reads, on every node | Shorter means faster delivery and more searches per node |
| `active_response_page_size` | `1000` | Documents per read; a positive integer | Larger means fewer round trips and a longer distance between two cursor writes, so more documents are dispatched again after a hold or a crash |
| `active_response_event_grace` | `120` | Seconds a response may wait for its event to become visible before it is discarded; `0` disables the hold | Longer tolerates slower event ingest at the cost of delaying every response behind the held one |

### Messages

All lines are in `logs/cluster.log`, tagged `[Active Response]`. Every path that loses a response
says so at `WARNING` or above; `wazuh_clusterd.debug=2` adds the query, the page size, each `mget`,
each task and each hold.

Each cycle ends with one `INFO` summary. A healthy cycle is one sentence:

```
Created 3 task(s) for 2 of 2 active response(s) read.
```

A cycle that held or lost something says so, and only then:

```
Created 1 task(s) for 1 of 5 active response(s) read. Held: 1. Discarded: event_not_visible_expired=1, invalid_schema=1, unusable_shape=1.
```

Every response read has exactly one outcome, so `read = dispatched + held + Σ discarded` on every
page. `dispatched` counts responses for which at least one task was created (a `location: all`
response is one response, however many tasks it made); `held` counts responses the page was held
for; the discard reasons are:

| Reason | The response was | Reported by |
|---|---|---|
| `invalid_schema` | rejected by `AR_SCHEMA` | the `Discarding active response document … Reason:` WARNING |
| `unusable_event_reference` | carrying an `event` reference the schema would reject; only reachable when validation is off | the `carries no usable event reference` WARNING |
| `event_not_visible_expired` | waiting for an event that never became visible within the grace window | the `not found after <grace>s` WARNING |
| `unparseable_timestamp` | missing its `@timestamp`, or carrying one that is not ISO 8601 | the `missing @timestamp` WARNING or the `Failed to parse @timestamp` ERROR |
| `unusable_shape` | raising while its payload or targets were resolved | the `unusable shape` WARNING |
| `zero_targets` | resolving to no agent at all (`location: all` on an empty fleet, or while the agent list could not be read) | the `targets no agent` WARNING |
| `task_manager_refused` | refused by the Task Manager for every one of its targets | the `Task Manager refused` ERROR, one per task |

A response refused for some targets and created for others counts as dispatched; the refused tasks
are in their own ERROR lines. A response with no task created because the Task Manager could not be
reached counts as held, together with the not-visible-yet case.

| Level | Message | Meaning | What to do |
|---|---|---|---|
| INFO | `Starting` / `Finished in N.NNNs.` | one polling cycle | nothing |
| INFO | `Created T task(s) for D of R active response(s) read.` (`Held: H.`, `Discarded: reason=n, ….` only when non-zero) | the cycle summary described above | nothing when it is one sentence; otherwise the WARNING or ERROR for each discard is above it |
| WARNING | ``Discarding active response document `<id>` (`<index>`). Reason: <schema error>`` | the document fails `AR_SCHEMA`; terminal | fix the channel, or the client that wrote the document; the document itself is skipped |
| WARNING | ``Active response `<id>` carries no usable event reference. Discarding it.`` | `event.index` or `event.doc_id` missing, empty or not a string; terminal | same |
| WARNING | ``Expected event `<doc_id>` (`<index>`) not found after <grace>s. Discarding active response `<id>`.`` | the referenced event never became visible; terminal | check that the monitored index still holds the event; a wrong `event.index` lands here once the response is older than the grace window |
| WARNING | ``Expected event `<doc_id>` (`<index>`) not found, and the response carries no readable @timestamp. Discarding active response `<id>`.`` | same, with no age to wait on | same |
| WARNING | `AR document <id> missing @timestamp, skipping` | no `@timestamp`; terminal | the document was not written by the notification channel |
| ERROR | `Failed to parse @timestamp '<value>' from AR <id>: <error>` | `@timestamp` is not ISO 8601; terminal | same |
| WARNING | ``Discarding active response document `<id>`: unusable shape (<Type>: <detail>).`` | the document raised while its payload or its targets were resolved, e.g. a referenced event whose `wazuh` is not an object; terminal | look at the document `event.index` and `event.doc_id` point to; the response itself passed the schema |
| WARNING | ``Active response `<id>` targets no agent. Discarding it.`` | `location: all` resolved to an empty agent list; terminal | register agents, or check `wazuh-manager-db` if `Error fetching agents` precedes it |
| ERROR | ``Task Manager refused the task for agent `<agent>`: <error>`` | the Task Manager answered with a non-2xx, e.g. a payload over the size cap or a `create_time` outside its admission window; terminal for that task | read the reason; the page still advances |
| ERROR | ``Failed to create task for agent `<agent>`: <error>`` | the Task Manager could not be reached; transient | check `wazuh-manager-modulesd`; the page is held, see the next row |
| WARNING | `Task Manager was unreachable for at least one active response. Holding the cursor so this page is read again on the next cycle.` | hold, transport case | resolves on its own once the Task Manager answers |
| WARNING | ``Active response bookmark `<path>` points at <ts>, ahead of the present instant. Capping it at <now>; …`` | the cursor was ahead of this node's clock; capped and saved | check the clocks; responses stamped between the two instants were skipped |
| WARNING | `Missing in cluster configuration (intervals.common): <keys>. Using defaults: <key=value, …>.` | `cluster.json` lacks one of the three settings; defaults apply | restore the shipped `cluster.json`, or add the keys |
| WARNING | `<key> must be <constraint>, got <value>. Using default: <n>.` | a setting is out of range; its default applies | fix the value |
| WARNING | `Cannot connect to Wazuh Indexer` | the indexer client could not be built or connected | transient; retried after the polling interval |
| ERROR | `Error fetching agents: <error>` | `wazuh-db` did not answer the agent list; a `location: all` response on this page is dispatched to nobody and lost | check `wazuh-manager-db` |
| ERROR | `Error during active response processing: <error>.` | an exception escaped the cycle; the cursor did not move | a poller defect; report it with the `_id`s on the page |

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
- [Configuration](configuration.md) - Agent-side options and the manager's polling setting
- [Executables Reference](executables.md) - Detailed executable inventory
- [Server architecture, flow 4](../../architecture.md) - Where Active Response sits among the manager daemons
- [Task Manager](../task_manager/README.md) - Agent task storage and delivery
- [Control Module](../control/index.html) - Agent restart/reload (separated in v5.0)

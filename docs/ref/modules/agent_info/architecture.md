# Architecture

The **agent_info** module is designed to be the definitive source of agent identity and group information. It implements a robust architecture to collect, persist, and synchronize this data, coordinating with other modules to ensure system-wide consistency.

---

## Main Components

### **AgentInfo Implementation (`AgentInfoImpl`)**

The core C++ class that orchestrates all module operations.

**Key responsibilities:**
*   Manages the main lifecycle, including periodic metadata collection.
*   Interfaces with `SysInfo` and file readers to gather agent data.
*   Uses `DBSync` to persist information and detect changes.
*   Triggers and manages the module coordination protocol when changes occur.
*   Integrates with the `AgentSyncProtocol` for reliable communication with the manager.

### **Data Sources**

The module gathers information from several sources:
*   **SysInfo**: Collects operating system details like OS name, version, architecture, and hostname.
*   **`client.keys` file**: Reads the agent's unique ID and name from the first line that has at least an ID and a name.
*   **Handshake data from agentd**: Every cycle, `agent_info` queries agentd (`gethandshake`) for the name of the manager cluster the agent is connected to (the cluster name, not the node name) and feeds it into `cluster_name`. If a query fails it keeps the last value obtained live, and before the first success it uses the value stored at module startup (`agent_info_get_cluster_name()`). A change in `cluster_name` alone triggers a groups synchronization.
*   **Agent groups**: The groups received in the handshake are used once, at startup, and then cleared. Later cycles read them from `merged.mg` (`etc/shared/merged.mg`; `shared\merged.mg` on Windows).
*   **`vd_feed_state`**: The durable vulnerability detection feed offset, if known, is added to the metadata published for the sync protocol as `vd_feed_offset`.

### **Database Integration (DBSync)**

Leverages the shared `DBSync` component for local SQLite database operations.

**Key responsibilities:**
*   Stores agent metadata in the `agent_metadata` table.
*   Stores group memberships in the `agent_groups` table.
*   Maintains operational state (e.g., sync flags, integrity timestamps) in the `db_metadata` table.
*   Stores the `/control` task IDs already handled in the `tasks` table and the VD feed offset in the `vd_feed_state` table.
*   Detects changes by comparing new scans with the stored state, triggering callbacks for insertions, modifications, and deletions.

### **Module Coordination Protocol**

A critical feature that ensures data consistency across the agent. When a change in agent groups or other critical metadata is detected, `agent_info` orchestrates a synchronization process with other modules.

**Coordinated Modules:**
*   `FIM` (File Integrity Monitoring)
*   `SCA` (Security Configuration Assessment)
*   `Syscollector` (System Inventory)

**Coordination Steps:**
1.  **Pause**: Send a "pause" command to each module, FIM first. FIM's pause is asynchronous, so `agent_info` polls `is_pause_completed` (up to 30 seconds). If FIM, SCA or Syscollector has not finished its first synchronization, the paused modules are resumed and the cycle is deferred: the sync flag is kept and the cycle is retried on the next interval. Modules that are disabled or not running are skipped.
2.  **Get Version / Set Version**: Retrieve the current synchronization version from each paused module, calculate the new global version (max version for a groups change, max+1 for a metadata change) and set it on all of them.
3.  **Flush**: Instruct each paused module to flush its pending data. The flush runs asynchronously in the module.
4.  **Resume**: Send a "resume" command to all modules. Their scans restart while the flushes finish.
5.  **Wait for flush completion**: Poll `is_flush_completed` on each module until it reports `completed`. If a flush fails, the version is not handed to the manager and the cycle is retried on the next interval.
6.  **Synchronize**: `agent_info` sends its changes to the manager, associated with the new version and the list of affected module indices.

If no module could be paused (all three disabled or not running), coordination returns success without sending anything and the sync flag is cleared, so that change is not sent by the delta path.

Each query to a module is retried up to 3 times, 1 second apart. The integrity check does not run this protocol: it only sends the checksum of each table through the sync protocol.

This protocol guarantees that configuration changes tied to agent groups are applied atomically across the system.

---

## Data Flow

### **Initialization Flow**
1.  `wm_agent_info_main()` loads the `agent_info` shared library and sets up C-style callbacks.
2.  `agent_info_task_registry_init()` builds the `AgentInfoImpl` instance, whose constructor initializes `DBSync` and `agent_info.db`, so the task registry is available before the message queue is opened.
3.  `wm_agent_info_main()` opens the message queue and waits (retrying every second) until agentd answers the handshake query, storing the cluster name and groups.
4.  `agent_info_start()` reuses the instance, creates the sync protocol (an instance without a queue database) and calls `AgentInfoImpl::start()`.
5.  `start()` calls `loadSyncFlags()` to read the last operational state from the `db_metadata` table and begins the main execution loop.

### **Metadata Population and Change Detection Flow**
1.  The `start()` method periodically calls `populateAgentMetadata()`.
2.  `populateAgentMetadata()` reads data from `SysInfo`, `client.keys`, and `merged.mg`.
3.  The collected data is passed to `updateChanges()`, which uses a `DBSync` transaction to compare it with the database content.
4.  If `DBSync` detects any difference, it invokes the `processEvent()` callback with the change type (`INSERTED`, `MODIFIED`, `DELETED`).

### **Event and Coordination Flow**
```
populateAgentMetadata()
         │
         ▼
updateChanges() ──────────────► DBSync transaction compares data
         │                           │
         │                           ▼
         │                      processEvent() callback (per changed row)
         │                           │
         │                           └─► Generate Stateless Event ─► report_callback() ─► Manager (immediate alert)
         │                               (skipped if only OS fields changed)
         ▼
setSyncFlag(true)  (m_shouldSyncMetadata / m_shouldSyncGroups, from the updateChanges() result)
         │
         ▼
Main loop in start() detects flag
         │
         ▼
performDeltaSync()
         │
         ▼
coordinateModules()
         │
         ├─► Pause, Versioning, Flush, Resume and flush wait for FIM, SCA, Syscollector
         │
         └─► synchronizeMetadataOrGroups() ───► AgentSyncProtocol ───► Manager (reliable delivery)
```

---

## Threading Model

The `agent_info` processing loop runs in a **single module thread**. The `start()` method contains a loop that sleeps for the configured `interval` and wakes up to perform its tasks. Asynchronous operations are handled by the module coordination protocol, which queries other modules and polls for completion (FIM's pause, and every module's flush).

Other threads call into the module: the sync dispatcher thread delivers manager responses (`agent_info_parse_response`), and the query handler thread serves task registry and VD offset queries. `stop()` only signals; the module thread releases the database and sync protocol connections once the loop has returned.

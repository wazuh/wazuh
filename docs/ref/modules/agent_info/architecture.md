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
*   **`client.keys` file**: Reads the agent's unique ID and name.
*   **`merged.mg` file**: Reads the agent's group memberships.

### **Database Integration (DBSync)**

Leverages the shared `DBSync` component for local SQLite database operations.

**Key responsibilities:**
*   Stores agent metadata in the `agent_metadata` table.
*   Stores group memberships in the `agent_groups` table.
*   Maintains operational state (e.g., sync flags, integrity timestamps) in the `db_metadata` table.
*   Detects changes by comparing new scans with the stored state, triggering callbacks for insertions, modifications, and deletions.

### **Module Coordination Protocol**

A critical feature that ensures data consistency across the agent. When a change in agent groups or other critical metadata is detected, `agent_info` orchestrates a synchronization process with other modules.

**Coordinated Modules:**
*   `FIM` (File Integrity Monitoring)
*   `SCA` (Security Configuration Assessment)
*   `Syscollector` (System Inventory)

**Coordination Steps:**
1.  **Pause**: Send a "pause" command to all coordination modules.
2.  **Flush**: Instruct each module to flush any pending data to ensure a clean state.
3.  **Get Version**: Retrieve the current synchronization version from each module.
4.  **Calculate & Set New Version**: Determine the new global version (max version or max+1) and set it on all modules.
5.  **Synchronize**: `agent_info` sends its changes to the manager, associated with the new version and the list of affected module indices.
6.  **Resume**: Send a "resume" command to all modules to restore normal operation.

This protocol guarantees that configuration changes tied to agent groups are applied atomically across the system.

---

## Data Flow

### **Initialization Flow**
1.  `wm_agent_info_main()` loads the `agent_info` shared library and sets up C-style callbacks.
2.  `agent_info_start()` creates and configures the `AgentInfoImpl` instance.
3.  The constructor initializes `DBSync`, and `loadSyncFlags()` reads the last operational state from the `db_metadata` table.
4.  `AgentInfoImpl::start()` begins the main execution loop.

### **Metadata Population and Change Detection Flow**
1.  The `start()` method periodically calls `populateAgentMetadata()`.
2.  `populateAgentMetadata()` reads data from `SysInfo`, `client.keys`, and `merged.mg`.
3.  The collected data is passed to `updateChanges()`, which uses a `DBSync` transaction to compare it with the database content.
4.  If `DBSync` detects any difference, it invokes the `processEvent()` callback with the change type (`INSERTED`, `MODIFIED`, `DELETED`).

### **Event and Coordination Flow**
```
Metadata Change Detected
         │
         ▼
populateAgentMetadata()
         │
         ▼
updateChanges() ──────────────► DBSync transaction compares data
         │                           │
         ▼                           ▼
processEvent() callback         (If a change is found)
         │
         ├─► Generate Stateless Event ─────► report_callback() ─────► Manager (immediate alert)
         │
         └─► Set Synchronization Flag ───────► setSyncFlag(true)
                   (e.g., m_shouldSyncGroups)      │
                                                   ▼
Main loop in start() detects flag ◄───────────────┘
         │
         ▼
performDeltaSync()
         │
         ▼
coordinateModules()
         │
         ├─► Pause, Flush, Versioning of FIM, SCA, Syscollector
         │
         └─► synchronizeMetadataOrGroups() ───► AgentSyncProtocol ───► Manager (reliable delivery)
```

---

## Threading Model

The `agent_info` module operates in a **single main thread**. The `start()` method contains a loop that sleeps for the configured `interval` and wakes up to perform its tasks. Asynchronous operations are handled by the module coordination protocol, which queries other modules and can poll for completion (e.g., waiting for `FIM` to finish flushing).

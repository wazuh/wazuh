# Architecture

The **SCA module** implements a security configuration assessment system that evaluates system compliance against security policies. The module loads these policies from YAML files, executes security checks, and synchronizes results with the manager.

---

## Main Components

### **SCA Implementation (sca_impl)**

The central C++ implementation (`SecurityConfigurationAssessment` class) that coordinates SCA operations.

**Key responsibilities:**
* Manages the main scanning loop
* Coordinates policy loading and execution
* Handles configuration setup and lifecycle management
* Integrates with DBSync for local data persistence
* Manages Agent Sync Protocol for manager communication

### **Policy Loader (`SCAPolicyLoader`)**

Handles loading and parsing of YAML policy files.

**Key responsibilities:**
* Loads policies from configured file paths
* Parses YAML policy structure using the configured YAML-to-JSON converter
* Validates policy metadata and check definitions
* Creates policy objects for execution
* Stores policy data in the database via DBSync

### **Rule Evaluators**

Individual evaluators for different rule types found in policy checks.

**Available evaluators:**
* **File Rule Evaluator**: Checks file existence, permissions, and content
* **Command Rule Evaluator**: Executes system commands and evaluates output
* **Registry Rule Evaluator**: Checks Windows registry keys and values
* **Directory Rule Evaluator**: Validates directory properties
* **Process Rule Evaluator**: Checks for running processes

Each evaluator processes specific rule syntax and returns pass/fail results.

### **Event Handler (`SCAEventHandler`)**

Manages the generation and delivery of SCA events.

**Key responsibilities:**
* Generates events when policy or check states change
* Handles both stateless (immediate) and stateful (persistent) message delivery
* Calls configured push functions to send events to the message queue
* Reports policy and check deltas during synchronization

### **Database Integration (DBSync)**

Uses the shared DBSync component for local SQLite database operations.

**Key responsibilities:**
* Stores policy metadata in the `sca_policy` table
* Maintains check results in the `sca_check` table
* Provides database abstraction layer for SCA data
* Handles database schema creation and management

### **Agent Sync Protocol**

Integrates with Wazuh's Agent Sync Protocol for reliable manager communication.

**Key responsibilities:**
* Persists SCA data changes for synchronization with the manager
* Handles periodic synchronization requests from the manager
* Manages the sync database and message queues
* Processes synchronization responses from the manager

---

## Data Flow

### **Initialization Flow**
1. `wm_sca_main()` loads the SCA dynamic library and sets up callbacks
2. `sca_start()` initializes the SCA implementation with configuration
3. `SecurityConfigurationAssessment` sets up DBSync connection
4. Agent Sync Protocol handle is created if synchronization is enabled
5. Module enters main scanning loop

### **Scan Execution Flow**
1. `SecurityConfigurationAssessment::Run()` executes the main loop
2. `SCAPolicyLoader` loads enabled policies from YAML files
3. For each policy, checks are executed using appropriate rule evaluators
4. `SCAEventHandler` compares results with stored state
5. Changed results trigger event generation via configured push functions

### **Synchronization Flow**
1. Stateful events are persisted via Agent Sync Protocol
2. Periodic synchronization sends accumulated changes to manager
3. Manager responses are parsed and processed
4. Database state is updated through DBSync

---

## Threading Model

The SCA module operates with the following threads:

* **Main Thread** (`wm_sca_main`): Runs the SCA implementation and handles policy execution
* **Sync Thread** (`wm_sca_sync_module`): Handles periodic synchronization with the manager (when enabled)

---

## Database Schema

### Policy Table
```sql
CREATE TABLE IF NOT EXISTS sca_policy (
    id TEXT PRIMARY KEY,
    name TEXT,
    file TEXT,
    description TEXT,
    refs TEXT
);
```

### Check Table
```sql
CREATE TABLE IF NOT EXISTS sca_check (
    checksum TEXT NOT NULL,
    id TEXT PRIMARY KEY,
    policy_id TEXT REFERENCES sca_policy(id),
    name TEXT,
    description TEXT,
    rationale TEXT,
    remediation TEXT,
    refs TEXT,
    result TEXT DEFAULT 'Not run',
    reason TEXT,
    condition TEXT,
    compliance TEXT,
    rules TEXT,
    regex_type TEXT DEFAULT 'pcre2'
);
```

---

## Event Types

### Stateful Events
- Persisted via Agent Sync Protocol for reliable delivery
- Synchronized with manager during periodic sync sessions
- Include check and policy data with operation types (CREATE, MODIFY, DELETE)

### Stateless Events  
- Sent immediately through the message queue system
- Used for real-time SCA alerts and notifications
- No local persistence or retry mechanism

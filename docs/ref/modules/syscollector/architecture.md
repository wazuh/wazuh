# Architecture

The Syscollector module follows a modular architecture designed for efficient system inventory collection, change detection, and reliable synchronization with the Wazuh manager.

## High-Level Architecture

```
┌─────────────────────────────────────────────┐
│              Wazuh Agent                    │
├─────────────────────────────────────────────┤
│                                             │
│  ┌─────────────────┐   ┌─────────────────┐  │
│  │ wm_syscollector │──▶│ Syscollector    │  │
│  │ (Configuration) │   │ Library (Scan)  │  │
│  └─────────────────┘   └─────────────────┘  │
│                                │            │
│                                ▼            │
│  ┌─────────────────┐   ┌─────────────────┐  │
│  │ Local Database  │◀──│  Event Queue    │  │
│  │   (SQLite)      │   │  (Messages)     │  │
│  └─────────────────┘   └─────────────────┘  │
│                                │            │
└────────────────────────────────┼────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────┐
│             Wazuh Manager                   │
├─────────────────────────────────────────────┤
│                                             │
│  ┌─────────────────┐   ┌─────────────────┐  │
│  │ Inventory       │──▶│ Wazuh Indexer   │  │
│  │ Harvester       │   │   (Storage)     │  │
│  └─────────────────┘   └─────────────────┘  │
│                                             │
└─────────────────────────────────────────────┘
```

## Core Components

### 1. Main Module (`wm_syscollector`)

**Location**: `src/wazuh_modules/wm_syscollector.c`

The main orchestrator responsible for:
- Loading the syscollector dynamic library
- Managing configuration from `ossec.conf`
- Controlling scan intervals and component selection
- Handling module lifecycle (start/stop/cleanup)

### 2. Syscollector Library

**Location**: `src/wazuh_modules/syscollector/`

Core inventory collection engine that:
- Performs periodic system scans
- Collects hardware, OS, network, and software inventory
- Detects changes between scans

**Inventory Categories:**
- Hardware (CPU, memory, storage)
- Operating system information
- Network interfaces, addresses, and ports
- Installed packages and software
- Running processes
- System users, groups, and services
- Browser extensions
- Windows hotfixes

### 3. Local Database

**Location**: SQLite database at `queue/syscollector/db/local.db`

Used for:
- Storing current system inventory state
- Change detection between scans
- Delta generation for efficient synchronization

### 4. Message Queue

Events are sent through the agent's message queue to the manager for direct processing by the Inventory Harvester.

## Data Flow

### Inventory Scan Process

1. **Timer Trigger**: Syscollector starts scan based on configured interval
2. **System Scan**: Library collects current inventory data
3. **Change Detection**: Compare with previous scan stored in SQLite
4. **Event Generation**: Create events for changes
5. **Message Queue**: Send events to manager via agent queue
6. **Manager Processing**: Inventory Harvester receives and indexes events

### Event Flow Diagram

```
[Timer] → [Scan] → [Compare] → [Generate Events] → [Send] → [Index]
            ↓
       [SQLite DB]
```

## Configuration

Syscollector is configured in the agent's `ossec.conf` file:

```xml
<wodle name="syscollector">
    <disabled>no</disabled>
    <interval>1h</interval>
    <scan_on_start>yes</scan_on_start>

    <!-- Inventory components -->
    <hardware>yes</hardware>
    <os>yes</os>
    <network>yes</network>
    <packages>yes</packages>
    <ports>yes</ports>
    <processes>yes</processes>
    <users>yes</users>
    <groups>yes</groups>
    <services>yes</services>
    <browser_extensions>yes</browser_extensions>
    <hotfixes>yes</hotfixes>

    <!-- Rate limiting -->
    <synchronization>
        <max_eps>10</max_eps>
    </synchronization>
</wodle>
```

See [Configuration Guide](configuration.md) for detailed options.

## Key Features

### Performance
- **Delta Synchronization**: Only sends changed inventory data
- **Configurable Intervals**: Balance freshness vs. resource usage
- **Component Selection**: Enable only needed inventory categories
- **Rate Limiting**: Control event transmission rate with `max_eps`

### Reliability
- **Change Detection**: SQLite-based state comparison
- **Automatic Retry**: Network failure recovery
- **Database Recovery**: Handles corruption gracefully
- **Modular Design**: Individual component failures don't affect others

### Security
- **Encrypted Transport**: Agent-manager communication is encrypted
- **Input Validation**: System data is sanitized before processing
- **Access Control**: Manager-side RBAC for inventory data
- **Privacy Controls**: Configurable collection of sensitive data

## Integration

### Internal
- **Message Queue**: Standard agent communication channel
- **Inventory Harvester**: Manager-side processing and indexing
- **Wazuh Database**: Agent state and configuration storage

### External
- **Wazuh Indexer**: Long-term inventory data storage and search
- **Wazuh Dashboard**: Web-based inventory visualization
- **REST API**: Programmatic access to inventory data
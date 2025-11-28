# InventorySync + Vulnerability Detection -- TestTool

## Overview

The **InventorySync VD Test Tool** (`inventory_sync_testtool`) is a comprehensive testing utility designed to validate the complete end-to-end integration between the **InventorySync** module and the **Vulnerability Detection (VD)** scanner in Wazuh. This tool simulates agent inventory data ingestion and triggers vulnerability scanning workflows without requiring a full Wazuh deployment.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Prerequisites](#prerequisites)
3. [Configuration](#configuration)
4. [Input Data Format](#input-data-format)
5. [Workflow & Message Flow](#workflow--message-flow)
6. [Usage Examples](#usage-examples)
7. [Debugging & Troubleshooting](#debugging--troubleshooting)
8. [Notes & Limitations](#notes--limitations)

---

## Architecture Overview

### Components

```
┌──────────────────┐
│   Test Tool      │ ← Simulates agent inventory messages
└────────┬─────────┘
         │
         ├─► RouterModule (queue/inventory-states)
         │
         ▼
┌──────────────────┐
│ InventorySync    │ ← Processes inventory messages
│   Facade         │   Stores in RocksDB
└────────┬─────────┘
         │
         ├─► Triggers VulnerabilityScanner
         │
         ▼
┌──────────────────┐
│ Vulnerability    │ ← Scans packages for CVEs
│   Scanner        │   Sends results to Indexer
└────────┬─────────┘
         │
         ├─► ResponseDispatcher (queue/alerts/ar)
         │
         ▼
┌──────────────────┐
│ Response Server  │ ← Receives StartAck/EndAck
│  (Test Tool)     │   Validates workflow completion
└──────────────────┘
```

### Key Features

- **End-to-End Testing**: Validates complete InventorySync → VD → Indexer pipeline
- **Message Protocol Simulation**: Uses authentic FlatBuffer-based protocol
- **Real-Time Monitoring**: Tracks StartAck/EndAck messages for synchronization
- **Comprehensive Logging**: Detailed output for debugging and analysis
- **Flexible Input**: JSON-based test data for packages, OS info, and hotfixes

---

## Prerequisites

### 1. **Indexer Instance**

The test tool **requires** a running Wazuh Indexer instance to validate end-to-end functionality.

### 2. **SSL/TLS Certificates**

The test tool requires valid SSL certificates for secure communication with the indexer.

> [!NOTE]
> Must be the same certificates that indexer is configured to use. These certs are set on the `config.json` file used by the test tool.

**Certificate Files:**

```
/path/to/certs/
├── root-ca.pem          # Root CA certificate
├── admin.pem            # Client certificate
└── admin-key.pem        # Client private key
```

---

## Configuration

### Config File Format (`config.json`)

```json
{
  "indexer": {
    "hosts": ["https://ChangeMe:9200"],
    "ssl": {
      "certificate_authorities": [
        "/var/ossec/etc/certs/root-ca.pem"
      ],
      "certificate": "/var/ossec/etc/certs/server.pem",
      "key": "/var/ossec/etc/certs/server-key.pem"
    }
  }
}
```

**Configuration Parameters:**

| Parameter                             | Required | Description                                        |
| ------------------------------------- | -------- | -------------------------------------------------- |
| `indexer.hosts`                       | Yes      | List of indexer host URLs (with protocol and port) |
| `indexer.ssl.certificate_authorities` | Yes      | Paths to CA certificates for SSL verification      |
| `indexer.ssl.certificate`             | Yes      | Path to client certificate for mutual TLS auth     |
| `indexer.ssl.key`                     | Yes      | Path to client private key for mutual TLS auth     |

---

## Input Data Format

### Input File Structure (`INPUT_XXX.json`)

The test tool accepts JSON input files containing agent inventory data.

#### **Complete Example**

```json
{
  "type": "VDFirst",
  "agent": {
    "id": "001"
  },
  "os": {
    "architecture": "x86_64",
    "hostname": "test_vm",
    "name": "Ubuntu",
    "platform": "ubuntu",
    "version": "22.04.3 LTS (Jammy Jellyfish)",
    "codename": "jammy",
    "major_version": "22",
    "minor_version": "04",
    "kernel_release": "6.5.0-18-generic"
  },
  "packages": [
    {
      "package": {
        "architecture": "amd64",
        "checksum": "eec8dacdb7087b2e0cc5ccebeb1259a6ec7a731e",
        "description": "Grafana monitoring platform",
        "name": "grafana",
        "size": 334,
        "format": "deb",
        "item_id": "f97fcd7d34fa7b705241093e8ba47c4458017285",
        "multiarch": "foreign",
        "groups": "utils",
        "version": "8.5.5"
      },
      "vendor": "contact@grafana.com",
      "id": "001_pkg_grafana"
    }
  ],
  "hotfixes": [
    {
      "hotfix": "KB5012345",
      "description": "Security Update for Windows"
    }
  ]
}
```

### Field Specifications

#### **Root Level**

| Field      | Type   | Required | Description                               |
| ---------- | ------ | -------- | ----------------------------------------- |
| `type`     | string | Yes      | Scan type: `VDFirst`, `VDSync`, `VDClean` |
| `agent.id` | string | Yes      | Agent identifier (e.g., "001", "002")     |
| `os`       | object | Yes      | Operating system information              |
| `packages` | array  | No       | List of installed packages                |
| `hotfixes` | array  | No       | List of installed hotfixes (Windows only) |

#### **OS Object**

| Field            | Type   | Required | Description                                         |
| ---------------- | ------ | -------- | --------------------------------------------------- |
| `name`           | string | Yes      | OS name (e.g., "Ubuntu", "Windows Server 2019")     |
| `version`        | string | Yes      | OS version string                                   |
| `platform`       | string | Yes      | Platform identifier (ubuntu, windows, centos, etc.) |
| `architecture`   | string | Yes      | System architecture (x86_64, aarch64, etc.)         |
| `hostname`       | string | No       | System hostname                                     |
| `codename`       | string | No       | OS codename (e.g., "jammy", "focal")                |
| `major_version`  | string | No       | Major version number                                |
| `minor_version`  | string | No       | Minor version number                                |
| `kernel_release` | string | No       | Kernel version string                               |

#### **Package Object**

**Nested Structure** (Recommended):

```json
{
  "package": {
    "name": "grafana",
    "version": "8.5.5",
    "architecture": "amd64",
    "format": "deb",
    "description": "Grafana monitoring platform",
    "size": 334,
    "item_id": "unique_package_id",
    "multiarch": "foreign",
    "groups": "utils"
  },
  "vendor": "contact@grafana.com",
  "id": "001_pkg_grafana"
}
```

| Field                  | Type    | Required | Description                                |
| ---------------------- | ------- | -------- | ------------------------------------------ |
| `package.name`         | string  | Yes      | Package name                               |
| `package.version`      | string  | Yes      | Package version                            |
| `package.format`       | string  | Yes      | Package format (deb, rpm, npm, pypi, etc.) |
| `package.architecture` | string  | No       | Package architecture                       |
| `package.description`  | string  | No       | Package description                        |
| `package.size`         | integer | No       | Package size in bytes                      |
| `vendor`               | string  | No       | Vendor/maintainer name                     |
| `id`                   | string  | No       | Unique package identifier                  |

#### **Hotfix Object** (Windows)

| Field         | Type   | Required | Description                           |
| ------------- | ------ | -------- | ------------------------------------- |
| `hotfix`      | string | Yes      | Hotfix identifier (e.g., "KB5012345") |
| `description` | string | No       | Hotfix description                    |

### Scan Types

| Type      | Description       | Use Case               |
| --------- | ----------------- | ---------------------- |
| `VDFirst` | Initial full scan | New agent registration |
| `VDSync`  | Delta scan        | Package changes only   |
| `VDClean` | Cleanup scan      | Remove all agent data  |

---

## Workflow & Message Flow

### 1. **Initialization Phase**

```
[Test Tool] → Initialize components
              ├─► RouterModule::start()
              ├─► InventorySync::start()
              └─► VulnerabilityScanner::start()
```

**Key Actions:**

- RouterModule creates UNIX domain socket at `queue/inventory-states`
- InventorySync opens RocksDB database
- VulnerabilityScanner loads CVE feed database
- ResponseServer binds to `queue/alerts/ar` for ack messages

### 2. **Start Message**

```
[Test Tool] ───Start(FlatBuffer)──► [RouterModule]
                                           │
                                           ▼
                                  [InventorySync]
                                           │
                                           ├─► Create scan session
                                           ├─► Store in RocksDB
                                           └──StartAck──► [ResponseServer]
```

**Start Message Structure:**

```cpp
{
  agentId: "001",
  mode: FULL_SCAN,
  option: VDFirst,
  totalMessages: 3,
  indices: ["wazuh-states-inventory-system", "wazuh-states-inventory-packages"],
  osData: {...}
}
```

**ResponseDispatcher Protocol:**

```
"(msg_to_agent) [] N!s <agentId> <size> <module>_sync <flatbuffer>"
Example: "(msg_to_agent) [] N!s 001 48 syscollector_sync <binary_data>"
```

### 3. **Data Messages (OS, Packages, Hotfixes)**

```
[Test Tool] ───DataValue(OS)───────► [RouterModule] ──► [InventorySync]
                                                                │
[Test Tool] ───DataValue(Package)──► [RouterModule] ──► [InventorySync]
                                                                │
[Test Tool] ───DataValue(Hotfix)───► [RouterModule] ──► [InventorySync]
                                                                │
                                                                ▼
                                                    Store in RocksDB
```

**Message Format:**

```cpp
DataValue {
  operation: INSERT | UPSERT | DELETE,
  data: JSON payload (simdjson parsed)
}
```

**Data Processing:**

```cpp
// OS Data
if (json.contains("platform") && json.contains("hostname"))
{
    Os osData = extractOSInfo(json);
    context->setOSData(osData);  // Builds CPE name
}

// Package Data
else if (json.contains("package") || json.contains("name"))
{
    PackageContextData pkg = extractPackageInfo(json);
    context->addPackageToContext(pkg, operation);
}

// Hotfix Data
else if (json.contains("hotfix"))
{
    HotfixInfo hotfix = extractHotfixInfo(json);
    RemediationDataCache::addHotfix(agentId, hotfix.id);
}
```

### 4. **End Message & Vulnerability Scanning**

```
[Test Tool] ───End(FlatBuffer)─────► [RouterModule]
                                           │
                                           ▼
                                  [InventorySync]
                                           │
                                           ├─► Finalize session
                                           ├─► Trigger VD scan
                                           │
                                           ▼
                              [VulnerabilityScanner]
                                           │
                                           ├─► Load packages from RocksDB
                                           ├─► Scan for CVEs
                                           ├─► Generate ECS events
                                           ├─► Send to Indexer
                                           │
                                           └──EndAck───► [ResponseServer]
```

**Vulnerability Scanning Pipeline:**

1. **Package Loading**: Read from RocksDB inventory
2. **CNA Resolution**: Determine CVE feed source (NVD, Debian, Ubuntu, etc.)
3. **Version Matching**: Compare installed vs vulnerable versions
4. **Platform Verification**: Validate OS compatibility
5. **Vendor Verification**: Match package vendor
6. **Hotfix Validation**: Check if CVE solved by hotfix (Windows)
7. **Event Generation**: Create ECS-formatted vulnerability events
8. **Indexer Dispatch**: Send events to OpenSearch

### 5. **Completion & Statistics**

```
[ResponseServer] ─── Receives EndAck ───► [Test Tool]
                                                │
                                                ▼
                                    Print scan statistics
                                    Show vulnerability count
                                    Exit
```

**Expected Output:**

```
[INFO] ✓ StartAck received - Session: 14039769528377457750
[INFO] Scanning package [1/1]: 'grafana' - Vendor: 'grafana' - Version: '8.5.5'
[INFO] Analyzing CVE: CVE-2022-23498 - Package 'grafana' (v.8.5.5) is VULNERABLE
[INFO] Scan for package 'grafana' ended - Found 21 vulnerabilities (analyzed 143 CVE candidates)
[INFO] Agent '001' - Scan completed in 245 ms: 1 packages scanned, 1 vulnerable packages, 21 total vulnerabilities found
[INFO] ✓ EndAck received - Session: 14039769528377457750
[INFO] Test completed successfully!
```

---

## Usage Examples

Add to `.vscode/launch.json`:

### VSCode `launch.json` example

```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "name": "(gdb) InventorySync VD Test - Full Scan",
      "type": "cppdbg",
      "request": "launch",
      "program": "${workspaceFolder}/src/build/wazuh_modules/inventory_sync/testtool/inventory_sync_testtool",
      "args": [
        "001",
        "delta",
        "VDSync",
        "--input",
        "${workspaceFolder}/src/wazuh_modules/inventory_sync/testtool/test_data/INPUT_000.json",
        "--config",
        "${workspaceFolder}/src/wazuh_modules/inventory_sync/testtool/test_data/config.json",
        "--wait",
        "15",
        "--verbose"
      ],
      "stopAtEntry": false,
      "cwd": "${workspaceFolder}",
      "environment": [],
      "externalConsole": false,
      "MIMode": "gdb",
      "setupCommands": [
        {
          "description": "Enable pretty-printing for gdb",
          "text": "-enable-pretty-printing",
          "ignoreFailures": true
        },
        {
          "description": "Set disassembly flavor to Intel",
          "text": "-gdb-set disassembly-flavor intel",
          "ignoreFailures": true
        }
      ],
      "preLaunchTask": "build",
      "miDebuggerPath": "/usr/bin/gdb"
    }
  ]
}
```

### Command Line Arguments

```
inventory_sync_testtool <agent_id> <mode> <option> [FLAGS]

POSITIONAL ARGUMENTS:
  agent_id              Agent identifier (e.g., 001, 002)
  mode                  Scan mode: full | delta
  option                Scan option: VDFirst | VDSync | VDClean

FLAGS:
  --input <file>        Input JSON file with test data (required)
  --config <file>       Configuration file with indexer settings (required)
  --wait <seconds>      Wait time after End message (default: 10)
  --verbose             Enable verbose logging
```

---

## Debugging & Troubleshooting

### Common Issues

#### 1. **No StartAck/EndAck Received**

**Symptom:**

```
[ERROR] Timeout waiting for StartAck
```

**Possible Causes:**

- InventorySync not running
- Incorrect socket path (`queue/alerts/ar`)
- ResponseDispatcher not sending messages

#### 2. **Indexer Connection Failed**

**Symptom:**

```
[ERROR] Failed to connect to indexer
[ERROR] SSL certificate verification failed
```

**Causes:**

- Incorrect indexer URL
- Invalid/missing SSL certificates
- Indexer on red or yellow status

#### 3. **FlatBuffer Parsing Errors**

**Symptom:**

```
[WARN] Invalid FlatBuffer message, skipping
[WARN] Failed to iterate JSON: INSUFFICIENT_PADDING
```

**Causes:**

- Incorrect message format
- simdjson padding issue
- Corrupted RocksDB data

#### 4. **No Vulnerabilities Found (False Negative)**

**Symptom:**

```
[INFO] Agent '001' - Scan completed: 0 vulnerabilities found
```

**Debugging Steps:**

1. **Check CTI Database**
2. **Enable Debug Logging**
3. **Verify Package Data**
4. **Check Version Matching**

```
[DEBUG] Analyzing CVE: CVE-2022-23498 - Package 'grafana' (v.8.5.5) is NOT vulnerable
[DEBUG] Installed version is HIGHER to affected version '8.5.3'
```

---

## Notes & Limitations

### Important Notes

1. **Stateful Testing**: The tool maintains state in RocksDB. Running multiple tests may require cleaning the database:

   ```bash
   rm -rf /tmp/wazuh_inventorysync_test.db
   ```

2. **Socket Cleanup**: UNIX domain sockets may persist after crashes:

   ```bash
   rm -f queue/inventory-states queue/alerts/ar
   ```

3. **Indexer Indices**: Ensure indices exist before running tests (see Prerequisites).

4. **CVE Feed**: Vulnerability detection requires a populated CVE feed database.

5. **Agent ID Uniqueness**: Use different agent IDs for parallel tests to avoid conflicts.

### Known Limitations

1. **No Agent Communication**: This tool simulates agent messages but doesn't connect to real agents.

2. **Single Agent**: Designed for single-agent testing. Multi-agent scenarios require separate runs or modify the tool.

3. **Feed Updates**: CVE feed updates are not triggered automatically. Use VulnerabilityScanner's feed update mechanism.

4. **Network Policies**: May fail in environments with strict firewall rules (requires indexer access).

5. **Windows Hotfixes**: Hotfix testing requires Windows-specific CVE data in the feed.

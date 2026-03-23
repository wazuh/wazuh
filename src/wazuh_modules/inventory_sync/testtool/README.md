# InventorySync + Vulnerability Detection -- TestTool

## Overview

The **InventorySync VD Test Tool** (`inventory_sync_testtool`) is a comprehensive testing utility designed to validate the complete end-to-end integration between the **InventorySync** module and the **Vulnerability Detection (VD)** scanner in Wazuh.

This tool now uses a **single JSON input file** that describes the whole inventory sync session:

- The initial **Start** message (agent metadata, mode, option, indices, etc.).
- All **DataValue** messages (packages, hotfixes, etc.).
- All **DataContext** messages (OS documents, additional context).

It simulates agent inventory data ingestion with real **FlatBuffer** messages and triggers vulnerability scanning workflows without requiring a full Wazuh deployment.

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

```text
┌──────────────────┐
│   Test Tool      │ ← Reads JSON input (Start + data_values + data_context)
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

- **End-to-End Testing**: Validates complete InventorySync → VD → Indexer pipeline.
- **Message Protocol Simulation**: Uses authentic FlatBuffer-based protocol (Start, DataValue, DataContext, End).
- **JSON-Driven Session**: A single JSON file describes the whole sync session.
- **Real-Time Monitoring**: Tracks StartAck/EndAck messages for synchronization.
- **Comprehensive Logging**: Detailed output for debugging and analysis.
- **Flexible Input**: JSON-based test data for packages, OS info, and hotfixes.

---

## Prerequisites

### 1. **Indexer Instance**

The test tool **requires** a running Wazuh Indexer instance to validate end-to-end functionality.

### 2. **SSL/TLS Certificates**

The test tool requires valid SSL certificates for secure communication with the indexer.

> **Note**
> Certificates must match the Indexer configuration. These paths are set in the `config.json` file used by the test tool.

**Certificate Files:**

```text
/path/to/certs/
├── root-ca.pem          # Root CA certificate
├── manager.pem           # Client certificate
└── manager-key.pem       # Client private key
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
        "/var/wazuh-manager/etc/certs/root-ca.pem"
      ],
      "certificate": "/var/wazuh-manager/etc/certs/manager.pem",
      "key": "/var/wazuh-manager/etc/certs/manager-key.pem"
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

The test tool accepts a **single JSON file** that fully describes one InventorySync session.
The high-level structure is:

```json
{
  "Start": {
    "... Start message fields ..."
  },
  "data_values": [
    {
      "operation": "upsert | delete",
      "payload": { "... Indexer document for a package/hotfix ..." }
    }
  ],
  "data_context": [
    {
      "payload": { "... Indexer document for OS or extra context ..." }
    }
  ]
}
```

- `Start` → Used to build the FlatBuffer **Start** message.
- `data_values[]` → Converted to **DataValue** messages.
- `data_context[]` → Converted to **DataContext** messages (always treated as upsert).

### `Start` Object

The `Start` block maps 1:1 to the InventorySync Start message:

```json
{
  "Start": {
    "agentid": "001",
    "mode": "delta",
    "option": "VDSync",
    "agentname": "ubuntu22",
    "agentversion": "v5.0.0",
    "architecture": "aarch64",
    "hostname": "ubuntu22",
    "osname": "Ubuntu",
    "osplatform": "ubuntu",
    "ostype": "linux",
    "osversion": "22.04.5 LTS (Jammy Jellyfish)",
    "groups": ["default"],
    "indices": [
      "wazuh-states-inventory-packages",
      "wazuh-states-inventory-system"
    ],
    "size": 3
  }
}
```

**Field Summary:**

| Field          | Type     | Required | Description                                             |
| -------------- | -------- | -------- | ------------------------------------------------------- |
| `agentid`      | string   | Yes      | Agent identifier (`Start.agentid`).                     |
| `mode`         | string   | Yes      | `"full"` or `"delta"` → mapped to `Mode_ModuleFull/Delta`. |
| `option`       | string   | Yes      | `"VDFirst"`, `"VDSync"`, or `"Sync"`.                   |
| `agentname`    | string   | Yes      | Agent name.                                             |
| `agentversion` | string   | Yes      | Agent version.                                          |
| `architecture` | string   | Yes      | Agent architecture (e.g., `x86_64`, `aarch64`).         |
| `hostname`     | string   | Yes      | Hostname reported by the agent.                         |
| `osname`       | string   | Yes      | OS name (e.g., `Ubuntu`, `Windows Server 2019`).        |
| `osplatform`   | string   | Yes      | OS platform (`ubuntu`, `windows`, `centos`, etc.).      |
| `ostype`       | string   | Yes      | OS type (`linux`, `windows`, etc.).                     |
| `osversion`    | string   | Yes      | OS version string.                                      |
| `groups`       | string[] | No       | Agent groups (defaults to `["default"]` if missing).    |
| `indices`      | string[] | Yes      | Inventory indices touched in this session.              |
| `size`         | integer  | Yes      | Total number of messages (`data_values + data_context`). |

### `data_values[]` Array

Each entry represents one **DataValue** message. The tool:

1. Reads `operation` (`"upsert"` or `"delete"`).
2. Reads `payload`.
3. Uses `payload._index` as the FlatBuffer index.
4. Serializes `payload._source` as the FlatBuffer `data` field (raw JSON).

#### Example

```json
"data_values": [
  {
    "operation": "upsert",
    "payload": {
      "_index": "wazuh-states-inventory-packages",
      "_id": "wazuh_001_f033cfe690b80a478fb4c832934f0fd55927c349",
      "_score": 2,
      "_source": {
        "wazuh": {
          "agent": {
            "id": "001",
            "name": "ubuntu22",
            "version": "v5.0.0",
            "groups": ["default"],
            "host": {
              "architecture": "aarch64",
              "hostname": "ubuntu22",
              "os": {
                "name": "Ubuntu",
                "platform": "ubuntu",
                "type": "linux",
                "version": "22.04.5 LTS (Jammy Jellyfish)"
              }
            }
          }
        },
        "checksum": {
          "hash": {
            "sha1": "c665573c916b60392f615c71742948813a60bbf5"
          }
        },
        "package": {
          "category": "misc",
          "installed": null,
          "path": null,
          "priority": "optional",
          "source": null,
          "type": "deb",
          "vendor": "contact@grafana.com",
          "version": "8.5.5",
          "architecture": "amd64",
          "checksum": "eec8dacdb7087b2e0cc5ccebeb1259a6ec7a731e",
          "description": "Grafana",
          "name": "grafana",
          "size": 334,
          "format": "deb",
          "item_id": "f97fcd7d34fa7b705241093e8ba47c4458017285",
          "multiarch": "foreign",
          "groups": "utils"
        },
        "state": {
          "document_version": 1,
          "modified_at": "2025-11-27T12:31:07.733Z"
        }
      }
    }
  },
  {
    "operation": "delete",
    "payload": {
      "_index": "wazuh-states-inventory-packages",
      "_id": "wazuh_001_f033cfe690b80a478fb4c832934f0fd55927c350",
      "_score": 2,
      "_source": {
        "wazuh": {
          "agent": {
            "id": "001",
            "name": "ubuntu22",
            "version": "v5.0.0",
            "groups": ["default"],
            "host": {
              "architecture": "aarch64",
              "hostname": "ubuntu22",
              "os": {
                "name": "Ubuntu",
                "platform": "ubuntu",
                "type": "linux",
                "version": "22.04.5 LTS (Jammy Jellyfish)"
              }
            }
          }
        },
        "checksum": {
          "hash": {
            "sha1": "82771c9b43f0434021653ebaa811e26e0ebaed5d"
          }
        },
        "package": {
          "architecture": "all",
          "category": "oldlibs",
          "description": "transitional package for https support",
          "installed": null,
          "multiarch": "foreign",
          "name": "apt-transport-https",
          "path": null,
          "priority": "optional",
          "size": 169984,
          "source": "apt",
          "type": "deb",
          "vendor": "Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>",
          "version": "2.4.14"
        },
        "state": {
          "document_version": 1,
          "modified_at": "2025-11-27T12:31:07.733Z"
        }
      }
    }
  }
]
```

- For **packages**, the orchestrator reads `_source.package` and extracts all package fields.
- `operation: "upsert"` → `ElementOperation::Upsert`.
- `operation: "delete"` → `ElementOperation::Delete`.

### `data_context[]` Array

Each entry becomes a **DataContext** message. There is **no operation flag**; all are treated as **upserts** and used to enrich OS/context data.

Example (OS context document):

```json
"data_context": [
  {
    "payload": {
      "_index": "wazuh-states-inventory-system",
      "_id": "wazuh_001_f033cfe690b80a478fb4c832934f0fd55927c351",
      "_score": 2,
      "_source": {
        "wazuh": {
          "agent": {
            "id": "001",
            "name": "ubuntu22",
            "version": "v5.0.0",
            "groups": ["default"],
            "host": {
              "architecture": "aarch64",
              "hostname": "ubuntu22",
              "os": {
                "name": "Ubuntu",
                "platform": "ubuntu",
                "type": "linux",
                "version": "22.04.5 LTS (Jammy Jellyfish)"
              }
            }
          }
        },
        "checksum": {
          "hash": {
            "sha1": "996d7206f3c607c7aa377702d65c1b53a80d2a84"
          }
        },
        "host": {
          "architecture": "aarch64",
          "hostname": "ubuntu24",
          "os": {
            "build": null,
            "codename": "noble",
            "distribution": {
              "release": null
            },
            "full": null,
            "kernel": {
              "name": "Linux",
              "release": "6.8.0-71-generic",
              "version": "#71-Ubuntu SMP PREEMPT_DYNAMIC Tue Jul 22 16:44:45 UTC 2025"
            },
            "major": "24",
            "minor": "04",
            "name": "Ubuntu",
            "patch": "2",
            "platform": "ubuntu",
            "type": "linux",
            "version": "24.04.2 LTS (Noble Numbat)"
          }
        },
        "state": {
          "document_version": 1,
          "modified_at": "2025-11-27T11:57:48.873Z"
        }
      }
    }
  }
]
```

- The orchestrator reads `_source.host.os` to populate `OsContextData`.
- Start already provides basic OS fields; DataContext OS documents fill in missing details (kernel, codename, major/minor, etc.).

### Scan Types

Controlled by `Start.option`:

| Value     | Description       | Use Case               |
| --------- | ----------------- | ---------------------- |
| `VDFirst` | Initial full scan | New agent registration |
| `VDSync`  | Delta scan        | Package changes only   |

---

## Workflow & Message Flow

### 1. **Initialization Phase**

```text
[Test Tool] → Initialize components
              ├─► RouterModule::start()
              ├─► InventorySync::start()
              └─► VulnerabilityScanner::start()
```

**Key Actions:**

- RouterModule creates UNIX domain socket at `queue/inventory-states`.
- InventorySync opens RocksDB database.
- VulnerabilityScanner loads CVE feed database.
- ResponseServer binds to `queue/alerts/ar` for ack messages.

### 2. **Start Message**

```text
[Test Tool] ───Start(FlatBuffer)──► [RouterModule]
                                           │
                                           ▼
                                  [InventorySync]
                                           │
                                           ├─► Create scan session
                                           ├─► Store basic context in RocksDB
                                           └──StartAck──► [ResponseServer]
```

The Start message is built directly from the `Start` object in the JSON file.

Conceptual structure:

```cpp
Start {
  agentid: "001",
  module: "syscollector",
  mode: Mode_ModuleDelta,
  option: Option_VDSync,
  size: <data_values + data_context>,
  index: ["wazuh-states-inventory-system", "wazuh-states-inventory-packages"],
  agentname: "ubuntu22",
  agentversion: "v5.0.0",
  architecture: "aarch64",
  hostname: "ubuntu22",
  osname: "Ubuntu",
  osplatform: "ubuntu",
  ostype: "linux",
  osversion: "22.04.5 LTS (Jammy Jellyfish)",
  groups: ["default"]
}
```

**ResponseDispatcher Protocol (manager side, for reference):**

```text
"(msg_to_agent) [] N!s <agentId> <size> <module>_sync <flatbuffer>"
Example: "(msg_to_agent) [] N!s 001 48 syscollector_sync <binary_data>"
```

### 3. **Data Messages (OS, Packages, Hotfixes)**

```text
[Test Tool] ───DataValue(Package)──► [RouterModule] ──► [InventorySync]
                                                                │
[Test Tool] ───DataValue(Hotfix)───► [RouterModule] ──► [InventorySync]
                                                                │
[Test Tool] ───DataContext(OS)─────► [RouterModule] ──► [InventorySync]
                                                                │
                                                                ▼
                                                    Store in RocksDB
```

**Message Format (conceptual):**

```cpp
DataValue {
  session: <StartAck.session>,
  seq: <0..N-1>,
  operation: INSERT | UPSERT | DELETE,
  index: "wazuh-states-inventory-packages" / "wazuh-states-inventory-hotfixes",
  data: <JSON payload stored as raw bytes>
}

DataContext {
  session: <StartAck.session>,
  seq: <...>,
  index: "wazuh-states-inventory-system" / ...,
  data: <JSON payload stored as raw bytes>
}
```

InventorySync writes these documents to RocksDB. Later, VD reads them and builds a `ScanContext`:

- Agent data from **Start**.
- OS data from **Start** + **DataContext (OS)**.
- Packages + operations from **DataValue (packages)**.
- Hotfixes from **DataValue/DataContext (hotfix index)**.

### 4. **End Message & Vulnerability Scanning**

```text
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
                                           ├─► Build ScanContext from RocksDB
                                           ├─► Scan packages for CVEs
                                           ├─► Generate ECS events
                                           ├─► Send to Indexer
                                           │
                                           └──EndAck───► [ResponseServer]
```

**Vulnerability Scanning Pipeline:**

1. **Package Loading**: Read inventory documents from RocksDB.
2. **OS Resolution**: Merge OS data from Start and OS DataContext.
3. **CNA/Feed Resolution**: Determine CVE feed source (NVD, Debian, Ubuntu, etc.).
4. **Version Matching**: Compare installed vs vulnerable versions.
5. **Platform & Vendor Checks**: Ensure OS and package vendor match the CVE conditions.
6. **Hotfix Validation**: Check if the CVE is remediated by installed hotfixes (Windows).
7. **Event Generation**: Build ECS-formatted vulnerability events.
8. **Indexer Dispatch**: Send ECS events to OpenSearch.

### 5. **Completion & Statistics**

```text
[ResponseServer] ─── Receives EndAck ───► [Test Tool]
                                                │
                                                ▼
                                    Print scan statistics
                                    Show vulnerability count
                                    Exit
```

**Expected Output (example):**

```text
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

### VSCode `launch.json` example

```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "name": "(gdb) InventorySync VD Test - Session from JSON",
      "type": "cppdbg",
      "request": "launch",
      "program": "${workspaceFolder}/src/build/bin/inventory_sync_testtool",
      "args": [
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
      "MIMode": "cppdbg",
      "setupCommands": [
        {
          "description": "Enable pretty-printing for gdb",
          "text": "-enable-pretty-printing",
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

The CLI is now **fully driven by the JSON input**.
You no longer pass `agent_id`, `mode`, or `option` as positional arguments; all of that lives in the `Start` object.

```text
inventory_sync_testtool [FLAGS]

FLAGS:
  --input <file>        Input JSON file with test data (required)
  --config <file>       Configuration file with indexer settings (required)
  --wait <seconds>      Wait time after End message (default: 10)
  --verbose             Enable verbose logging
```

Example:

```bash
./inventory_sync_testtool \
  --input src/wazuh_modules/inventory_sync/testtool/test_data/INPUT_000.json \
  --config src/wazuh_modules/inventory_sync/testtool/test_data/config.json \
  --wait 15 \
  --verbose
```

---

## Debugging & Troubleshooting

### Common Issues

#### 1. **No StartAck/EndAck Received**

**Symptom:**

```text
[ERROR] Timeout waiting for StartAck
```

**Possible Causes:**

- InventorySync not running correctly.
- Incorrect socket path (`queue/alerts/ar`).
- ResponseDispatcher not sending messages.
- Start message malformed (check `Start` object in the JSON).

#### 2. **Indexer Connection Failed**

**Symptom:**

```text
[ERROR] Failed to connect to indexer
[ERROR] SSL certificate verification failed
```

**Causes:**

- Incorrect indexer URL.
- Invalid/missing SSL certificates.
- Indexer in red/yellow status or unavailable.

#### 3. **FlatBuffer Parsing Errors**

**Symptom:**

```text
[WARN] Invalid FlatBuffer message, skipping
[WARN] Failed to iterate JSON: INSUFFICIENT_PADDING
```

**Causes:**

- Incorrect message format.
- simdjson padding issue when building JSON payloads.
- Corrupted RocksDB data from previous runs.

#### 4. **No Vulnerabilities Found (False Negative)**

**Symptom:**

```text
[INFO] Agent '001' - Scan completed: 0 vulnerabilities found
```

**Debugging Steps:**

1. **Check CTI Database**: Ensure the CVE feed is populated and up to date.
2. **Enable Debug Logging**: Run with `--verbose` and check VD logs.
3. **Verify Package Data**: Confirm versions, vendors, and platforms in `data_values`.
4. **Check Version Matching**:

   ```text
   [DEBUG] Analyzing CVE: CVE-2022-23498 - Package 'grafana' (v.8.5.5) is NOT vulnerable
   [DEBUG] Installed version is HIGHER than affected version '8.5.3'
   ```

---

## Notes & Limitations

### Important Notes

1. **Stateful Testing**
   The tool maintains state in RocksDB. Running multiple tests with the same agent/session may require cleaning the database:

   ```bash
   rm -rf /tmp/wazuh_inventorysync_test.db
   ```

2. **Socket Cleanup**
   UNIX domain sockets may persist after crashes:

   ```bash
   rm -f queue/inventory-states queue/alerts/ar
   ```

3. **Indexer Indices**
   Ensure inventory indices exist and are healthy before running tests (see Prerequisites).

4. **CVE Feed**
   Vulnerability detection requires a populated CVE feed database (ADP/NVD + vendor feeds).

5. **Agent ID Uniqueness**
   Use different agent IDs for parallel tests to avoid conflicts in RocksDB and Indexer.

### Known Limitations

1. **No Real Agent Communication**
   This tool simulates agent messages only; it does not connect to real agents.

2. **Single-Agent Flow**
   Designed primarily for single-agent testing. Multi-agent scenarios require separate runs or custom modifications.

3. **Feed Updates**
   CVE feed updates are not triggered automatically. Use the VulnerabilityScanner feed update mechanism separately.

4. **Network Policies**
   May fail in environments with strict firewall rules (requires network access to the Indexer).

5. **Windows Hotfix Coverage**
   Hotfix-based remediation testing requires Windows-specific CVE data to be present in the feed.

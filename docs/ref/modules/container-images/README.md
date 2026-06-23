# Container Images

The **Container Images** module introduces agent-side support for collecting inventory from container images. In the first development stage, the module discovers image references from configured local OCI image layouts and reads basic image metadata during periodic scans.

The module is implemented as an **agent-only** `wazuh-modulesd` module. It follows the same module layout used by other inventory components: a C glue layer handles configuration and lifecycle, while a C++ shared library contains the scan logic.

> **Note:** This stage covers module scaffolding, local OCI layout discovery, metadata reading, and logging. Package extraction, local persistence, change events, manager synchronization, indexing, Vulnerability Detector integration, and runtime or registry readers are not implemented yet.

## Overview

Container Images scans configured image sources and reports what it discovers in the agent logs. The current implementation focuses on local OCI image layouts, which can be read directly from disk without a container daemon.

### Key Features

- **Agent-only module**: Available in agent builds and excluded from the server/manager build.
- **Periodic scanning**: Supports scan on start and interval-based rescans.
- **Local OCI layout reader**: Reads OCI image layouts from configured local paths.
- **Format detection**: Detects unsupported local formats, logs them, and skips them safely.
- **C/C++ module split**: Uses the same dynamic-library pattern as other Wazuh modules.
- **Extensible reader interface**: New source types can be added through the `IImageReader` interface.

### How It Works

1. **Configuration**: The agent parses the `<container_images>` block in `ossec.conf`.
2. **Startup**: `wazuh-modulesd` loads `libcontainer_images.so` and initializes the C++ implementation.
3. **Scanning**: The module scans on start when configured, then waits for the next interval.
4. **Discovery**: Each configured local path is inspected and read when it contains an OCI image layout.
5. **Logging**: The module logs discovered image references and the scan summary.

## Supported Sources

| Source | Status | Description |
|--------|--------|-------------|
| Local OCI image layout | Supported | A local directory containing an OCI image layout. |
| Docker archive | Detected only | The format is detected and skipped. |
| containerd content store | Detected only | The format is detected and skipped. |
| Runtime sockets | Not implemented | Reserved for a future stage. |
| Remote registries | Not implemented | Reserved for a future stage. |

## Quick Start

### Basic Configuration

Add a `<container_images>` block to the agent `ossec.conf` file:

```xml
<container_images>
  <enabled>yes</enabled>
  <scan_on_start>yes</scan_on_start>
  <interval>1h</interval>
  <references>
    <local>/path/to/oci/layout</local>
  </references>
</container_images>
```

### Verify Operation

Run the agent with debug logging enabled and check the `wazuh-modulesd:container_images` log entries:

```sql
wazuh-modulesd:container_images: DEBUG: Module initialized.
wazuh-modulesd:container_images: DEBUG: Scan on start.
wazuh-modulesd:container_images: INFO: Scan started.
wazuh-modulesd:container_images: DEBUG: Discovered image reference /path/to/oci/layout (local) digest=sha256:d529dd0c....
wazuh-modulesd:container_images: INFO: Scan ended. Discovered 1 image references.
```

## Current Limitations

- Package extraction from image layers is not implemented.
- Local SQLite persistence and DBSync integration are not implemented.
- Agent Sync Protocol synchronization is not implemented.
- Vulnerability Detector integration is not implemented.
- Runtime, registry, archive, Windows, and Kubernetes integrations are not implemented.

## Documentation

| Document | Description |
|----------|-------------|
| [Configuration](configuration.md) | Configuration options, defaults, and source references |
| [Architecture](architecture.md) | Technical architecture, data flow, and threading model |
| [API Reference](api-reference.md) | Internal C and C++ interfaces |

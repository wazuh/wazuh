# Container Images

The **Container Images** module introduces agent-side support for collecting inventory from container images. The module discovers image references from configured image inputs on disk and inventories the packages their layers contain during periodic scans.

The module is implemented as an **agent-only** `wazuh-modulesd` module. It follows the same module layout used by other inventory components: a C glue layer handles configuration and lifecycle, while a C++ shared library contains the scan logic.

> **Note:** This stage covers image discovery from saved archives and OCI image layouts, package extraction for the `dpkg` and `apk` formats, and local persistence of the inventory. RPM extraction, change events, manager synchronization, indexing, Vulnerability Detector integration, and the container engine and registry readers are not implemented yet.

## Overview

Container Images scans configured image sources, stores what it finds in a local database, and reports the scan in the agent logs. The inputs are images on disk, which are read without a container daemon: saved image archives and OCI image layout directories.

### Key Features

- **Agent-only module**: The shared library that performs the scan is built for agent targets only. The C glue is compiled everywhere, so the manager validates the configuration but never runs the module.
- **Periodic scanning**: Supports scan on start and interval-based rescans.
- **Digest check**: An image still reporting the configuration digest already stored is not read again, so an unchanged image costs its metadata and nothing more.
- **Read failure handling**: A reference that cannot be read keeps the inventory an earlier scan stored for it, instead of having it reported as deleted.
- **Archive reader**: Reads saved image archives (`docker save`) and OCI image layout directories.
- **Streaming layer reader**: Streams layer blobs, gzip-compressed, zstd-compressed or plain, without extracting an image to disk.
- **Package extraction**: Composes the image layers in manifest order, applies the OverlayFS deletion markers, and parses the `dpkg` and `apk` databases.
- **Format detection**: Detects the inputs and package formats that are not implemented yet, logs them, and continues.
- **C/C++ module split**: Uses the same dynamic-library pattern as other Wazuh modules.
- **Extensible reader interface**: New source types can be added through the `IImageReader` interface.

### How It Works

1. **Configuration**: The agent parses the `<container_images>` block in `ossec.conf`.
2. **Startup**: `wazuh-modulesd` loads `libcontainer_images.so` and initializes the C++ implementation.
3. **Scanning**: The module scans on start when configured, then waits for the next interval.
4. **Discovery**: Each configured reference is read, and the images it holds are enumerated from the image metadata.
5. **Extraction**: The layers of each image are streamed in manifest order, and the package databases they carry are parsed.
6. **Persistence**: The references and their packages are stored in the local database, which reports what changed since the previous scan.
7. **Logging**: The module logs the discovered image references and the scan summary.

## Supported Sources

| Source | Entry | Status | Description |
|--------|-------|--------|-------------|
| Saved image archive | `<archive>` | Supported | The output of `docker save`, holding either an OCI layout or the older `manifest.json` layout. |
| OCI image layout | `<archive>` | Supported | A directory containing an OCI image layout. |
| Container engine store | `<local>` | Not implemented | Accepted by the configuration and reported. |
| Remote registries | `<ref>` | Not implemented | Accepted by the configuration and reported. |

## Supported Package Formats

| Format | Status |
|--------|--------|
| dpkg (`var/lib/dpkg/status`) | Parsed. Installed packages only. |
| apk (`lib/apk/db/installed`, `usr/lib/apk/db/installed`) | Parsed. |
| rpm, sqlite and ndb databases (`var/lib/rpm/`, `usr/lib/sysimage/rpm/`) | Parsed. |
| rpm, Berkeley DB database (`var/lib/rpm/Packages`) | Recognized. The image is inventoried with zero packages and a warning. |
| pacman, portage, xbps, swupd | Recognized. The image is inventoried with zero packages and a warning. |

## Supported Layer Compressions

| Compression | Status |
|-------------|--------|
| gzip | Decompressed. |
| zstd | Decompressed. |
| none | Read as a plain tar. |
| xz, bzip2, lz4 | Recognized. The layer is skipped with a warning. |

gzip, zstd and none are the compressions the OCI image specification defines for a layer. The rest cannot appear in a conformant image, and are recognized so that a layer using one is reported rather than read as if it were corrupt.

## Quick Start

### Basic Configuration

Add a `<container_images>` block to the agent `ossec.conf` file:

```xml
<container_images>
  <enabled>yes</enabled>
  <scan_on_start>yes</scan_on_start>
  <interval>1h</interval>
  <references>
    <archive>/var/tmp/images/myapp.tar</archive>
  </references>
</container_images>
```

### Verify Operation

Run the agent with debug logging enabled and check the `wazuh-modulesd:container_images` log entries:

```sql
wazuh-modulesd:container_images: INFO: Configuration loaded: enabled=yes, scan_on_start=yes, interval=3600, references=1.
wazuh-modulesd:container_images: DEBUG: Reference configured: <archive>/var/tmp/images/myapp.tar.
wazuh-modulesd:container_images: DEBUG: Module initialized.
wazuh-modulesd:container_images: DEBUG: Scan on start.
wazuh-modulesd:container_images: INFO: Scan started.
wazuh-modulesd:container_images: DEBUG: Parsed 132 packages from 'var/lib/dpkg/status'.
wazuh-modulesd:container_images: DEBUG: Reference '/var/tmp/images/myapp.tar' manifest=sha256:d529dd0c... packages=132.
wazuh-modulesd:container_images: INFO: Scan ended. 1 references, 132 packages.
```

## Current Limitations

- RPM package extraction is not implemented; an RPM-based image is inventoried with zero packages and a warning.
- Agent Sync Protocol synchronization is not implemented, so the stored inventory stays on the agent.
- Vulnerability Detector integration is not implemented.
- Remote images are read from GitHub Container Registry. Other registries, the container engine, Windows registry support, and Kubernetes integrations are not implemented.

## Documentation

| Document | Description |
|----------|-------------|
| [Configuration](configuration.md) | Configuration options, defaults, and source references |
| [Architecture](architecture.md) | Technical architecture, data flow, and threading model |
| [API Reference](api-reference.md) | Internal C and C++ interfaces |
| [Persistence](persistence.md) | Package inventory storage, schema, and change detection |

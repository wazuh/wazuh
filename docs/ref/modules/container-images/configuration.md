# Configuration

The Container Images module is configured in the agent `ossec.conf` file using the `<container_images>` section. The configuration is agent-only: the block is parsed in agent builds and ignored by the server/manager.

Synchronization options are not available in this stage. State synchronization and manager-side cleanup are planned for later development stages; this stage stores the inventory locally on the agent.

The block is optional. When the block is present, all settings have defaults and the module can be disabled with `<enabled>no</enabled>`.

> **Note:** Image inputs on disk are read through the `<archive>` reference type: saved image archives (`docker save`) and OCI image layout directories. The `<ref>` and `<local>` entry types are accepted by the parser and reported as unimplemented, so the grammar does not change when they are implemented.

---

## Basic Configuration

### Minimal Configuration

```xml
<container_images>
  <enabled>yes</enabled>
  <references>
    <archive>/var/tmp/images/myapp.tar</archive>
  </references>
</container_images>
```

This enables the module with default settings:

- Scan on start: enabled
- Scan interval: `1h`
- Source type: image archive or OCI image layout on disk

### Full Configuration Example

```xml
<container_images>
  <enabled>yes</enabled>
  <scan_on_start>yes</scan_on_start>
  <interval>1h</interval>
  <references>
    <archive>/var/tmp/images/myapp.tar</archive>
    <archive>/var/tmp/images/myapp-oci-layout</archive>
  </references>
</container_images>
```

---

## Configuration Options

### Core Settings

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | boolean | `yes` | Enable or disable the module. When disabled, the module thread exits without scanning. |
| `scan_on_start` | boolean | `yes` | Run a scan when the agent starts. |
| `interval` | time | `1h` | Time between scans. |

### Reference Management

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `references` | section | empty | Container section for image sources. |
| `references/archive` | string | empty | Path to a saved image archive or to an OCI image layout directory. This element can be repeated. |
| `references/ref` | string | empty | Image in a remote registry. Accepted and reported as unimplemented. |
| `references/local` | string | empty | Image in the local container engine store. Accepted and reported as unimplemented. |

---

## Time Interval Format

The `interval` option accepts a positive integer with an optional unit suffix:

| Format | Example | Description |
|--------|---------|-------------|
| Seconds | `3600s` or `3600` | Scan every 3600 seconds |
| Minutes | `60m` | Scan every 60 minutes |
| Hours | `1h` | Scan every hour |
| Days | `1d` | Scan once per day |

Invalid values include `0`, an empty value, or a value with an unsupported suffix.

---

## Reference Configuration

### Entry Types

The grammar holds three entry types. Only `<archive>` is implemented; the other two are accepted so that implementing them later adds behaviour without touching the configuration.

| Entry | Meaning | Status |
|-------|---------|--------|
| `<archive>` | Saved image archive or OCI image layout on disk. | Implemented. |
| `<ref>` | Image in a remote registry. | Accepted, reported as unimplemented. |
| `<local>` | Image in the local container engine store. | Accepted, reported as unimplemented. |

```xml
<references>
  <archive>/var/tmp/images/myapp.tar</archive>
  <archive>/var/tmp/images/myapp-oci-layout</archive>
</references>
```

An unimplemented entry type is reported once per scan and costs nothing else:

```sql
wazuh-modulesd:container_images: WARNING: NOT IMPLEMENTED: the '<ref>' reference 'nginx:1.27' needs remote registry support, which is not available yet. Skipping it.
```

### Archive Input Detection

An `<archive>` value is either a file or a directory, and the layout it holds is identified from its content:

| Input | Marker | Behavior |
|-------|--------|----------|
| Saved image archive | A tar file holding `index.json` or `manifest.json` | The images it holds are inventoried. |
| OCI image layout directory | `oci-layout` file | The images it holds are inventoried. |
| Saved archive extracted into a directory | `manifest.json` file | The images it holds are inventoried. |
| containerd content store | `io.containerd.content.v1.content` entry | Reported as unimplemented, it belongs to the engine store. |
| Unknown | none of the above | Logged and skipped. |

An input that cannot be read is not fatal. The module logs a warning and continues with the remaining references.

### Supported Package Formats

The packages of an image come from the package database its layers carry:

| Format | Database path | Status |
|--------|---------------|--------|
| dpkg | `var/lib/dpkg/status` | Parsed. Installed packages only. |
| apk | `lib/apk/db/installed`, `usr/lib/apk/db/installed` | Parsed. The second path is used by Wolfi and Chainguard images. |
| rpm | `var/lib/rpm/`, `usr/lib/sysimage/rpm/` | Recognized, not parsed yet. |
| pacman | `var/lib/pacman/local/` | Recognized, not parsed yet. |
| portage | `var/db/pkg/` | Recognized, not parsed yet. |
| xbps | `var/db/xbps/` | Recognized, not parsed yet. |
| swupd | `usr/share/clear/bundles/` | Recognized, not parsed yet. |

### Layer Compression

A layer blob is identified from its own first bytes rather than from the media type the image declares:

| Compression | Status |
|-------------|--------|
| gzip | Decompressed. |
| zstd | Decompressed. |
| none | Read as a plain tar. |
| xz, bzip2, lz4 | Recognized, not supported. The layer is skipped and reported. |

A layer using a compression that is recognized but not supported is skipped, and the image is inventoried with whatever its other layers hold:

```sql
wazuh-modulesd:container_images: WARNING: NOT IMPLEMENTED: layer 'blobs/sha256/<digest>' of '/var/tmp/images/myapp.tar' is xz compressed, which is recognized but not supported yet. Skipping it.
```

An image whose package format is recognized but not parsed yet is still inventoried, with zero packages and one warning:

```sql
wazuh-modulesd:container_images: WARNING: NOT IMPLEMENTED: image at '/var/tmp/images/centos.tar' uses the package format(s) rpm, which are recognized but not supported yet. Reporting zero packages.
```

---

## Configuration Validation

### Validation Rules

The Container Images module validates configuration at startup:

1. `enabled` must be `yes` or `no`.
2. `scan_on_start` must be `yes` or `no`.
3. `interval` must be a positive time value.

### Error Handling

An invalid module setting, meaning `enabled`, `scan_on_start` or `interval`, causes a configuration error and rejects the module block.

Anything wrong with a single entry inside `<references>` costs that entry only: it is logged with a warning and ignored, and the remaining references are still configured. This covers an entry name that is not one of the three types, and an entry whose value is empty. Unknown elements directly inside `<container_images>` are also logged with a warning and ignored.

A reference entry is skipped rather than rejected because rejecting it invalidates the whole module configuration, which stops `wazuh-modulesd` from starting; since the control script tests every daemon's configuration before starting any of them, a single empty entry would otherwise leave the agent with no daemon running.

---

## Platform Notes

- The module is configured only on agents.
- Images are read from disk: saved archives and OCI image layout directories. No container engine and no registry access is involved.
- Layers are streamed, gzip-compressed, zstd-compressed or plain, so no image is extracted to disk and the image filesystem is never reconstructed.
- No existing module configuration options are changed by this block.

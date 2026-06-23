# Configuration

The Container Images module is configured in the agent `ossec.conf` file using the `<container_images>` section. The configuration is agent-only: the block is parsed in agent builds and ignored by the server/manager.

The block is optional. When the block is present, all settings have defaults and the module can be disabled with `<enabled>no</enabled>`.

> **Note:** This first development stage supports local OCI image layout paths through the `<local>` reference type. Other source types are reserved for later stages.

---

## Basic Configuration

### Minimal Configuration

```xml
<container_images>
  <enabled>yes</enabled>
  <references>
    <local>/path/to/oci/layout</local>
  </references>
</container_images>
```

This enables the module with default settings:

- Scan on start: enabled
- Scan interval: `1h`
- Source type: local OCI image layout

### Full Configuration Example

```xml
<container_images>
  <enabled>yes</enabled>
  <scan_on_start>yes</scan_on_start>
  <interval>1h</interval>
  <references>
    <local>/path/to/oci/layout</local>
    <local>/another/oci/layout</local>
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
| `references/local` | string | empty | Path to a local OCI image layout. This element can be repeated. |

Synchronization options are not available in this stage. Local persistence, state synchronization, and manager-side cleanup are planned for later development stages.

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

### Local OCI Layout Paths

The `<local>` option points to a local path on the agent host:

```xml
<references>
  <local>/var/lib/container-images/app</local>
</references>
```

The path must point to a directory. In the current stage, the reader only processes directories that contain an OCI image layout.

### Local Source Format Detection

For each configured local path, the module inspects the directory and determines the local format:

| Detected format | Marker | Behavior |
|-----------------|--------|----------|
| OCI image layout | `oci-layout` file | The image references are enumerated. |
| containerd content store | `io.containerd.content.v1.content` entry | Detected and skipped. |
| Docker archive | `manifest.json` file | Detected and skipped. |
| Unknown | none of the above | Logged and skipped. |

Unsupported formats are not fatal. The module logs a warning and continues with the remaining sources.

```sql
wazuh-modulesd:container_images: WARNING: NOT IMPLEMENTED: local format 'docker-archive' at '/path' is not supported yet, skipping.
```

---

## Configuration Validation

### Validation Rules

The Container Images module validates configuration at startup:

1. `enabled` must be `yes` or `no`.
2. `scan_on_start` must be `yes` or `no`.
3. `interval` must be a positive time value.
4. `references/local` values must not be empty.

### Error Handling

Invalid required values cause a configuration error and reject the module block. Unknown elements inside `<container_images>` and unsupported reference types inside `<references>` are logged with a warning and ignored.

---

## Platform Notes

- The module is configured only on agents.
- The first implementation reads local on-disk OCI image layouts.
- No existing module configuration options are changed by this block.

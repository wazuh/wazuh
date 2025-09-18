# Configuration

Syscollector is configured in the agent's `ossec.conf` file using the `<wodle name="syscollector">` section.

## Basic Configuration

```xml
<wodle name="syscollector">
    <disabled>no</disabled>
    <interval>1h</interval>
    <scan_on_start>yes</scan_on_start>

    <!-- Inventory categories -->
    <hardware>yes</hardware>
    <os>yes</os>
    <network>yes</network>
    <packages>yes</packages>
    <ports all="yes">yes</ports>
    <processes>yes</processes>
    <users>yes</users>
    <groups>yes</groups>
    <services>yes</services>
    <browser_extensions>yes</browser_extensions>
    <hotfixes>yes</hotfixes> <!-- Windows only -->

    <!-- Rate limiting -->
    <synchronization>
        <max_eps>10</max_eps>
    </synchronization>
</wodle>
```

## Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `disabled` | `no` | Enable/disable the module |
| `interval` | `1h` | Scan interval (minimum 60s) |
| `scan_on_start` | `yes` | Scan when agent starts |

### Inventory Categories

| Category | Default | Description |
|----------|---------|-------------|
| `hardware` | `yes` | CPU, memory, storage |
| `os` | `yes` | Operating system info |
| `network` | `yes` | Network interfaces |
| `packages` | `yes` | Installed software |
| `ports` | `yes` | Open network ports |
| `processes` | `yes` | Running processes |
| `users` | `yes` | System user accounts |
| `groups` | `yes` | System groups |
| `services` | `yes` | System services |
| `browser_extensions` | `yes` | Browser add-ons |
| `hotfixes` | `yes` | Windows updates (Windows only) |

### Advanced Options

| Option | Default | Range | Description |
|--------|---------|-------|-------------|
| `max_eps` | `10` | 0-1000000 | Events per second limit |

**Note**: The `ports` element accepts an optional `all` attribute:
- `<ports all="yes">`: Scan all ports
- `<ports all="no">`: Scan only listening ports

## Common Configuration Examples

### Minimal Configuration (Performance Optimized)
```xml
<wodle name="syscollector">
    <disabled>no</disabled>
    <interval>24h</interval>
    <hardware>yes</hardware>
    <os>yes</os>
    <packages>yes</packages>
    <!-- Disable resource-intensive scans -->
    <processes>no</processes>
    <ports>no</ports>
    <browser_extensions>no</browser_extensions>
</wodle>
```

### Security-Focused Configuration
```xml
<wodle name="syscollector">
    <disabled>no</disabled>
    <interval>1h</interval>
    <packages>yes</packages>
    <services>yes</services>
    <users>yes</users>
    <groups>yes</groups>
    <hotfixes>yes</hotfixes>
    <ports all="yes">yes</ports>
</wodle>
```

### High-Frequency Monitoring
```xml
<wodle name="syscollector">
    <disabled>no</disabled>
    <interval>5m</interval>
    <processes>yes</processes>
    <ports>yes</ports>
    <synchronization>
        <max_eps>50</max_eps>
    </synchronization>
</wodle>
```

## Platform Notes

- **Windows**: `hotfixes` category is Windows-specific
- **Linux**: Package collection varies by distribution (RPM, DEB, etc.)
- **macOS**: Includes .pkg files and Homebrew packages
- **All platforms**: Browser extensions support major browsers

## Testing Configuration

Validate configuration syntax:
```bash
/var/ossec/bin/wazuh-agentd -t
```

Monitor for errors:
```bash
tail -f /var/ossec/logs/ossec.log | grep syscollector
```
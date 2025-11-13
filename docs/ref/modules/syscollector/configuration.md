# Configuration

Syscollector is configured in the agent's `ossec.conf` file using the `<wodle name="syscollector">` section. The module supports both basic inventory collection and advanced synchronization features for persistent inventory state management.

---

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
    <max_eps>50</max_eps>                        <!-- Stateless/real-time inventory event rate limit -->
    <notify_first_scan>no</notify_first_scan>    <!-- First scan notification -->

    <!-- Advanced synchronization settings -->
    <synchronization>
        <enabled>yes</enabled>                    <!-- Enable/disable persistence -->
        <interval>300</interval>                  <!-- Sync interval in seconds -->
        <response_timeout>60</response_timeout>   <!-- Response timeout in seconds -->
        <max_eps>10</max_eps>                    <!-- Max sync events per second (0 = unlimited) -->
    </synchronization>
</wodle>
```

---

## Configuration Options

### Basic Module Settings

| Option | Default | Range | Description |
|--------|---------|-------|-------------|
| `disabled` | `no` | `yes`/`no` | Enable/disable the module |
| `interval` | `1h` | `>= 60s` | Scan interval (minimum 60 seconds) |
| `scan_on_start` | `yes` | `yes`/`no` | Scan when agent starts |
| `max_eps` | `50` | `0` - `1000000` | Maximum events per second for **stateless/real-time inventory events** (0 = unlimited) |
| `notify_first_scan` | `no` | `yes`/`no` | Generate events during initial inventory scan |

### Inventory Categories

| Category | Default | Description |
|----------|---------|-------------|
| `hardware` | `yes` | CPU, memory, storage information |
| `os` | `yes` | Operating system details |
| `network` | `yes` | Network interfaces and configuration |
| `packages` | `yes` | Installed software packages |
| `ports` | `yes` | Open network ports |
| `processes` | `yes` | Running processes |
| `users` | `yes` | System user accounts |
| `groups` | `yes` | System groups |
| `services` | `yes` | System services |
| `browser_extensions` | `yes` | Browser add-ons and extensions |
| `hotfixes` | `yes` | Windows updates (Windows only) |

**Note**: The `ports` element accepts an optional `all` attribute:
- `<ports all="yes">`: Scan all ports
- `<ports all="no">`: Scan only listening ports

---

## Synchronization Configuration

The synchronization feature enables persistent inventory state management through the Agent Sync Protocol.

### Synchronization Configuration Parameters

| Parameter | Type | Default | Range | Description |
|-----------|------|---------|--------|-------------|
| `enabled` | Boolean | `yes` | `yes`/`no` | Enable or disable Syscollector synchronization persistence |
| `interval` | Integer | `300` | `1` - `∞` | How often to trigger synchronization with the manager (seconds) |
| `response_timeout` | Integer | `60` | `1` - `∞` | Timeout for waiting manager responses during sync (seconds) |
| `max_eps` | Integer | `10` | `0` - `1000000` | Maximum events per second for **sync messages** (0 = unlimited) |

---

## Configuration Details

### Enable/Disable Persistence

The `enabled` parameter controls whether Syscollector uses persistence or falls back to legacy behavior:

```xml
<synchronization>
    <enabled>yes</enabled>
</synchronization>
```

**Implementation:**
```c
unsigned int enable_synchronization:1;  /* Enable database synchronization */
```

When disabled, Syscollector only generates stateless events without persistence.

### Synchronization Interval

Controls how frequently the agent attempts to synchronize pending inventory events:

```xml
<synchronization>
    <interval>300</interval>  <!-- 5 minutes -->
</synchronization>
```

**Implementation:**
```c
uint32_t sync_interval;  /* Synchronization interval */
```

**Considerations:**
- Lower values provide faster synchronization but increase manager load
- Higher values reduce network traffic but delay inventory delivery
- Should account for inventory scan frequency to avoid overwhelming sync queue

### Response Timeout

Defines how long to wait for manager acknowledgments during synchronization:

```xml
<synchronization>
    <response_timeout>60</response_timeout>
</synchronization>
```

**Implementation:**
```c
uint32_t sync_response_timeout;  /* Minimum interval for the synchronization process */
```

**Considerations:**
- Should be adjusted based on network latency
- Too low may cause unnecessary retries
- Too high may delay error detection
- Inventory payloads can be larger than FIM events, may need higher timeouts

### Sync Events Per Second

Controls the rate of synchronization messages sent to the manager:

```xml
<synchronization>
    <max_eps>10</max_eps>
</synchronization>
```

**Implementation:**
```c
uint32_t sync_max_eps;  /* Maximum sync events per second */
```

**Purpose:**
- Prevents overwhelming the manager with inventory synchronization traffic
- Separate from stateless inventory event rate limiting
- Set to `0` for unlimited (not recommended for production)

### First Scan Notification

Controls whether Syscollector generates events during the initial inventory scan:

```xml
<notify_first_scan>no</notify_first_scan>
```

**Implementation:**
```c
unsigned int notify_first_scan:1;  /* Generate events on first scan */
```

**Behavior:**
- When `yes`: Generates events for all inventory items found during initial scan
- When `no` (default): Suppresses events during first scan, only reports changes after baseline establishment

### Stateless Inventory Event Rate Limit

Controls the maximum rate of stateless inventory events sent to the manager:

```xml
<max_eps>50</max_eps>
```

**Implementation:**
```c
uint32_t max_eps;  /* Maximum events per second for stateless inventory */
```

**Purpose:**
- Limits immediate inventory change notifications
- Separate from synchronization event rate limiting

---

## Event Rate Control

### Dual Rate Limiting

Syscollector implements separate rate controls for different event types:

#### Stateless Inventory Events

```xml
<max_eps>50</max_eps>  <!-- Outside synchronization block -->
```

**Controls:**
- Stateless immediate inventory change alerts
- Higher priority than sync messages

#### Synchronization Events

```xml
<synchronization>
    <max_eps>10</max_eps>  <!-- Inside synchronization block -->
</synchronization>
```

**Controls:**
- Stateful persistence messages sent during sync sessions
- Batch inventory state synchronization

## Configuration Examples

### High-Frequency Environments

For environments with frequent inventory changes:

```xml
<wodle name="syscollector">
    <max_eps>100</max_eps>
    <notify_first_scan>no</notify_first_scan>

    <synchronization>
        <enabled>yes</enabled>
        <interval>120</interval>         <!-- Sync every 2 minutes -->
        <response_timeout>60</response_timeout>
        <max_eps>25</max_eps>           <!-- Higher sync throughput -->
    </synchronization>
</wodle>
```

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

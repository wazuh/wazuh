# Configuration

The **Syscollector** module's persistence functionality can be configured through the `<synchronization>` section within the `<wodle name="syscollector">` block in `ossec.conf`. The module works with default settings but allows fine-tuning of synchronization behavior for different environments.

---

## Synchronization Configuration

### Basic Configuration

```xml
<wodle name="syscollector">
    <max_eps>50</max_eps>                        <!-- Stateless/real-time inventory event rate limit -->
    <notify_first_scan>no</notify_first_scan>    <!-- First scan notification -->

    <synchronization>
        <enabled>yes</enabled>                    <!-- Enable/disable persistence -->
        <interval>300</interval>                  <!-- Sync interval in seconds -->
        <response_timeout>30</response_timeout>   <!-- Response timeout in seconds -->
        <max_eps>10</max_eps>                    <!-- Max sync events per second (0 = unlimited) -->
    </synchronization>
</wodle>
```

### Synchronization Configuration Parameters

| Parameter | Type | Default | Range | Description |
|-----------|------|---------|--------|-------------|
| `enabled` | Boolean | `yes` | `yes`/`no` | Enable or disable Syscollector synchronization persistence |
| `interval` | Integer | `300` | `1` - `∞` | How often to trigger synchronization with the manager (seconds) |
| `response_timeout` | Integer | `30` | `1` - `∞` | Timeout for waiting manager responses during sync (seconds) |
| `max_eps` | Integer | `10` | `0` - `1000000` | Maximum events per second for **sync messages** (0 = unlimited) |

### General Syscollector Parameters

| Parameter | Type | Default | Range | Description |
|-----------|------|---------|--------|-------------|
| `max_eps` | Integer | `50` | `0` - `1000000` | Maximum events per second for **stateless/real-time inventory events** (0 = unlimited) |
| `notify_first_scan` | Boolean | `no` | `yes`/`no` | Generate events during initial inventory scan |

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
    <response_timeout>30</response_timeout>
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

---

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

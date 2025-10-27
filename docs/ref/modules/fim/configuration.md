# Configuration

The **FIM** module's persistence functionality can be configured through the `<synchronization>` section within the `<syscheck>` block in `ossec.conf`. The module works with default settings but allows fine-tuning of synchronization behavior for different environments.

---

## Synchronization Configuration

### Basic Configuration

```xml
<syscheck>
    <max_eps>50</max_eps>                        <!-- Stateless/real-time FIM event rate limit -->
    <notify_first_scan>no</notify_first_scan>    <!-- First scan notification -->

    <synchronization>
        <enabled>yes</enabled>                    <!-- Enable/disable persistence -->
        <interval>300</interval>                  <!-- Sync interval in seconds -->
        <response_timeout>60</response_timeout>   <!-- Response timeout in seconds -->
        <max_eps>10</max_eps>                    <!-- Max sync events per second (0 = unlimited) -->
        <integrity_interval>86400</integrity_interval> <!-- Integrity check interval in seconds -->
    </synchronization>
</syscheck>
```

### Synchronization Configuration Parameters

| Parameter | Type | Default | Range | Description |
|-----------|------|---------|--------|-------------|
| `enabled` | Boolean | `yes` | `yes`/`no` | Enable or disable FIM synchronization persistence |
| `interval` | Integer | `300` | `1` - `∞` | How often to trigger synchronization with the manager (seconds) |
| `response_timeout` | Integer | `60` | `1` - `∞` | Timeout for waiting manager responses during sync (seconds) |
| `max_eps` | Integer | `10` | `0` - `1000000` | Maximum events per second for **sync messages** (0 = unlimited) |
| `integrity_interval` | Integer | `86400` | `1` - `∞` | How often to perform integrity validation checks (seconds) |

### General Syscheck Parameters

| Parameter | Type | Default | Range | Description |
|-----------|------|---------|--------|-------------|
| `max_eps` | Integer | `50` | `0` - `1000000` | Maximum events per second for **stateless/real-time FIM events** (0 = unlimited) |
| `notify_first_scan` | Boolean | `no` | `yes`/`no` | Generate events during initial scan |

---

## Configuration Details

### Enable/Disable Persistence

The `enabled` parameter controls whether FIM uses persistence or falls back to legacy behavior:

```xml
<synchronization>
    <enabled>yes</enabled>
</synchronization>
```

**Implementation:**
```c
unsigned int enable_synchronization:1;  /* Enable database synchronization */
```

When disabled, FIM only generates stateless events without persistence.

### Synchronization Interval

Controls how frequently the agent attempts to synchronize pending events:

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
- Higher values reduce network traffic but delay event delivery

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

### Rate Limiting (max_eps)

Controls the maximum rate of synchronization message transmission:

```xml
<synchronization>
    <max_eps>100</max_eps>  <!-- 100 events per second -->
</synchronization>
```

**Implementation:**
```c
long sync_max_eps;  /* Maximum events per second for synchronization messages. */
```

**Special Values:**
- `0`: No rate limiting (unlimited)
- `1-1000000`: Events per second limit

### Integrity Interval

Controls how frequently the agent performs integrity validation checks to detect inconsistencies between the agent and manager databases:

```xml
<synchronization>
    <integrity_interval>86400</integrity_interval>  <!-- 24 hours -->
</synchronization>
```

**Implementation:**
```c
uint32_t integrity_interval;  /* Integrity check interval */
```

---

## Hard-coded Constants

Some synchronization parameters are defined as constants and cannot be changed via configuration:

```c
#define FIM_SYNC_PROTOCOL_DB_PATH   "queue/fim/db/fim_sync.db"  // Database path
#define FIM_SYNC_RETRIES 3                                      // Retry attempts
```

### Retry Logic

The sync protocol automatically retries failed operations up to `FIM_SYNC_RETRIES` (3) times before giving up.

---

## Database Paths

### Fixed Paths

The following database paths are hard-coded and cannot be changed:

- **FIM Database**: `queue/fim/db/fim.db`
- **Sync Protocol Database**: `queue/fim/db/fim_sync.db` (`FIM_SYNC_PROTOCOL_DB_PATH`)

These paths are relative to the Wazuh installation directory.

---

## General Syscheck Configuration

FIM configuration options at the main syscheck level:

### max_eps

Controls the maximum rate of FIM event generation (separate from sync rate limiting):

```xml
<syscheck>
    <max_eps>100</max_eps>  <!-- Maximum FIM events per second -->
</syscheck>
```

**Implementation:**
```c
int max_eps;  /* Maximum events per second. */
```

**Configuration Details:**
- **Range:** `0` - `1000000`
- **Default:** `50`
- **Purpose:** Rate limiting for stateless/real-time FIM event generation
- **Event Types:** Applies to immediate FIM events sent to the manager in real-time
- **Note:** This is different from `synchronization->max_eps` which only limits synchronization messages for stateful events

### notify_first_scan

Controls whether to generate events during the initial file system scan:

```xml
<syscheck>
    <notify_first_scan>yes</notify_first_scan>  <!-- Generate events on first scan -->
</syscheck>
```

**Implementation:**
```c
unsigned int notify_first_scan;  /* Notify the first scan */
```

**Configuration Details:**
- **Values:** `yes`/`no`
- **Default:** `no`
- **Purpose:** When enabled, FIM generates events for all files found during the initial scan
- **Use Case:** Useful for getting immediate visibility into the file system state

---

## Configuration Examples

### Basic Configuration with General Options

```xml
<syscheck>
    <max_eps>100</max_eps>                     <!-- Stateless/real-time FIM event rate limit -->
    <notify_first_scan>yes</notify_first_scan> <!-- Generate events on first scan -->

    <synchronization>
        <enabled>yes</enabled>
        <interval>300</interval>
        <response_timeout>60</response_timeout>
        <max_eps>10</max_eps>                  <!-- Sync-specific rate limit -->
        <integrity_interval>86400</integrity_interval>  <!-- Integrity check every 24 hours -->
    </synchronization>
</syscheck>
```

### High-Performance Environment

For environments with high file change rates:

```xml
<syscheck>
    <max_eps>1000</max_eps>                    <!-- High stateless/real-time event rate -->
    <notify_first_scan>no</notify_first_scan>  <!-- Skip first scan events -->

    <synchronization>
        <enabled>yes</enabled>
        <interval>60</interval>                <!-- More frequent sync -->
        <response_timeout>60</response_timeout>
        <max_eps>500</max_eps>                 <!-- High sync rate limit -->
        <integrity_interval>43200</integrity_interval>  <!-- More frequent integrity checks (12 hours) -->
    </synchronization>
</syscheck>
```

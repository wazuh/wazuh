# Client Configuration Reference

Complete configuration reference for the Wazuh agent daemon (agentd).

**Configuration file:** `/var/ossec/etc/ossec.conf` (Linux/Unix) or `C:\Program Files (x86)\ossec-agent\ossec.conf` (Windows)

**XML Sections:** `<client>`, `<client_buffer>`, `<anti_tampering>`

**Module:** Agent-only

**Internal Options:** `agent.*`, `windows.*` (Windows only)

For module overview and architecture, see [Client Module](index.html).

---

## Client Configuration (`<client>`)

Configures the agent's connection to the Wazuh manager.

### server

Manager server configuration block. Multiple `<server>` blocks can be defined for failover.

**Sub-options:**

#### address

Manager IP address or hostname.

- **Required:** Yes (at least one server must be defined)
- **Allowed values:** Valid IPv4, IPv6 address, or hostname
- **Example:** `192.168.1.100`, `manager.example.com`, `::1`

#### port

Manager port number.

- **Default value:** `1514`
- **Allowed values:** Valid port number (1-65535)
- **Example:** `1514`

#### protocol

Communication protocol.

- **Default value:** `tcp`
- **Allowed values:** `tcp`, `udp`
- **Recommendation:** Use `tcp` for reliable delivery

#### max_retries

Maximum connection retry attempts before failing over to next server.

- **Default value:** `5`
- **Allowed values:** Positive integer
- **Note:** Only applicable when multiple servers are configured

### config-profile

Agent configuration profile (used with centralized configuration via `agent.conf`).

- **Default value:** None
- **Allowed values:** Comma-separated profile names (no spaces)
- **Example:** `webserver,production,linux`
- **Usage:** Manager uses this to target specific configurations in `agent.conf`

### notify_time

Interval between agent keep-alive notifications to the manager.

- **Default value:** `60`
- **Allowed values:** Positive integer (seconds)
- **Minimum:** `10`
- **Note:** Manager considers agent disconnected after 3x this interval

### time-reconnect

Time to wait before attempting to reconnect after connection loss.

- **Default value:** `60`
- **Allowed values:** Positive integer (seconds)
- **Minimum:** `1`

### auto_restart

Automatically restart agent when receiving configuration updates from manager.

- **Default value:** `yes`
- **Allowed values:** `yes`, `no`
- **Note:** Required for centralized configuration updates to take effect

### crypto_method

Encryption method for communication with manager.

- **Default value:** `aes`
- **Allowed values:** `aes`, `blowfish`
- **Recommendation:** Use `aes` (modern, secure)

### enrollment

Agent auto-enrollment configuration block (optional).

**Sub-options:**

#### enabled

Enable automatic agent enrollment.

- **Default value:** `yes`
- **Allowed values:** `yes`, `no`

#### manager_address

Manager address for enrollment (can differ from data connection).

- **Default value:** Value from `<server><address>`
- **Allowed values:** Valid IPv4, IPv6 address, or hostname

#### port

Manager enrollment port (authd).

- **Default value:** `1515`
- **Allowed values:** Valid port number (1-65535)

#### agent_name

Custom agent name for enrollment.

- **Default value:** System hostname
- **Allowed values:** Any string

#### groups

Comma-separated list of groups to assign during enrollment.

- **Default value:** `default`
- **Allowed values:** Comma-separated group names

#### authorization_pass_path

Path to file containing enrollment authorization password.

- **Default value:** None
- **Allowed values:** Valid file path
- **Note:** Password must match manager's authd password

---

## Client Buffer Configuration (`<client_buffer>`)

Configures event buffering when the manager is unreachable.

### disabled

Enable or disable client buffering.

- **Default value:** `no`
- **Allowed values:** `yes`, `no`
- **Note:** When enabled (`no`), events are buffered during manager disconnections

### queue_size

Maximum number of events to buffer.

- **Default value:** `5000`
- **Allowed values:** Positive integer
- **Minimum:** `1`
- **Maximum:** System memory dependent
- **Note:** Events exceeding this limit are dropped

### events_per_second

Maximum events per second to send when reconnecting (rate limiting).

- **Default value:** `500`
- **Allowed values:** Positive integer
- **Minimum:** `1`
- **Note:** Prevents overwhelming manager during reconnection

### buffer_type

Buffer storage type.

- **Default value:** `disk`
- **Allowed values:** `disk`, `memory`
- **Note:** Disk buffering persists across agent restarts

---

## Anti-Tampering Configuration (`<anti_tampering>`)

Protects against unauthorized agent modifications and uninstallation.

**Platform:** Linux/Unix only (not available on Windows or macOS)

### disabled

Enable or disable anti-tampering protection.

- **Default value:** `no`
- **Allowed values:** `yes`, `no`

### package_uninstallation

Prevent agent package uninstallation.

- **Default value:** `yes`
- **Allowed values:** `yes`, `no`
- **Behavior:** When enabled, prevents `apt remove`, `yum remove`, etc.

---

## Internal Options

Additional client settings can be configured in the internal options file.

**Configuration file:** `/var/ossec/etc/local_internal_options.conf` (recommended) or `/var/ossec/etc/internal_options.conf`

**Note:** Modify `local_internal_options.conf` instead of `internal_options.conf` to preserve settings across upgrades.

### Connection and Network Settings

```ini
# Debug level for agentd (0=no debug, 1=basic, 2=verbose)
agent.debug=0

# Receive timeout in seconds (default: 60)
agent.recv_timeout=60

# Send timeout in seconds (default: 60)
agent.send_timeout=60

# TCP keep-alive idle time in seconds (default: 30)
agent.tcp_keepidle=30

# TCP keep-alive interval between probes in seconds (default: 10)
agent.tcp_keepintvl=10

# TCP keep-alive probe count (default: 3)
agent.tcp_keepcnt=3

# Maximum retry attempts for failed requests (default: 4)
agent.max_attempts=4

# Request pool size (default: 1024)
agent.request_pool=1024

# Request RTO (retransmission timeout) in seconds (default: 1)
agent.request_rto_sec=1

# Request RTO in milliseconds (default: 0)
agent.request_rto_msec=0

# Remote configuration enabled (0=no, 1=yes, default: 1)
agent.remote_conf=1

# Minimum events per second threshold (default: 50)
agent.min_eps=50

# State reporting interval in seconds (default: 5)
agent.state_interval=5
```

### Buffer Settings

```ini
# Warning level for buffer usage percentage (default: 90)
agent.warn_level=90

# Normal level for buffer usage percentage (default: 70)
agent.normal_level=70

# Tolerance for buffer fluctuations (default: 10)
agent.tolerance=10
```

### Log Rotation Settings

```ini
# Compress rotated logs (0=no, 1=yes, default: 1)
monitord.compress=1

# Days to keep rotated logs (default: 365)
monitord.keep_log_days=365

# Time of day to rotate logs (hh:mm format, default: 00:00)
monitord.day_wait=0

# Maximum log file size in MB before rotation (default: 0 = unlimited)
monitord.size_rotate=0

# Number of daily rotations to keep (default: 12)
monitord.daily_rotations=12

# Enable automatic log rotation (0=no, 1=yes, default: 1)
monitord.rotate_log=1
```

---

## Configuration Examples

### Basic Client Configuration

Single manager, standard settings:

```xml
<client>
  <server>
    <address>10.0.0.10</address>
    <port>1514</port>
    <protocol>tcp</protocol>
  </server>
  <config-profile>webserver,production</config-profile>
  <notify_time>60</notify_time>
  <time-reconnect>60</time-reconnect>
  <auto_restart>yes</auto_restart>
  <crypto_method>aes</crypto_method>
</client>
```

### Failover Configuration

Multiple managers for high availability:

```xml
<client>
  <server>
    <address>manager1.example.com</address>
    <port>1514</port>
    <protocol>tcp</protocol>
    <max_retries>3</max_retries>
  </server>
  <server>
    <address>manager2.example.com</address>
    <port>1514</port>
    <protocol>tcp</protocol>
    <max_retries>3</max_retries>
  </server>
  <server>
    <address>manager3.example.com</address>
    <port>1514</port>
    <protocol>tcp</protocol>
    <max_retries>3</max_retries>
  </server>
  <notify_time>30</notify_time>
  <time-reconnect>30</time-reconnect>
</client>
```

### Auto-Enrollment Configuration

Automatic agent registration:

```xml
<client>
  <enrollment>
    <enabled>yes</enabled>
    <manager_address>manager.example.com</manager_address>
    <port>1515</port>
    <agent_name>web-server-prod-01</agent_name>
    <groups>webservers,production</groups>
    <authorization_pass_path>/var/ossec/etc/authd.pass</authorization_pass_path>
  </enrollment>
  <server>
    <address>manager.example.com</address>
    <port>1514</port>
    <protocol>tcp</protocol>
  </server>
</client>
```

### Client Buffer Configuration

High-volume environment with disk buffering:

```xml
<client_buffer>
  <disabled>no</disabled>
  <queue_size>50000</queue_size>
  <events_per_second>1000</events_per_second>
  <buffer_type>disk</buffer_type>
</client_buffer>
```

### Anti-Tampering Configuration

Maximum protection (Linux only):

```xml
<anti_tampering>
  <disabled>no</disabled>
  <package_uninstallation>yes</package_uninstallation>
</anti_tampering>
```

### Complete Agent Configuration

Full example with all sections:

```xml
<ossec_config>
  <client>
    <server>
      <address>manager1.example.com</address>
      <port>1514</port>
      <protocol>tcp</protocol>
      <max_retries>5</max_retries>
    </server>
    <server>
      <address>manager2.example.com</address>
      <port>1514</port>
      <protocol>tcp</protocol>
      <max_retries>5</max_retries>
    </server>
    <config-profile>webserver,production,linux</config-profile>
    <notify_time>60</notify_time>
    <time-reconnect>60</time-reconnect>
    <auto_restart>yes</auto_restart>
    <crypto_method>aes</crypto_method>
    <enrollment>
      <enabled>yes</enabled>
      <manager_address>manager1.example.com</manager_address>
      <port>1515</port>
      <groups>webservers,production</groups>
    </enrollment>
  </client>

  <client_buffer>
    <disabled>no</disabled>
    <queue_size>10000</queue_size>
    <events_per_second>600</events_per_second>
    <buffer_type>disk</buffer_type>
  </client_buffer>

  <anti_tampering>
    <disabled>no</disabled>
    <package_uninstallation>yes</package_uninstallation>
  </anti_tampering>

  <logging>
    <log_format>plain</log_format>
  </logging>
</ossec_config>
```

---

## See Also

- [Client Module](index.html) - Module overview and architecture
- [Remote Configuration](../../configuration/manager/remote.md) - Manager-side agent listener configuration
- [Centralized Configuration](../../configuration/centralized/agent.conf.md) - Group-based configuration
- [Agent Enrollment](../agent-management/enrollment.md) - Agent registration process

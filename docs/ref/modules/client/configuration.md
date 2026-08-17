# Client Configuration Reference

Complete configuration reference for the Wazuh agent daemon (agentd).

**Configuration file:** `/var/ossec/etc/ossec.conf` (Linux/Unix) or `C:\Program Files (x86)\ossec-agent\ossec.conf` (Windows)

**XML Sections:** `<agent>`, `<anti_tampering>`

**Module:** Agent-only

**Internal Options:** `agent.*`, `windows.*` (Windows only)

For module overview and architecture, see [Client Module](index.html).

---

## Agent Configuration (`<agent>`)

Configures the agent's connection to the Wazuh manager.

`<client>` is the 4.X name of this block and is renamed to `<agent>` in 5.0. A configuration left by a 4.X agent still starts: `<server><address>` is read from `<client>` and the port defaults to `1517`. No other option inside `<client>` is read, so rename the block to `<agent>` to keep them all.

### server

Manager server configuration block.

**Sub-options:**

#### address

Manager IP address or hostname.

- **Required:** Yes (at least one server must be defined)
- **Allowed values:** Valid IPv4, IPv6 address, or hostname
- **Example:** `192.168.1.100`, `manager.example.com`, `::1`

#### port

Manager port number for the agent's HTTPS connection.

- **Default value:** `1517`
- **Allowed values:** Valid port number (1-65535)
- **Example:** `1517`
- **Note:** A `<port>` inside a legacy `<client><server>` block is not read.

#### protocol

**DEPRECATED:** This option is parsed but ignored. Communication protocol is hard-coded to TCP.

- **Status:** Deprecated (kept for backward compatibility)
- **Behavior:** Always uses TCP regardless of configured value
- **Note:** The parser accepts this tag but logs "Ignoring the 'protocol' option. Switching to TCP."

#### max_retries

Maximum connection retry attempts before failing over to next server.

- **Default value:** `5`
- **Allowed values:** Positive integer
- **Note:** Only applicable when multiple servers are configured

#### retry_interval

Time in seconds to wait between connection retry attempts.

- **Default value:** `10`
- **Allowed values:** Positive integer (seconds)
- **Note:** Applies when retrying connection to the same server

#### interface_index

Network interface index to bind for manager connection.

- **Default value:** Auto-select
- **Allowed values:** Positive integer (interface index number)
- **Note:** Platform-specific; forces agent to use specific network interface

### ip_update_interval

Interval in seconds for updating agent's IP address with the manager.

- **Default value:** `0` (disabled)
- **Allowed values:** `0` (disabled) or positive integer (seconds)
- **Note:** When `0`, IP updates are disabled; set to positive value (e.g., `3600`) to enable periodic IP update messages

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

**DEPRECATED:** This option is parsed but ignored. Encryption method is hard-coded to AES.

- **Status:** Deprecated (kept for backward compatibility)
- **Behavior:** Always uses AES regardless of configured value
- **Note:** The parser accepts this tag but logs "Ignoring the 'crypto_method' option. Switching to AES."

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

#### agent_address

Agent's IP address to use for enrollment (overrides auto-detected address).

- **Default value:** Auto-detected
- **Allowed values:** Valid IPv4 or IPv6 address
- **Note:** Useful when agent has multiple network interfaces

#### ssl_cipher

TLS 1.3 ciphersuite list for the enrollment connection. Enrollment requires TLS 1.3, so this must be a colon-separated list of TLS 1.3 ciphersuite names.

- **Default value:** `TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256`
- **Allowed values:** Colon-separated TLS 1.3 ciphersuite names (`TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`, `TLS_AES_128_CCM_SHA256`, `TLS_AES_128_CCM_8_SHA256`)
- **Example:** `TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256`

#### server_ca_path

Path to CA certificate file for verifying manager certificate during enrollment.

- **Default value:** None
- **Allowed values:** Valid file path
- **Note:** Required for SSL verification during enrollment

#### agent_certificate_path

Path to agent's client certificate for mutual TLS authentication during enrollment.

- **Default value:** None
- **Allowed values:** Valid file path

#### agent_key_path

Path to agent's private key for mutual TLS authentication during enrollment.

- **Default value:** None
- **Allowed values:** Valid file path
- **Note:** Must correspond to `agent_certificate_path`

#### delay_after_enrollment

Delay in seconds after successful enrollment before starting normal agent operations.

- **Default value:** `20`
- **Allowed values:** Positive integer (seconds) from `1` upward
- **Note:** Allows time for manager to process new agent before receiving events; `0` is invalid and rejected by parser

#### use_source_ip

Use agent's source IP address for enrollment instead of configured address.

- **Default value:** `no`
- **Allowed values:** `yes`, `no`
- **Note:** Useful for NAT scenarios

#### interface_index

Network interface index to bind for enrollment connection.

- **Default value:** Auto-select
- **Allowed values:** Positive integer (interface index number)
- **Note:** Platform-specific; use `ip link` or `ifconfig` to find interface indices

---

## Client Buffer Configuration (`<client_buffer>`)

Removed in 5.0.0: buffering and pacing belong to the HTTPS transport's
accumulator, configured under `<agent><batch>`. The section is still accepted
and ignored, with a warning.

---

## Anti-Tampering Configuration (`<anti_tampering>`)

Protects against unauthorized agent modifications and uninstallation.

**Platform:** Linux/Unix only (not available on Windows or macOS)

**Note:** To disable anti-tampering, remove or comment out the entire `<anti_tampering>` block. There is no disable option within the block.

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
<agent>
  <server>
    <address>10.0.0.10</address>
    <port>1517</port>
    <protocol>tcp</protocol>
  </server>
  <config-profile>webserver,production</config-profile>
  <notify_time>60</notify_time>
  <time-reconnect>60</time-reconnect>
  <auto_restart>yes</auto_restart>
  <crypto_method>aes</crypto_method>
</agent>
```

### Auto-Enrollment Configuration

Automatic agent registration:

```xml
<agent>
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
    <port>1517</port>
    <protocol>tcp</protocol>
  </server>
</agent>
```

### Client Buffer Configuration

High-volume environment:

```xml
<agent>
  <batch>
    <size>10MB</size>
    <interval>5s</interval>
  </batch>
</agent>
```

### Anti-Tampering Configuration

Maximum protection (Linux only):

```xml
<anti_tampering>
  <package_uninstallation>yes</package_uninstallation>
</anti_tampering>
```

### Complete Agent Configuration

Full example with all sections:

```xml
<ossec_config>
  <agent>
    <server>
      <address>manager1.example.com</address>
      <port>1517</port>
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
  </agent>

  <anti_tampering>
    <package_uninstallation>yes</package_uninstallation>
  </anti_tampering>

  <logging>
    <log_format>plain</log_format>
  </logging>
</ossec_config>
```

---

## Deprecated Options

### disable-active-response

**DEPRECATED:** The `<disable-active-response>` tag within `<agent>` is parsed but has no effect.

- **Status:** Deprecated silent no-op
- **Behavior:** Parser accepts the tag but does not use the value
- **Note:** Active response behavior is controlled by the active-response module configuration, not by this client-side setting
- **Recommendation:** Remove from configuration; use `<active-response><disabled>` in the active-response module instead

---

## See Also

- [Client Module](index.html) - Module overview and architecture
- [Remoted Configuration](../remoted/configuration.md) - Manager-side agent listener configuration
- [Centralized Configuration](../agent-management/centralized-configuration.md) - Group-based configuration
- [Agent Enrollment](../agent-management/enrollment.md) - Agent registration process

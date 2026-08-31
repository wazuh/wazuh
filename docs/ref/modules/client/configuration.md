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

`<client>` is the 4.X name of this block and is renamed to `<agent>` in 5.0; the inner block is `<manager>`. A configuration left by a 4.X agent still starts: `<client><server><address>` is read and the port defaults to `1517`. No other option inside `<client>` is read, so rename the block to `<agent><manager>` to keep them all.

### manager

Manager connection configuration block.

**Sub-options:**

#### endpoint

The complete connection target: the manager's address, optionally a port, and optionally the
URL path prefix it is served under. This one option replaces the separate `address` and `port`
tags.

```
endpoint = [ "https://" ] host [ ":" port ] [ "/" [ prefix ] ]
```

- **Required:** Yes — `host` is the only mandatory part.
- **Allowed values:** `host` is an IPv4 address, a hostname, or a **bracketed** IPv6 literal
  (the brackets keep its colons from reading as the port separator, and are dropped from the
  stored value). A link-local IPv6 address may carry a zone id with `%` percent-encoded as
  `%25`; an interface name is resolved to its index while the configuration is parsed, so an
  unknown name is rejected there. `port` defaults to `1517`. An `https://` scheme is accepted
  and ignored; any other scheme is rejected.
- **Example:** `192.168.1.100`, `manager.example.com:8443/gateway`,
  `[2001:db8::1]:1517`, `[fe80::1%25eth0]:1517`
- **Note on the prefix:** omitting the slash entirely selects the default prefix
  `wazuh-manager`, matching a manager whose `<remote><https><global_prefix>` is the shipped
  `/wazuh-manager/`. A **trailing slash with nothing after it** is the explicit opt-out for a
  manager serving unprefixed endpoints — so `192.168.1.100` and `192.168.1.100/` mean
  different things. This mirrors the manager, where `<global_prefix>` is `/` to serve no
  prefix; on both sides an **empty** value is a configuration error, not an opt-out. A prefix
  mismatch between the two surfaces as `404`.

#### address

**DEPRECATED:** folded into `endpoint`. Still read so that an agent upgraded in place — an
upgrade never rewrites `ossec.conf` — keeps connecting: the agent composes the target from
`address`, `port` (or its `1517` default) and the default prefix, and logs at `INFO` the single
`<endpoint>` line that replaces them. If `endpoint` is also present it wins, whatever the order,
and `address`/`port` are ignored with a warning.

- **Allowed values:** Valid IPv4, IPv6 address, or hostname
- **Example:** `192.168.1.100`, `manager.example.com`, `::1`

#### port

**DEPRECATED:** folded into `endpoint`. See `address`.

- **Default value:** `1517`
- **Allowed values:** Valid port number (1-65535)
- **Note:** A `<port>` inside a legacy `<client><server>` block is not read.

#### protocol

**DEPRECATED:** This option is parsed but ignored. Communication protocol is hard-coded to TCP.

- **Status:** Deprecated (kept for backward compatibility)
- **Behavior:** Always uses TCP regardless of configured value
- **Note:** The parser accepts this tag but logs "Ignoring the 'protocol' option. Switching to TCP."

#### max_retries

**DEPRECATED:** parsed but ignored. Server rotation and the connection-retry loop were removed
with the HTTPS transport; the parser accepts the tag so an upgraded configuration does not fail
and logs that it no longer has any effect.

#### retry_interval

**DEPRECATED:** parsed but ignored. See `max_retries`.


### ssl

TLS configuration for the agent's HTTPS connection to the manager. Controls how the agent
verifies the manager's certificate and, optionally, presents its own client certificate.

**Sub-options:**

#### certificate

Path to an optional client (mTLS) certificate the agent presents to the manager.

- **Default value:** None (no client certificate presented)
- **Allowed values:** Path to a PEM-encoded certificate file, readable by the agent
- **Note:** Must be set together with `<key>`; setting only one of the two is rejected.

#### key

Path to the private key matching `<certificate>`.

- **Default value:** None
- **Allowed values:** Path to a PEM-encoded private key file, readable by the agent
- **Note:** Must be set together with `<certificate>`; setting only one of the two is rejected.

#### certificate_authorities

Path to the CA bundle used to verify the manager's certificate.

- **Default value:** None
- **Allowed values:** Path to a PEM-encoded CA bundle file, readable by the agent
- **Required:** Yes, when `<verification_mode>` is `full` or `certificate` -- the agent fails
  closed (refuses to start) without a readable CA file in that case.
- **Note:** Must NOT be set when `<verification_mode>` is `system` -- the agent fails closed if
  it is, since the OS trust store is used as the anchor instead and a configured CA would go
  silently unused. Ignored (with a warning if set but unreadable) when `<verification_mode>` is
  `none`.

#### verification_mode

How strictly the agent verifies the manager's TLS certificate.

- **Default value:** `none`
- **Allowed values:**
  - `full` — verify the certificate against `<certificate_authorities>` AND check that it
    matches the manager's hostname (strictest).
  - `certificate` — verify the certificate against `<certificate_authorities>`, but do not
    check the hostname.
  - `none` — no TLS verification at all. Insecure; intended for quick testing only.
  - `system` — verify the certificate (and hostname, like `full`) against the operating
    system's own trusted CA store instead of `<certificate_authorities>`, the way a web
    browser trusts a public website. Useful when the manager's certificate is issued by a
    publicly (or OS-) trusted CA, so a CA bundle does not need to be distributed to every
    agent by hand. On Windows and macOS this uses the native certificate store (Windows
    Certificate Store / Keychain); on Linux it probes a fixed set of well-known distribution
    paths (e.g. `/etc/ssl/certs/ca-certificates.crt` on Debian-family systems,
    `/etc/pki/tls/certs/ca-bundle.crt` on RHEL-family systems) and fails closed at startup if
    none is found on the host.
- **Note:** Any value other than the four above is rejected at config-parse time.

#### ciphers

TLS 1.3 ciphersuite list to offer during the handshake.

- **Default value:** None (libcurl/OpenSSL default TLS 1.3 ciphersuites)
- **Allowed values:** Colon-separated list of TLS 1.3 ciphersuite names
- **Example:** `TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256`

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

Agent auto-enrollment configuration block (optional). Since 5.0.0 (#38465),
enrollment runs over the same HTTPS channel and TLS material as every other
manager endpoint — it dials `<agent><manager>` and presents `<agent><ssl>`,
instead of opening a second connection to `authd` on port 1515. There is no
longer a separate address/port/certificate/key/CA/cipher configuration for
enrollment: the options that used to duplicate that (see **Removed options**
below) are gone.

**Sub-options:**

#### enabled

Enable automatic agent enrollment.

- **Default value:** `yes`
- **Allowed values:** `yes`, `no`

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
- **Note:** Password must match manager's authd password. Re-read on every
  enrollment attempt, so rotating the file does not require an agent restart.

#### agent_address

Agent's IP address to use for enrollment (overrides auto-detected address).

- **Default value:** Auto-detected
- **Allowed values:** Valid IPv4 or IPv6 address
- **Note:** Useful when agent has multiple network interfaces. Incompatible
  with `use_source_ip`.

#### delay_after_enrollment

Delay in seconds after successful enrollment before starting normal agent operations.

- **Default value:** `20`
- **Allowed values:** Positive integer (seconds) from `1` upward
- **Note:** Allows time for manager to process new agent before receiving events; `0` is invalid and rejected by parser

#### use_source_ip

Use agent's source IP address for enrollment instead of configured address.

- **Default value:** `no`
- **Allowed values:** `yes`, `no`
- **Note:** Useful for NAT scenarios. Incompatible with `agent_address`.

#### Removed options

The following options are **no longer used**: `manager_address`, `port`,
`interface_index` (superseded by `<agent><manager>`; the interface for a link-local
IPv6 manager is now the zone id inside `<endpoint>`, e.g.
`<endpoint>[fe80::1%25eth0]:1517</endpoint>`) and `ssl_cipher`,
`server_ca_path`, `agent_certificate_path`, `agent_key_path` (superseded by
`<agent><ssl>`). A configuration carrying them — e.g. left over from a 4.x
`ossec.conf`, which an in-place upgrade does not rewrite — still starts the
agent normally: each is recognized and logged at `INFO`, not rejected.

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

### HTTPS Connection Timing

These control the agent's half of the HTTPS timing contract with the manager. Each one pairs with
a manager-side deadline, so they should be changed together with the corresponding
`remoted.*` option rather than on their own — see
[remoted configuration](../remoted/configuration.md#https-agent-server-remoted_module).

An attempt count is the **total** number of tries, not retries after the first: `1` means "send
once, never retry". Only retryable failures and back-pressure (`503`) consume an attempt;
authentication failures, permanent errors and version rejections stop immediately. A step's worst
case is therefore about `attempts × timeout` plus the jittered backoff between tries — check that
figure against `<global><agents_disconnection_time>` before raising either.

```ini
# Per-request budget for /control, /stateless, /stats and /config, in
# milliseconds (default: 10000, range 1000-600000). Covers DNS, TCP, TLS and
# transfer -- there is no separate connect or handshake timeout.
agent.https_request_timeout=10000

# Per-request budget for large transfers: /stateful and both POST /download
# kinds, config and WPK (default: 90000, range 1000-3600000)
agent.https_stateful_timeout=90000

# Retry backoff, full jitter: the delay before attempt n is uniform in
# [0, min(cap, base * 2^n)], reset on success, tracked per stream.
agent.https_backoff_base=1000
agent.https_backoff_cap=60000

# Retry cadence for Startup after the manager rejects the agent's version,
# in seconds (default: 60, range 1-86400)
agent.https_rejected_retry_interval=60

# Largest WPK accepted by a remote_upgrade download, in bytes
# (default: 209715200 = 200 MiB)
agent.https_wpk_max_download_bytes=209715200

# Per-stream retry budgets, total tries (range 1-64)
agent.https_control_attempts=4
agent.https_stateless_attempts=5
agent.https_stateful_attempts=5
agent.https_download_attempts=2

# Consecutive undeliverable /control steps before event producers pause;
# one deliverable step releases the pause (default: 2, range 1-1000)
# Undeliverable means unreachable, a rejected key or a rejected version. Answers that
# clear on their own (5xx, 429, 503, 413, 400) are excluded and reset the streak, so
# persistent 503s never reach this threshold.
agent.https_producer_pause_threshold=2
```

### Enrollment Retry

Not part of the HTTPS request path, but it bounds how long the agent can be held up before it
next talks to the manager.

```ini
# Enrollment retry ramp, shared by the initial-enrollment loop and the
# https_client re-enrollment loop: the delay grows by <delta> seconds after
# each failed attempt, up to <max>. Both loops read these same two options,
# so they cannot drift apart.
agent.enrollment_retry_delta=5
agent.enrollment_retry_max=60
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
  <manager>
    <address>10.0.0.10</address>
    <port>1517</port>
    <protocol>tcp</protocol>
  </manager>
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
    <agent_name>web-server-prod-01</agent_name>
    <groups>webservers,production</groups>
    <authorization_pass_path>/var/ossec/etc/authd.pass</authorization_pass_path>
  </enrollment>
  <manager>
    <address>manager.example.com</address>
    <port>1517</port>
    <protocol>tcp</protocol>
  </manager>
</agent>
```

Enrollment dials the address/port from `<manager>` above (and, if configured,
presents the TLS material from `<ssl>`) — there is no separate
`manager_address`/`port` to set under `<enrollment>` any more.

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
    <manager>
      <address>manager1.example.com</address>
      <port>1517</port>
    </manager>
    <config-profile>webserver,production,linux</config-profile>
    <notify_time>60</notify_time>
    <time-reconnect>60</time-reconnect>
    <auto_restart>yes</auto_restart>
    <crypto_method>aes</crypto_method>
    <enrollment>
      <enabled>yes</enabled>
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

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

`<client>` is the 4.X name of this block and is renamed to `<agent>` in 5.0; the inner block is `<manager>`. A configuration left by a 4.X agent still starts, and two things are read out of the legacy block: `<client><server><address>`, with the port defaulting to `1517`, and the whole `<client><enrollment>` sub-block, so an upgraded agent keeps the identity it enrolls with. Every other option directly inside `<client>` is ignored and warned about at startup; the options nested in its `<server>` block are dropped without a message. Rename the block to `<agent><manager>` to keep them all.

### manager

Manager connection configuration block.

**Sub-options:**

#### endpoint

The complete connection target: the manager's address, optionally a port, and optionally the
URL path prefix it is served under. This one option replaces the separate `address` and `port`
tags.

```text
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

- **Default value:** None in `ossec.conf`. When the option is absent and the resolved mode is
  `full` or `certificate`, the agent uses the trust anchor described below as the CA, so an
  agent that bootstrapped from an enrollment token verifies without this option being set at
  all.
- **Allowed values:** Path to a PEM-encoded CA bundle file, readable by the agent
- **Required:** Only when neither this option nor the trust anchor is present and
  `<verification_mode>` is `full` or `certificate` -- the agent then fails closed (refuses to
  start) with `(4118)`.
- **Note:** Must NOT be set when `<verification_mode>` is `system` -- the agent fails closed
  with `(4120)` if it is, since the OS trust store is used as the anchor instead and a
  configured CA would go silently unused. Ignored when `<verification_mode>` is `none`.
- **Note:** A file that is readable but holds no certificate the agent can parse is refused at
  startup with `(4123)`, rather than at the first handshake. Readable is not usable.

#### verification_mode

How strictly the agent verifies the manager's TLS certificate.

- **Default value:** There is no single default. The mode is resolved at startup from what
  `<ssl>` says and whether a trust anchor is on disk:

  | What is configured | Resolved mode |
  |---|---|
  | An explicit `<verification_mode>` | That mode, `none` included |
  | `<certificate_authorities>`, no explicit mode | `certificate` (mirrors the manager's own inference for `<remote><https><ca>`), logged as a warning |
  | Neither, but the trust anchor is present | `full`, with the anchor as the CA |
  | Nothing at all | `none` |

- **Allowed values:**
  - `full` -- verify the certificate against the CA AND check that it matches the manager's
    hostname (strictest).
  - `certificate` -- verify the certificate against the CA, but do not check the hostname.
  - `none` -- no TLS verification at all. Insecure; intended for quick testing only.
  - `system` -- verify the certificate (and hostname, like `full`) against the operating
    system's own trusted CA store instead of `<certificate_authorities>`, the way a web
    browser trusts a public website. Useful when the manager's certificate is issued by a
    publicly (or OS-) trusted CA, so a CA bundle does not need to be distributed to every
    agent by hand. On Windows and macOS this uses the native certificate store (Windows
    Certificate Store / Keychain); on Linux it probes a fixed set of well-known distribution
    paths (e.g. `/etc/ssl/certs/ca-certificates.crt` on Debian-family systems,
    `/etc/pki/tls/certs/ca-bundle.crt` on RHEL-family systems) and fails closed at startup if
    none is found on the host.
- **Note:** Any value other than the four above is rejected at config-parse time.
- **Note:** An explicit mode always wins, and that includes turning verification off on a host
  that could verify. An explicit `none` with a trust anchor present keeps `none` and logs
  `(4122)` at warning level, naming the anchor it is declining to use.

#### ciphers

TLS 1.3 ciphersuite list to offer during the handshake.

- **Default value:** None (libcurl/OpenSSL default TLS 1.3 ciphersuites)
- **Allowed values:** Colon-separated list of TLS 1.3 ciphersuite names
- **Example:** `TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256`

### The trust anchor

The certificate authority the agent verifies the manager against when `<ssl>` does not name
one. It is a file, not a configuration option, and its presence **is** the default
verification state -- see the resolution table under `verification_mode` above.

| | Path | Ownership |
|---|---|---|
| Linux, macOS | `etc/certs/root-ca.pem`, relative to the installation directory | `0640 root:wazuh`, in a `0750 root:wazuh` directory |
| Windows | `certs\root-ca.pem` | The inherited ACL of the directory the agent creates |

Three things put it there, and the file is identical whichever did:

- **The enrollment-token bootstrap**, on the agent's first start after a token install. It
  fetches the manager's CA, checks it against the token's pin and installs only the certificate
  that matched.
- **A WPK upgrade from 4.x**, where the manager delivers its CA over the upgrade channel. See
  [Trust anchor delivery to legacy agents](../../../guide/migration/remote-agent-upgrade.md#trust-anchor-delivery-to-legacy-agents).
- **An operator**, placing the file by hand or through configuration management.

It is root-owned and not writable by the `wazuh` user the agent runs as, so it is always
written by root before the daemon drops privileges -- the same pattern `client.keys` follows.

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

- **Default value:** `10`
- **Allowed values:** Positive integer (seconds).
- **Note:** This is not what decides when the agent is marked `disconnected`. The manager uses
  `<global><agents_disconnection_time>` (default `15m`) against the last keepalive it recorded, so
  `notify_time` only has to be comfortably below that figure — see the
  [manager configuration reference](../../configuration/manager/reference.md#global).

### time-reconnect

**DEPRECATED:** parsed but ignored. There is no persistent connection to reconnect under the
HTTPS transport; the parser accepts the tag so an upgraded configuration does not fail and logs
that it no longer has any effect.

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

#### Enrollment token

Not an `ossec.conf` option: a one-shot file the installer leaves for the agent to consume on
its first start.

| | Path | Ownership |
|---|---|---|
| Linux, macOS | `etc/enrollment_token` | `0600 root:root` |
| Windows | `enrollment_token` | SYSTEM and Administrators, inheritance broken |

Written by the installer from `WAZUH_ENROLLMENT_TOKEN` (see
[Installation](../../getting-started/installation.md#enrollment)).
An agent enrolled after its install is enrolled with
[`wazuh-agent-auth`](README.md#enrolling-or-re-pointing-an-agent), which reads a token from any
path and leaves it alone.

The bootstrap runs at agent start, before the privilege drop, and takes these steps in order:
decode the token, open an unverified connection to the address it names and fetch the manager's
CA, compare the SHA-256 of that certificate's SubjectPublicKeyInfo against the token's pin,
install only the matching certificate as the trust anchor, open a **new** fully verified
connection, enroll, and delete this file. No credential crosses the unverified connection. A
pin mismatch aborts with a named error and no enrollment is attempted.

The file is also deleted, unused, whenever it can no longer be consumed -- on an agent that
already holds an anchor or an identity, and when the manager reports the token as unknown,
revoked or out of uses. It is a credential; it is not left at rest once it is spent.

Failures are split into permanent and transient. A
transient one -- an unreachable manager, a misprovisioned CA, a `5xx` -- is retried in place, on
the same ramp as enrollment itself -- the `agent.enrollment_retry_delta` and
`agent.enrollment_retry_max` internal options under **Enrollment Retry** below -- so an agent
that starts before its manager does still bootstraps. A permanent one -- a malformed token, a
pin mismatch, a `404` from `/cacerts` -- is not retried.

#### authorization_pass_path

Path to file containing enrollment authorization password.

- **Default value:** `etc/authd.pass` (`authd.pass` on Windows)
- **Allowed values:** Valid file path
- **Note:** Password must match manager's authd password. Re-read on every
  enrollment attempt, so rotating the file does not require an agent restart.
- **Removed from the endpoint in 5.0.** This is a *fleet-wide* secret: one value
  that enrolls any endpoint, stored at rest on every endpoint that has it. Use
  an enrollment token (`WAZUH_ENROLLMENT_TOKEN` at install time), which is
  single-use and per-endpoint, and the per-agent re-enrollment secret the
  manager issues thereafter (see *Re-enrollment* below).
- A **fresh 5.0 install never creates** `etc/authd.pass`. `WAZUH_REGISTRATION_PASSWORD`
  is accepted but ignored, and says so in `ossec.log`.
- The **5.0 package upgrade deletes** an existing `etc/authd.pass` — once, at
  upgrade, in the package scripts rather than in the agent, so it does not
  depend on the agent ever reaching a manager. It is overwritten before it is
  unlinked.
- Only the compiled default path is removed. A path configured **explicitly**
  here is operator-owned — a shared mount, a templated file, one kept for
  re-imaging — and is never touched, so an agent that still reads a password
  from a path of your choosing keeps working.

#### Re-enrollment

An agent that enrolls against a 5.0 manager receives a **per-agent
re-enrollment secret** in the `/enroll` response and stores it at
`etc/reenroll.secret` (`reenroll.secret` on Windows), as `<id> <secret>`. It is
rotated on every subsequent enrollment.

The secret is what the agent re-enrolls with when the manager reports that its
key is no longer known, and it replaces the fleet password as the endpoint's
unattended recovery capability:

- It is **narrower**: it rotates the key of that one agent id and cannot mint a
  new identity. A stolen secret is worth one endpoint, not the fleet.
- It gets `client.keys`'s protection (mode `0640`, same owner), because it has
  `client.keys`'s power. A process that can rewrite the key already owns the
  agent.
- It must stay writable by the unprivileged agent user: every rotation is
  performed by the running daemon, after the privilege drop.

**Agents enrolled before the 5.0 upgrade.** The secret is only ever issued in an
`/enroll` response, and an agent that is already enrolled has no way to ask for
one: the manager refuses an enrollment whose `key_hash` matches an agent it
already knows, and omitting the hash re-registers the agent under a new id. Such
an agent keeps working on the key it holds, but the upgrade removes its
`authd.pass`, so it has no unattended recovery left. If it is ever removed on the
manager it will stop with *"operator action is required"* and wait. Re-point it
with an enrollment token.

The agent only discards an identity when the manager explicitly says it is
unknown. Any other authentication failure — a clock outside the manager's
accepted window, an enrollment key that has not synced to the node serving the
request, or a response whose failure class cannot be read — is retried with the
existing credential. A credential the manager has judged and refused stops the
retry loop instead of repeating for ever.

#### Moving an agent to another manager or CA

Use [`wazuh-agent-auth`](README.md#enrolling-or-re-pointing-an-agent): `--certs-only` when the
same deployment rotated its certificate authority or changed its address, `--force-enroll` for a
deployment that has never seen this agent.

The bootstrap that runs at first start does not repeat once the agent holds a trust anchor or an
identity, so editing these files by hand does not move an agent.

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
`<agent><ssl>`), and `auto_method` (removed outright: enrollment always negotiates
TLS 1.3). A configuration carrying them — e.g. left over from a 4.x
`ossec.conf`, which an in-place upgrade does not rewrite — still starts the
agent normally: each is recognized and logged at `INFO`, not rejected.

### batch

Size and cadence of the HTTPS `/events/stateless` accumulator. The same size is the ceiling held
for one `/stateful` session.

```xml
<agent>
  <batch>
    <size>1MB</size>
    <interval>10s</interval>
  </batch>
</agent>
```

- **`size`** — Default `1MB`. Positive byte count with the usual suffixes, up to `1GB`.
- **`interval`** — Default `10s`. Positive duration, up to one day.
- **Note:** `size` has to stay under the manager's request-body caps, which the agent cannot see.
  Up to `remoted.auth_max_body_size` (5 MiB by default) an oversized batch is answered `413` and the
  agent splits it and resends smaller without losing events. Above `<remote><https><max_body_size>`
  (10 MiB by default) the manager closes the connection with no response; the agent reads that as a
  network failure, keeps the batch and retries it indefinitely, and no further events leave the
  agent. If this value is raised, raise both manager settings first and keep `size` at or below the
  auth cap. See [remoted's configuration](../remoted/configuration.md#httpsmax_body_size).

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
[remoted configuration](../remoted/configuration.md#https-agent-server-remoted_module) for the
manager half, and
[connection timing tuning](../remoted/timing-tuning.md) for which pairs must move together and
what measurably breaks when only one does.

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

Both values are resolved once, when the agent starts, and the loops use the resolved value for the
life of the process. Editing either one on a running agent has no effect until it restarts, and an
out-of-range value refuses the start rather than terminating the agent later, at its first failed
re-enrollment.

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
    <endpoint>10.0.0.10:1517</endpoint>
  </manager>
  <config-profile>webserver,production</config-profile>
  <notify_time>60</notify_time>
  <auto_restart>yes</auto_restart>
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
  </enrollment>
  <manager>
    <endpoint>manager.example.com:1517</endpoint>
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
      <endpoint>manager1.example.com:1517</endpoint>
    </manager>
    <config-profile>webserver,production,linux</config-profile>
    <notify_time>60</notify_time>
    <auto_restart>yes</auto_restart>
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
- [Enrollment lifecycle](../authd/enrollment-lifecycle.md) - Agent registration, end to end

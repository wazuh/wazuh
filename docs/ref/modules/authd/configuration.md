# Auth Daemon Configuration Reference

Complete configuration reference for the Wazuh enrollment service (authd), which issues keys and registers new agents.

**Configuration file:** `/var/wazuh-manager/etc/wazuh-manager.conf`

**XML Section:** `<auth>`

**Module:** Manager-only

**Internal Options:** `authd.*`

For module overview and architecture, see [Auth Daemon Module](README.md).

---

## Configuration Options

The `<auth>` section configures the enrollment service that handles agent registration.

### disabled

Disables the enrollment service entirely.

- **Default value:** `no`
- **Allowed values:** `yes`, `no`
- **Note:** When the `<auth>` block is present but this option is not set, the service starts

### port

TCP port on which the enrollment service listens.

- **Default value:** `1515`
- **Allowed values:** Integer from `1` to `65535`
- **Note:** Only `0` is rejected by the code; there is no upper-bound check, so values above `65535` are silently truncated rather than validated. Operators should keep the configured value within the valid port range themselves.

### ipv6

Enable IPv6 support.

- **Default value:** `no`
- **Allowed values:** `yes`, `no`

### use_source_ip

Register agents using their source IP address instead of `any`.

- **Default value:** `no`
- **Allowed values:** `yes`, `no`
- **Note:** When enabled, agents can only connect from the IP they enrolled from. Both listeners
  enforce this: the classic one via `OS_IsAllowedDynamicID()`, and the HTTPS one via the `ip` column
  check described in
  [Registered address](../remoted/https-events-api.md#registered-address-ip-column).
- **Note:** Do not enable this when agents reach the manager through a **NAT or a load balancer**. The
  address recorded at enrollment is the one the manager observes, which is the proxy's rather than the
  agent's, and it is not necessarily the address the event listener will observe for the same agent if
  the two are reached over different paths. In proxied deployments, register agents with `any`.

### purge

Controls whether a deleted or replaced agent's old entry is kept as an audit trail. When an agent
is removed — including the implicit removal that happens when another agent re-enrolls and forces
it out (see [Force re-enrollment](README.md#force-re-enrollment)) — the active `client.keys` entry
is always deleted regardless of this setting. What `purge` decides is whether that deleted entry is
also retained as a `!`-prefixed placeholder line in `client.keys` (e.g. `001 !oldname 1.2.3.4
<key>`), which keeps a record of the old ID/name/IP so it is not reused. By default the placeholder
line is kept; setting `purge` to `yes` suppresses it, so the entry is removed with no trace left
behind.

- **Default value:** `no`
- **Allowed values:** `yes`, `no`

### use_password

Require agents to provide a shared enrollment password.

- **Default value:** `no` (the configuration shipped by the installer sets it to `yes`)
- **Allowed values:** `yes`, `no`

When enabled, the password is read from `/var/wazuh-manager/etc/authd.pass` (a single line). If the file does not exist, `wazuh-manager-authd` generates a random password on start (32 bytes straight from the CSPRNG, written as 64 lowercase hexadecimal characters), stores it in that file, and reuses it on later starts. A password written by hand is not held to that format: any single line longer than two characters is accepted. If the file exists but is empty or invalid, `wazuh-manager-authd` does not start. In a cluster, the password belongs to the master and is distributed to the workers automatically; a worker rejects enrollment until it receives the file.

**Agent-side setup:** Because `use_password` is `yes` by default, agents must supply the enrollment password or their enrollment request will be rejected. First retrieve the password from the manager:

```bash
sudo cat /var/wazuh-manager/etc/authd.pass
```

The recommended way to provide it to an agent is the `WAZUH_REGISTRATION_PASSWORD` install variable, which writes `etc/authd.pass` and sets its ownership and permissions automatically:

```bash
sudo env WAZUH_MANAGER="<manager-ip>" WAZUH_REGISTRATION_PASSWORD="<password>" apt install ./wazuh-agent.deb
```

To add it to an already-installed agent, write the file manually. The agent daemon (`wazuh-agentd`) runs as the `wazuh` user, so the file must be readable by that user:

```bash
echo "<password>" | sudo tee /var/ossec/etc/authd.pass
sudo chown root:wazuh /var/ossec/etc/authd.pass
sudo chmod 640 /var/ossec/etc/authd.pass
```

The agent reads the password from `etc/authd.pass` (relative to its install directory, typically `/var/ossec/etc/authd.pass`) at startup.

**Password rotation:** The generated password persists across restarts. To rotate it (for example after a security incident), delete `/var/wazuh-manager/etc/authd.pass` on the master and restart `wazuh-manager-authd`. A new random password will be generated, persisted, and distributed to workers automatically. If the CSPRNG fails, `wazuh-manager-authd` exits instead of writing a weaker password. The reuse of an existing password is logged at `INFO` level on every start.

### remote_enrollment

Master switch for **all** remote (network) self-enrollment — both this daemon's own TCP/TLS
listener on port 1515 and the HTTPS `POST /enroll` bridge served by `remoted_module` (see
[HTTPS enrollment](../remoted/https-events-api.md#enrollment-endpoint-post-enroll)). Disabling it
turns off both at once; use [`legacy_enrollment`](#legacy_enrollment) to turn off only port 1515
while keeping `/enroll`. Either way, the local socket (`queue/sockets/auth.sock`) used by
`manage_agents`/the API stays available regardless of this setting.

- **Default value:** `yes`
- **Allowed values:** `yes`, `no`

### legacy_enrollment

Narrows `remote_enrollment` further, without affecting it: when `remote_enrollment` is `yes`, this
flag controls whether port 1515's TCP/TLS listener specifically starts. Set to `no` to retire
legacy 1515 while keeping `/enroll` — the manager's intended long-term enrollment path — available.
Has no effect when `remote_enrollment` is `no` (both paths are already off), and no effect on
`/enroll` at all, which this flag exists specifically to leave alone.

| `disabled` | `remote_enrollment` | `legacy_enrollment`  | Port 1515 | `POST /enroll` |
| ---------- | -------------------- | --------------------- | --------- | -------------- |
| `yes`      | –                    | –                     | off       | off            |
| `no`       | `no`                 | –                     | off       | off            |
| `no`       | `yes`                | `yes` (default)       | on        | on             |
| `no`       | `yes`                | `no`                  | off       | **on**         |

- **Default value:** `yes`
- **Allowed values:** `yes`, `no`

### ciphers

Colon-separated list of TLS 1.3 cipher suites accepted by the enrollment TLS session (applied via OpenSSL's `SSL_CTX_set_ciphersuites`). `wazuh-manager-authd` requires TLS 1.3 as the minimum protocol version, so this option only accepts TLS 1.3 cipher suite names — legacy OpenSSL cipher-list strings (e.g. `HIGH:!ADH:...`) used before TLS 1.3 enforcement are no longer valid and are rejected at startup with a clear error.

- **Default value:** `TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256`
- **Allowed values:** Colon-separated combination of `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`, `TLS_AES_128_CCM_SHA256`, `TLS_AES_128_CCM_8_SHA256`

### ssl_agent_ca

Path to the CA certificate used to verify agent client certificates during mutual TLS.

- **Default value:** none (agent certificate verification disabled)
- **Allowed values:** Path to a PEM-encoded CA certificate (existence checked at startup)

### ssl_verify_host

Verify that the CN of the agent certificate matches the agent's IP address. Requires `ssl_agent_ca` to be set.

- **Default value:** `no`
- **Allowed values:** `yes`, `no`

### ssl_manager_cert

Path to the manager's TLS certificate presented to agents during enrollment. Shared with the
HTTPS agent server (`remoted_module`'s `POST /enroll`): both listeners present the same manager
identity, since `/enroll`'s mTLS mode treats this certificate as the enrollment credential.

- **Default value:** `etc/certs/remoted.pem` (resolved relative to the Wazuh install directory, e.g. `/var/wazuh-manager/etc/certs/remoted.pem`) -- authd does not generate or own a certificate of its own, and neither does the manager: the pair is provisioned externally (Wazuh installation assistant, `wazuh-certs-tool`; see [Deploy certificates](../../getting-started/installation.md#deploy-certificates)) and the manager fails closed without it. When the SSL context cannot be built from these files authd logs `SSL context setup failed (certificate '…', key '…')` with the provisioning hint and exits
- **Allowed values:** Path to a PEM-encoded certificate (relative paths resolved from the Wazuh install directory)

### ssl_manager_key

Path to the private key corresponding to `ssl_manager_cert`.

- **Default value:** `etc/certs/remoted-key.pem` (resolved relative to the Wazuh install directory)
- **Allowed values:** Path to a PEM-encoded private key (relative paths resolved from the Wazuh install directory)

### force

Sub-element that controls forced re-enrollment behavior when an agent already exists in the manager keystore.

**Sub-options:**

#### force / enabled

Allow forced re-enrollment (overwrite an existing agent entry).

- **Default value:** `yes`
- **Allowed values:** `yes`, `no`

#### force / key_mismatch

Force re-enrollment when an agent reconnects with a key that does not match what the manager has stored.

- **Default value:** `yes`
- **Allowed values:** `yes`, `no`

#### force / disconnected_time

Minimum time an agent must have been disconnected before it can be forcibly re-enrolled. The `enabled` attribute gates this check. The value is the duration; `enabled` controls whether the check is active.

- **Default value:** `1h` with `enabled="yes"`
- **Allowed values:** Time value with optional suffix — `s`, `m`, `h`, `d`; attribute `enabled`: `yes`/`no`

```xml
<!-- Enable the check, require 2h disconnection -->
<disconnected_time enabled="yes">2h</disconnected_time>

<!-- Disable the check entirely -->
<disconnected_time enabled="no">0</disconnected_time>
```

#### force / after_registration_time

Minimum time since an agent was last registered before a forced re-enrollment is permitted. This prevents an agent from being replaced immediately after its initial enrollment.

- **Default value:** `1h`
- **Allowed values:** Time value with optional suffix — `s`, `m`, `h`, `d`

### agents / allow_higher_versions

Accept enrollment from agents running a newer Wazuh version than the manager.

- **Default value:** `no`
- **Allowed values:** `yes`, `no`

**Note:** This option controls the **enrollment gate** (authd, port 1515). There is an independent option with the same name under `<remote><agents>` that controls the **connection gate** (remoted, port 1514). Both must be set to `yes` for a higher-version agent to both enroll and connect. Setting them differently — for example allowing enrollment but not connection — will result in agents that obtain keys but cannot communicate, which is difficult to diagnose.

```xml
<agents>
  <allow_higher_versions>no</allow_higher_versions>
</agents>
```

---

## Internal Options

The enrollment token store's two limits — 5000 tokens and 7 MiB of file — are constants, not
options: they are sized against what the managers' read-only replica accepts, so raising one on a
single node would only move the failure elsewhere. Room is made by purging
(`--purge-enrollment-tokens`), which is what the refusal tells the operator to do.

The [identity journal](architecture.md#the-identity-journal)'s two ceilings are constants for the
same kind of reason: 5000 pending entries for append admission and an 8 MiB file limit at startup
load (not enforced by append). Neither is a tuning knob. At the admission ceiling, inspect database
write/commit failures and authd's backlog before retrying enrollment.

Every option below is read once at start with a compiled-in default. Three things follow:

- **The shipped file is empty.** It carries only comments, so tuning one of these means adding the
  `name=value` line yourself.
- **An out-of-range or non-numeric value is fatal**, not clamped: the daemon refuses to start and
  names the option it rejected.
  Put comments on separate lines beginning with `#`; an inline comment becomes part of the value.
- **The file is per node and is never synchronized.** Nothing in a cluster propagates it.

Additional authd settings can be configured in `/var/wazuh-manager/etc/wazuh-manager-internal-options.conf`:

```ini
# Auth daemon debug level (0-2)
authd.debug=0

# Timeout for agent enrollment requests (seconds)
auth.timeout_seconds=1

# Timeout for agent enrollment requests (microseconds)
auth.timeout_microseconds=0

# Maximum number of agents allowed (0 = unlimited)
authd.max_agents=0

# Seconds a deletion waits before its indexer purge may run (0 = immediate)
authd.purge_delay=120

# Seconds authd allows for one wazuh-db round trip
authd.wdb_timeout=10

# Deletions still waiting to reach the indexer before new ones are refused (0 = unlimited)
wazuh_modules.manager_task_max_pending_deletes=20000
```

### authd.purge_delay

How long an agent's deletion waits before its indexer purge may run. The deletion itself is never
delayed: `client.keys` and wazuh-db are updated immediately, and only the indexer purge is held back —
authd records it as a Task Manager task whose first attempt is this far out.

- **Default value:** `120`
- **Allowed values:** `0` to `3600` (seconds)

The default is chosen from the three intervals the purge has to outlast, because **whatever a purge
misses survives forever** — the agent is gone, so nothing will overwrite those documents again:

| Interval | Why it matters |
|---|---|
| index refresh, ~1 s | a `_delete_by_query` is a *search*: it cannot match documents the indexer has not made searchable yet |
| cluster integrity sync, 9 s | until a worker node pulls the new `client.keys`, it keeps accepting that agent's data and writing it |
| keepalive tolerance, 120 s | the longest a worker can be out of touch and still be considered alive, so the longest it can legitimately be behind |

120 seconds covers the widest of the three. **A single-node manager** only faces the first one and can
lower this to a few seconds safely. `0` makes the purge eligible immediately and exists for tests;
raising it beyond a couple of minutes only makes documents linger longer.

The deletion is a durable task, so the wait survives a restart: see
[Agent removal and the indexer](README.md#agent-removal-and-the-indexer).

### authd.wdb_timeout

How long authd allows for one wazuh-db round trip.

- **Default value:** `10`
- **Allowed values:** `1` to `300` (seconds)

It exists because the thread that records a deletion is the same thread that persists `client.keys`.
With an unbounded client a wedged wazuh-db would **hang** it, and a stuck writer has no next cycle to
recover in; bounded, the same failure is just a phase that did not complete, and the next cycle
retries it. There is no reason to raise this on a healthy manager — a local socket answers in
milliseconds.

### wazuh_modules.manager_task_max_pending_deletes

How many agent deletions may be waiting to reach the indexer before authd refuses new ones with
`9021` (`1766` through the server API). A refused deletion leaves the agent **untouched**.

- **Default value:** `20000`
- **Allowed values:** `0` (unlimited) to `1000000`

It lives in the Task Manager's namespace on purpose: this is one bound on one queue, enforced when the
task is created and pre-checked by authd so a caller gets a refusal instead of a deletion that only
half-succeeds. Two keys would let the two halves disagree.

Raising it lets a larger fleet-wide deletion be admitted in one go, at the cost of a deeper backlog if
the indexer is slow or unreachable. Setting it to `0` removes the bound entirely, which is only safe
if you are certain the indexer keeps up.

### remoted.jwt_max_age and remoted.jwt_clock_skew

Two of **remoted's** internal options that authd reads as well, for one purpose: the time window of the
re-enrollment credential. An agent that re-enrolls keeping its id signs a `wazuh-enroll+jwt` bearer with
its `reenroll_secret`; remoted forwards it unverified and authd on the master judges it (see
[Re-enrollment secret](README.md#re-enrollment-secret)) with the same window remoted applies to the
agent's every other request. A bearer outside it is refused with `9028`.

- **Default values:** `remoted.jwt_max_age=60`, `remoted.jwt_clock_skew=30` (seconds)
- **Allowed values:** `1` to `43200` and `0` to `43200` — remoted's own bounds

They are read from the `remoted.*` namespace on purpose — authd has no keys of its own for this, so the
two daemons cannot drift apart — and the `authd.*` options above are unchanged. Reference:
[`remoted.jwt_max_age`](../remoted/configuration.md#remotedjwt_max_age),
[`remoted.jwt_clock_skew`](../remoted/configuration.md#remotedjwt_clock_skew).

**Note:** Use `wazuh-manager-internal-options.conf` to preserve settings across upgrades.

---

## Configuration Examples

### Basic Configuration

Standard enrollment with password protection:

```xml
<auth>
  <disabled>no</disabled>
  <port>1515</port>
  <use_password>yes</use_password>
  <force>
    <enabled>yes</enabled>
    <key_mismatch>yes</key_mismatch>
    <disconnected_time enabled="yes">1h</disconnected_time>
    <after_registration_time>1h</after_registration_time>
  </force>
</auth>
```

### Secure Configuration with TLS

Mutual TLS with client certificate verification:

```xml
<auth>
  <disabled>no</disabled>
  <port>1515</port>
  <use_password>yes</use_password>
  <ssl_agent_ca>/var/wazuh-manager/etc/rootCA.pem</ssl_agent_ca>
  <ssl_verify_host>yes</ssl_verify_host>
  <ssl_manager_cert>/var/wazuh-manager/etc/certs/remoted.pem</ssl_manager_cert>
  <ssl_manager_key>/var/wazuh-manager/etc/certs/remoted-key.pem</ssl_manager_key>
  <ciphers>TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256</ciphers>
  <force>
    <enabled>yes</enabled>
    <key_mismatch>yes</key_mismatch>
    <disconnected_time enabled="yes">2h</disconnected_time>
    <after_registration_time>2h</after_registration_time>
  </force>
</auth>
```

### Strict IP Binding

Register agents with their source IP:

```xml
<auth>
  <disabled>no</disabled>
  <port>1515</port>
  <use_source_ip>yes</use_source_ip>
  <use_password>yes</use_password>
  <purge>yes</purge>
  <force>
    <enabled>no</enabled>
  </force>
</auth>
```

### Allow Higher Agent Versions

Accept enrollment from newer agent versions:

```xml
<auth>
  <disabled>no</disabled>
  <port>1515</port>
  <use_password>yes</use_password>
  <agents>
    <allow_higher_versions>yes</allow_higher_versions>
  </agents>
  <force>
    <enabled>yes</enabled>
    <key_mismatch>yes</key_mismatch>
    <disconnected_time enabled="yes">1h</disconnected_time>
    <after_registration_time>1h</after_registration_time>
  </force>
</auth>
```

### Local-Only Enrollment

Disable remote enrollment (require local socket):

```xml
<auth>
  <disabled>no</disabled>
  <port>1515</port>
  <remote_enrollment>no</remote_enrollment>
  <use_password>yes</use_password>
  <force>
    <enabled>yes</enabled>
  </force>
</auth>
```

### Development/Testing Configuration

Relaxed settings for testing (NOT for production):

```xml
<auth>
  <disabled>no</disabled>
  <port>1515</port>
  <use_password>no</use_password>
  <purge>yes</purge>
  <force>
    <enabled>yes</enabled>
    <key_mismatch>yes</key_mismatch>
    <disconnected_time enabled="no">0</disconnected_time>
    <after_registration_time>0</after_registration_time>
  </force>
</auth>
```

---

## See Also

- [Auth Daemon Module](README.md) - Module overview and architecture
- [Client Configuration](../client/configuration.md) - Agent enrollment settings
- [Remote Configuration](../remoted/configuration.md) - Agent connection settings
- [Agent Management](../agent-management/README.md) - Agent lifecycle management

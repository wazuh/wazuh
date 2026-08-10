# Auth Daemon Configuration Reference

Complete configuration reference for the Wazuh enrollment service (authd), which issues keys and registers new agents.

**Configuration file:** `/var/wazuh-manager/etc/wazuh-manager.conf`

**XML Section:** `<auth>`

**Module:** Manager-only

**Internal Options:** `authd.*`

For module overview and architecture, see [Auth Daemon Module](index.html).

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

### ipv6

Enable IPv6 support.

- **Default value:** `no`
- **Allowed values:** `yes`, `no`

### use_source_ip

Register agents using their source IP address instead of `any`.

- **Default value:** `no`
- **Allowed values:** `yes`, `no`
- **Note:** When enabled, agents can only connect from the IP they enrolled from

### purge

Remove all previous keys for an agent when it re-enrolls with the same name.

- **Default value:** `no`
- **Allowed values:** `yes`, `no`

### use_password

Require agents to provide a shared enrollment password.

- **Default value:** `no` (the configuration shipped by the installer sets it to `yes`)
- **Allowed values:** `yes`, `no`

When enabled, the password is read from `/var/wazuh-manager/etc/authd.pass` (a single line). If the file does not exist, `wazuh-authd` generates a random password on start, stores it in that file, and reuses it on later starts. If the file exists but is empty or invalid, `wazuh-authd` does not start. In a cluster, the password belongs to the master and is distributed to the workers automatically; a worker rejects enrollment until it receives the file.

**Agent-side setup:** Because `use_password` is `yes` by default, agents must supply the enrollment password or their enrollment request will be rejected. First retrieve the password from the manager:

```bash
sudo cat /var/wazuh-manager/etc/authd.pass
```

The recommended way to provide it to an agent is the `WAZUH_REGISTRATION_PASSWORD` install variable, which writes `etc/authd.pass` and sets its ownership and permissions automatically:

```bash
WAZUH_MANAGER="<manager-ip>" WAZUH_REGISTRATION_PASSWORD="<password>" apt install ./wazuh-agent.deb
```

To add it to an already-installed agent, write the file manually. The agent daemon (`wazuh-agentd`) runs as the `wazuh` user, so the file must be readable by that user:

```bash
echo "<password>" | sudo tee /var/ossec/etc/authd.pass
sudo chown root:wazuh /var/ossec/etc/authd.pass
sudo chmod 640 /var/ossec/etc/authd.pass
```

The agent reads the password from `etc/authd.pass` (relative to its install directory, typically `/var/ossec/etc/authd.pass`) at startup.

**Password rotation:** The generated password persists across restarts. To rotate it (for example after a security incident), delete `/var/wazuh-manager/etc/authd.pass` on the master and restart `wazuh-authd`. A new random password will be generated, persisted, and distributed to workers automatically. The reuse of an existing password is logged at `INFO` level on every start.

### remote_enrollment

Accept enrollment requests over the network (port 1515). Disable to restrict enrollment to the local socket only.

- **Default value:** `yes`
- **Allowed values:** `yes`, `no`

### ciphers

Colon-separated list of TLS 1.3 cipher suites accepted by the enrollment TLS session (applied via OpenSSL's `SSL_CTX_set_ciphersuites`). `wazuh-authd` requires TLS 1.3 as the minimum protocol version, so this option only accepts TLS 1.3 cipher suite names — legacy OpenSSL cipher-list strings (e.g. `HIGH:!ADH:...`) used before TLS 1.3 enforcement are no longer valid and are rejected at startup with a clear error.

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

Path to the manager's TLS certificate presented to agents during enrollment.

- **Default value:** `etc/certs/authd.pem` (resolved relative to the Wazuh install directory, e.g. `/var/wazuh-manager/etc/certs/authd.pem`)
- **Allowed values:** Path to a PEM-encoded certificate (relative paths resolved from the Wazuh install directory)

### ssl_manager_key

Path to the private key corresponding to `ssl_manager_cert`.

- **Default value:** `etc/certs/authd-key.pem` (resolved relative to the Wazuh install directory)
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
```

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
  <ssl_manager_cert>/var/wazuh-manager/etc/certs/authd.pem</ssl_manager_cert>
  <ssl_manager_key>/var/wazuh-manager/etc/certs/authd-key.pem</ssl_manager_key>
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

- [Auth Daemon Module](index.html) - Module overview and architecture
- [Client Configuration](../client/configuration.md) - Agent enrollment settings
- [Remote Configuration](../remoted/configuration.md) - Agent connection settings
- [Agent Management](../agent-management/index.html) - Agent lifecycle management

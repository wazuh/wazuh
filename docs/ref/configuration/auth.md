# Auth (Enrollment) Configuration

The `<auth>` section configures the enrollment service (`wazuh-manager-authd`), which issues keys and registers new agents.

Configuration file: `/var/wazuh-manager/etc/wazuh-manager.conf`

Parser: `src/config/src/authd-config.c`

## Configuration Options

### disabled

Disables the enrollment service entirely. When the `<auth>` block is present but this option is not set, the service starts (`disabled=no`).

- **Default value**: `no`
- **Allowed values**: `yes`, `no`

### port

TCP port on which the enrollment service listens.

- **Default value**: `1515`
- **Allowed values**: Integer from `1` to `65535`

### ipv6

Enable IPv6 support.

- **Default value**: `no`
- **Allowed values**: `yes`, `no`

### use_source_ip

Register agents using their source IP address instead of `any`.

- **Default value**: `no`
- **Allowed values**: `yes`, `no`

### purge

Remove all previous keys for an agent when it re-enrolls with the same name.

- **Default value**: `no`
- **Allowed values**: `yes`, `no`

### use_password

Require agents to provide a shared enrollment password.

- **Default value**: `no` (the configuration shipped by the installer sets it to `yes`)
- **Allowed values**: `yes`, `no`

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

- **Default value**: `yes`
- **Allowed values**: `yes`, `no`

### ciphers

OpenSSL cipher string applied to the TLS session.

- **Default value**: `HIGH:!ADH:!EXP:!MD5:!RC4:!3DES:!CAMELLIA:@STRENGTH`
- **Allowed values**: Any valid OpenSSL cipher string

### ssl_agent_ca

Path to the CA certificate used to verify agent client certificates during mutual TLS.

- **Default value**: none (agent certificate verification disabled)
- **Allowed values**: Path to a PEM-encoded CA certificate (existence checked at startup)

### ssl_verify_host

Verify that the CN of the agent certificate matches the agent's IP address. Requires `ssl_agent_ca` to be set.

- **Default value**: `no`
- **Allowed values**: `yes`, `no`

### ssl_manager_cert

Path to the manager's TLS certificate presented to agents during enrollment.

- **Default value**: `etc/sslmanager.cert` (resolved relative to the Wazuh install directory, e.g. `/var/wazuh-manager/etc/sslmanager.cert`)
- **Allowed values**: Path to a PEM-encoded certificate (relative paths resolved from the Wazuh install directory)

### ssl_manager_key

Path to the private key corresponding to `ssl_manager_cert`.

- **Default value**: `etc/sslmanager.key` (resolved relative to the Wazuh install directory)
- **Allowed values**: Path to a PEM-encoded private key (relative paths resolved from the Wazuh install directory)

### ssl_auto_negotiate

Allow the TLS handshake to automatically select the highest available protocol version.

- **Default value**: `no`
- **Allowed values**: `yes`, `no`

### force

Sub-element that controls forced re-enrollment behavior when an agent already exists in the manager keystore.

```xml
<force>
  <enabled>yes</enabled>
  <key_mismatch>yes</key_mismatch>
  <disconnected_time enabled="yes">1h</disconnected_time>
  <after_registration_time>1h</after_registration_time>
</force>
```

#### force / enabled

Allow forced re-enrollment (overwrite an existing agent entry).

- **Default value**: `yes`
- **Allowed values**: `yes`, `no`

#### force / key_mismatch

Force re-enrollment when an agent reconnects with a key that does not match what the manager has stored.

- **Default value**: `yes`
- **Allowed values**: `yes`, `no`

#### force / disconnected_time

Minimum time an agent must have been disconnected before it can be forcibly re-enrolled. The `enabled` attribute gates this check. The value is the duration; `enabled` controls whether the check is active.

- **Default value**: `1h` with `enabled="yes"`
- **Allowed values**: Time value with optional suffix — `s`, `m`, `h`, `d`; attribute `enabled`: `yes`/`no`

```xml
<!-- Enable the check, require 2h disconnection -->
<disconnected_time enabled="yes">2h</disconnected_time>

<!-- Disable the check entirely -->
<disconnected_time enabled="no">0</disconnected_time>
```

#### force / after_registration_time

Minimum time since an agent was last registered before a forced re-enrollment is permitted. This prevents an agent from being replaced immediately after its initial enrollment.

- **Default value**: `1h`
- **Allowed values**: Time value with optional suffix — `s`, `m`, `h`, `d`

### agents / allow_higher_versions

Accept enrollment from agents running a newer Wazuh version than the manager.

- **Default value**: `no`
- **Allowed values**: `yes`, `no`

> **Note:** This option controls the **enrollment gate** (authd, port 1515). There is an independent option with the same name under `<remote><agents>` that controls the **connection gate** (remoted, port 1514). Both must be set to `yes` for a higher-version agent to both enroll and connect. Setting them differently — for example allowing enrollment but not connection — will result in agents that obtain keys but cannot communicate, which is difficult to diagnose.

```xml
<agents>
  <allow_higher_versions>no</allow_higher_versions>
</agents>
```

## Configuration Example

```xml
<auth>
  <disabled>no</disabled>
  <port>1515</port>
  <use_source_ip>no</use_source_ip>
  <purge>yes</purge>
  <use_password>yes</use_password>
  <ssl_verify_host>no</ssl_verify_host>
  <ssl_manager_cert>/var/wazuh-manager/etc/sslmanager.cert</ssl_manager_cert>
  <ssl_manager_key>/var/wazuh-manager/etc/sslmanager.key</ssl_manager_key>
  <ssl_auto_negotiate>no</ssl_auto_negotiate>
  <force>
    <enabled>yes</enabled>
    <key_mismatch>yes</key_mismatch>
    <disconnected_time enabled="yes">1h</disconnected_time>
    <after_registration_time>1h</after_registration_time>
  </force>
</auth>
```

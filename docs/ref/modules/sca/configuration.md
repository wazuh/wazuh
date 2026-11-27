# SCA Configuration Reference

Complete configuration reference for the Security Configuration Assessment (SCA) module.

The SCA module evaluates system security posture against predefined policies, implementing a dual event system for both real-time alerts and reliable state synchronization with the manager.

For module overview and architecture, see [SCA Module](README.md).

---

**Configuration file:** `/var/ossec/etc/ossec.conf`

**XML Section:** `<sca>`

**Module:** Agent-only

**Internal Options:** `sca.*`

---

## Configuration Options

**Deprecated options:**

- `<skip_nfs>`, `<day>`, `<wday>` and `<time>`: parsed but no longer have any effect, each logging `The <option> option is deprecated and no longer has any effect.` (at info level for `<skip_nfs>`, which the 4.x default configuration sets, and as a warning for the rest). NFS scanning is not configurable, and SCA scans on its `<interval>` only.

### enabled

Enable or disable the SCA module.

- **Default value:** `yes`
- **Allowed values:** `yes`, `no`
- **Note:** When disabled, no security configuration assessments are performed

### scan_on_start

Run a security assessment scan immediately when the agent starts.

- **Default value:** `yes`
- **Allowed values:** `yes`, `no`
- **Note:** Ensures initial compliance status is available as soon as the agent initializes

### interval

Time interval between security configuration assessment scans.

- **Default value:** `12h` as shipped in the generated agent configuration (the built-in fallback when the option is absent is `1d`)
- **Allowed values:** A number with an optional `s`, `m`, `h` or `d` suffix (a bare number is seconds)
- **Note:** Any positive value up to `4294967294` seconds. `0`, larger values and any other suffix (the 4.x `w` and `M` included) are rejected with `Invalid interval at module 'sca'`, a configuration error: in the agent's `ossec.conf` it stops `wazuh-modulesd` from starting. Examples: `12h`, `30m`, `1d`

### max_eps

Maximum events per second that the SCA module can generate.

- **Default value:** `50`
- **Allowed values:** Integer from `0` to `1000000`. `0` means the default (`50`). Any other value (negative, above `1000000`, or not a plain integer) is ignored with a warning and the previous value is kept
- **Note:** Controls rate limiting for SCA events to prevent overwhelming the manager

### policies

Configuration section containing individual policy file definitions.

- **Default value:** Every `.yml` and `.yaml` file in the `ruleset/sca/` directory of the installation
- **Allowed values:** Contains one or more `<policy>` elements
- **Note:** The files present in `ruleset/sca/` are decided by the installed package, so the default policies depend on the operating system the agent was installed on. A `<policy>` element for a file already loaded by default only changes its `enabled` attribute. A `<policy>` element whose value is a prefix of one of the obsolete 4.x policy file names (for example `cis_debian_linux_rcl.yml`) is silently skipped; the match is on the raw configured text, so a path such as `ruleset/sca/cis_debian_linux_rcl.yml` is not skipped

### policy

Path to an individual SCA policy file.

- **Default value:** None (must be explicitly specified)
- **Allowed values:** Absolute path (e.g., `/opt/wazuh-sca/custom_linux.yml`) or a path relative to the agent's installation directory (e.g., `etc/shared/sca/custom_linux.yml`)
- **Note:** Supports optional `enabled` attribute: `<policy enabled="no">path/to/policy.yml</policy>` to disable specific policies. A policy declared in the shared `agent.conf` whose file is not under `ruleset/sca/` is a remote policy: its command (`c:`) rules run only when [`sca.remote_commands`](#scaremote_commands) is `1`; otherwise they are not run, and a check that no other rule settles is reported as `Not applicable` with the reason `Remote commands are disabled for this policy`

---

## Synchronization Options

The `<synchronization>` section controls database synchronization between agent and manager.

### synchronization/enabled

Enable or disable database synchronization for SCA results.

- **Default value:** `yes`
- **Allowed values:** `yes`, `no`
- **Note:** When disabled, only stateless alerts are sent; no state synchronization occurs, and `interval` and `integrity_interval` are not used

### synchronization/interval

Time interval between database synchronization cycles.

- **Default value:** `300s` (5 minutes)
- **Allowed values:** Time format strings (`s`, `m`, `h`, `d` or `w` suffix; a bare number is seconds), greater than `0` and up to `4294967295` seconds. An invalid value is ignored with a warning
- **Note:** Controls how frequently the agent synchronizes SCA state with the manager

### synchronization/integrity_interval

Interval between integrity checks for automatic recovery.

- **Default value:** `86400s` (24 hours)
- **Allowed values:** Time format strings (`s`, `m`, `h`, `d` or `w` suffix; a bare number is seconds) up to `4294967295` seconds, or `0` to disable. An invalid value is ignored with a warning
- **Note:** Set to `0` to disable automatic integrity verification and recovery

---

## Internal Options

**Configuration file:** `/var/ossec/etc/local_internal_options.conf` (Linux/Unix) or `C:\Program Files (x86)\ossec-agent\local_internal_options.conf` (Windows). An upgrade replaces `internal_options.conf`, so set overrides in `local_internal_options.conf`.

Internal options provide advanced tuning for the SCA module. These options are global and apply to all SCA operations.

### sca.remote_commands

Allow execution of commands from SCA policies pushed from the manager via shared configuration.

- **Default value:** `0` (disabled)
- **Allowed values:** `0` (disabled), `1` (enabled)
- **Format:** `sca.remote_commands=0`
- **Note:** Local policies ignore this option and can always execute commands. Enabling this allows manager-distributed policies to execute system commands. Any other value stops `wazuh-modulesd` with `(2302): Invalid definition for sca.remote_commands: '<value>'.`

### sca.commands_timeout

Default timeout for commands executed during an SCA scan.

- **Default value:** `30` (seconds)
- **Allowed values:** Integer from `1` to `300` (seconds)
- **Format:** `sca.commands_timeout=30`
- **Note:** A command rule that times out is reported as not run, and its check as `Not run` when no other rule settles it. A value out of range stops `wazuh-modulesd` with `(2302): Invalid definition for sca.commands_timeout: '<value>'.`

---

## Configuration Examples

### Minimal Configuration

Enable SCA with default settings:

```xml
<sca>
  <enabled>yes</enabled>
</sca>
```

This configuration:
- Enables the SCA module
- Runs scan on agent startup
- Uses auto-detected OS-specific policies
- Applies default scan intervals

### Standard Configuration

Common SCA configuration with custom interval:

```xml
<sca>
  <enabled>yes</enabled>
  <scan_on_start>yes</scan_on_start>
  <interval>12h</interval>
  <max_eps>100</max_eps>
</sca>
```

### Custom Policy Configuration

Specify custom policy files:

```xml
<sca>
  <enabled>yes</enabled>
  <scan_on_start>yes</scan_on_start>
  <interval>6h</interval>
  <policies>
    <policy>/opt/wazuh-sca/custom_linux.yml</policy>
    <policy>/opt/wazuh-sca/custom_apache.yml</policy>
    <policy enabled="no">ruleset/sca/cis_debian12.yml</policy>
  </policies>
</sca>
```

The `enabled="no"` attribute allows keeping policy references in configuration while temporarily disabling them; here it disables a policy the package installed in `ruleset/sca/`.

### Full Configuration with Synchronization

Complete configuration including synchronization settings:

```xml
<sca>
  <enabled>yes</enabled>
  <scan_on_start>yes</scan_on_start>
  <interval>12h</interval>
  <max_eps>100</max_eps>
  <policies>
    <policy>/opt/wazuh-sca/custom_linux.yml</policy>
    <policy>/opt/wazuh-sca/custom_apache.yml</policy>
  </policies>
  <synchronization>
    <enabled>yes</enabled>
    <interval>300</interval>
    <integrity_interval>86400</integrity_interval>
  </synchronization>
</sca>
```

### High-Frequency Scanning

Configuration for environments requiring frequent security assessments:

```xml
<sca>
  <enabled>yes</enabled>
  <scan_on_start>yes</scan_on_start>
  <interval>1h</interval>
  <max_eps>200</max_eps>
  <synchronization>
    <enabled>yes</enabled>
    <interval>180</interval>
    <integrity_interval>43200</integrity_interval>  <!-- 12 hours -->
  </synchronization>
</sca>
```

### Low-Resource Environment

Optimized configuration for systems with limited resources:

```xml
<sca>
  <enabled>yes</enabled>
  <scan_on_start>yes</scan_on_start>
  <interval>24h</interval>
  <max_eps>25</max_eps>
  <synchronization>
    <enabled>yes</enabled>
    <interval>600</interval>
    <integrity_interval>172800</integrity_interval>  <!-- 48 hours -->
  </synchronization>
</sca>
```

### Disable SCA Module

Completely disable security configuration assessment:

```xml
<sca>
  <enabled>no</enabled>
</sca>
```

---

## Policy File Configuration

### Policy File Paths

Policy files can be specified using:

- **Absolute paths:** `/opt/wazuh-sca/custom_linux.yml`
- **Relative paths:** `etc/shared/sca/custom_linux.yml` (relative to the agent's installation directory)
- **Shared paths:** a file placed in a group directory on the manager, `/etc/wazuh-manager/shared/<group>/`, is delivered to the agents of that group under `etc/shared/` (`shared\` on Windows); it is scanned only when a `<policy>` element names it

Do not store custom policies in `ruleset/sca/`: installing or upgrading the agent package deletes every file in that directory before it installs the stock policies. For shared and remote policies and the 4.x differences, see [SCA policies from 4.x to 5.x](../../../guide/migration/sca-policies-4x-to-5x.md).

### Policy File Structure

Policy files are YAML documents containing:

- **Policy metadata:** Name, description, and requirements
- **Security checks:** Rules with conditions for system evaluation
- **Compliance mappings:** CIS, NIST, PCI-DSS, and other framework references

The format is described in [Creating custom SCA policies](custom-policies.md). Policy files are read again at the start of every scan, so a change to a policy file takes effect on the next scan.

### Operating System Specific Defaults

The module does not detect the operating system. When no policies are configured, it loads every policy file found in `ruleset/sca/`, and the installed package decides which files are there: it installs the one policy that matches the operating system and version it is installed on.

**Linux Systems:**
- **Debian:** `cis_debian7.yml` to `cis_debian13.yml`
- **Ubuntu:** `cis_ubuntu14-04.yml` to `cis_ubuntu26-04.yml` (Ubuntu 12.04 gets `cis_debian7.yml`)
- **RHEL:** `cis_rhel6_linux.yml` to `cis_rhel10_linux.yml`
- **CentOS:** `cis_centos6_linux.yml` to `cis_centos10_linux.yml`
- **Oracle Linux:** `cis_oracle_linux_9.yml`, `cis_oracle_linux_10.yml`
- **AlmaLinux:** `cis_alma_linux_8.yml` to `cis_alma_linux_10.yml`
- **Rocky Linux:** `cis_rocky_linux_8.yml` to `cis_rocky_linux_10.yml`
- **Amazon Linux:** `cis_amazon_linux_1.yml`, `cis_amazon_linux_2.yml`, `cis_amazon_linux_2023.yml`
- **SLES/SUSE:** `cis_sles12_linux.yml`, `cis_sles15_linux.yml`, `cis_sles16_linux.yml`
- **Fedora and other distributions:** `sca_distro_independent_linux.yml`

**Windows Systems:**
- **Windows Server:** `cis_win2012_non_r2.yml`, `cis_win2012r2.yml`, `cis_win2016.yml`, `cis_win2019.yml`, `cis_win2022.yml`, `cis_win2025.yml`
- **Windows Desktop:** `cis_win10_enterprise.yml`, `cis_win11_enterprise.yml`

**macOS Systems:**
- **macOS:** `cis_apple_macOS_<version>.yml`, from macOS 10.11 to macOS 26

The application policies of the repository's `ruleset/sca/` (Apache, MySQL, nginx, PostgreSQL, MongoDB, IIS, SQL Server, Oracle Database) are not installed by the packages.

---

## Time Format

Time-based configuration options support flexible time format specifications:

| Format | Example | Description |
|--------|---------|-------------|
| Seconds | `3600s` | 3600 seconds |
| Minutes | `60m` | 60 minutes |
| Hours | `12h` | 12 hours |
| Days | `1d` | 1 day |
| Seconds (no suffix) | `3600` | 3600 seconds |

The `<synchronization>` options also accept `w` (weeks); `<interval>` does not.

**Valid ranges:**
- **Scan interval:** Any positive value up to `4294967294` seconds; `0` and larger values are rejected
- **Synchronization interval:** Any positive value up to `4294967295` seconds, recommended `60s` or higher
- **Integrity interval:** `0` (disabled) or any positive value up to `4294967295` seconds

---

## Validation

### Configuration Validation Rules

The SCA module validates configuration at agent startup:

1. **Policy file existence:** A `<policy>` path that does not resolve to an existing file is logged as a warning and skipped
2. **YAML syntax:** A policy file that cannot be parsed, or has no `policy` object or no `checks` list, is skipped with a warning when it is loaded
3. **Time intervals:** `interval` must be a positive value; `<synchronization>` values must be in range
4. **Option values:** `enabled` and `scan_on_start` accept `yes` or `no`

### Error Handling

Invalid configuration results in:

- **Configuration error (the module configuration is rejected):** an invalid `enabled` or `scan_on_start` value, an invalid `interval`, an unknown tag, an empty or over-long `<policy>` value
- **Warning messages and the value is ignored:** an invalid `max_eps`, an invalid `<synchronization>` value or unknown tag inside `<synchronization>`, a policy file that is not found
- **Deprecated options:** `skip_nfs`, `day`, `wday` and `time` are reported and ignored

Check `/var/ossec/logs/ossec.log` for SCA configuration validation messages.

---

## See Also

- [SCA Module](README.md) - Module overview and features
- [SCA Architecture](architecture.md) - Module architecture and synchronization protocol
- [Custom Policies](custom-policies.md) - Creating custom SCA policies
- [Database Schema](database-schema.md) - SCA database structure
- [API Reference](api-reference.md) - SCA API endpoints
- [Agent Configuration Reference](../../configuration/agent/README.md) - All agent configuration options

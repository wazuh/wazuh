# SCA Configuration Reference

Complete configuration reference for the Security Configuration Assessment (SCA) module.

The SCA module evaluates system security posture against predefined policies, implementing a dual event system for both real-time alerts and reliable state synchronization with the manager.

For module overview and architecture, see [SCA Module](index.html).

---

**Configuration file:** `/var/ossec/etc/ossec.conf`

**XML Section:** `<sca>`

**Module:** Agent-only

**Internal Options:** `sca.*`

---

## Configuration Options

**Deprecated option:** `<skip_nfs>` (parsed but no longer has any effect; NFS scanning behavior is no longer configurable)

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

- **Default value:** Inherited from scan schedule
- **Allowed values:** Time format strings (`s` for seconds, `m` for minutes, `h` for hours, `d` for days)
- **Note:** Valid range is `60s` (1 minute) to `1d` (1 day). Examples: `12h`, `30m`, `1d`

### max_eps

Maximum events per second that the SCA module can generate.

- **Default value:** `50`
- **Allowed values:** Positive integer
- **Note:** Controls rate limiting for SCA events to prevent overwhelming the manager

### policies

Configuration section containing individual policy file definitions.

- **Default value:** Policies are auto-detected based on operating system
- **Allowed values:** Contains one or more `<policy>` elements
- **Note:** If no policies are specified, the module loads default policies matching the system OS

### policy

Path to an individual SCA policy file.

- **Default value:** None (must be explicitly specified)
- **Allowed values:** Absolute path (e.g., `/var/ossec/etc/shared/cis_debian10.yml`) or relative path (e.g., `etc/shared/cis_apache_24.yml`)
- **Note:** Supports optional `enabled` attribute: `<policy enabled="no">path/to/policy.yml</policy>` to disable specific policies

---

## Synchronization Options

The `<synchronization>` section controls database synchronization between agent and manager.

### synchronization/enabled

Enable or disable database synchronization for SCA results.

- **Default value:** `yes`
- **Allowed values:** `yes`, `no`
- **Note:** When disabled, only stateless alerts are sent; no state synchronization occurs

### synchronization/interval

Time interval between database synchronization cycles.

- **Default value:** `300s` (5 minutes)
- **Allowed values:** Time format strings in seconds (e.g., `300s`, `600s`)
- **Note:** Controls how frequently the agent synchronizes SCA state with the manager

### synchronization/max_eps

Maximum events per second for synchronization operations.

- **Default value:** `75`
- **Allowed values:** Positive integer
- **Note:** Separate rate limit for synchronization events, independent of `max_eps`

### synchronization/integrity_interval

Interval between integrity checks for automatic recovery.

- **Default value:** `86400s` (24 hours)
- **Allowed values:** Time format strings in seconds, or `0` to disable
- **Note:** Set to `0` to disable automatic integrity verification and recovery

---

## Internal Options

**Configuration file:** `/var/ossec/etc/internal_options.conf` (Linux/Unix) or `C:\Program Files (x86)\ossec-agent\internal_options.conf` (Windows)

Internal options provide advanced tuning for the SCA module. These options are global and apply to all SCA operations.

### sca.remote_commands

Allow execution of commands from SCA policies pushed from the manager via shared configuration.

- **Default value:** `0` (disabled)
- **Allowed values:** `0` (disabled), `1` (enabled)
- **Format:** `sca.remote_commands=0`
- **Note:** Local policies ignore this option and can always execute commands. Enabling this allows manager-distributed policies to execute system commands

### sca.commands_timeout

Default timeout for commands executed during an SCA scan.

- **Default value:** `30` (seconds)
- **Allowed values:** Integer from `1` to `300` (seconds)
- **Format:** `sca.commands_timeout=30`
- **Note:** Prevents hung commands from blocking SCA scans indefinitely

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
    <policy>/var/ossec/etc/shared/cis_debian10.yml</policy>
    <policy>/var/ossec/etc/shared/cis_apache_24.yml</policy>
    <policy enabled="no">/var/ossec/etc/shared/cis_debian9.yml</policy>
  </policies>
</sca>
```

The `enabled="no"` attribute allows keeping policy references in configuration while temporarily disabling them.

### Full Configuration with Synchronization

Complete configuration including synchronization settings:

```xml
<sca>
  <enabled>yes</enabled>
  <scan_on_start>yes</scan_on_start>
  <interval>12h</interval>
  <max_eps>100</max_eps>
  <policies>
    <policy>/var/ossec/etc/shared/cis_debian10.yml</policy>
    <policy>/var/ossec/etc/shared/cis_apache_24.yml</policy>
  </policies>
  <synchronization>
    <enabled>yes</enabled>
    <interval>300</interval>
    <max_eps>75</max_eps>
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
    <max_eps>150</max_eps>
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
    <max_eps>25</max_eps>
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

- **Absolute paths:** `/var/ossec/etc/policies/custom.yml`
- **Relative paths:** `etc/shared/cis_debian10.yml` (relative to Wazuh installation directory)
- **Shared paths:** Policies in `/var/ossec/etc/shared/` are distributed by the manager to agents

### Policy File Structure

Policy files are YAML documents containing:

- **Policy metadata:** Name, description, and requirements
- **Security checks:** Rules with conditions for system evaluation
- **Compliance mappings:** CIS, NIST, PCI-DSS, and other framework references

### Operating System Specific Defaults

When no policies are explicitly configured, SCA automatically loads policies based on the detected operating system:

**Linux Systems:**
- **Debian/Ubuntu:** `cis_debian*.yml`, `cis_ubuntu*.yml`
- **RHEL/CentOS:** `cis_rhel*.yml`, `cis_centos*.yml`
- **Amazon Linux:** `cis_amazon*.yml`

**Windows Systems:**
- **Windows Server:** `cis_win2016.yml`, `cis_win2019.yml`
- **Windows Desktop:** `cis_win10_enterprise.yml`, `cis_win11_enterprise.yml`

**macOS Systems:**
- **macOS:** `cis_apple_macOS*.yml`

---

## Time Format

Time-based configuration options support flexible time format specifications:

| Format | Example | Description |
|--------|---------|-------------|
| Seconds | `3600s` | 3600 seconds |
| Minutes | `60m` | 60 minutes |
| Hours | `12h` | 12 hours |
| Days | `1d` | 1 day |

**Valid ranges:**
- **Scan interval:** Minimum `60s` (1 minute), maximum `1d` (1 day)
- **Synchronization interval:** Minimum `1s`, recommended `60s` or higher

---

## Validation

### Configuration Validation Rules

The SCA module validates configuration at agent startup:

1. **Policy file existence:** All specified policy files must exist and be readable
2. **YAML syntax:** Policy files must be valid YAML with correct structure
3. **Required fields:** Policies must contain required metadata fields
4. **Time intervals:** Must be within valid ranges
5. **Path permissions:** Agent must have read access to policy file paths

### Error Handling

Invalid configuration results in:

- **Warning messages:** Logged for non-critical issues (e.g., missing optional fields)
- **Module disabled:** Critical configuration errors prevent module initialization
- **Default values:** Invalid optional parameters fall back to default values

Check `/var/ossec/logs/ossec.log` for SCA configuration validation messages.

---

## See Also

- [SCA Module](index.html) - Module overview and features
- [SCA Architecture](architecture.md) - Module architecture and synchronization protocol
- [Custom Policies](custom-policies.md) - Creating custom SCA policies
- [Database Schema](database-schema.md) - SCA database structure
- [API Reference](api-reference.md) - SCA API endpoints
- [Agent Configuration Reference](../../configuration/agent/README.md) - All agent configuration options

# Configuration

The SCA module configuration defines how security configuration assessments are performed, including scan intervals, policy selection, and operational parameters.

---

## Basic Configuration

### Minimal Configuration
```xml
<sca>
  <enabled>yes</enabled>
</sca>
```

This enables the SCA module with default settings:
- Scan on start: enabled
- Scan interval: inherited from scheduling
- Default policies: auto-detected based on OS

### Full Configuration Example
```xml
<sca>
  <enabled>yes</enabled>
  <scan_on_start>yes</scan_on_start>
  <interval>12h</interval>
  <max_eps>100</max_eps>
  <policies>
    <policy>/var/ossec/etc/shared/cis_debian10.yml</policy>
    <policy>/var/ossec/etc/shared/cis_apache_24.yml</policy>
    <policy enabled="no">/custom/policies/disabled_policy.yml</policy>
  </policies>
  <synchronization>
    <enabled>yes</enabled>
    <interval>300</interval>
    <response_timeout>60</response_timeout>
    <max_eps>10</max_eps>
  </synchronization>
</sca>
```

---

## Configuration Options

### Core Settings

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | boolean | `yes` | Enable or disable the SCA module |
| `scan_on_start` | boolean | `yes` | Run assessment when agent starts |
| `interval` | time | inherited from scan schedule | Time between scans (scheduling tags) |
| `max_eps` | number | `50` | Maximum events per second |

### Policy Management

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `policies` | section | auto-loaded | Configuration section for policy files |
| `policy` | string | — | Individual policy file path (can have `enabled` attribute) |

### Synchronization Settings

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `synchronization/enabled` | boolean | `yes` | Enable database synchronization |
| `synchronization/interval` | time | `300s` | Database synchronization interval |
| `synchronization/response_timeout` | time | `60s` | Synchronization response timeout |
| `synchronization/max_eps` | number | `10` | Max events per second for sync |

---

## Time Interval Format

The `interval` option supports various time formats:

| Format | Example | Description |
|--------|---------|-------------|
| Seconds | `3600s` | Scan every 3600 seconds |
| Minutes | `60m` | Scan every 60 minutes |
| Hours | `2h` | Scan every 2 hours |
| Days | `1d` | Scan once per day |

**Valid ranges:**
- Minimum: `60s` (1 minute)
- Maximum: `1d` (1 day)

---

## Policy Configuration

### Policy File Structure
Policy files are YAML documents containing:
- Policy metadata (name, description, requirements)
- Security checks with rules and conditions
- Compliance mappings

### Policy Paths
Policies can be specified using:
- **Absolute paths**: `/var/ossec/etc/policies/custom.yml`
- **Relative paths**: `etc/shared/cis_debian10.yml` (relative to Wazuh installation)
- **Shared paths**: Policies in the shared folder distributed by manager

---

## Operating System Specific Defaults

### Linux Systems
Default policies based on distribution:
- **Debian/Ubuntu**: `cis_debian*.yml`, `cis_ubuntu*.yml`
- **RHEL/CentOS**: `cis_rhel*.yml`, `cis_centos*.yml`
- **Amazon Linux**: `cis_amazon*.yml`

### Windows Systems
Default policies:
- **Windows Server**: `cis_win2016.yml`, `cis_win2019.yml`
- **Windows Desktop**: `cis_win10_enterprise.yml`, `cis_win11_enterprise.yml`

### macOS Systems
Default policies:
- **macOS**: `cis_apple_macOS*.yml`

---

## Configuration Validation

### Validation Rules
The SCA module validates configuration at startup:

1. **Policy file existence**: All specified policy files must exist
2. **YAML syntax**: Policy files must be valid YAML
3. **Required fields**: Policies must contain required metadata
4. **Time intervals**: Must be within valid ranges
5. **Path permissions**: Agent must have read access to policy files

### Error Handling
Invalid configuration results in:
- Warning messages in logs for non-critical issues
- Module disabled for critical configuration errors
- Default values used for invalid optional parameters

---

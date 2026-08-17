# Syscollector Configuration Reference

Complete configuration reference for the Syscollector module that collects system inventory information including hardware, OS, packages, processes, network configuration, and more.

**Configuration file:** `/var/ossec/etc/ossec.conf` (agent)

**XML Section:** `<wodle name="syscollector">`

**Module:** Agent-only

**Internal Options:** None

For module overview and architecture, see [Syscollector Module](index.html).

> **Important:** Starting in version 5.0, vulnerability detection is handled by a separate Vulnerability Detector module. Syscollector focuses exclusively on inventory collection (packages, OS, hotfixes, etc.), while vulnerability detection and CVE correlation are performed independently.

---

## Configuration Options

### Basic Module Settings

#### disabled

Enable or disable the Syscollector module.

- **Default value:** `no`
- **Allowed values:** `yes`, `no`
- **Note:** When disabled, no inventory scans are performed

#### interval

How frequently the module performs inventory scans.

- **Default value:** `1h`
- **Allowed values:** Time period (minimum `60s`)
- **Note:** Accepts time suffixes: `s` (seconds), `m` (minutes), `h` (hours), `d` (days)

#### scan_on_start

Perform an inventory scan when the agent starts.

- **Default value:** `yes`
- **Allowed values:** `yes`, `no`
- **Note:** Provides immediate inventory after agent startup

#### max_eps

Maximum events per second for stateless/real-time inventory events.

- **Default value:** `50`
- **Allowed values:** `0` to `1000000`
- **Note:** Set to `0` for unlimited (not recommended). This limit applies only to stateless inventory events, not synchronization messages.

#### notify_first_scan

Generate events during the initial inventory scan.

- **Default value:** `no`
- **Allowed values:** `yes`, `no`
- **Note:** When `no`, suppresses events during first scan and only reports changes after baseline establishment

### Inventory Categories

#### hardware

Collect CPU, memory, and storage information.

- **Default value:** `yes`
- **Allowed values:** `yes`, `no`
- **Note:** Includes processor details, RAM capacity, and disk information

#### os

Collect operating system details.

- **Default value:** `yes`
- **Allowed values:** `yes`, `no`
- **Note:** Includes OS name, version, architecture, and kernel information

#### network

Collect network interfaces and configuration.

- **Default value:** `yes`
- **Allowed values:** `yes`, `no`
- **Note:** Includes interface details, IP addresses, MAC addresses, and network protocols

#### packages

Collect installed software packages.

- **Default value:** `yes`
- **Allowed values:** `yes`, `no`
- **Note:** Package collection varies by platform (RPM, DEB, .pkg, Homebrew, MSI, etc.)

#### ports

Collect open network ports.

- **Default value:** `yes`
- **Allowed values:** `yes`, `no`
- **Note:** Accepts optional `all` attribute: `<ports all="yes">` scans all ports, `<ports all="no">` scans only listening ports

#### processes

Collect running processes.

- **Default value:** `yes`
- **Allowed values:** `yes`, `no`
- **Note:** Includes process name, PID, user, and command line arguments

#### users

Collect system user accounts.

- **Default value:** `yes`
- **Allowed values:** `yes`, `no`
- **Note:** Includes username, UID, group membership, and home directory

#### groups

Collect system groups.

- **Default value:** `yes`
- **Allowed values:** `yes`, `no`
- **Note:** Includes group name, GID, and member users

#### services

Collect system services.

- **Default value:** `yes`
- **Allowed values:** `yes`, `no`
- **Note:** Platform-specific: systemd units (Linux), services (Windows), launchd (macOS)

#### browser_extensions

Collect browser add-ons and extensions.

- **Default value:** `yes`
- **Allowed values:** `yes`, `no`
- **Note:** Supports major browsers: Chrome, Firefox, Edge, Safari

#### hotfixes

Collect Windows updates and hotfixes.

- **Default value:** `yes`
- **Allowed values:** `yes`, `no`
- **Note:** Windows only - includes KB updates and patches

---

## Synchronization Configuration

The synchronization feature enables persistent inventory state management through the Agent Sync Protocol. This section is wrapped in `<synchronization>` tags within the wodle configuration.

### enabled

Enable or disable Syscollector synchronization persistence.

- **Default value:** `yes`
- **Allowed values:** `yes`, `no`
- **Note:** When disabled, Syscollector only generates stateless events without persistence

### interval

How often to trigger synchronization with the manager.

- **Default value:** `300` (5 minutes)
- **Allowed values:** `1` to unlimited (seconds)
- **Note:** Lower values provide faster synchronization but increase manager load. Higher values reduce network traffic but delay inventory delivery.

### max_eps

Maximum events per second for synchronization messages.

- **Default value:** `75`
- **Allowed values:** `0` to `1000000`
- **Note:** Prevents overwhelming the manager with inventory synchronization traffic. Separate from stateless inventory event rate limiting. Set to `0` for unlimited (not recommended).

### integrity_interval

Time between integrity checks for each inventory table.

- **Default value:** `86400` (24 hours)
- **Allowed values:** `60` to unlimited (seconds)
- **Note:** Each of the 13 inventory tables (osinfo, hwinfo, packages, processes, ports, network_iface, network_protocol, network_address, users, groups, services, browser_extensions, hotfixes) is checked independently. When the interval elapses for a table:
  1. Agent calculates checksum-of-checksums for the table
  2. Sends checksum to manager for validation
  3. If checksums match: integrity confirmed, `last_sync_time` updated
  4. If checksums mismatch: full table recovery initiated (all rows sent to manager)

---

## Internal Options

Syscollector does not have configurable internal options.

---

## Configuration Examples

### Default Configuration

Standard configuration for most deployments:

```xml
<wodle name="syscollector">
    <disabled>no</disabled>
    <interval>1h</interval>
    <scan_on_start>yes</scan_on_start>

    <!-- Inventory categories -->
    <hardware>yes</hardware>
    <os>yes</os>
    <network>yes</network>
    <packages>yes</packages>
    <ports all="yes">yes</ports>
    <processes>yes</processes>
    <users>yes</users>
    <groups>yes</groups>
    <services>yes</services>
    <browser_extensions>yes</browser_extensions>
    <hotfixes>yes</hotfixes>

    <!-- Rate limiting -->
    <max_eps>50</max_eps>
    <notify_first_scan>no</notify_first_scan>

    <!-- Synchronization -->
    <synchronization>
        <enabled>yes</enabled>
        <interval>300</interval>
        <max_eps>75</max_eps>
        <integrity_interval>86400</integrity_interval>
    </synchronization>
</wodle>
```

### Performance Optimized (Minimal Configuration)

Reduce resource usage by disabling resource-intensive scans:

```xml
<wodle name="syscollector">
    <disabled>no</disabled>
    <interval>24h</interval>
    <scan_on_start>yes</scan_on_start>

    <!-- Core inventory only -->
    <hardware>yes</hardware>
    <os>yes</os>
    <packages>yes</packages>

    <!-- Disable resource-intensive scans -->
    <network>no</network>
    <processes>no</processes>
    <ports>no</ports>
    <users>no</users>
    <groups>no</groups>
    <services>no</services>
    <browser_extensions>no</browser_extensions>
    <hotfixes>no</hotfixes>

    <synchronization>
        <enabled>yes</enabled>
    </synchronization>
</wodle>
```

### Security-Focused Configuration

Emphasize security-relevant inventory data:

```xml
<wodle name="syscollector">
    <disabled>no</disabled>
    <interval>1h</interval>
    <scan_on_start>yes</scan_on_start>

    <!-- Security-relevant categories -->
    <hardware>yes</hardware>
    <os>yes</os>
    <packages>yes</packages>
    <ports all="yes">yes</ports>
    <users>yes</users>
    <groups>yes</groups>
    <services>yes</services>
    <hotfixes>yes</hotfixes>

    <!-- Optional categories -->
    <network>no</network>
    <processes>no</processes>
    <browser_extensions>no</browser_extensions>

    <synchronization>
        <enabled>yes</enabled>
    </synchronization>
</wodle>
```

### High-Frequency Monitoring

For environments with frequent inventory changes:

```xml
<wodle name="syscollector">
    <disabled>no</disabled>
    <interval>5m</interval>
    <scan_on_start>yes</scan_on_start>

    <!-- Focus on dynamic data -->
    <processes>yes</processes>
    <ports>yes</ports>
    <services>yes</services>

    <!-- Static data less frequently needed -->
    <hardware>no</hardware>
    <os>no</os>
    <network>no</network>
    <packages>no</packages>
    <users>no</users>
    <groups>no</groups>
    <browser_extensions>no</browser_extensions>
    <hotfixes>no</hotfixes>

    <!-- Increased throughput -->
    <max_eps>100</max_eps>

    <synchronization>
        <enabled>yes</enabled>
        <interval>120</interval>         <!-- Sync every 2 minutes -->
        <max_eps>150</max_eps>           <!-- Higher sync throughput -->
        <integrity_interval>3600</integrity_interval>  <!-- Check integrity every hour -->
    </synchronization>
</wodle>
```

### High-Performance Synchronization

Optimized for large-scale deployments with fast networks:

```xml
<wodle name="syscollector">
    <disabled>no</disabled>
    <interval>1h</interval>
    <scan_on_start>yes</scan_on_start>

    <!-- All categories enabled -->
    <hardware>yes</hardware>
    <os>yes</os>
    <network>yes</network>
    <packages>yes</packages>
    <ports all="yes">yes</ports>
    <processes>yes</processes>
    <users>yes</users>
    <groups>yes</groups>
    <services>yes</services>
    <browser_extensions>yes</browser_extensions>
    <hotfixes>yes</hotfixes>

    <max_eps>200</max_eps>
    <notify_first_scan>no</notify_first_scan>

    <synchronization>
        <enabled>yes</enabled>
        <interval>120</interval>
        <max_eps>200</max_eps>
        <integrity_interval>43200</integrity_interval>  <!-- 12 hours -->
    </synchronization>
</wodle>
```

---

## Platform-Specific Notes

### Windows

- **hotfixes:** Windows-specific category for KB updates and patches
- **packages:** Includes MSI packages and Windows installed programs
- **services:** Windows services from Service Control Manager
- **Configuration file:** `C:\Program Files (x86)\ossec-agent\ossec.conf`

### Linux

- **packages:** Varies by distribution (RPM, DEB, APK, etc.)
- **services:** Typically systemd units on modern distributions
- **hotfixes:** Not applicable (category disabled)
- **Configuration file:** `/var/ossec/etc/ossec.conf`

### macOS

- **packages:** Includes .pkg files and Homebrew packages
- **services:** launchd services and agents
- **hotfixes:** Not applicable (category disabled)
- **Configuration file:** `/Library/Ossec/etc/ossec.conf`

### All Platforms

- **browser_extensions:** Supports Chrome, Firefox, Edge, Safari (platform-dependent availability)
- **network:** Includes IPv4 and IPv6 interfaces and addresses

---

## Event Rate Control

Syscollector implements separate rate controls for different event types:

### Stateless Inventory Events

Configured at the module level:

```xml
<max_eps>50</max_eps>  <!-- Outside synchronization block -->
```

Controls stateless immediate inventory change alerts with higher priority than sync messages.

### Synchronization Events

Configured within the synchronization block:

```xml
<synchronization>
    <max_eps>75</max_eps>  <!-- Inside synchronization block -->
</synchronization>
```

Controls stateful persistence messages sent during sync sessions for batch inventory state synchronization.

---

## Validation and Monitoring

### Validate Configuration

Test configuration syntax before applying:

```bash
# Linux/Unix
/var/ossec/bin/wazuh-agentd -t

# Windows
"C:\Program Files (x86)\ossec-agent\wazuh-agent.exe" -t
```

### Monitor Syscollector Activity

View module logs:

```bash
# Linux/Unix
tail -f /var/ossec/logs/ossec.log | grep syscollector

# Windows
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Wait | Select-String "syscollector"
```

### Check Synchronization Status

Monitor synchronization events in manager logs:

```bash
tail -f /var/ossec/logs/ossec.log | grep -E "syscollector|dbsync"
```

---

## Troubleshooting

### No Inventory Data Collected

**Check module is enabled:**
```bash
grep -A2 'wodle name="syscollector"' /var/ossec/etc/ossec.conf
```

**Verify scan interval:**
```bash
grep -A5 'wodle name="syscollector"' /var/ossec/etc/ossec.conf | grep interval
```

**Force manual scan:**
```bash
# Restart agent to trigger scan_on_start
/var/ossec/bin/wazuh-control restart
```

### Synchronization Not Working

**Check synchronization is enabled:**
```bash
grep -A10 '<synchronization>' /var/ossec/etc/ossec.conf
```

**Verify agent-manager connectivity:**
```bash
grep "Connected to the server" /var/ossec/logs/ossec.log
```

**Check for sync errors:**
```bash
grep -i "sync.*error" /var/ossec/logs/ossec.log
```

### High CPU or Memory Usage

**Reduce scan frequency:**
```xml
<interval>24h</interval>  <!-- Increase from default 1h -->
```

**Disable resource-intensive categories:**
```xml
<processes>no</processes>
<ports>no</ports>
<browser_extensions>no</browser_extensions>
```

**Adjust rate limiting:**
```xml
<max_eps>25</max_eps>  <!-- Reduce from default 50 -->
```

### Integrity Check Failures

**Increase integrity interval:**
```xml
<synchronization>
    <integrity_interval>172800</integrity_interval>  <!-- 48 hours -->
</synchronization>
```

---

## See Also

- [Syscollector Module](index.html) - Module overview and features
- [Syscollector Architecture](architecture.md) - Technical architecture and design
- [Syscollector Events](events.md) - Event format and structure
- [Syscollector Database Schema](database-schema.md) - Database tables and fields
- [Agent Configuration Reference](../../configuration/agent/README.md) - All agent configuration options

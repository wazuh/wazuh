# Syscollector Configuration Reference

Complete configuration reference for the Syscollector module that collects system inventory information including hardware, OS, packages, processes, network configuration, and more.

**Configuration file:** `/var/ossec/etc/ossec.conf` (agent)

**XML Section:** `<wodle name="syscollector">`

**Module:** Agent-only

**Internal Options:** None

For module overview and architecture, see [Syscollector Module](README.md).

> **Important:** Syscollector only collects inventory. Vulnerability detection runs on the manager. Syscollector sends the OS, packages and hotfixes tables, which feed it, through a second sync protocol instance of its own (`syscollector_vd`), configured by the same `<synchronization>` block.

---

## Configuration Options

### Basic Module Settings

#### disabled

Enable or disable the Syscollector module.

- **Default value:** `no`
- **Allowed values:** `yes`, `no`
- **Note:** When disabled, no inventory scans are performed. If the Syscollector database already exists, the module notifies the manager to remove the agent's inventory indices and then deletes its local databases

#### interval

How frequently the module performs inventory scans.

- **Default value:** `1h`
- **Allowed values:** Positive time period up to `4294967294` seconds; `0` and larger values are rejected
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
- **Note:** `0` is accepted but has no effect: the module keeps the default of `50`, and there is no unlimited setting. This limit applies only to stateless inventory events, not synchronization messages.

#### notify_first_scan

Generate events during the initial inventory scan.

- **Default value:** `no`
- **Allowed values:** `yes`, `no`
- **Note:** When `no`, suppresses events during first scan and only reports changes after baseline establishment. Applies only to the agent's very first scan ever, since installation — it does not reoccur on later restarts.

### Inventory Categories

#### hardware

Collect CPU, memory and serial number information.

- **Default value:** `yes`
- **Allowed values:** `yes`, `no`
- **Note:** Includes the processor (name, cores, speed), memory (total, free, used) and the serial number

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
- **Note:** Accepts an optional `all` attribute (`yes` or `no`, default `no`). With `no`, only TCP ports in the listening state are collected; with `yes`, every TCP port. UDP ports are always collected

#### processes

Collect running processes.

- **Default value:** `yes`
- **Allowed values:** `yes`, `no`
- **Note:** Includes process name, PID, parent PID, state, CPU times, start time and command line arguments

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
- **Note:** Browsers and their `browser.name` values, per platform:
  - Linux: Chrome (`chrome`, `chrome_beta`, `chrome_dev`), Brave (`brave`), Chromium (`chromium`), Yandex (`yandex`), Opera (`opera`), Vivaldi (`vivaldi`) and Firefox (`firefox`)
  - macOS: the Linux list plus Chrome Canary (`chrome_canary`), Edge (`edge`, `edge_beta`), Arc (`arc`), Comet (`comet`) and Safari (`safari`)
  - Windows: the Linux list plus Chrome Canary (`chrome_canary`), Edge (`edge`, `edge_beta`), Comet (`comet`) and Internet Explorer (`ie`)

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
- **Note:** A `max_eps` element inside `<synchronization>` (accepted by 4.x) is ignored and reported at INFO level

### interval

How often to trigger synchronization with the manager.

- **Default value:** `300` (5 minutes)
- **Allowed values:** `1` to `4294967295` seconds; time suffixes (`s`, `m`, `h`, `d`, `w`) are accepted
- **Note:** Lower values provide faster synchronization but increase manager load. Higher values reduce network traffic but delay inventory delivery.

### integrity_interval

Time between integrity checks for each inventory table.

- **Default value:** `86400` (24 hours)
- **Allowed values:** `0` to `4294967295` seconds; time suffixes (`s`, `m`, `h`, `d`, `w`) are accepted. There is no minimum, and `0` does not disable the check: each table is then validated after every successful synchronization
- **Note:** Each enabled inventory table (osinfo, hwinfo, packages, processes, ports, network_iface, network_protocol, network_address, users, groups, services, browser_extensions and, on Windows, hotfixes) is checked independently. When the interval elapses for a table:
  1. Agent calculates checksum-of-checksums for the table
  2. Sends checksum to manager for validation
  3. If checksums match: integrity confirmed, `last_sync_time` updated
  4. If checksums mismatch: full table recovery initiated (all rows sent to manager)

---

## Internal Options

Syscollector has no agent internal options. The per-index document limits are manager internal options (`syscollector.<type>_limit`) that the manager sends to the agent; see the [`startup` response](../remoted/https-events-api.md#startup) and [Document Limits](architecture.md#document-limits).

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
    <ports all="no">yes</ports>
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
- **hotfixes:** Not applicable (the option is ignored with a warning)
- **Configuration file:** `/var/ossec/etc/ossec.conf`

### macOS

- **packages:** Includes .pkg files and Homebrew packages
- **services:** launchd services and agents
- **hotfixes:** Not applicable (the option is ignored with a warning)
- **Configuration file:** `/Library/Ossec/etc/ossec.conf`

### All Platforms

- **browser_extensions:** The browsers collected differ per platform; see [`browser_extensions`](#browser_extensions)
- **network:** Includes IPv4 and IPv6 interfaces and addresses

---

## Event Rate Control

The module-level `max_eps` limits the stateless inventory change events:

```xml
<max_eps>50</max_eps>
```

Synchronization messages are not limited by this option.

---

## Validation and Monitoring

### Validate Configuration

Test the configuration before applying it (Linux and macOS; use `/Library/Ossec` on macOS). `wazuh-modulesd` is the daemon that reads the `syscollector` wodle, so its `-t` is the one that checks it:

```bash
/var/ossec/bin/wazuh-modulesd -t
```

The Windows agent runs the modules inside `wazuh-agent.exe`, which has no `-t` option.

### Monitor Syscollector Activity

View module logs:

```bash
# Linux/Unix
tail -f /var/ossec/logs/ossec.log | grep syscollector

# Windows
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Wait | Select-String "syscollector"
```

### Check Synchronization Status

Monitor synchronization events in the agent log:

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

**Verify agent-manager connectivity** (`status='connected'` when the agent is connected):
```bash
grep "^status=" /var/ossec/var/run/wazuh-agentd.state
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

- [Syscollector Module](README.md) - Module overview and features
- [Syscollector Architecture](architecture.md) - Technical architecture and design
- [Syscollector Events](events.md) - Event format and structure
- [Syscollector Database Schema](database-schema.md) - Database tables and fields
- [Agent Configuration Reference](../../configuration/agent/README.md) - All agent configuration options

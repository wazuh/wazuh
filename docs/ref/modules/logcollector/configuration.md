# Configuration for monitoring log files

You can use a local configuration file on the Wazuh agent or Wazuh server to monitor log files. There is also a centralized configuration file on the Wazuh server to monitor log files across multiple endpoints.

---

## Local configuration

The `ossec.conf` file is the main configuration file on the Wazuh agent. The Wazuh agent collects logs from monitored endpoints and forwards these logs to the Wazuh server for analysis. You can configure the agent to collect logs from specific files.

### Location of `ossec.conf`

| Operating system | Location |
|------------------|----------|
| Windows | `C:\Program Files (x86)\ossec-agent\ossec.conf` |
| Linux / Unix | `/var/ossec/etc/ossec.conf` |
| macOS | `/Library/Ossec/etc/ossec.conf` |

!!! note
    The `agent.conf` file on the Wazuh server allows centralized distribution of configuration settings to multiple monitored endpoints. Configuration values defined in `agent.conf` take precedence over `ossec.conf`.

---

## Monitoring basic log files

You can configure the Wazuh agent on Windows, Linux, and macOS to monitor basic log files.

Add the following configuration inside the `<ossec_config>` tags of the agent configuration file:

```xml
<localfile>
  <location>/<FILE_PATH>/file.log</location>
  <log_format>syslog</log_format>
</localfile>
```

Restart the Wazuh agent to apply the configuration:

- **Linux**
  ```bash
  systemctl restart wazuh-agent
  ```

- **Windows (PowerShell)**
  ```powershell
  Restart-Service -Name wazuh
  ```

- **macOS**
  ```bash
  /Library/Ossec/bin/wazuh-control restart
  ```

---

## Monitoring date-based log files

Wazuh can dynamically monitor log files whose names change based on the date using `strftime` formatting.

Example for `file-23-06-15.log`:

```xml
<localfile>
  <location>/<FILE_PATH>/file-%y-%m-%d.log</location>
  <log_format>syslog</log_format>
</localfile>
```

!!! note
    - `23` → year
    - `06` → month
    - `15` → day

Restart the agent after applying the configuration.

---

## Monitoring log files using wildcard patterns

Wildcard patterns allow flexible file selection.

Example: monitor all files starting with `file` and ending with `.log`.

```xml
<localfile>
  <location>/<FILE_PATH>/file*.log</location>
  <log_format>syslog</log_format>
</localfile>
```

Restart the agent to apply the configuration.

---

## Monitoring log files with environment variables

!!! note
    Environment variables in log file paths are supported **only on Windows**.

Example using `%WINDIR%`:

```xml
<localfile>
  <location>%WINDIR%\Logs\StorGroupPolicy.log</location>
  <log_format>syslog</log_format>
</localfile>
```

`%WINDIR%` expands to `C:\Windows`.

Restart the agent:

```powershell
Restart-Service -Name wazuh
```

---

# Configuring log collection for different operating systems

## Windows

Windows logs provide detailed information about system and application events. The Wazuh agent collects relevant event data and forwards it to the server for analysis and normalization.

---

## Windows event channel

Event channels are supported on Windows Vista and later. By default, the Wazuh agent monitors:

- System
- Application
- Security

Additional channels can be configured.

### Supported channels and providers

| Source | Channel name | Provider name | Description |
|------|-------------|---------------|-------------|
| Application | Application | Any | Application management events |
| Security | Security | Any | Authentication and audit events |
| System | System | Any | Kernel and service events |
| Sysmon | Microsoft-Windows-Sysmon/Operational | Microsoft-Windows-Sysmon | Process, network, and file activity |
| Windows Defender | Microsoft-Windows-Windows Defender/Operational | Microsoft-Windows-Windows Defender | Malware detection events |
| McAfee | Application | McLogEvent | Antivirus scan results |
| EventLog | System | Eventlog | Audit and system logs |
| Microsoft Security Essentials | System | Microsoft Antimalware | Antivirus activity |
| Powershell | Microsoft-Windows-PowerShell/Operational | Microsoft-Windows-PowerShell | PowerShell execution events |

---

## Monitoring the Windows event channel

To monitor a specific event channel, configure the following in `ossec.conf`:

```xml
<localfile>
  <location>Microsoft-Windows-PrintService/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

Restart the agent:

```powershell
Restart-Service -Name wazuh
```

---

## Monitoring specific events using queries

### Filter by event level

```xml
<localfile>
  <location>System</location>
  <log_format>eventchannel</log_format>
  <query>
    <QueryList>
      <Query Id="0" Path="System">
        <Select Path="System">*[System[(Level&lt;=3)]]</Select>
      </Query>
    </QueryList>
  </query>
</localfile>
```

### Filter by Event ID

```xml
<localfile>
  <location>System</location>
  <log_format>eventchannel</log_format>
  <query>Event/System[EventID=7040]</query>
</localfile>
```

---

## Windows event channel ruleset

Wazuh includes a predefined ruleset organized by event channel.

### Rule ID ranges

| Source | Rule ID range | Rule file |
|------|--------------|-----------|
| Base rules | 60000 – 60099 | 0575-win-base_rules.xml |
| Security | 60100 – 60599 | 0580-win-security_rules.xml |
| Application | 60600 – 61099 | 0585-win-application_rules.xml |
| System | 61100 – 61599 | 0590-win-system_rules.xml |
| Sysmon | 61600 – 62099 | 0595-win-sysmon_rules.xml |
| Windows Defender | 62100 – 62599 | 0600-win-wdefender_rules.xml |
| McAfee | 62600 – 63099 | 0605-win-mcafee_rules.xml |
| Eventlog | 63100 – 63599 | 0610-win-ms_logs_rules.xml |
| Microsoft Security Essentials | 63600 – 64099 | 0615-win-ms-se_rules.xml |
| Generic | 64100 – 64599 | 0620-win-generic_rules.xml |
| Powershell | 91801 – 92000 | 0915-win-powershell_rules.xml |

---

## Windows event log format

This format is compatible with all Windows versions and monitors Application, Security, and System logs.

```xml
<localfile>
  <location>Application</location>
  <log_format>eventlog</log_format>
</localfile>
```

Restart the agent after configuration.


## macOS

macOS uses the Unified Logging System (ULS), which does not write logs to plain text files. Wazuh collects logs using the macOS `log` CLI tool.

### Collecting macOS ULS logs

```xml
<localfile>
  <location>macos</location>
  <log_format>macos</log_format>
  <query type="trace,log,activity" level="info">
    (process == "sudo") or
    (process == "sessionlogoutd" and message contains "logout is complete.") or
    (process == "sshd")
  </query>
</localfile>
```

!!! note
    Only one `<localfile>` block with `log_format` set to `macos` is allowed.

### macOS `<query>` attributes

The `<query>` tag accepts the following attributes:

| Attribute | Description | Values |
|-----------|-------------|--------|
| `type` | Types of log entries to collect. | Comma-separated list of: `activity`, `log`, `trace` |
| `level` | Minimum log level to collect. | `default`, `info`, `debug` |

### Collecting specific macOS subsystem logs

You can filter by subsystem and category to narrow the collected logs:

```xml
<localfile>
  <location>macos</location>
  <log_format>macos</log_format>
  <query type="log" level="info">(subsystem == "com.apple.securityd") or (subsystem == "com.apple.opendirectoryd")</query>
</localfile>
```

### Collecting macOS authentication logs

To monitor authentication events on macOS:

```xml
<localfile>
  <location>macos</location>
  <log_format>macos</log_format>
  <query type="trace,log,activity" level="info">(process == "sudo") or (process == "sessionlogoutd" and message contains "logout is complete.") or (process == "sshd") or (process == "tccd" and message contains "Update Access Record") or (message contains "SessionAgentNotificationCenter") or (process == "screensharingd" and message contains "Authentication") or (process == "securityd" and eventMessage contains "Session" and subsystem == "com.apple.securityd")</query>
</localfile>
```

Restart the Wazuh agent to apply the configuration:

```bash
/Library/Ossec/bin/wazuh-control restart
```

---

## macOS ULS log levels

- `fault`: Always stored and displayed
- `error`: Always stored and displayed
- `default`: Stored on disk
- `info`: Stored in memory
- `debug`: Not stored by default

---

## macOS ULS predicates

### Useful filtering keys

- `eventType`
- `eventMessage`
- `messageType`
- `process`
- `processImagePath`
- `sender`
- `senderImagePath`
- `subsystem`
- `category`

### Comparison operators

- `=`, `==`
- `!=`, `<>`
- `>`, `<`
- `>=`, `<=`
- `BETWEEN`

### Logical operators

- `AND`, `&&`
- `OR`, `||`
- `NOT`, `!`

### String operators

- `BEGINSWITH`
- `CONTAINS`
- `ENDSWITH`
- `LIKE`
- `MATCHES`
- `IN`

---

## Docker log collection via journald

On Linux systems using systemd, Docker can be configured to send container logs to the journald logging driver. Wazuh can then collect these Docker logs through the journald log format in Logcollector.

### Prerequisites

- Docker configured to use the `journald` logging driver.
- The Wazuh agent running on the same host as Docker.

### Configure Docker to use the journald logging driver

Edit the Docker daemon configuration file (`/etc/docker/daemon.json`):

```json
{
  "log-driver": "journald"
}
```

Restart Docker to apply the change:

```bash
systemctl restart docker
```

After this change, all new containers send their logs to the systemd journal.

### Configure Wazuh to collect Docker logs from journald

Add the following configuration to the Wazuh agent's `ossec.conf`:

```xml
<localfile>
  <location>journald</location>
  <log_format>journald</log_format>
  <filter_type>value</filter_type>
  <filter field="CONTAINER_NAME">my-container</filter>
</localfile>
```

This configuration collects journal entries from a specific Docker container. To collect from all Docker containers, filter by the `_TRANSPORT` field:

```xml
<localfile>
  <location>journald</location>
  <log_format>journald</log_format>
  <filter_type>value</filter_type>
  <filter field="_TRANSPORT">journal</filter>
  <filter field="CONTAINER_NAME">.*</filter>
</localfile>
```

### Journald filter options

| Option | Description |
|--------|-------------|
| `filter_type` | Type of filter matching. Use `value` for exact match. |
| `filter field` | Journal field to filter by. Docker sets fields such as `CONTAINER_NAME`, `CONTAINER_ID`, `CONTAINER_TAG`, and `IMAGE_NAME`. |

### Restart the agent

```bash
systemctl restart wazuh-agent
```

### Docker listener module

Wazuh also includes a Docker listener module that monitors Docker events (container start, stop, create, destroy) through the Docker socket. This module is configured separately from log collection:

```xml
  <wodle name="docker-listener">
    <disabled>no</disabled>
    <run_on_start>yes</run_on_start>
    <interval>1m</interval>
    <attempts>5</attempts>
  </wodle>
```

| Option | Default | Description |
|--------|---------|-------------|
| `disabled` | `no` | Disables the Docker listener module when set to `yes`. |
| `run_on_start` | `yes` | Start listening for Docker events immediately. |
| `interval` | `1m` | Time interval for reconnection attempts. |
| `attempts` | `5` | Number of reconnection attempts before giving up. |

---

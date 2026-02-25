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

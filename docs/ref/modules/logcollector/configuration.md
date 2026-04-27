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

## Monitoring UNIX datagram sockets

On UNIX platforms, Logcollector can bind a UNIX datagram socket and receive log messages sent to it by external processes, by using `log_format` set to `socket`.

```xml
<localfile>
  <location>/var/run/app.sock</location>
  <log_format>socket</log_format>
  <target>agent</target>
  <out_format target="agent">$(timestamp) $(log)</out_format>
  <label key="source">app</label>
  <ignore>healthcheck</ignore>
  <restrict>ERROR|WARN</restrict>
</localfile>
```

The `location` value is a UNIX socket path where Logcollector will create a datagram socket. External processes send log messages as datagrams using `SOCK_DGRAM`. Each datagram is treated as a single log message. If the socket file is removed, Logcollector will detect this and re-create it. Date-based paths and wildcard expansion follow the same resolution flow used by file-backed `localfile` entries.

### Socket-specific options

| Option         | Default       | Description                                                         |
|----------------|---------------|---------------------------------------------------------------------|
| `socket_mode`  | `0660`        | Octal permission bits for the socket file.                          |
| `socket_group` | Process group | Group name for the socket file, resolved at creation time.          |
| `recv_buffer`  | `65536` (64K) | Minimum kernel receive buffer size (`SO_RCVBUF`). Accepts K/M/G suffixes. Maximum 16M. |

!!! note
    `recv_buffer` sets a minimum value for `SO_RCVBUF`. If the kernel default is already larger, no change is made. For high-volume sources, increase this to absorb bursts (e.g. `1M`). The value must be between 65536 (the maximum datagram size) and 16M.

### rsyslog integration example

A common use case is forwarding syslog messages from rsyslog to Logcollector via a local UNIX socket. Logcollector creates and owns the socket; rsyslog writes to it.

**Wazuh agent** (`ossec.conf`):

```xml
<localfile>
  <location>/var/run/wazuh-rsyslog.sock</location>
  <log_format>socket</log_format>
  <socket_mode>0660</socket_mode>
  <socket_group>syslog</socket_group>
  <recv_buffer>1M</recv_buffer>
</localfile>
```

**rsyslog** (`/etc/rsyslog.d/wazuh.conf`):

```
# rsyslog v8.24+ (RainerScript)
module(load="omuxsock")
action(type="omuxsock" socket="/var/run/wazuh-rsyslog.sock"
       template="RSYSLOG_TraditionalFileFormat")

# rsyslog legacy syntax (v8.21 and earlier)
# $ModLoad omuxsock
# $OMUxSockSocket /var/run/wazuh-rsyslog.sock
# *.* :omuxsock:
```

Ensure the rsyslog user belongs to the configured `socket_group`, or set `socket_mode` to `0666`.

!!! note
    - This log format is available only on UNIX platforms.
    - Messages must be valid UTF-8 text. Binary payloads and invalid UTF-8 are dropped.
    - Logcollector creates and owns the socket file — it is removed when the source is closed.
    - The `age` option is accepted for compatibility but ignored for `log_format=socket`.
    - Socket readers do not use `file_status.json`, bookmarks, or file rotation and truncation semantics.

Restart the agent after applying the configuration.

---

## Streaming logs from an HTTP endpoint over a UNIX stream socket

On UNIX platforms, Logcollector can act as an HTTP/1.1 client over a UNIX **stream** socket (`SOCK_STREAM`) and treat each newline-delimited line of the response body as a log event. Use `log_format` set to `http-unix`. Unlike `log_format=socket` (which binds and waits for datagrams), this mode **connects to a socket owned by another process**, issues a `GET`, and consumes the streamed response.

```xml
<localfile>
  <location>/var/run/example.sock</location>
  <log_format>http-unix</log_format>
  <endpoint>/events</endpoint>
  <reconnect_interval>5</reconnect_interval>
  <target>agent</target>
</localfile>
```

The `location` value is the UNIX stream socket path of the producing service. A dedicated worker thread per `<localfile>` issues the configured HTTP request, parses the response (supports `Transfer-Encoding: chunked`, `Content-Length`, and read-until-close), and forwards each non-empty UTF-8 line to the output queue. If the connection is closed by the peer or fails, the worker waits `reconnect_interval` seconds and retries indefinitely.

### http-unix-specific options

| Option               | Default | Description                                                                  |
|----------------------|---------|------------------------------------------------------------------------------|
| `endpoint`           | `/`     | HTTP path to request. Must start with `/`.                                   |
| `reconnect_interval` | `5`     | Seconds to wait between reconnect attempts. Allowed range: `1`–`3600`.       |

### Streaming Docker events

The Docker daemon exposes a streaming `/events` endpoint over `/var/run/docker.sock`. Logcollector can consume it directly:

```xml
<localfile>
  <location>/var/run/docker.sock</location>
  <log_format>http-unix</log_format>
  <endpoint>/events</endpoint>
  <reconnect_interval>5</reconnect_interval>
</localfile>
```

The Wazuh user must have read access to `/var/run/docker.sock` (typically by joining the `docker` group).

!!! note
    This is **not** a drop-in replacement for the existing Docker Listener wodle (`wodles/docker-listener/DockerListener.py`). The wodle wraps each event in `{"integration":"docker","docker":<event>}` and sends with the `Wazuh-Docker` queue header so the bundled Docker rules match. `log_format=http-unix` forwards each line of the Docker stream verbatim — rules consuming raw Docker events would need to be adjusted accordingly. The wodle remains supported; choose the path that matches your decoder/rule pipeline.

!!! note
    - This log format is available only on UNIX platforms.
    - The unix socket file must be a **stream** socket owned by the producer; Logcollector connects but does not bind or unlink.
    - Lines must be valid UTF-8 text. Binary payloads and invalid UTF-8 are dropped.
    - Each `<localfile>` of this type creates one dedicated worker thread that owns the connection lifecycle (connect, parse, reconnect).
    - Lines exceeding `OS_MAXSTR` bytes are dropped with a warning.
    - The `age`, `ignore_binaries`, and `only-future-events` options are ignored for `log_format=http-unix`.

Restart the agent after applying the configuration.

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

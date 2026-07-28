# Logcollector Configuration Reference

Complete configuration reference for the Logcollector module.

The Logcollector module collects logs from monitored endpoints and forwards them to the Wazuh server for analysis. It supports multiple log sources including plain text files, JSON logs, Windows Event Logs, macOS Unified Logging System, and systemd journal.

For module overview and architecture, see [Logcollector Module](index.html).

---

**Configuration file:** `/var/ossec/etc/ossec.conf`

**XML Sections:** `<localfile>`, `<socket>`

**Module:** Agent-only

**Internal Options:** `logcollector.*`

---

## Configuration Options

The Logcollector module uses two main XML sections:

- **`<localfile>`** - Configures file-based log collection
- **`<socket>`** - Configures socket-based log reception

---

## `<localfile>` Section

The `<localfile>` section configures file-based log collection. Multiple `<localfile>` blocks can be defined to monitor different log sources.

### location

Specifies the path to the log file or log source to monitor.

- **Default value:** None (required)
- **Allowed values:**
  - Static file paths (e.g., `/var/log/syslog`)
  - Date-based patterns using `strftime` format (e.g., `/var/log/app-%y-%m-%d.log`)
  - Wildcard patterns (e.g., `/var/log/app*.log`)
  - Windows environment variables (Windows only, e.g., `%WINDIR%\Logs\file.log`)
  - Special values: `macos` (macOS ULS), `journald` (systemd journal)
  - Windows Event channels (e.g., `Application`, `Security`, `System`)
- **Note:** For Windows Event channels, the value depends on the `log_format` setting

### log_format

Defines the format of the log source to determine how logs are read and parsed.

- **Default value:** None (required)
- **Allowed values:**
  - `syslog` - Plain text log files (one event per line)
  - `json` - JSON-formatted log files (one JSON object per line)
  - `eventchannel` - Windows Event Channel (Windows Vista and later)
  - `eventlog` - Windows Event Log (all Windows versions)
  - `macos` - macOS Unified Logging System
  - `journald` - Linux systemd journal
  - `command` - Output from a command
  - `full_command` - Full output from a command including empty lines
  - `audit` - Linux audit logs
  - `nmapg` - NMAP grepable output
  - `mysql_log` - MySQL logs
  - `postgresql_log` - PostgreSQL logs
  - `djb-multilog` - DJB multilog format
  - `multi-line` - Multi-line log entries
- **Note:** The format determines which collector is used to read the log source

### query

XPath or predicate query to filter events (Windows Event Channel and macOS ULS only).

- **Default value:** None (optional)
- **Allowed values:**
  - **Windows Event Channel:** XPath query or simple Event ID filter (e.g., `Event/System[EventID=7040]`)
  - **macOS ULS:** Predicate expression using process, subsystem, category, message fields
- **Note:** For Windows, supports both simple queries and full QueryList XML format. For macOS, accepts `type` and `level` attributes

#### Windows Event Channel Query Attributes

None (query value is the XPath expression itself)

#### macOS ULS Query Attributes

- **`type`** - Types of log entries to collect
  - **Allowed values:** Comma-separated list: `activity`, `log`, `trace`
  - **Example:** `<query type="log,trace" level="info">process == "sshd"</query>`

- **`level`** - Minimum log level to collect
  - **Allowed values:** `default`, `info`, `debug`
  - **Example:** `<query type="log" level="info">subsystem == "com.apple.securityd"</query>`

### filter

Filter journal entries by field (journald only).

- **Default value:** None (optional)
- **Allowed values:** Journal field name with PCRE2 regex pattern
- **Format:** `<filter field="FIELD_NAME">^regex_pattern$</filter>`
- **Note:** Multiple `<filter>` elements can be used. Use anchors (`^`, `$`) for exact matching
- **Example:** `<filter field="SYSLOG_IDENTIFIER">^sshd$</filter>`

### only-future-events

Collect only events generated after the agent starts (Windows Event Channel only).

- **Default value:** `yes`
- **Allowed values:** `yes`, `no`
- **Note:** When set to `yes`, ignores historical events. When set to `no`, processes all available events from the channel

### target

Specifies a target socket or file for routing logs.

- **Default value:** None (logs sent to standard analysis queue)
- **Allowed values:** Socket name or file path
- **Note:** Used for custom log routing and processing pipelines

### out_format

Custom output format template for logs.

- **Default value:** None (uses default format based on log_format)
- **Allowed values:** Format string with field placeholders
- **Note:** Allows customization of how log events are formatted before forwarding

### ignore_binaries

Ignore binary files when using wildcard patterns.

- **Default value:** `no`
- **Allowed values:** `yes`, `no`
- **Note:** When enabled, skips files that appear to be binary when expanding wildcards

### labels

Adds custom labels to collected log events.

- **Default value:** None (optional)
- **Allowed values:** Contains one or more `<label>` elements
- **Format:** `<label key="key_name">value</label>`
- **Note:** Labels are injected into JSON logs and added as metadata to other log formats

### age

Specifies the maximum age for log files to read (for wildcard patterns).

- **Default value:** None (reads all files)
- **Allowed values:** Time interval (e.g., `1d`, `12h`, `30m`)
- **Note:** Files older than the specified age are ignored when using wildcards

### exclude

Excludes files matching a pattern when using wildcards.

- **Default value:** None (optional)
- **Allowed values:** Regex pattern
- **Note:** Files matching this pattern are excluded from monitoring

### reconnect_time

Time to wait before reconnecting to a log source after failure.

- **Default value:** `5s`
- **Allowed values:** Time interval in seconds
- **Note:** Applies to log sources that can disconnect and reconnect (e.g., sockets, commands)

---

## `<socket>` Section

The `<socket>` section configures socket-based log reception. The agent listens on the specified socket for incoming log messages.

### name

Path to the Unix socket or name of the Windows named pipe.

- **Default value:** None (required)
- **Allowed values:**
  - **Linux/Unix:** Socket path (e.g., `/var/run/custom.sock`)
  - **Windows:** Named pipe name (e.g., `custom-pipe`)
- **Note:** The agent must have permissions to create and read from the socket

### location

Alias for the socket name (alternative to `name`).

- **Default value:** None (mutually exclusive with `name`)
- **Allowed values:** Same as `name`
- **Note:** Either `name` or `location` must be specified

### mode

Socket connection mode.

- **Default value:** `tcp`
- **Allowed values:** `tcp`, `udp`
- **Note:** Determines the protocol used for socket communication

### prefix

Prefix to add to messages received from the socket.

- **Default value:** None (optional)
- **Allowed values:** Any string
- **Note:** Useful for identifying the source of socket messages

---

## Internal Options

**Configuration file:** `/var/ossec/etc/internal_options.conf` (Linux/Unix) or `C:\Program Files (x86)\ossec-agent\internal_options.conf` (Windows)

Internal options provide advanced tuning for the Logcollector module. These options are global and apply to all log collection operations.

### logcollector.loop_timeout

File check interval for detecting log file changes.

- **Default value:** `2` (seconds)
- **Allowed values:** Positive integer
- **Format:** `logcollector.loop_timeout=2`
- **Note:** Controls how frequently Logcollector checks monitored files for changes

### logcollector.open_attempts

Number of attempts to open a log file before giving up.

- **Default value:** `0` (infinite retries)
- **Allowed values:** Integer from `2` to `998`, or `0` for infinite
- **Format:** `logcollector.open_attempts=0`
- **Note:** Set to `0` for continuous retry on file open failures

### logcollector.remote_commands

Accept remote commands from the manager to modify log collection.

- **Default value:** `0` (disabled)
- **Allowed values:** `0` (disabled), `1` (enabled)
- **Format:** `logcollector.remote_commands=0`
- **Note:** Enables or disables remote configuration of Logcollector via manager commands

### logcollector.vcheck_files

Interval for checking file metadata changes (rotation, deletion).

- **Default value:** `64` (seconds)
- **Allowed values:** Integer from `0` to `1024`
- **Format:** `logcollector.vcheck_files=64`
- **Note:** Controls how often file verification occurs to detect rotations and modifications

### logcollector.max_lines

Maximum number of lines to read from a single file in one iteration.

- **Default value:** `10000`
- **Allowed values:** Integer from `100` to `1000000`, or `0` to disable
- **Format:** `logcollector.max_lines=10000`
- **Note:** Prevents a single busy log file from monopolizing processing time. Set to `0` to disable burst limitation

### logcollector.max_files

Maximum number of files that can be monitored simultaneously.

- **Default value:** `1000`
- **Allowed values:** Integer from `1` to `100000`
- **Format:** `logcollector.max_files=1000`
- **Note:** Limits total number of monitored files to prevent resource exhaustion

### logcollector.sock_fail_time

Wait time before reattempting a socket connection after failure.

- **Default value:** `300` (seconds)
- **Allowed values:** Integer from `1` to `3600`
- **Format:** `logcollector.sock_fail_time=300`
- **Note:** Controls retry interval for failed socket connections

### logcollector.input_threads

Number of threads for reading log files.

- **Default value:** `4`
- **Allowed values:** Positive integer
- **Format:** `logcollector.input_threads=4`
- **Note:** Higher values improve throughput for high-volume log collection

### logcollector.queue_size

Size of the internal output queue for log events.

- **Default value:** `1024`
- **Allowed values:** Integer from `128` to `220000`
- **Format:** `logcollector.queue_size=1024`
- **Note:** Larger queue sizes improve burst handling but increase memory usage

### logcollector.sample_log_length

Maximum length of log samples shown in error messages.

- **Default value:** `64` (characters)
- **Allowed values:** Integer from `1` to `4096`
- **Format:** `logcollector.sample_log_length=64`
- **Note:** Limits log samples in error messages to prevent excessive output

### logcollector.rlimit_nofile

Maximum number of file descriptors Logcollector can open.

- **Default value:** `1100`
- **Allowed values:** Integer from `1024` to `1048576`
- **Format:** `logcollector.rlimit_nofile=1100`
- **Note:** Must be higher than `logcollector.max_files`. Adjust system limits if necessary

### logcollector.force_reload

Force periodic reloading of file handlers (close and reopen files).

- **Default value:** `0` (disabled)
- **Allowed values:** `0` (disabled), `1` (enabled)
- **Format:** `logcollector.force_reload=0`
- **Note:** Enables periodic file descriptor recycling to handle certain log rotation schemes

### logcollector.reload_interval

Interval for forced file handler reload when `force_reload` is enabled.

- **Default value:** `64` (seconds)
- **Allowed values:** Integer from `1` to `86400`
- **Format:** `logcollector.reload_interval=64`
- **Note:** Must be greater than or equal to `vcheck_files`. Only applies when `force_reload=1`

### logcollector.reload_delay

Delay between closing and reopening files during forced reload.

- **Default value:** `1000` (milliseconds)
- **Allowed values:** Integer from `0` to `30000`
- **Format:** `logcollector.reload_delay=1000`
- **Note:** Prevents race conditions during file reload. Only applies when `force_reload=1`

### logcollector.exclude_files_interval

Interval for refreshing the list of excluded files.

- **Default value:** `86400` (seconds / 24 hours)
- **Allowed values:** Integer from `1` to `172800`
- **Format:** `logcollector.exclude_files_interval=86400`
- **Note:** Controls how often exclusion patterns are re-evaluated

### logcollector.state_interval

Interval for updating the Logcollector state file.

- **Default value:** `60` (seconds)
- **Allowed values:** Integer from `0` to `3600`, or `0` to disable
- **Format:** `logcollector.state_interval=60`
- **Note:** Set to `0` to disable state file creation and updating

### logcollector.debug

Debug level for Logcollector module.

- **Default value:** `0`
- **Allowed values:**
  - `0` - No debug output
  - `1` - First level debug
  - `2` - Full debugging
- **Format:** `logcollector.debug=0`
- **Note:** Higher values produce more verbose logging. Use for troubleshooting only

---

## Configuration Examples

### Monitoring Basic Log Files

Monitor a plain text syslog file on Linux:

```xml
<localfile>
  <location>/var/log/syslog</location>
  <log_format>syslog</log_format>
</localfile>
```

### Monitoring JSON Log Files

Collect JSON-formatted application logs:

```xml
<localfile>
  <location>/var/log/app.json</location>
  <log_format>json</log_format>
  <labels>
    <label key="app">myapp</label>
    <label key="environment">production</label>
  </labels>
</localfile>
```

### Monitoring Date-Based Log Files

Monitor log files with date-based naming using `strftime` patterns:

```xml
<localfile>
  <location>/var/log/application-%y-%m-%d.log</location>
  <log_format>syslog</log_format>
</localfile>
```

This example monitors files like `application-26-07-03.log` (year-month-day format).

### Monitoring Wildcard Patterns

Monitor all log files matching a wildcard pattern:

```xml
<localfile>
  <location>/var/log/app*.log</location>
  <log_format>syslog</log_format>
  <exclude>\.old$</exclude>
  <age>7d</age>
</localfile>
```

This configuration monitors all files starting with `app` and ending with `.log`, excluding files with `.old` extension and files older than 7 days.

### Windows Event Channel

Monitor Windows Security events on Vista and later:

```xml
<localfile>
  <location>Security</location>
  <log_format>eventchannel</log_format>
</localfile>
```

### Windows Event Channel with Query Filter

Filter Windows events by Event ID:

```xml
<localfile>
  <location>System</location>
  <log_format>eventchannel</log_format>
  <query>Event/System[EventID=7040]</query>
</localfile>
```

Filter by event level (errors and critical events only):

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

### Windows Event Log (Legacy)

Monitor Windows Application log using the legacy API (compatible with all Windows versions):

```xml
<localfile>
  <location>Application</location>
  <log_format>eventlog</log_format>
</localfile>
```

### Windows Environment Variables

Use Windows environment variables in file paths (Windows only):

```xml
<localfile>
  <location>%WINDIR%\System32\LogFiles\Firewall\pfirewall.log</location>
  <log_format>syslog</log_format>
</localfile>
```

### macOS Unified Logging System

Collect macOS authentication logs:

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

Filter by specific subsystem:

```xml
<localfile>
  <location>macos</location>
  <log_format>macos</log_format>
  <query type="log" level="info">
    (subsystem == "com.apple.securityd") or
    (subsystem == "com.apple.opendirectoryd")
  </query>
</localfile>
```

### Linux systemd Journal

Monitor SSH authentication via journald:

```xml
<localfile>
  <location>journald</location>
  <log_format>journald</log_format>
  <filter field="SYSLOG_IDENTIFIER">^sshd$</filter>
</localfile>
```

### Docker Logs via journald

Monitor Docker container logs through systemd journal:

```xml
<localfile>
  <location>journald</location>
  <log_format>journald</log_format>
  <filter field="CONTAINER_NAME">^my-container$</filter>
</localfile>
```

Monitor all Docker containers:

```xml
<localfile>
  <location>journald</location>
  <log_format>journald</log_format>
  <filter field="_TRANSPORT">^journal$</filter>
</localfile>
```

### Socket-Based Log Collection

Create a Unix socket for receiving syslog messages:

```xml
<socket>
  <name>/var/run/custom.sock</name>
  <mode>tcp</mode>
  <prefix>custom-app</prefix>
</socket>
```

### Multi-Line Log Collection

Collect multi-line log entries (e.g., Java stack traces):

```xml
<localfile>
  <location>/var/log/app.log</location>
  <log_format>multi-line</log_format>
</localfile>
```

### Command Output Collection

Collect output from a command:

```xml
<localfile>
  <log_format>command</log_format>
  <command>df -h</command>
  <frequency>360</frequency>
</localfile>
```

---

## Performance Tuning

### High-Volume Log Collection

For environments with high log volume, increase thread count and queue size:

```
logcollector.input_threads=8
logcollector.queue_size=4096
logcollector.max_lines=50000
```

### Large Number of Files

When monitoring many files with wildcards, increase file limits:

```
logcollector.max_files=5000
logcollector.rlimit_nofile=5500
```

### Slow or Unreliable File Systems

Adjust timing parameters for slow storage or network file systems:

```
logcollector.loop_timeout=5
logcollector.vcheck_files=120
logcollector.force_reload=1
logcollector.reload_interval=300
```

---

## Monitoring

### Check Logcollector Status

View active log sources in the agent state file:

```bash
# Linux/Unix
cat /var/ossec/var/run/wazuh-logcollector.state

# Windows
type "C:\Program Files (x86)\ossec-agent\wazuh-logcollector.state"
```

### View Logcollector Logs

```bash
# Linux/Unix
tail -f /var/ossec/logs/ossec.log | grep logcollector

# Windows
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Wait | Select-String "logcollector"
```

### Enable Debug Mode

Temporarily enable debug logging:

```bash
# Add to local_internal_options.conf
echo "logcollector.debug=2" >> /var/ossec/etc/local_internal_options.conf

# Restart agent
systemctl restart wazuh-agent
```

---

## Troubleshooting

### File Not Being Monitored

**Check file permissions:**

```bash
ls -la /var/log/application.log
```

Ensure the Wazuh agent user (`wazuh` or `ossec`) has read permissions.

**Verify configuration:**

```bash
grep -A5 "location>/var/log/application.log" /var/ossec/etc/ossec.conf
```

**Check for file limit:**

```bash
grep "max_files" /var/ossec/etc/internal_options.conf
```

### High CPU Usage

**Reduce file check frequency:**

```
logcollector.loop_timeout=5
logcollector.vcheck_files=120
```

**Limit burst reading:**

```
logcollector.max_lines=5000
```

**Reduce thread count on low-resource systems:**

```
logcollector.input_threads=2
```

### Events Not Being Forwarded

**Check queue size:**

```
logcollector.queue_size=2048
```

**Verify agent connectivity:**

```bash
/var/ossec/bin/agent_control -ls
```

**Check for rate limiting:**

Review `agent.conf` for EPS (events per second) limits.

### Windows Event Channel Issues

**Verify channel exists:**

```powershell
Get-WinEvent -ListLog * | Select-String "ChannelName"
```

**Check only-future-events setting:**

If historical events are needed:

```xml
<localfile>
  <location>Security</location>
  <log_format>eventchannel</log_format>
  <only-future-events>no</only-future-events>
</localfile>
```

### macOS ULS Not Collecting Logs

**Verify permissions:**

macOS requires full disk access for the Wazuh agent to read ULS logs.

**Check query syntax:**

```bash
# Test query manually
log show --predicate 'process == "sshd"' --info
```

**Only one macOS localfile allowed:**

Ensure only one `<localfile>` block with `log_format=macos` exists.

### Socket Connection Failures

**Verify socket path exists:**

```bash
ls -la /var/run/custom.sock
```

**Check socket permissions:**

```bash
chmod 660 /var/run/custom.sock
chown wazuh:wazuh /var/run/custom.sock
```

**Increase retry time:**

```
logcollector.sock_fail_time=60
```

---

## See Also

- [Logcollector Module](index.html) - Module overview and architecture
- [Log Collectors](collectors.md) - Detailed collector documentation
- [Client Configuration](../client/configuration.md) - Agent connectivity settings
- [Agent Configuration Reference](../../configuration/agent/README.md) - All agent configuration options

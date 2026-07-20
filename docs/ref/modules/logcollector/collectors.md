# Log collectors

Logcollector reads events from different log sources on the monitored endpoint. Each source is configured with a `<localfile>` block in `ossec.conf`, where `<log_format>` selects the collector.

| Format | Operating system | Description |
|--------|-----------------|-------------|
| `syslog` | Linux, macOS, Windows | Plain text log files, one event per line |
| `json` | Linux, macOS, Windows | JSON-encoded log files, one object per line |
| `eventchannel` | Windows | Windows Event Log via the EventChannel API (Vista and later) |
| `eventlog` | Windows | Windows Event Log via the `OpenEventLog` / `ReadEventLog` API |
| `macos` | macOS | macOS Unified Logging System (ULS) |
| `journald` | Linux | systemd journal |

For full configuration options, see [Configuration](configuration.md).

---

## syslog — Plain text files

Reads plain text log files one line at a time. It is the standard format for most Linux and macOS log files.

```xml
<localfile>
  <location>/var/log/auth.log</location>
  <log_format>syslog</log_format>
</localfile>
```

The `<location>` field supports static paths, date-based patterns (`strftime` format), and wildcards.

---

## json — JSON log files

Reads JSON-encoded log files one line at a time. Each line must be a valid JSON object; lines that fail to parse are silently discarded. If `<labels>` are configured, they are injected into each JSON object before the event is forwarded.

```xml
<localfile>
  <location>/var/log/app.json</location>
  <log_format>json</log_format>
</localfile>
```

---

## eventchannel — Windows Event Channel

Collects events from the Windows Event Log using the EventChannel API (`EvtSubscribe` / `EvtRender`). Supported on Windows Vista and later. By default the agent monitors the **System**, **Application**, and **Security** channels; any channel exposed by Windows can be added.

```xml
<localfile>
  <location>Security</location>
  <log_format>eventchannel</log_format>
</localfile>
```

Events can be filtered with XPath queries using the `<query>` element. See [Configuration](configuration.md#windows-event-channel) for details.

### Event output format

#### Wazuh 4.x

The agent wrapped each event in a JSON object containing a human-readable message and the raw XML:

```json
{"Message": "Event description.", "Event": "<Event>...</Event>"}
```

#### Wazuh 5.0

The agent now forwards the native Windows Event XML exactly as returned by `EvtRender()`, matching the export format of Windows Event Viewer:

```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/>
    <EventID>4624</EventID>
    <Channel>Security</Channel>
    <Computer>HOST</Computer>
    <Security/>
  </System>
  <EventData>
    <Data Name='SubjectUserName'>SYSTEM</Data>
    <Data Name='LogonType'>5</Data>
    ...
  </EventData>
</Event>
```

Key differences from the previous format:

- No `<?xml version="1.0" encoding="UTF-8"?>` declaration.
- `<Event>` is the root element.
- Namespaces and attributes are preserved exactly as provided by the EventChannel API.

This change standardizes event data for downstream processing and makes forwarded events directly comparable to native Windows Event Viewer exports.

!!! note
    This change applies to **Windows agents only**. The `<log_format>eventchannel</log_format>` configuration is unchanged.

---

## eventlog — Windows Event Log

Collects events from the Windows Event Log using the `OpenEventLog` / `ReadEventLog` API. Compatible with all Windows versions. Covers the **Application**, **Security**, and **System** logs.

```xml
<localfile>
  <location>Application</location>
  <log_format>eventlog</log_format>
</localfile>
```

!!! note
    For Windows Vista and later, prefer `eventchannel` — it provides access to additional channels and richer event metadata.

---

## macos — macOS Unified Logging System

Collects events from the macOS Unified Logging System (ULS) using the `log` CLI. Only one `<localfile>` block with `log_format` set to `macos` is allowed per agent.

```xml
<localfile>
  <location>macos</location>
  <log_format>macos</log_format>
  <query type="log,trace" level="info">process == "sshd"</query>
</localfile>
```

The `<query>` attribute `type` accepts a comma-separated list of `activity`, `log`, and `trace`. The `level` attribute sets the minimum log level (`default`, `info`, `debug`). See [Configuration](configuration.md#macos) for predicate syntax and filtering examples.

---

## journald — systemd journal

Collects entries from the Linux systemd journal. Entries can be filtered by journal field using `<filter>` elements. Filter values are compiled as PCRE2 regular expressions; use anchors (`^`, `$`) for exact matching.

```xml
<localfile>
  <location>journald</location>
  <log_format>journald</log_format>
  <filter field="SYSLOG_IDENTIFIER">^sshd$</filter>
</localfile>
```

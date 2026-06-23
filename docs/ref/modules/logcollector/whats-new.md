# What's new in Wazuh 5.0 — Log data collection

This page summarizes the changes to the log data collection flow introduced in Wazuh 5.0.

## Overview

| Area | Change |
|------|--------|
| Windows EventChannel output format | Native XML instead of JSON wrapper (Windows agents only) |
| Filebeat removed | Events flow directly from `analysisd` to `wazuh-indexer` |
| Syslog server removed | `wazuh-remoted` no longer accepts syslog input |
| Manager separated from agent | Log collection always requires a dedicated agent |
| Events no longer written to file by default | No longer needed without Filebeat |

---

## Agent-side changes

### Windows EventChannel output format

The output format for Windows EventChannel events has changed. The agent now forwards the native Windows Event XML as rendered by the EventChannel API (`EvtRender()`), matching the format exported by Windows Event Viewer.

**Before (Wazuh 4.x)** — JSON wrapper:

```json
{"message": "Event description.", "event": "<Event>...</Event>"}
```

**After (Wazuh 5.0)** — native XML:

```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/>
    <EventID>4624</EventID>
    ...
  </System>
  <EventData>
    <Data Name='SubjectUserName'>SYSTEM</Data>
    ...
  </EventData>
</Event>
```

Key structural differences:

- No `<?xml version="1.0" encoding="UTF-8"?>` declaration.
- `<Event>` is the root element.
- Namespaces and attributes are preserved as provided by the EventChannel API, matching the Windows Event Viewer export structure.

!!! note
    This change applies to **Windows agents only**. The `<log_format>eventchannel</log_format>` configuration option is unchanged.

### Unchanged behavior

The following aspects of the `agent → remoted` flow are **unchanged** in Wazuh 5.0:

- **Transport protocol**: Events continue to flow through the same secure agent protocol (`logcollector → agentd → remoted`).
- **Custom socket outputs**: The `<socket>` + `<localfile><target>` + `<out_format>` configuration is fully supported and functionally unchanged on Linux, Unix, and macOS.
- **All other log formats**: No changes to the event payload for any other log format (syslog, journald, macos, eventlog, etc.).

---

## Manager/server-side changes

### Filebeat removed

Filebeat has been removed from the Wazuh server. Events are now forwarded directly from `analysisd` (the engine) to `wazuh-indexer`. This change is transparent to agents and users.

For details on how the engine processes and forwards events, see the [engine architecture documentation](../engine/architecture.md).

### Syslog server removed

The built-in syslog server in `wazuh-remoted` has been removed. Wazuh 5.0 no longer accepts direct syslog input through remoted.

### Manager no longer functions as an agent

In Wazuh 5.0, the manager and agent are fully separate components. Log collection always occurs via a dedicated Wazuh agent — the manager does not perform log collection itself.

### Events no longer written to file by default

Events are no longer written to disk by default. In Wazuh 4.x this was required because Filebeat read from that file; with Filebeat removed, writing to file is unnecessary.

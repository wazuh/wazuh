# Rootcheck Output Samples

This document shows the events the manager's engine (`wazuh-manager-analysisd`) produces from rootcheck messages, and
how to find them.

> **Note:** Wazuh 5.0 normalizes events to the Wazuh Common Schema (ECS-based). The engine sends them to the Wazuh
> indexer (rootcheck events land in the `wazuh-events-v5-security` data stream) and, when a policy has a `file`
> output, writes them under `/var/wazuh-manager/logs/<channel>/<YYYY>/<MMM>/wazuh-<channel>-<DD>.json` (see
> [File output](../engine/ref-output.md#file)). The samples below were captured from a 5.0 manager running the
> default content; the decoders come from that content, so a different content version can add or rename fields.

## Event structure

The agent sends each rootcheck message on queue `9` (`57` in `wazuh.protocol.queue`) with location `rootcheck`. The
engine decodes it with `decoder/core-wazuh-message/0` and then `decoder/wazuh-rootcheck/0`, and adds the agent's
metadata under `wazuh.agent`, the cluster under `wazuh.cluster`, the space under `wazuh.space` and a per-event
UUID in `wazuh.event.id`. There is no rootcheck-specific object: the detection is described with ECS fields
(`event.*`, `file.*`, `threat.indicator.*`, …). For example, the end-of-scan event:

```json
{
  "@timestamp": "2026-10-27T17:57:49.700412839Z",
  "wazuh": {
    "protocol": {
      "queue": 57,
      "location": "rootcheck"
    },
    "agent": {
      "groups": ["default"],
      "host": {
        "architecture": "aarch64",
        "hostname": "tomas",
        "os": {
          "name": "Ubuntu",
          "platform": "ubuntu",
          "type": "linux",
          "version": "24.04.5 LTS (Noble Numbat)"
        }
      },
      "id": "001",
      "name": "tomas",
      "version": "v5.0.0"
    },
    "cluster": {
      "name": "wazuh",
      "node": "node01"
    },
    "event": {
      "id": "52a4b9a7-92cd-4728-8865-1f334e2d5f11"
    },
    "integration": {
      "category": "security",
      "name": "wazuh-rootcheck",
      "decoders": ["decoder/core-wazuh-message/0", "decoder/wazuh-rootcheck/0"]
    },
    "space": {
      "name": "standard"
    }
  },
  "event": {
    "original": "Ending rootcheck scan.",
    "dataset": "wazuh.rootcheck",
    "kind": "event",
    "type": ["info", "end"],
    "category": ["host"],
    "outcome": "success"
  },
  "data_stream": {
    "dataset": "wazuh.rootcheck",
    "type": "logs"
  }
}
```

`Starting rootcheck scan.` produces the same shape, with an `event.type` that marks the start.

## Detection example: file in /dev

**Message:** `File '/dev/shm/e2etest' present on /dev. Possible hidden file.`

The detection fields the engine adds to the common structure above (`wazuh.*` omitted):

```json
{
  "@timestamp": "2026-10-27T18:09:03.483127506Z",
  "event": {
    "original": "File '/dev/shm/e2etest' present on /dev. Possible hidden file.",
    "dataset": "wazuh.rootcheck",
    "kind": "event",
    "type": ["info", "indicator"],
    "category": ["malware", "file"],
    "action": "malware-detected"
  },
  "data_stream": {
    "dataset": "wazuh.rootcheck",
    "type": "logs"
  },
  "file": {
    "path": "/dev/shm/e2etest"
  },
  "threat": {
    "indicator": {
      "type": "file"
    }
  }
}
```

## Messages and the fields extracted from them

The rootcheck decoder recognizes these messages (`<…>` marks the part it extracts and the field it fills). Every
event keeps the whole message in `event.original`. The ECS classification (`event.category`, `event.action`,
`threat.indicator.type`) is set by the decoder per detection; the /dev example above shows it for one of them.

| Detection | Message | Extracted field |
|-----------|---------|-----------------|
| File in `/dev` | `File '<path>' present on /dev. Possible hidden file.` | `file.path` |
| Files hidden in a directory | `Files hidden inside directory '<path>'. Link count does not match number of files (<n>,<m>).` | `file.path` |
| World-writable file owned by root | `File '<path>' is owned by <owner> and has written permissions to anyone.` | `file.path`, `file.owner` |
| Hidden process | `Process '<pid>' hidden from kill (0), getsid (0) or getpgid. Possible kernel-level rootkit.` | `process.pid` |
| Hidden process | `Process '<pid>' hidden from <source>. Possible kernel level rootkit.` | `process.pid` |
| Hidden port | `Port '<port>'(tcp) hidden. Kernel-level rootkit or trojaned version of netstat.` | `destination.port` |
| Promiscuous interface | `Interface '<name>' in promiscuous mode.` | `observer.ingress.interface.name` |
| Scan markers | `Starting rootcheck scan.` / `Ending rootcheck scan.` | — |

## Event fields

| Field | Description | Example |
|-------|-------------|---------|
| `@timestamp` | When the engine received the event, in UTC with nine fractional digits (nanoseconds) | `2026-10-27T18:09:03.483127506Z` |
| `wazuh.protocol.location` | Source of the message | `rootcheck` |
| `wazuh.integration.name` | Integration that decoded it | `wazuh-rootcheck` |
| `wazuh.agent.id`, `wazuh.agent.name`, `wazuh.agent.version` | Reporting agent | `001`, `tomas`, `v5.0.0` |
| `wazuh.agent.host.os.*` | Agent operating system | `Ubuntu` |
| `wazuh.event.id` | Per-event UUID | `52a4b9a7-…` |
| `event.original` | Full detection message | `File '/dev/shm/e2etest' present on /dev. …` |
| `event.dataset` | Dataset | `wazuh.rootcheck` |
| `event.kind` | Event kind | `event` |
| `event.type` | `["info", "indicator"]` for a detection; the scan markers carry `info` and the scan phase (`end` for the end marker) | `["info", "indicator"]` |
| `event.category` | Categories | `["malware", "file"]` |
| `threat.indicator.type` | Kind of indicator | `file` |
| `file.path`, `file.owner`, `process.pid`, `destination.port`, `observer.ingress.interface.name` | Detection-specific, see the table above | `/dev/shm/e2etest` |

## Viewing Alerts

### On Wazuh Manager

These commands read the engine's file output, which exists only when a policy has a `file` output stage; the channel is `<space>-<channel name>` (see [File output](../engine/ref-output.md#file)). Set `EVENTS` to today's file:

```bash
EVENTS=/var/wazuh-manager/logs/<channel>/$(date +%Y/%b)/wazuh-<channel>-$(date +%d).json
```

**Real-time JSON alerts:**
```bash
tail -f "$EVENTS"
```

**Filter rootcheck alerts with jq:**
```bash
tail -f "$EVENTS" | jq 'select(.wazuh.protocol.location=="rootcheck")'
```

**Pretty print specific fields:**
```bash
tail -f "$EVENTS" | jq 'select(.wazuh.protocol.location=="rootcheck") | {
  time: ."@timestamp",
  agent: .wazuh.agent.name,
  message: .event.original,
  indicator: .threat.indicator.type
}'
```

**Exclude scan start/end messages:**
```bash
tail -f "$EVENTS" | jq 'select(.wazuh.protocol.location=="rootcheck" and (.event.original | test("^(Starting|Ending) rootcheck scan") | not))'
```

### Query Specific Alert Types

**Files in /dev directory:**
```bash
jq 'select(.wazuh.protocol.location=="rootcheck" and (.event.original | contains("present on /dev")))' "$EVENTS"
```

**World-writable files:**
```bash
jq 'select(.wazuh.protocol.location=="rootcheck" and (.event.original | contains("written permissions to anyone")))' "$EVENTS"
```

**Promiscuous mode (search in message):**
```bash
jq 'select(.wazuh.protocol.location=="rootcheck" and (.event.original | contains("promiscuous")))' "$EVENTS"
```

**Specific agent:**
```bash
jq 'select(.wazuh.protocol.location=="rootcheck" and .wazuh.agent.name=="ubuntu22")' "$EVENTS"
```

### On Wazuh Dashboard

Navigate to **Threat Hunting** or **Discover** module and use these filters:

**All rootcheck alerts:**
```
wazuh.protocol.location: rootcheck
```

`event.original` is stored but not indexed, so a query on it never matches (or errors): filter on the fields the
decoder extracts instead (see [Messages and the fields extracted from them](#messages-and-the-fields-extracted-from-them)).

**Exclude scan messages** (detections carry `indicator` in `event.type`, the scan markers do not):
```
wazuh.protocol.location: rootcheck AND event.type: indicator
```

**Specific detection types:**
```
wazuh.protocol.location: rootcheck AND threat.indicator.type: file
wazuh.protocol.location: rootcheck AND file.path: /dev/*
wazuh.protocol.location: rootcheck AND file.owner: *
wazuh.protocol.location: rootcheck AND process.pid: *
wazuh.protocol.location: rootcheck AND destination.port: *
wazuh.protocol.location: rootcheck AND observer.ingress.interface.name: *
```

They select, in order: file indicators, files in `/dev`, world-writable files owned by root, hidden processes,
hidden ports and promiscuous interfaces.

**Specific agent:**
```
wazuh.protocol.location: rootcheck AND wazuh.agent.name: ubuntu22
```

**By event category:**
```
wazuh.protocol.location: rootcheck AND event.category: malware
```

## Alert Response Actions

### Recommended Actions by Detection Type

| Detection | Severity | Recommended Action |
|-----------|----------|-------------------|
| **Suspicious /dev file** | Medium | Examine file content, check file history |
| **Promiscuous Mode** | Medium | Verify legitimate use (monitoring tools), investigate if unexpected |
| **Hidden Process** | Critical | Immediately isolate system, conduct forensic analysis, check for rootkit |
| **Hidden Port** | Critical | Immediately isolate system, investigate C2 communication, analyze network traffic |
| **World-Writable** | Medium | Correct permissions, investigate how they changed |

### Investigation Steps

1. **Isolate the system** (if critical detection)
2. **Collect forensic data** before remediation
3. **Cross-reference with other logs** (FIM, Syscollector, command monitoring)
4. **Verify with manual checks** (ls -la, ip link, stat)
5. **Take action** based on findings

## False Positives

### Common False Positive Scenarios

1. **Promiscuous Mode - Legitimate monitoring:**
   - **Cause:** Legitimate network monitoring tools (tcpdump, Wireshark, network security tools)
   - **Solution:** Verify tool legitimacy and add exception if needed

2. **Device Directory Files:**
   - **Cause:** Custom device drivers, special hardware, test files
   - **Solution:** Add to ignore list if verified legitimate

3. **World-Writable Test Files:**
   - **Cause:** Temporary test files, development environments
   - **Solution:** Review and remove unnecessary test files, or add to ignore list

### Handling False Positives

Use ignore patterns in configuration:

```xml
<rootcheck>
  <ignore type="sregex">/dev/custom-device</ignore>
  <ignore type="sregex">/tmp/test_.*</ignore>
</rootcheck>
```

Or create custom rules to reduce severity of known false positives.

## Working with JSON Alerts

### Extract Specific Information

**Get all rootcheck alert messages:**
```bash
jq -r 'select(.wazuh.protocol.location=="rootcheck") | .event.original' "$EVENTS"
```

**Count alerts by indicator type:**
```bash
jq -r 'select(.wazuh.protocol.location=="rootcheck") | .threat.indicator.type // empty' "$EVENTS" | sort | uniq -c
```

**List affected agents:**
```bash
jq -r 'select(.wazuh.protocol.location=="rootcheck") | .wazuh.agent.name' "$EVENTS" | sort -u
```

**Export alerts to CSV:**
```bash
jq -r 'select(.wazuh.protocol.location=="rootcheck") | [."@timestamp", .wazuh.agent.name, .event.original, .threat.indicator.type // "N/A"] | @csv' "$EVENTS" > rootcheck_alerts.csv
```

**Get file paths from detections:**
```bash
jq -r 'select(.wazuh.protocol.location=="rootcheck" and .file.path?) | .file.path' "$EVENTS"
```

### Advanced Filtering

**Alerts from last hour:**
```bash
# Get timestamp from 1 hour ago
ONE_HOUR_AGO=$(date -u -d '1 hour ago' '+%Y-%m-%dT%H:%M:%SZ')

jq --arg time "$ONE_HOUR_AGO" 'select(.wazuh.protocol.location=="rootcheck" and ."@timestamp" > $time)' "$EVENTS"
```

**Multiple conditions:**
```bash
# Malware category alerts from specific agent
jq 'select(.wazuh.protocol.location=="rootcheck" and .wazuh.agent.name=="ubuntu22" and (.event.category | index("malware")))' "$EVENTS"
```

**Group by agent and indicator type:**
```bash
jq -r 'select(.wazuh.protocol.location=="rootcheck") | "\(.wazuh.agent.name),\(.threat.indicator.type // "N/A")"' "$EVENTS" | sort | uniq -c
```

### Statistical Analysis

**Count alerts per agent:**
```bash
jq -r 'select(.wazuh.protocol.location=="rootcheck") | .wazuh.agent.name' "$EVENTS" | sort | uniq -c | sort -rn
```

**Alerts timeline (by hour):**
```bash
jq -r 'select(.wazuh.protocol.location=="rootcheck") | ."@timestamp" | split("T")[1] | split(":")[0]' "$EVENTS" | sort | uniq -c
```

## See Also

- [Configuration](configuration.md) - Configure rootcheck options
- [Architecture](architecture.md) - Technical details of detection methods
- [README](README.md) - Module overview

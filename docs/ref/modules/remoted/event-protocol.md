# Event Protocol Specification

## Overview

The Wazuh Event Protocol version 1 (x-wev1) defines how enriched events are transmitted from remoted to analysisd. This protocol ensures that every event carries complete agent metadata for stateless processing.

## Protocol Identifier

- **Name**: Wazuh Event Protocol v1
- **Content-Type**: `application/x-wev1`
- **Version**: 1.0
- **Status**: Active (Wazuh 5.0+)

## Transport

HTTP POST over Unix socket at `/var/wazuh-manager/queue/sockets/queue` with content-type `application/x-wev1`.

## Message Format

Batch structure:
```
H <JSON_HEADER><LF>
E <EVENT_1><LF>
E <EVENT_2><LF>
```

- `H` = Header line (JSON metadata, once per batch)
- `E` = Event line (raw event data)
- ` ` = Space character (0x20)
- `<LF>` = Line feed (0x0A)

## Header Line (H)

### Format

```
H <JSON_HEADER><LF>
```

### Header JSON Schema

The header is a JSON object conforming to Elastic Common Schema (ECS):

```json
{
  "wazuh": {
    "agent": {
      "id": "string",
      "name": "string",
      "version": "string",
      "groups": ["string"],
      "host": {
        "architecture": "string",
        "hostname": "string",
        "os": {
          "name": "string",
          "version": "string",
          "platform": "string",
          "type": "string"
        }
      }
    },
    "cluster": {
      "name": "string",
      "node": "string"
    }
  }
}
```

### Field Specifications

| Field | Type | Required | Description | Example |
|-------|------|----------|-------------|---------|
| `wazuh.agent.id` | string | **Yes** | Agent numeric ID | `"001"` |
| `wazuh.agent.name` | string | No | Agent name | `"web-server-01"` |
| `wazuh.agent.version` | string | No | Wazuh agent version | `"v5.0.0"` |
| `wazuh.agent.groups` | array[string] | No | Agent groups | `["web", "production"]` |
| `wazuh.agent.host.architecture` | string | No | CPU architecture | `"x86_64"` |
| `wazuh.agent.host.hostname` | string | No | System hostname | `"web-server-01"` |
| `wazuh.agent.host.os.name` | string | No | OS name | `"Ubuntu"` |
| `wazuh.agent.host.os.version` | string | No | OS version | `"22.04"` |
| `wazuh.agent.host.os.platform` | string | No | OS platform | `"ubuntu"` |
| `wazuh.agent.host.os.type` | string | No | ECS OS type | `"linux"` |
| `wazuh.cluster.name` | string | No | Cluster name | `"production"` |
| `wazuh.cluster.node` | string | No | Manager node | `"master-node"` |

### Rules

- Exactly one header per batch (first line)
- JSON must be compact (no newlines)
- UTF-8 encoding required

### Example Headers

**Minimal Header** (only required fields):
```
H	{"agent":{"id":"001"}}
```

**Full Header** (all fields):
```
H	{"agent":{"id":"001","name":"web-server-01","version":"v5.0.0","groups":["web","production"],"host":{"architecture":"x86_64","hostname":"web-server-01","os":{"name":"Ubuntu","version":"22.04","platform":"ubuntu","type":"linux"}}},"wazuh":{"cluster":{"name":"production","node":"master-node"}}}
```

## Event Line (E)

Format: `E <EVENT_PAYLOAD><LF>`

Payload is raw event data (JSON or text), UTF-8 encoded. Newlines must be escaped. Max 64KB per event.

## Complete Batch Example

### Simple Batch

```
H	{"agent":{"id":"001","name":"web-01","version":"v5.0.0","groups":["web"],"host":{"os":{"type":"linux"}}}}
E	{"timestamp":"2026-01-05T10:00:00Z","log":"Connection from 192.168.1.100"}
E	{"timestamp":"2026-01-05T10:00:01Z","log":"Authentication successful"}
```

### Full Batch

```http
POST /events/enriched HTTP/1.1
Host: localhost
Content-Type: application/x-wev1
Content-Length: 512
User-Agent: wazuh-remoted/1.0
Connection: keep-alive

H	{"agent":{"id":"001","name":"web-server-01","version":"v5.0.0","groups":["web","production"],"host":{"architecture":"x86_64","hostname":"web-server-01","os":{"name":"Ubuntu","version":"22.04","platform":"ubuntu","type":"linux"}}},"wazuh":{"cluster":{"name":"production","node":"master-node"}}}
E	{"timestamp":"2026-01-05T10:00:00.000Z","log":"sshd[1234]: Connection from 192.168.1.100 port 54321"}
E	{"timestamp":"2026-01-05T10:00:01.123Z","log":"sshd[1234]: Accepted publickey for admin from 192.168.1.100"}
E	{"timestamp":"2026-01-05T10:00:02.456Z","log":"sudo: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/systemctl restart nginx"}
```

## Parsing

Split by `\n`, check first char (`H` or `E`), extract payload after space (index 2).

## Error Handling

- `400`: Malformed batch
- `413`: Batch too large - split and retry
- `5xx`: Retry with backoff

## Performance

Batch 100-500 events for optimal throughput. Header generated once per batch.

## Security

Unix socket transport (no network exposure). Socket permissions: wazuh:wazuh 0660.

## References

- [Elastic Common Schema (ECS)](https://www.elastic.co/guide/en/ecs/current/)
- [Stateless Metadata](stateless-metadata.md)
- [Remoted Architecture](architecture.md)
- [RFC 7230: HTTP/1.1 Message Syntax](https://tools.ietf.org/html/rfc7230)

# Event Protocol Specification

## Overview

The Wazuh Event Protocol version 1 (x-wev1) defines how enriched events are transmitted from remoted to the engine. This protocol ensures that every event carries complete agent metadata for stateless processing.

## Protocol Identifier

- **Name**: Wazuh Event Protocol v1
- **Content-Type**: `application/x-wev1` (classic C dispatcher, `src/remoted/src/secure.c`), or
  `application/x-ndjson` (the HTTPS `remoted_module` ingestion path,
  `src/remoted/remoted_module/src/endpoints/statelessEndpoint.cpp`) — both carry the same `H`/`E`
  wire format described below

## Transport

HTTP POST over Unix socket at `/var/wazuh-manager/queue/sockets/engine-ingest-http.sock` with content-type
`application/x-wev1` (classic C dispatcher) or `application/x-ndjson` (HTTPS `remoted_module`
ingestion path, forwarding to `POST /events/enriched`).

## Message Format

Batch structure:
```
H <JSON_HEADER><LF>
E <QUEUE>:<LOCATION>:<MESSAGE><LF>
E <QUEUE>:<LOCATION>:<MESSAGE><LF>
```

- `H` = Header line (JSON metadata, once per batch)
- `E` = Event line: one event in the `<queue>:<location>:<message>` format (see
  [Event Line (E)](#event-line-e))
- ` ` = Space character (0x20): the header starts with `H ` and each event starts with `E `.
  Continuation lines use the indentation below; they do not require an `H`/`E` marker. Extra spaces
  after the two-byte marker belong to the JSON whitespace or event payload, not the marker.
- `<LF>` = Line feed (0x0A)

## Header Line (H)

### Format

```
H <JSON_HEADER><LF>
```

### Header JSON Schema

The header is a JSON object with every field under `wazuh`; `wazuh.agent.host.os.type` takes the ECS
`os.type` values (`linux`, `macos`, `unix`, `windows`):

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
| `wazuh.agent.version` | string | No | Wazuh agent version: `v5.0.0` from a 5.x agent; on the legacy path, the 4.x keep-alive's text, with its prefix (`Wazuh v4.14.3`) | `"v5.0.0"` |
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
- **The identity path must not be repeated.** Within the header, `wazuh`, `wazuh.agent` and
  `wazuh.agent.id` must each appear exactly once, and `wazuh` and `wazuh.agent` must be objects.
  Names are compared after JSON unescaping, so `"wazuh"` and `"\u0077azuh"` are the same name. A header
  that repeats any of those is rejected with `400 Invalid event batch` and the batch is never
  ingested — see [HTTPS events API](https-events-api.md#error-responses). Repeating other fields is
  not rejected, but it is still outside this specification: each field is defined to appear once,
  and which copy survives is not contractual.
- **`wazuh.agent.id` is a JSON string equal, byte for byte, to the authenticated agent's id** on
  `POST /stateless` (`"001"`, not `"1"` or `1`); anything else is answered `400 Invalid event batch`.
- **No dotted member names that reach `wazuh.*`.** The indexer expands a dotted name into a field
  path, so a root member such as `"wazuh.agent.id"`, or any dotted name inside the root `wazuh`
  object (`"agent.id"`), would index a second value of the identity field. `POST /stateless` answers
  such a header `400 Invalid event batch`; dotted names elsewhere in the header are left alone.

### Example Headers

**Minimal Header** (only required fields):
```
H {"wazuh":{"agent":{"id":"001"}}}
```

**Full Header** (all fields):
```
H {"wazuh":{"agent":{"id":"001","name":"web-server-01","version":"v5.0.0","groups":["web","production"],"host":{"architecture":"x86_64","hostname":"web-server-01","os":{"name":"Ubuntu","version":"22.04","platform":"ubuntu","type":"linux"}}},"cluster":{"name":"production","node":"master-node"}}}
```

## Event Line (E)

Format: `E <EVENT_PAYLOAD><LF>`, where the payload is `<queue>:<location>:<message>`, UTF-8 encoded:

| Part | Description | Example |
|------|-------------|---------|
| `<queue>` | Exactly one byte, `0x01` to `0x7F`, identifying the source queue; it is stored as its numeric value (`1` is `49`) | `1` (log collector), `8` (FIM), `d` (syscollector) |
| `:` | Separator; it must be the second byte of the payload | |
| `<location>` | Where the event came from, not empty; a `:` inside it is escaped as `\|:` | `/var/log/auth.log`, `EventChannel`, `C\|:\app\service.log` for `C:\app\service.log` |
| `:` | Separator: the first `:` not preceded by `\|` ends the location | |
| `<message>` | The event itself, raw text or JSON; it may contain `:` | `sshd[1234]: Accepted publickey for admin` |

The whole payload comes from the sender and neither channel rewrites it: the 5.x agent builds each
event line from its local message queue, which already carries this format, and remoted forwards the
`/stateless` body to the engine byte for byte; the legacy dispatcher posts each 4.x message as it was
decrypted. What remoted adds is the header line on the legacy channel only — on `/stateless` the agent
writes the header too, and remoted only checks its `wazuh.agent.id` against the authenticated agent.

The engine checks only the header and the batch framing when it accepts a request: it answers `200`
(remoted then answers the agent `202`) before it parses the event lines. A line that is not a valid
`<queue>:<location>:<message>` payload — shorter than 5 bytes, no `:` after the queue byte, a queue
byte outside `0x01`..`0x7F`, no unescaped `:` after the location, or an empty location — is **dropped
later, silently for the sender**: the engine counts it in
[`router.events.malformed`](../engine/README.md#routereventsmalformed) and logs
`Dropped a malformed event: <reason>` (the first one, then at most one line per minute per router
worker). A client that sends a bare JSON or text event (`E {"log":"..."}`) therefore gets `202` for
every batch and loses every event.

**Multi-line payloads are supported and are not escaped.** Events are framed by the `\nE `
delimiter, so a payload containing that sequence would otherwise be read as two events. The sender
therefore indents every *continuation* line (each line after the first within one event) with a
single space, and the receiver strips exactly one leading space from each continuation line to
recover the continuation text. Trailing framing newlines are trimmed before unindenting; a final
unindented payload newline is not preserved. Quotes, tabs and non-ASCII characters are not escaped
by this framing layer.

A three-line payload travels as one event, its second and third lines each indented by one space
(the leading space is protocol framing, not part of the payload):

```
E 1:/var/log/app/error.log:java.lang.IllegalStateException: pool closed
     at com.example.Pool.acquire(Pool.java:88)
     at com.example.Worker.run(Worker.java:31)
```

JSON string values must escape newlines, but pretty-printed JSON may contain raw newlines between
tokens. Both that JSON and plain-text stack traces use the continuation indentation when sent as
a single multi-line event.

The manager applies no per-event size limit of its own on the HTTPS path; what bounds a request
there is the whole body: the transport limit is
[`https.max_body_size`](configuration.md#httpsmax_body_size), 10 MiB by default, and the authentication
limit is [`remoted.auth_max_body_size`](configuration.md#remotedauth_max_body_size), 5 MiB by default.
Both limits apply to the bytes received on the wire. For zstd on `/stateless`, the decoded body is
capped by [`remoted.auth_max_decoded_body_size`](configuration.md#remotedauth_max_decoded_body_size),
32 MiB by default, and charged to the shared
[in-flight byte budget](configuration.md#remotedmax_inflight_bytes) and to the agent's
[share of it](configuration.md#remotedmax_inflight_bytes_per_agent); the decoder also limits its
window to 8 MiB. `/stateless` separately limits
the header JSON to 8 KiB. On the legacy
TCP/UDP channel a single agent message is bounded by the receive buffer, `OS_MAXSTR` (64 KiB).

## Complete Batch Example

### Simple Batch

```
H {"wazuh":{"agent":{"id":"001","name":"web-01","version":"v5.0.0","groups":["web"],"host":{"os":{"type":"linux"}}}}}
E 1:/var/log/auth.log:Jan  5 10:00:00 web-01 sshd[1234]: Connection from 192.168.1.100 port 54321
E 1:/var/log/auth.log:Jan  5 10:00:01 web-01 sshd[1234]: Accepted publickey for admin from 192.168.1.100
```

### Full Batch

```http
POST /events/enriched HTTP/1.1
Host: localhost
Content-Type: application/x-wev1
Content-Length: 665
User-Agent: wazuh-manager-remoted/1.0
Connection: keep-alive

H {"wazuh":{"agent":{"id":"001","name":"web-server-01","version":"Wazuh v4.14.3","groups":["web","production"],"host":{"architecture":"x86_64","hostname":"web-server-01","os":{"name":"Ubuntu","version":"22.04","platform":"ubuntu","type":"linux"}}},"cluster":{"name":"production","node":"master-node"}}}
E 1:/var/log/auth.log:Jan  5 10:00:00 web-server-01 sshd[1234]: Connection from 192.168.1.100 port 54321
E 1:/var/log/auth.log:Jan  5 10:00:01 web-server-01 sshd[1234]: Accepted publickey for admin from 192.168.1.100
E 1:/var/log/auth.log:Jan  5 10:00:02 web-server-01 sudo: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/systemctl restart nginx
```

## Parsing

Read the first line as the header: it must begin with `H ` and the rest of the line is the JSON.
Then split the remainder on the `\nE ` delimiter rather than on bare newlines, take the payload
after the leading `E `, and unindent continuation lines by removing one leading space from each.
Trailing newlines are trimmed from each event; blank lines between events are skipped. Finally split
each payload into its queue byte, its location (up to the first `:` not preceded by `|`, with `|:`
unescaped to `:`) and its message.

## Engine Responses

- `200`: the header and the framing were parsed and the events queued for processing; an event line
  that is not a valid `<queue>:<location>:<message>` payload is dropped afterwards (see
  [Event Line (E)](#event-line-e)).
- `400`: the batch could not be parsed (`{"error": "<parser message>", "code": 400}`); nothing of it
  is ingested. The engine logs `[API::Event] Failed to parse request: '<message>'` at most once per minute,
  with the count of requests rejected since the previous line.
- `500`: internal error in the engine.

The engine's event server sets no request-size limit of its own. On the HTTPS path, remoted maps these
answers onto what the agent receives (see [HTTPS Agent API](https-events-api.md#error-responses));
the legacy dispatcher does not retry a failed batch.

## Security

Unix socket transport (no network exposure). The engine sets the socket to mode `0660` after binding
it, so only its owner and the `wazuh-manager` group can post events.

## References

- [Elastic Common Schema (ECS)](https://www.elastic.co/guide/en/ecs/current/)
- [Stateless Metadata](stateless-metadata.md)
- [Remoted Architecture](architecture.md)
- [RFC 7230: HTTP/1.1 Message Syntax](https://tools.ietf.org/html/rfc7230)

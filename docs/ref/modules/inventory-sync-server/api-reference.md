# Inventory Sync Server API Reference

All routes are served over a Unix domain socket at `queue/sockets/inventory-sync.sock`, relative to the
installation directory. There is no TCP listener.

The only production peer is [Remoted](../remoted/README.md), which authenticates the agent and forwards
the request. Requests are HTTP/1.1, `Content-Length` delimited, one request per connection
(`Connection: close`); chunked transfer encoding is rejected.

## Routes

| Method | Path | Success | Notes |
|---|---|---|---|
| `GET` | `/` | `200` | Liveness probe. Exempt from the in-flight byte budget, so it keeps answering under memory pressure. |
| `POST` | `/inventory/sync` | `202` | **Provisional.** Accepts and discards the payload; the ingestion pipeline is not implemented yet. |
| `POST` | `/stats` | `200` | Indexes the agent's statistics report into `wazuh-agent-stats` (see [`POST /stats`](#post-stats) below). Answers `{}`. |
| `POST` | `/config` | `200` | Indexes the agent's reported configuration into `wazuh-agent-config` (see [Indexing `/config`](#indexing-config) below). Answers `{}`. |

Both endpoints are implemented for real (issues #38024 and #38023): each takes the agent's
`modules`-keyed report, moves it under its own subtree, and indexes one document per agent.

### `POST /stats`

The agent reports every module it can collect statistics from in one push, keyed by module:

```json
{
  "modules": {
    "agent":        {"status": "connected", "last_keepalive": "2026-08-02T10:06:50Z",
                     "messages": {"count": 602},
                     "tasks": {"dispatched": {"total": 4}, "discarded_duplicate": {"total": 0},
                               "failed": {"total": 0}}},
    "logcollector": {"global": {"files": []}, "interval": {"files": []}}
  }
}
```

The module moves `modules` under `wazuh.agent.statistics`, adds the envelope below, and indexes one
document into `wazuh-agent-stats` whose **document id is the agent id**, so every push replaces the
agent's previous report:

```json
{
  "state": {"modified_at": "2026-08-02T10:07:12.431Z", "document_version": 1},
  "wazuh": {
    "schema": {"version": "1"},
    "cluster": {"name": "wazuh", "node": "node01"},
    "agent": {"id": "001", "statistics": {"agent": {…}, "logcollector": {…}}}
  }
}
```

Two details worth knowing:

- The document is built from scratch, so an `agent_id` or `cluster` the agent writes at the root of its
  own report is dropped rather than indexed next to the authoritative `wazuh.agent.id`.
- The report is stored as it arrives. The module renames no metric and reshapes no module body, so the
  field names in the index are the ones the agent emits, and a metric the agent adds needs no change
  here.

`400` when the body is not a JSON object, when `modules` is missing, is not an object, is empty, or
holds a module whose body is not an object. The empty case is a rejection on purpose: indexing a
report with no statistics would replace the agent's last good one.
>>>>>>> beb5a272de5 (docs: document POST /stats and the index it writes)

## Request headers

| Header | Required | Meaning |
|---|---|---|
| `X-Wazuh-Agent-Id` | Yes, for `/inventory/sync`, `/stats` and `/config` | The agent identity remoted authenticated. Its absence is a contract violation, not agent input, so it is answered `400`. |
| `Content-Type` | No | Recorded, not interpreted. |

## Enrichment (`/stats`)

For `/stats` and `/config`, the module writes the identity and the time itself. Every one of these is
authoritative and replaces whatever the agent sent:

| JSON pointer | Endpoint | Source |
|---|---|---|
| `/wazuh/agent/id` | both | The authenticated `X-Wazuh-Agent-Id` header |
| `/wazuh/cluster/name` | both | `<cluster><name>` in the manager configuration |
| `/wazuh/cluster/node` | both | `<cluster><node_name>` |
| `/state/modified_at` | `/stats` | The manager's clock, ISO 8601 with milliseconds, UTC |
| `/state/document_version` | `/stats` | Constant. Versions the stored layout, not the report |
| `/wazuh/schema/version` | `/stats` | Constant, and a **string**: `wazuh-metrics-agents` declares it `keyword`, so this index follows |
| `/@timestamp` | `/config` | The manager's clock, same format |

`/stats` writes `state.modified_at` rather than `@timestamp` because its index follows the schema's
stateful convention: a stable document id, replaced in place, with no time series behind it.

A cluster name or node name containing bytes that are not valid UTF-8 is sanitized once at startup, with
a warning, rather than being allowed to break the serialization of every request.

## Indexing `/config`

Unlike `/stats`, the body is a JSON **array** of `{"module": <string>, "config": <object>}` pairs, one
per agent module (e.g. `fim`, `logcollector`) -- not a single JSON object. Each element is reduced to
exactly those two keys (anything else the agent sent on that element is dropped) and folded into a
`{"<module>": <config>}` object: a module is unique per report, so a later entry for the same module
name overwrites an earlier one rather than being treated as an error. `config` itself is never
validated against a schema here -- it is copied through as an opaque JSON value; per-module field
typing lives entirely in the `wazuh-agent-config` index mapping.

The result is indexed under the agent id as `_id`, via a plain upsert -- each report replaces the
previous one for that agent in full, there is no delete step:

```json
{
  "state": { "modified_at": "<manager clock, ISO 8601 UTC>", "document_version": 1 },
  "wazuh": {
    "schema": { "version": "1.0.0" },
    "agent": { "id": "<authenticated X-Wazuh-Agent-Id>",
               "configuration": { "modules": ["fim", "logcollector", ...],
                                  "content": { "fim": {...}, "logcollector": {...}, ... } } },
    "cluster": { "name": "<cluster><name>", "node": "<cluster><node_name>" }
  }
}
```

`modules` is derived from `content`'s keys (never collected separately), so the two can never drift
apart. `wazuh.agent.id` and `wazuh.cluster.*` are authoritative and always overwrite anything the
agent's payload might claim; there is no per-request source for the cluster identity, it is this
manager's own configuration read once at registration time.

A `POST /config` that fails indexer-availability validation (see status codes below) never reaches the
write path; a request that passes validation but whose serialization later fails (e.g. an agent id
header that is not valid UTF-8) is answered `400` rather than crashing the handler.

## Status codes

These can be returned on any route, by the transport rather than by a handler:

| Status | Cause |
|---|---|
| `400` | Malformed HTTP, a missing agent id header, or a body that does not match the route's shape (a non-empty `modules`-keyed object whose every module value is an object, for both `/stats` and `/config`) |
| `404` | Unknown path |
| `405` | Known path, wrong verb. Carries an `Allow` header listing that path's verbs |
| `411` | Chunked transfer encoding, which is not supported |
| `413` | Body over `max_body_size` |
| `414` | Request target over `max_url_size` |
| `431` | A header name or value over its cap, or more than 32 header lines |
| `500` | A route handler threw. The server keeps serving |
| `503` | No healthy indexer host (`/stats`, `/config`), the in-flight byte budget is exhausted, the connection cap is reached, or the module is shutting down |
| `504` | A handler was dispatched but never answered within `response_timeout` |

A `503` is retryable and a `400` is not: validation runs BEFORE the indexer availability check on
purpose, so a malformed document is never masked as a transient failure the agent would retry forever.

## Manual testing

`tools/send_sync.py` in the module's source directory drives every route over the socket at the
transport level (health check, oversized bodies, malformed encodings) but does not build a
route-specific payload. The liveness probe with curl:

```bash
curl --unix-socket /var/wazuh-manager/queue/sockets/inventory-sync.sock http://localhost/
```

A `/config` report, simulating what remoted forwards for an authenticated agent:

```bash
curl --unix-socket /var/wazuh-manager/queue/sockets/inventory-sync.sock http://localhost/config \
  -X POST -H "Content-Type: application/json" -H "x-wazuh-agent-id: 001" \
  -d '[{"module":"fim","config":{"frequency":43200}},{"module":"logcollector","config":{"localfile":[{"file":"/var/log/syslog","logformat":"syslog"}]}}]'
```

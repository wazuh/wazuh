# Inventory Sync Server API Reference

All routes are served over a Unix domain socket at `queue/sockets/inventory-sync.sock`, relative to the
installation directory. There is no TCP listener.

The only production peer is [Remoted](../remoted/README.md), which authenticates the agent and forwards
the request. Requests are HTTP/1.1, `Content-Length` delimited, one request per connection
(`Connection: close`); chunked transfer encoding is rejected.

## Routes

| Method | Path | Success | Notes |
|---|---|---|---|
| `GET` | `/` | `200` | Liveness probe, answers `{"status":"ok","module":"inventory_sync_server"}`. Exempt from the in-flight byte budget, so it keeps answering under memory pressure. |
| `GET` | `/metrics` | `200` | The module's runtime statistics as JSON (see [`GET /metrics`](#get-metrics) below). Budget-exempt, like the probe. |
| `POST` | `/stateful` | `200` | One whole synchronization session (FlatBuffers `Message{FullSession}`). `200` `{"status":"ok"}` means applied AND flushed to the indexer (and scanned, for VD sessions); `{"status":"ok","noop":true}` means everything was filtered. Other statuses: `400` invalid session, `403` identity mismatch, `409` `{"status":"checksum_mismatch"}` for a `ModuleCheck` session (the agent full-resyncs) OR `{"error":"version_mismatch","current_version":N}` for a VDFirst/VDSync session whose `feed_offset` doesn't match this node's current VD feed offset (the agent retries with `current_version`; see [vulnerability-scanner's architecture.md](../vulnerability-scanner/architecture.md#feed-update-rescan-scanvd--rescandisconnectedagents)), `413` the session declares more bytes than the total budget, `500` failed with nothing indexed (including a failed vulnerability scan), `503` not ready / no capacity — with a `Retry-After` header when the CVE feed is still downloading. |
| `DELETE` | `/agents` | `200` | Deletes every document of the agent named by `X-Wazuh-Agent-Id` across `wazuh-states-*`, `wazuh-agent-config` and `wazuh-agent-stats` (this cluster's scope), one delete-by-query per index. Deferred to the agent's worker shard, so it orders after that agent's in-flight sessions; `200` means every delete-by-query was flushed. Two documented windows can still leave a document behind — see [Whole-agent deletion semantics](#whole-agent-deletion-semantics). UDS-local only: the production caller is authd. |
| `POST` | `/agents/delete` | `200` | Alias of `DELETE /agents` with the same handler, for C callers whose HTTP helper only speaks POST. |
| `POST` | `/stats` | `200` | Indexes the agent's statistics report into `wazuh-agent-stats` (see [`POST /stats`](#post-stats) below). Answers `{}`. |
| `POST` | `/config` | `200` | Indexes the agent's reported configuration into `wazuh-agent-config` (see [Indexing `/config`](#indexing-config) below). Answers `{}`. |

The stats and config endpoints take the agent's `modules`-keyed report, move it under their own
subtree, and index one document per agent (issues #38024 and #38023).

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
    "cluster": {"name": "wazuh"},
    "agent": {"id": "001", "statistics": {"agent": {…}, "logcollector": {…}}}
  }
}
```

Three details worth knowing:

- The document is built from scratch, so an `agent_id` or `cluster` the agent writes at the root of its
  own report is dropped rather than indexed next to the authoritative `wazuh.agent.id`.
- The report is stored as it arrives. The module renames no metric and reshapes no module body, so the
  field names in the index are the ones the agent emits, and a metric the agent adds needs no change
  here.
- It does need one in the index template. `wazuh-agent-stats` is mapped `dynamic: strict` with every
  leaf declared, so a module or metric it does not declare makes the indexer reject the whole document
  with `strict_dynamic_mapping_exception`. The write is fire-and-forget and the agent already has its
  `200`, so that rejection is invisible from here — read the document back off the indexer to see it.

`400` when the body is not a JSON object, when `modules` is missing, is not an object, is empty, or
holds a module whose body is not an object. The empty case is a rejection on purpose: indexing a
report with no statistics would replace the agent's last good one.

## Request headers

| Header | Required | Meaning |
|---|---|---|
| `X-Wazuh-Agent-Id` | Yes, for every route except `GET /` and `GET /metrics` | For `/stateful`, `/stats` and `/config`: the agent identity remoted authenticated (the session's own claimed identity must match it, or the answer is `403`). For the deletion routes: the TARGET agent, set by the calling daemon. Missing or non-numeric is answered `400`. |
| `Content-Type` | No | Recorded, not interpreted. |

## Enrichment (`/stats`)

For `/stats` and `/config`, the module writes the identity and the time itself. Every one of these is
authoritative and replaces whatever the agent sent:

| JSON pointer | Endpoint | Source |
|---|---|---|
| `/wazuh/agent/id` | both | The authenticated `X-Wazuh-Agent-Id` header |
| `/wazuh/cluster/name` | both | `<cluster><name>` in the manager configuration |
| `/state/modified_at` | `/stats` | The manager's clock, ISO 8601 with milliseconds, UTC |
| `/state/document_version` | `/stats` | Constant. Versions the stored layout, not the report |
| `/wazuh/schema/version` | `/stats` | Constant, and a **string**: `wazuh-metrics-agents` declares it `keyword`, so this index follows |
| `/@timestamp` | `/config` | The manager's clock, same format |

`/stats` writes `state.modified_at` rather than `@timestamp` because its index follows the schema's
stateful convention: a stable document id, replaced in place, with no time series behind it.

A cluster name containing bytes that are not valid UTF-8 is sanitized once at startup, with a warning,
rather than being allowed to break the serialization of every request.

## Indexing `/config`

Like `/stats`, the body is a `modules`-keyed object -- `{"modules": {"<module>": <config>, ...}}`,
one entry per agent module (e.g. `fim`, `logcollector`). A module is unique per report by construction
(object keys cannot repeat), and its `config` is never validated against a schema here -- it is copied
through as an opaque JSON value into `configuration.content`; per-module field typing lives entirely in
the `wazuh-agent-config` index mapping. An empty `modules` object is rejected, for the same reason
`/stats` rejects an empty report.

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
    "cluster": { "name": "<cluster><name>" }
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

## Whole-agent deletion semantics

`DELETE /agents` (and its `POST /agents/delete` alias) removes every document of one agent across the
deletion scope: `wazuh-states-*`, `wazuh-agent-config` and `wazuh-agent-stats`, one delete-by-query per
index.

What a `200` guarantees: every delete-by-query in the scope was flushed, AND none of them reported
per-shard failures or skipped documents. An index that does not exist counts as success, so repeating
a deletion is harmless — that is the caller's retry contract, and authd relies on it.

Two windows can still leave a single document behind, and neither turns the `200` into a failure.
Repeating the deletion clears either one:

- **The index refresh interval.** A delete-by-query is a SEARCH, so it only sees refreshed segments,
  and authd deletes immediately after removing the agent from `client.keys`. Documents the agent's
  last session wrote inside that interval are invisible to the query, and with the agent gone nothing
  overwrites them. Refreshing each index first would close this, but `_refresh` requires the
  `indices:admin/refresh` privilege, which the manager's least-privilege indexer role does not grant —
  granting it and restoring the refresh is tracked as a follow-up.
- **The asynchronous write queue.** `POST /config` and `POST /stats` are written through the module's
  asynchronous connector, whose queue the deletion cannot drain. A report still queued when the
  deletion runs lands after it and recreates that document. Ordering those two routes against the
  deletion (as `/stateful` sessions already are, through the agent's worker shard) is the other
  follow-up.

## The `/stateful` session semantics

The body is a FlatBuffers `Message{FullSession}` (see [Schemas](flatbuffers.md)):
`Start` names the agent, the module, the target indices, the mode and the option;
`SessionPayload` carries exactly ONE of `SyncData`, `Cleans`, or `ChecksumModule`. The valid
`mode` × `payload` combinations — anything else is a `400`:

| `Start.mode` | Accepted payload | What it does |
|---|---|---|
| `ModuleDelta` | `SyncData` (values ≥ 1, contexts optional) | Upserts/deletes state documents. Each value maps to one document: `_id` = `{cluster}_{agent}_{id}`, the document is overlaid with authoritative `wazuh.*` fields (agent id/name/version, groups, cluster) so a payload can never impersonate another agent, and a positive `version` becomes a versioned upsert. Documents targeting an index outside the allowlist are skipped with a warning, never failing the request; if everything was skipped the answer is a no-op `200`. |
| `ModuleDelta` | `Cleans` (items ≥ 1) | Deletes this agent's documents from each named index (deduplicated, allowlisted). A full resync is composed by the agent as two requests: a `Cleans` of the module's indices, then a `ModuleDelta` with the complete dataset. |
| `ModuleCheck` | `ChecksumModule` | Integrity verification of one index: the server pages this agent's documents in deterministic order, aggregates their checksums (SHA-1), and compares with the declared value — `200` on match, `409` on mismatch. One attempt, no retry loop: a mismatch means the agent full-resyncs. |
| `MetadataDelta` / `GroupDelta` | *(none)* | Reconciles agent metadata (or group membership) across the agent's already-indexed documents with one update-by-query, guarded by `global_version` so a stale update can never overwrite a newer one. |
| `MetadataCheck` / `GroupCheck` | *(none)* | Same update, conditioned to touch only documents that differ — a cheap "repair if needed". |

Sessions whose `Start.option` is `VDFirst` or `VDSync` additionally run the vulnerability scanner
synchronously BEFORE indexing (see [Architecture](architecture.md)); only `SyncData` sessions
scan — a VD-flagged `Cleans`/`ChecksumModule` follows the normal path.

Re-POSTing any session is idempotent: same `_id`s, same overlay, versioned upserts. That is the
whole retry contract — there are no acknowledgments and no session state to resume.

### Response contract

| Status | Body | The agent... |
|---|---|---|
| `200` | `{"status":"ok"}` | marks success. The data is FLUSHED to the indexer (and scanned, for VD sessions), not merely queued. |
| `200` | `{"status":"ok","noop":true}` | ditto — every document was filtered (e.g. unknown indices). |
| `409` | `{"status":"checksum_mismatch"}` | triggers a full resync of the module (`ModuleCheck`). |
| `409` | `{"error":"version_mismatch","current_version":N}` | a VDFirst/VDSync session whose `feed_offset` is stale; the agent rebuilds and retries with `current_version` (see [vulnerability-scanner's architecture.md](../vulnerability-scanner/architecture.md#feed-update-rescan-scanvd--rescandisconnectedagents)). |
| `400` | `{"error":"<reason>","code":400}` | has a protocol bug; retrying the same request cannot succeed. |
| `403` | `{"error":"identity mismatch","code":403}` | claimed an identity that does not match the authenticated one (or a foreign cluster). |
| `413` | `{"error":...,"code":413}` | declared more bytes than the server's TOTAL in-flight budget; must split the session. |
| `500` | `{"error":"vulnerability scan failed","code":500}` or `{"error":"Internal error","code":500}` | retries next cycle; NOTHING was indexed for this session. |
| `503` | One deliberately GENERIC body for indexer-unavailable / admission-queue-full / shutting-down (which of them fired is an operator concern, visible in logs and `GET /metrics`, not the agent's). The two VD gates are the exception, with reason-specific bodies: `"vulnerability feed not ready"` — the only `503` that carries `Retry-After: <seconds>` — and `"scan capacity exhausted"`. | retries later; on `Retry-After` it re-sends the same session after the delay. |

## `GET /metrics`

The D18 statistics dump. UDS-local like every route here — remoted exposes nothing that reaches
it, so agents cannot read it; the consumers are operators and the benchmark harness:

```bash
curl -s --unix-socket /var/wazuh-manager/queue/sockets/inventory-sync.sock http://localhost/metrics
```

```json
{
  "name": "inventory_sync_server",
  "timestamp": "2026-08-06T14:41:07Z",
  "metrics": [
    {"name": "sync.bulk.flushes", "type": "counter", "enabled": true, "value": 41,
     "description": "Group-commit flushes", "unit": "count"},
    {"name": "sync.session.duration.bulk", "type": "histogram", "enabled": true, "value": 41,
     "unit": "microseconds",
     "summary": {"count": 41, "sum": 5150000, "min": 900, "max": 410000,
                  "p50": 98304, "p90": 229376, "p99": 393216}}
  ]
}
```

Entries are sorted by name; counters are exact integers; a histogram's `value` is its observation
count and its `summary` carries bucket-resolution percentiles (~12.5% relative error). The full
metric catalog and where each is measured is in the
[architecture page](architecture.md#statistics-get-metrics). Counters accumulate for the life of
the process (they survive the module's internal restart retries); there is no reset endpoint.

Note it is NOT `POST /stats`: that route is the *ingest* of agent statistics reports, unrelated
to this module's own runtime metrics.

## Status codes

These can be returned on any route, by the transport rather than by a handler:

| Status | Cause |
|---|---|
| `400` | Malformed HTTP, a missing/invalid agent id header, or a body that does not match the route's shape (for `/stats` and `/config`: a non-empty `modules`-keyed object whose every module value is an object — an empty `modules` is rejected on purpose, since indexing a report with nothing to store would replace the agent's last good document) |
| `404` | Unknown path |
| `405` | Known path, wrong verb. Carries an `Allow` header listing that path's verbs |
| `411` | Chunked transfer encoding, which is not supported |
| `413` | A body declaring more bytes than the total in-flight budget (or over `max_body_size`, when one is explicitly configured) |
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
  -d '{"modules":{"fim":{"frequency":43200},"logcollector":{"localfile":[{"file":"/var/log/syslog","logformat":"syslog"}]}}}'
```

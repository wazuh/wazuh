# Inventory Sync Server API Reference

All routes are served over a Unix domain socket at `queue/sockets/inventory-sync-http.sock`, relative to the
installation directory. There is no TCP listener.

Agent traffic arrives through [Remoted](../remoted/README.md), which authenticates the agent and
forwards the request. The `_internal` route below is not agent traffic: it is a manager-internal
contract, called only by the Task Manager's dispatcher, and carries no compatibility promise.
Requests are HTTP/1.1, `Content-Length` delimited, one request per connection (`Connection: close`);
chunked transfer encoding is rejected.

## Routes

| Method | Path | Success | Notes |
|---|---|---|---|
| `GET` | `/` | `200` | Liveness probe, answers `{"status":"ok","module":"inventory_sync_server"}`. Exempt from the in-flight byte budget, so it keeps answering under memory pressure. |
| `GET` | `/metrics` | `200` | The module's runtime statistics as JSON (see [`GET /metrics`](#get-metrics) below). Budget-exempt, like the probe. |
| `POST` | `/stateful` | `200` | One whole synchronization session (FlatBuffers `Message{FullSession}`). `200` `{"status":"ok"}` means applied AND flushed to the indexer (and scanned, for VD sessions); `{"status":"ok","noop":true}` means everything was filtered. Other statuses: `400` invalid session, `403` identity mismatch, `409` `{"status":"checksum_mismatch"}` for a `ModuleCheck` session (the agent full-resyncs) OR `{"error":"version_mismatch","current_version":N}` for a VDFirst/VDSync session whose `feed_offset` doesn't match this node's current VD feed offset (the agent retries with `current_version`; see [vulnerability-scanner's architecture.md](../vulnerability-scanner/architecture.md#feed-update-rescan-scanvd--rescandisconnectedagents)), `413` the session declares more bytes than the total budget, `500` failed with nothing indexed (including a failed vulnerability scan), `503` not ready / no capacity — with a `Retry-After` header when the CVE feed is still downloading. |
| `POST` | `/_internal/agents/delete` | `200` | Deletes every document of the agent named in the body (`{"agent_id":"7"}`), in two halves: `wazuh-states-*` by delete-by-query (this cluster's scope, deferred to the agent's worker shard so it orders after that agent's in-flight sessions), and the `wazuh-agent-config` / `wazuh-agent-stats` documents by document id, queued on the asynchronous connector that writes them so the deletion orders after a `/config` or `/stats` report that connector has accepted but not yet pushed. `200` `{"status":"ok"}` means the by-query half has run **and flushed**; the by-id half is queued. One documented window can still leave a state document behind — see [Whole-agent deletion semantics](#whole-agent-deletion-semantics). Manager-internal and UDS-local: the only caller is the Task Manager's dispatcher. `400` malformed body or no usable `agent_id`, `503` indexer unavailable or the module is stopping. |
| `POST` | `/_internal/vd/scan` | `200` | On-demand vulnerability rescan of the agent named in the body (`{"agent_id":"7"}`), executed on the VD scan lane. `200` `{"status":"ok"}` means the scan RAN; `{"status":"ok","skipped":true}` means this node runs no vulnerability scanner, which is a completion rather than a failure. Manager-internal and UDS-local: the only caller is the Task Manager's dispatcher. `400` malformed body or no usable `agent_id`, `409` `scan_in_progress` when that agent already has a scan in flight, `404` `agent_not_found`, `500` the scan failed, `503` scan capacity exhausted, the feed is still loading, or the module is stopping. See [On-demand vulnerability scans](#on-demand-vulnerability-scans). |
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
  here, nor in the index template: `wazuh-agent-stats` is mapped `dynamic: true`, so a module or
  metric it does not declare is indexed like any other field rather than rejected.

`400` when the body is not a JSON object, when `modules` is missing, is not an object, is empty, or
holds a module whose body is not an object. The empty case is a rejection on purpose: indexing a
report with no statistics would replace the agent's last good one.

## Request headers

| Header | Required | Meaning |
|---|---|---|
| `X-Wazuh-Agent-Id` | Yes for `/stateful`, `/stats` and `/config` | The agent identity remoted authenticated; the session's own claimed identity must match it, or the answer is `403`. Missing or non-numeric is answered `400`. **Ignored by `/_internal/agents/delete`**, which reads its target from the body — its caller sends no headers of its own. |
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

`POST /_internal/agents/delete` removes every document of one agent across the deletion scope:
`wazuh-states-*`, `wazuh-agent-config` and `wazuh-agent-stats`.

Its caller is the Task Manager's dispatcher, executing a durable `agent_delete_indexer` task that
authd created after removing the agent from `client.keys`. The agent id travels in the **body**, not
in `X-Wazuh-Agent-Id`: the dispatcher POSTs a task row's payload verbatim and sets no headers of its
own, so the header is ignored even when present. Both `{"agent_id":"7"}` and `{"agent_id":7}` are
accepted.

The deletion has **two halves, one per writer**, because a document can only be deleted in order by
the connector that writes it:

| Half | Indices | Mechanism | Ordered against |
|---|---|---|---|
| By query | `wazuh-states-*` | one `deleteByQuery`, cluster-scoped, on the sync connector | that agent's in-flight `/stateful` sessions, by the shard FIFO |
| By document id | `wazuh-agent-config`, `wazuh-agent-stats` | one `bulkDelete` each, queued on the **asynchronous** connector at admission | that agent's `/config` and `/stats` reports, by the queue's FIFO |

The second half is why a report in flight can no longer outlive its agent. Those two documents are
written by `POST /config` and `POST /stats` through the asynchronous connector, which accumulates and
pushes in batches; queueing their deletes on that same queue means a report it had accepted but not
yet pushed is applied *before* the delete that follows it. A by-id delete also resolves against the
live version map, so unlike a search-based one it is unaffected by the index refresh interval. Those
two indices are therefore no longer in the by-query scope at all.

**Answered at completion.** The dispatcher records its task row `completed` on the `200`, so a `200`
meaning "queued" would record a purge that has not happened. What it guarantees: the by-query half ran
and flushed with no per-shard failures or skipped documents, and the by-id half was **queued**.

That second half stays fire-and-forget by construction — the asynchronous connector's FIFO queue is
the only thing that can order those deletes behind a report it has already accepted, and it exposes
nothing to wait on. An index that does not exist counts as success, and deleting a document that is
not there is a no-op, so repeating a deletion is harmless — that is the caller's retry contract, and
this task type has no attempt budget, so it retries until it succeeds.

One window can still leave a document behind, and it does not turn the `200` into a failure.
Repeating the deletion clears it:

- **The index refresh interval, for `wazuh-states-*`.** A delete-by-query is a SEARCH, so it only sees
  refreshed segments. State documents the agent's last session wrote inside that interval are
  invisible to the query, and with the agent gone nothing overwrites them. Refreshing each index first
  would close this, but `_refresh` requires the `indices:admin/refresh` privilege, which the manager's
  least-privilege indexer role does not grant — granting it and restoring the refresh is tracked as a
  follow-up. In practice authd's `authd.purge_delay` (default 120 s) means the refresh has long since
  happened by the time the query runs. The by-id half is not exposed to this window.

## On-demand vulnerability scans

`POST /_internal/vd/scan` rescans one agent. It carries no session and no inventory: the scanner
reads the agent's already-stored packages and writes its findings with its own connector, so the
response is the scan's outcome and nothing more.

Its caller is the Task Manager's dispatcher, executing a durable `vd_scan` task that
`POST /vulnerability-detector/scan` created on the scanner's own socket when an agent noticed the
feed offset had moved. **That admission route is unchanged** — same validation, same readiness
preflight, same `503 scan_queue_full`; what changed is only what it does after admitting.

**Answered at completion.** The task row reads `completed` on the `200`, so a `200` meaning "queued"
would record a scan that has not happened.

**It runs on the same lane as vulnerability-detection sessions**, which is the point. That lane holds
the per-agent exclusion this module shares with its ingestion pipeline, so a scan can never run while
a session of the same agent is mid-apply. A scan started outside this module would be invisible to
that exclusion.

Two statuses are worth calling out:

| Status | Meaning | What the caller does |
|---|---|---|
| `409` `scan_in_progress` | That agent already has a scan in flight | Defers without consuming a retry attempt |
| `404` `agent_not_found` | The agent has no record to scan, most likely deleted between the request and its execution | Stops; retrying cannot produce one |

The `409` exists because a client-side timeout does not cancel server-side work. The dispatcher gives
up at `manager_task_vd_scan_timeout` and re-posts while the first scan is very likely still running;
without the interlock that request would either wait out the transport's backstop or start a second
concurrent scan of the same agent.

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
| `503` | One deliberately GENERIC body for indexer-unavailable / admission-queue-full / shutting-down (which of them fired is an operator concern, not the agent's — the pipeline and VD-capacity gates have their own counters in [`GET /metrics`](metrics.md), `sync.pipeline.shed.total` and `vd.capacity.503.total`; the transport's byte-budget and connection-cap gates are visible only as the `server.*` levels there, plus the logs). The two VD gates are the exception, with reason-specific bodies: `"vulnerability feed not ready"` — the only `503` that carries `Retry-After: <seconds>` — and `"scan capacity exhausted"`. | retries later; on `Retry-After` it re-sends the same session after the delay. |

## `GET /metrics`

The D18 statistics dump. UDS-local like every route here — remoted exposes nothing that reaches
it, so agents cannot read it; the consumers are operators and the benchmark harness:

```bash
curl -s --unix-socket /var/wazuh-manager/queue/sockets/inventory-sync-http.sock http://localhost/metrics
```

```json
{
  "name": "inventory_sync_server",
  "timestamp": "2026-08-06T14:41:07Z",
  "metrics": [
    {"name": "sync.bulk.flushes", "type": "counter", "enabled": true, "value": 41,
     "description": "Successful pipeline group-commit flushes", "unit": "count"},
    {"name": "sync.session.duration.bulk", "type": "histogram", "enabled": true, "value": 41,
     "description": "Enqueue-to-response time of bulk sessions", "unit": "microseconds",
     "summary": {"count": 41, "sum": 5150000, "min": 900, "max": 410000,
                  "p50": 98304, "p90": 229376, "p99": 393216}}
  ]
}
```

Entries are sorted by name and every one carries its `description` and `unit`. Four `type`
strings appear in a real dump: `counter`, `gauge_int` (the shard/lane depth levels), `pull`
(the `server.*` transport levels, read at dump time), and `histogram` — a histogram's `value`
is its observation count and its `summary` carries bucket-resolution percentiles (~12.5%
relative error). The full metric catalog — each metric with the setting it helps size — is in
[Metrics](metrics.md); where each sits in the pipeline is in the
[architecture page](architecture.md#statistics-get-metrics). Counters accumulate for the life
of the process (they survive the module's internal restart retries); there is no reset
endpoint. During shutdown the route itself can answer `503 {"error":"Service
unavailable","code":503}` (the registry is gone); that response is not counted anywhere.

Note it is NOT `POST /stats`: that route is the *ingest* of agent statistics reports, unrelated
to this module's own runtime metrics.

## Status codes

These can be returned on any route, by the transport rather than by a handler:

| Status | Cause |
|---|---|
| `400` | Malformed HTTP, a missing/invalid agent id header, or a body that does not match the route's shape (for `/stats` and `/config`: a non-empty `modules`-keyed object whose every module value is an object — an empty `modules` is rejected on purpose, since indexing a report with nothing to store would replace the agent's last good document; for `/_internal/agents/delete`: an object carrying a usable `agent_id`) |
| `404` | Unknown path |
| `405` | Known path, wrong verb. Carries an `Allow` header listing that path's verbs |
| `411` | Chunked transfer encoding, which is not supported |
| `413` | A body declaring more bytes than the total in-flight budget (or over `max_body_size`, when one is explicitly configured) |
| `414` | Request target over `max_url_size` |
| `431` | A header name or value over its cap, or more than 32 header lines |
| `500` | A route handler threw. The server keeps serving |
| `503` | No healthy indexer host (`/stats`, `/config`), the in-flight byte budget is exhausted, the connection cap is reached, or the module is shutting down |
| `504` | A handler was dispatched but never answered within its response backstop — `response_timeout` server-wide, or the route's own override. The two `_internal` routes raise their own (900 s for the deletion, 450 s for the scan), because their peers wait 600 s and 300 s respectively and the backstop is only meaningful while the peer's deadline is the shorter one |

A `503` is retryable and a `400` is not: validation runs BEFORE the indexer availability check on
purpose, so a malformed document is never masked as a transient failure the agent would retry forever.

## Manual testing

`tools/send_sync.py` in the module's source directory drives every route over the socket at the
transport level (health check, oversized bodies, malformed encodings) but does not build a
route-specific payload. The liveness probe with curl:

```bash
curl --unix-socket /var/wazuh-manager/queue/sockets/inventory-sync-http.sock http://localhost/
```

A `/config` report, simulating what remoted forwards for an authenticated agent:

```bash
curl --unix-socket /var/wazuh-manager/queue/sockets/inventory-sync-http.sock http://localhost/config \
  -X POST -H "Content-Type: application/json" -H "x-wazuh-agent-id: 001" \
  -d '{"modules":{"fim":{"frequency":43200},"logcollector":{"localfile":[{"file":"/var/log/syslog","logformat":"syslog"}]}}}'
```

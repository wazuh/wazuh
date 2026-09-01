# Metrics

The inventory sync server keeps its runtime statistics (D18) in a `wazuh_metrics` registry
(the shared library at `src/shared_modules/metrics/` — the same one remoted's HTTPS agent
server uses) and serves a JSON dump of the whole registry on **`GET /metrics` over its local
socket**, `queue/sockets/inventory-sync-http.sock`. The route is UDS-local (agents can never reach
it — remoted exposes nothing that forwards to it) and **budget-exempt**: reading metrics never
consumes the `server.budget.*` it reports, so it keeps answering exactly when the byte budget
is under pressure. Do not confuse it with `POST /stats`, which is the *ingest* of agent
statistics reports.

Every metric answers a concrete tuning or triage question. This page is the full catalog:
what each metric means, and — where one exists — the internal option to act on. The
**Tuning** column links into the [configuration reference](configuration.md); *diagnostic*
means there is deliberately no setting behind the number (the fix is elsewhere: the indexer,
the vulnerability-detection module, agent-driven volume, or nothing at all).

## Querying

```bash
curl -s --unix-socket /var/wazuh-manager/queue/sockets/inventory-sync-http.sock http://localhost/metrics
```

The dump is one JSON document: an envelope with the daemon name and a UTC timestamp, plus one
entry per metric, sorted by name (compact on the wire; pretty-printed here):

```json
{
  "name": "inventory_sync_server",
  "timestamp": "2026-08-19T14:41:07Z",
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

Reading notes:

- Four `type` strings appear in a real dump: `counter` (cumulative), `gauge_int` (a level the
  workers set — the shard and lane depths), `pull` (a level read at dump time from a live
  component — the `server.*` block), and `histogram` (its `value` is the observation count,
  its `summary` carries bucket-resolution percentiles with ~12.5% relative error, in
  microseconds).
- **Counters accumulate for the life of the process** and survive the module's internal
  restart retries (the registry is created once and never reset). There is no reset endpoint,
  and no rates in the dump: derive events-per-second by diffing counters between polls (the
  in-repo scraper `src/engine/tools/devContainer/scripts/monitor.py` does exactly this).
- **The catalog is dynamic**: the `sync.shard.<i>.*` gauges exist once the pipeline is built
  (one pair per worker), and the seven `server.*` pulls appear only after the transport's
  first successful start. A manager still waiting on its startup gate answers `200` with a
  partial catalog — that is not an error.
- `GET /metrics` itself answers `503` if the registry is gone (module shutting down); that
  response is not counted anywhere.

## Catalog

### Request outcomes — `sync.requests.total.<code>`

What the `/stateful` and agent-deletion handlers answered, one counter per contract status:
`200`, `400`, `403`, `409`, `500`, `503`, plus an `other` catch-all. Every handler-sent
response is counted exactly once, at the site that sends it (the endpoint's inline rejection,
the pipeline worker, or the VD scan lane). All counters, unit `count`.

**There is no `413` cell**: the contract's `413` (declared bytes over the budget) — like every
transport-level answer (`504`, `400` malformed HTTP, `431`, `503` from the connection cap or
byte budget) — is sent by the shared transport before any handler runs and is **not counted
in this family** (see [Accounting boundaries](#accounting-boundaries)).

| Cell | Meaning | Tuning |
|---|---|---|
| `200` | Session applied (or deletion flushed) | — |
| `400` | Malformed session / bad agent-id header | diagnostic — producer-side content |
| `403` | Identity rejection: the session's agent id does not match the authenticated one | diagnostic |
| `409` | Checksum or feed-offset mismatch (the agent retries with a fresh session) | diagnostic |
| `500` | Scan or apply failed server-side | diagnostic — check the indexer and the logs |
| `503` | Shed or unavailable: any of the admission gates | the gate counters below say which: [`…sync_queue_bytes`](configuration.md#wazuh_modulesinventory_sync_server_sync_queue_bytes), [`…vd_scan_queue_slots`](configuration.md#wazuh_modulesinventory_sync_server_vd_scan_queue_slots); transport gates have no counter, only the `server.*` levels |
| `other` | Any status outside the set (structurally zero today) | diagnostic — a bug signal |

### Sync pipeline — `sync.pipeline.*`, `sync.shard.<i>.*`, `sync.session.duration.*`

The sharded ingestion pipeline behind `POST /stateful`: sessions land on
`hash(agentId) % workers`, so per-shard depth/bytes show load skew directly.

| Metric | Type | Unit | Meaning | Tuning |
|---|---|---|---|---|
| `sync.pipeline.shed.total` | counter | count | Enqueue refusals: the pipeline queue **byte** cap was reached (the endpoint answers the 503) | [`…sync_queue_bytes`](configuration.md#wazuh_modulesinventory_sync_server_sync_queue_bytes); drain rate: [`…sync_workers`](configuration.md#wazuh_modulesinventory_sync_server_sync_workers) |
| `sync.shard.<i>.depth` (one per worker) | gauge_int | items | Items queued on shard `i` (sessions **and** deletions ride the same queue) | [`…sync_workers`](configuration.md#wazuh_modulesinventory_sync_server_sync_workers) sets the shard count |
| `sync.shard.<i>.bytes` | gauge_int | bytes | Request payload bytes queued on shard `i` — the sum across shards is the quantity `sync_queue_bytes` caps | [`…sync_queue_bytes`](configuration.md#wazuh_modulesinventory_sync_server_sync_queue_bytes) |
| `sync.session.duration.bulk` | histogram | microseconds | Enqueue-to-response time of bulk sessions, all outcomes (failures included) | [`…sync_workers`](configuration.md#wazuh_modulesinventory_sync_server_sync_workers), [`…indexer_sync_max_bulk_size`](configuration.md#wazuh_modulesinventory_sync_server_indexer_sync_max_bulk_size) (batch hold time), [`…session_query_batch_size`](configuration.md#wazuh_modulesinventory_sync_server_session_query_batch_size) (indexer search pages while draining the session: fewer, larger pages mean fewer round trips per session); bounded by [`…response_timeout`](configuration.md#wazuh_modulesinventory_sync_server_response_timeout) (the transport's 504) |
| `sync.session.duration.immediate` | histogram | microseconds | Same, for immediate (non-batched) sessions — deletions and pre-enqueue rejections are never sampled | as above |

VD data sessions are routed to the scan lane and land in `vd.lane.time`, never in these two
histograms.

### Group commit — `sync.bulk.*`

A worker flushes its open batch when the accumulated **request payload bytes** reach the
group-commit threshold, or when its queue drains. The threshold is fed from the same option as
the connector's own serialized-bulk cap, so
[`…indexer_sync_max_bulk_size`](configuration.md#wazuh_modulesinventory_sync_server_indexer_sync_max_bulk_size)
plays two roles against two **different** byte measures — see its entry in the configuration
reference.

| Metric | Type | Unit | Meaning | Tuning |
|---|---|---|---|---|
| `sync.bulk.flushes` | counter | count | **Successful** pipeline group-commit flushes (immediate-session and lane flushes are not counted here) | [`…indexer_sync_max_bulk_size`](configuration.md#wazuh_modulesinventory_sync_server_indexer_sync_max_bulk_size) |
| `sync.bulk.bytes.total` | counter | bytes | Request payload bytes (wire FlatBuffer size) of the sessions flushed by group commits — NOT the serialized indexer bytes (that is `sync.bytes.ingested`) | as above |
| `sync.bulk.sessions.total` | counter | count | Sessions answered by group-commit flushes | as above |

### Documents — `sync.docs.*`, `sync.bytes.ingested`

Volume actually staged toward the indexer. **Purely diagnostic** (agent-driven volume plus a
fixed allowlist policy — no knob).

| Metric | Type | Unit | Meaning |
|---|---|---|---|
| `sync.docs.indexed` | counter | count | Documents staged into bulk operations — upserts **and** deletes; the by-query paths (cleans, whole-agent deletion, metadata/group updates) count no documents |
| `sync.docs.skipped` | counter | count | Documents dropped by the per-document allowlist policy (bulk path only) |
| `sync.bytes.ingested` | counter | bytes | Serialized document bytes staged for indexing (upserts only; counted at staging, so a later flush failure does not roll it back) |

### Vulnerability-detection lane — `vd.*`

VD data sessions take a dedicated lane: scan first, index only on an OK (or a legitimate
skip). The scan itself is the vulnerability-scanner module's work — its duration and verdicts
are diagnostic **from this module's side**.

| Metric | Type | Unit | Meaning | Tuning |
|---|---|---|---|---|
| `vd.lane.depth` | gauge_int | items | VD sessions queued in the lane | [`…vd_workers`](configuration.md#wazuh_modulesinventory_sync_server_vd_workers) (drain), [`…vd_scan_queue_slots`](configuration.md#wazuh_modulesinventory_sync_server_vd_scan_queue_slots) (cap) |
| `vd.capacity.503.total` | counter | count | VD sessions refused because the scan queue was full (the endpoint answers the 503). **Not** `remoted.scanvd.queue_full`, which remoted raises for the agent-initiated `POST /scan/vd` path on a different socket ([remoted metrics](../remoted/metrics.md#vd-scan-admission--remotedscanvd)) | [`…vd_scan_queue_slots`](configuration.md#wazuh_modulesinventory_sync_server_vd_scan_queue_slots) |
| `vd.lane.time` | histogram | microseconds | Enqueue-to-response time of VD data sessions, **all outcomes** (including the feed-not-ready 503 and offset-mismatch 409) | [`…vd_workers`](configuration.md#wazuh_modulesinventory_sync_server_vd_workers); bounded by [`…response_timeout`](configuration.md#wazuh_modulesinventory_sync_server_response_timeout) |
| `vd.retry_after.total` | counter | count | 503s carrying a `Retry-After` header: the CVE feed was not ready (counted at both gates — strand-side admission and the dispatch-time re-check) | [`…vd_feed_retry_after_seconds`](configuration.md#wazuh_modulesinventory_sync_server_vd_feed_retry_after_seconds) sets the header **value** only — the *rate* is driven by the CVE-feed download state, which this module does not configure |
| `vd.offset_mismatch.total` | counter | count | VD data sessions rejected (409) for a stale or ahead-of-node feed offset | diagnostic — offsets realign as feeds settle |
| `vd.scan.duration` | histogram | microseconds | Time inside the vulnerability scanner (success and throw both sampled) | diagnostic — owned by the vulnerability-scanner module |
| `vd.scans.ok` | counter | count | Scans completed | diagnostic |
| `vd.scans.failed` | counter | count | Scans failed (the scanner threw); the session is answered 500 with nothing indexed | diagnostic |
| `vd.scans.skipped` | counter | count | Scans skipped legitimately (scanner disabled); the inventory is indexed anyway | diagnostic |

### Transport — `server.*`

The shared UDS transport's own backpressure state, published as pull metrics (levels, read at
dump time). These are the only visibility into the two transport-side 503 gates — the byte
budget and the connection caps have **no cumulative shed counter** in this module.

| Metric | Type | Unit | Meaning | Tuning |
|---|---|---|---|---|
| `server.budget.available.bytes` | pull | bytes | Bytes the in-flight payload budget can still admit (`0` also reads while the server is quiesced; an unlimited budget reads as a huge number, not "unlimited") | [`…max_inflight_bytes`](configuration.md#wazuh_modulesinventory_sync_server_max_inflight_bytes) |
| `server.budget.inflight.bytes` | pull | bytes | Bytes currently reserved by admitted requests | as above; per-request size: [`…max_body_size`](configuration.md#wazuh_modulesinventory_sync_server_max_body_size) |
| `server.budget.inflight.requests` | pull | requests | Requests currently holding a budget reservation | as above |
| `server.sessions.live` | pull | connections | Open transport connections, deferred replies included — a **superset**: the three per-class counts below exclude connections still reading their head, so they need not sum to this | [`…max_parallel_connections`](configuration.md#wazuh_modulesinventory_sync_server_max_parallel_connections) |
| `server.sessions.data` | pull | connections | Sessions on data-class routes (`/stateful`, `/stats`, `/config`) | effective cap = `max_parallel_connections` − [`…reserved_control_connections`](configuration.md#wazuh_modulesinventory_sync_server_reserved_control_connections) |
| `server.sessions.control` | pull | connections | Sessions on control-class routes (agent deletion) | [`…control_max_sessions`](configuration.md#wazuh_modulesinventory_sync_server_control_max_sessions) |
| `server.sessions.liveness` | pull | connections | Sessions on liveness-class routes (`GET /`, `GET /metrics`) | diagnostic — the liveness cap is fixed in the shared transport |

## Accounting boundaries

These rules say what sums to what — read them before comparing families:

- **Handler-sent responses only.** `sync.requests.total.*` counts what the `/stateful` and
  deletion handlers (endpoint, pipeline, scan lane) answered. Responses the shared transport
  sends on its own — `413` declared-bytes-over-budget, `503` byte-budget or connection-cap
  shed, `504` response timeout, malformed-HTTP `400`/`431` — appear in **no counter**; the
  transport gates are visible only as the `server.*` levels.
- **Shed counters are cause counters.** `sync.pipeline.shed.total` and
  `vd.capacity.503.total` count the *refusal decision*; the corresponding `503` response is
  counted once by the endpoint. So `sync.requests.total.503 ≥ shed + capacity` (the remainder
  is availability-gate and shutdown 503s).
- **VD data sessions live in the lane's numbers**: their durations are `vd.lane.time`, never
  `sync.session.duration.*`; their documents still count in `sync.docs.*`.
- `/stats`, `/config` and `GET /` have no counters of their own (only one of the module's
  routes — the `/stateful`+deletion plane — is instrumented per-response).
- No rates in the dump: derive them externally by diffing counters per interval.

## See Also

- [Configuration](configuration.md#internal-options) — every
  `wazuh_modules.inventory_sync_server_*` option linked from the Tuning columns above
- [Architecture — Statistics](architecture.md#statistics-get-metrics) — where each metric sits
  in the pipeline narrative
- [API Reference — GET /metrics](api-reference.md#get-metrics) — the route contract
- [Remoted — Metrics](../remoted/metrics.md) — the other side of the same request:
  `remoted.http.stateful.responses.*` counts what the agent got, `sync.requests.total.*`
  counts what this module answered remoted
- Developer-level detail (where each metric is counted, the null-object pattern, invariants):
  `src/wazuh_modules/inventory_sync_server/README.md`, section *Statistics (D18)* (in-repo,
  outside this book)

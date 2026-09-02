# Metrics

The HTTPS agent server (`remoted_module`, the C++ module inside `wazuh-manager-remoted`) keeps
its statistics in a `wazuh_metrics` registry (the shared library at
`src/shared_modules/metrics/` — the same one the inventory sync server uses) and serves a JSON
dump of the whole registry on **`GET /metrics` over the module's local admin socket**,
`queue/sockets/remote-admin-http.sock`. See the admin-socket contract in the
[module overview](README.md#local-admin-socket): the socket is local-only, optional
(a failed bind is a warning, never fatal), and none of this is ever exposed on the public
HTTPS listener. The legacy daemon statistics (`wazuh-manager-remoted.state`, the cluster
daemons-stats API) are a separate, untouched mechanism — see
[Monitoring](configuration.md#monitoring).

Every metric answers a concrete tuning or triage question. This page is the full catalog:
what each metric means, and — where one exists — the configuration setting to act on. The
**Tuning** column links into the [configuration reference](configuration.md); *diagnostic*
means there is deliberately no setting behind the number (the fix is elsewhere: the
downstream service, agent enrollment, deployed content, or nothing at all).

## Querying

```bash
curl --unix-socket /var/wazuh-manager/queue/sockets/remote-admin-http.sock http://localhost/metrics
```

The dump is one JSON document: an envelope with the daemon name and a UTC timestamp, plus one
entry per metric, sorted by name:

```json
{
  "name": "remoted",
  "timestamp": "2026-08-19T12:00:00Z",
  "metrics": [
    {
      "name": "remoted.control.notify",
      "type": "counter",
      "enabled": true,
      "value": 421337,
      "description": "Keepalive (notify) control requests handled",
      "unit": "count"
    },
    {
      "name": "remoted.http.stateless.latency",
      "type": "histogram",
      "enabled": true,
      "value": 98213,
      "description": "POST /stateless end-to-end time, gateway receipt to response delivery",
      "unit": "microseconds",
      "summary": { "count": 98213, "sum": 210394821, "min": 312, "max": 90210,
                   "p50": 1830, "p90": 4110, "p99": 9920 }
    }
  ]
}
```

Reading notes:

- **Counters** are cumulative since the module started, and survive internal HTTP-server
  restart retries. There are no rates in the dump: derive events-per-second externally by
  diffing counters between polls (the in-repo scraper
  `src/engine/tools/devContainer/scripts/monitor.py` does exactly this).
- **Pull metrics** (`"type": "pull"`) are read at dump time from live components. While the
  module is stopped (or a component is torn down) they read `0` — the documented quiesced
  value, not an error.
- **Histograms** carry their distribution in `summary` (values in microseconds); `value` is
  the observation count. Percentiles are log-linear-bucket estimates (~12.5% relative error).

## Catalog

### Public transport backpressure — `remoted.server.budget.*`

The in-flight byte budget of the public HTTPS listener: requests are shed with HTTP 503 *on
the transport's I/O thread, before any route runs*, so budget sheds appear **only** here —
never in the per-endpoint `remoted.http.*.responses.*` cells (see
[Accounting boundaries](#accounting-boundaries)).

| Metric | Type | Unit | Meaning | Tuning |
|---|---|---|---|---|
| `remoted.server.budget.available.bytes` | gauge (pull) | bytes | Bytes the budget can still admit | [`remoted.max_inflight_bytes`](configuration.md#remotedmax_inflight_bytes) |
| `remoted.server.budget.inflight.bytes` | gauge (pull) | bytes | Bytes currently reserved (request payloads plus zstd decompression scratch) | [`remoted.max_inflight_bytes`](configuration.md#remotedmax_inflight_bytes) |
| `remoted.server.budget.inflight.requests` | gauge (pull) | requests | Admitted requests currently resident — exactly one per request, compressed or not | [`remoted.max_parallel_connections`](configuration.md#remotedmax_parallel_connections), [`https.max_body_size`](configuration.md#httpsmax_body_size) |
| `remoted.server.budget.rejected.total` | counter (pull) | requests | Requests the budget refused to admit (503, admission only) — cumulative | [`remoted.max_inflight_bytes`](configuration.md#remotedmax_inflight_bytes) |

Running with `inflight.bytes` near the configured cap at peak, or `rejected.total` moving,
means the budget is the active bottleneck: raise
[`remoted.max_inflight_bytes`](configuration.md#remotedmax_inflight_bytes), or reduce what a
single request may cost ([`https.max_body_size`](configuration.md#httpsmax_body_size)).

### Deferred forwarding — `remoted.forwarder.deferred.*`

The second half of the two-phase backpressure: how many requests are parked awaiting a
downstream service (engine, inventory sync). A limiter shed is the endpoint's own answer, so
it counts **both** here and as that endpoint's `responses.503`.

| Metric | Type | Unit | Meaning | Tuning |
|---|---|---|---|---|
| `remoted.forwarder.deferred.inflight` | gauge (pull) | requests | Requests currently parked awaiting a downstream service | [`remoted.max_deferred_requests`](configuration.md#remotedmax_deferred_requests) |
| `remoted.forwarder.deferred.capacity` | gauge (pull) | requests | The configured slot cap (reads 0 only while the module is stopped) | [`remoted.max_deferred_requests`](configuration.md#remotedmax_deferred_requests) |
| `remoted.forwarder.deferred.rejected.total` | counter (pull) | requests | Requests shed with 503 because every slot was taken — cumulative | [`remoted.max_deferred_requests`](configuration.md#remotedmax_deferred_requests) |

`inflight` pinned at `capacity` with `rejected.total` climbing means either the cap is too
small for the traffic or — more often — the downstream is not keeping up: check the
[downstream failure taxonomy](#downstream-failures--remotedforwarder) before raising the cap.

### Downstream failures — `remoted.forwarder.*`

*Why* forwarded requests fail (the per-endpoint `responses.503` cells say *which* path is
failing; these say why). One aggregate family across all downstream services; each counter
sits at the same classification point as the throttled log line naming the same cause.

| Metric | Type | Unit | Meaning | Tuning |
|---|---|---|---|---|
| `remoted.forwarder.error.connect` | counter | count | Could not connect to the downstream socket (nothing listening) | diagnostic — start/repair the downstream service |
| `remoted.forwarder.error.connect_timeout` | counter | count | The connect deadline elapsed | [`remoted.downstream_connect_timeout`](configuration.md#remoteddownstream_connect_timeout) |
| `remoted.forwarder.error.write_timeout` | counter | count | The request-body write deadline elapsed (peer not reading) | [`remoted.downstream_write_timeout`](configuration.md#remoteddownstream_write_timeout) |
| `remoted.forwarder.error.response_timeout` | counter | count | The post-send response deadline elapsed | [`remoted.downstream_response_timeout`](configuration.md#remoteddownstream_response_timeout), [`remoted.downstream_stateful_response_timeout`](configuration.md#remoteddownstream_stateful_response_timeout) (for `/stateful`) |
| `remoted.forwarder.error.transport` | counter | count | Socket read/write error or unexpected close mid-exchange | diagnostic |
| `remoted.forwarder.error.protocol` | counter | count | The downstream response was not valid HTTP | diagnostic |
| `remoted.forwarder.error.response_too_large` | counter | count | Downstream response body over the cap | [`remoted.downstream_max_response_body_size`](configuration.md#remoteddownstream_max_response_body_size) |
| `remoted.forwarder.downstream_5xx` | counter | count | The downstream answered a 5xx (relayed to the agent as 503) | diagnostic — investigate the downstream service |
| `remoted.forwarder.route_mismatch` | counter | count | The downstream answered 404/405: mismatched route contract (the two sides run different versions/configurations) | diagnostic — align versions |

The three timeouts are sequential phases of one request: their sum must stay inside
[`remoted.http_request_timeout`](configuration.md#remotedhttp_request_timeout), or the HTTP
server cuts the request off before the downstream deadline fires (`remoted` warns at startup
when the deadlines cannot be honored).

### Request outcomes — `remoted.http.<endpoint>.responses.<code>`

What each endpoint actually answered its agents. One family per endpoint — `stateless`,
`stateful`, `stats`, `config` and `enroll` — each with the same closed set of eight status
cells, so a scraper's columns line up across endpoints (some cells are structurally zero for
a given endpoint, e.g. `/stateless` never answers 409). Every response is counted exactly
once, at the single place it is sent. All units are `count`; all are counters.

| Cell (`remoted.http.<endpoint>.responses.` + code) | Meaning | Tuning |
|---|---|---|
| `2xx` | Success (202 for `/stateless`, 200 elsewhere) | — |
| `400` | Client fault: empty body, bad batch, payload-identity mismatch | diagnostic — agent-side content |
| `403` | Identity rejection relayed from the sync server (`/stateful` contract), or enrollment administratively disabled (`/enroll`) | diagnostic — the sync server's own view is [`sync.requests.total.*`](../inventory-sync-server/metrics.md#request-outcomes--syncrequeststotalcode); for `/enroll` see [`remoted.enroll.disabled`](#agent-enrollment--remotedenroll) |
| `409` | Checksum mismatch relayed from the sync server (`/stateful` contract) | diagnostic — same cross-reference as `403` |
| `413` | Body over the accepted size | [`remoted.auth_max_body_size`](configuration.md#remotedauth_max_body_size), [`https.max_body_size`](configuration.md#httpsmax_body_size) |
| `500` | Internal error while building the reply | diagnostic — a bug signal, report it |
| `503` | Downstream failure or a deferred-limiter shed | [`remoted.max_deferred_requests`](configuration.md#remotedmax_deferred_requests) for the limiter share; the [downstream failures](#downstream-failures--remotedforwarder) family for the rest |
| `other` | Any status outside the set above | diagnostic |

Rejections produced by the **auth gateway** (bad MAC, clock skew, oversized body caught at
authentication) happen before any endpoint handler runs and are therefore *not* in these
cells — they are counted, with their cause, in
[`remoted.auth.reject.*`](#authentication-rejections--remotedauthreject).

`/enroll` is the exception to that split: it is not registered through the auth gateway (an
enrolling agent has no `client.keys` entry to authenticate with), so its own handler answers
every rejection and **all** of them land in its cells — including the ones whose cause is
recorded in `remoted.auth.reject.*`. There is no `401` cell in the closed set, so a credential
rejection — the most common `/enroll` failure — is counted in **`other`**; read it together with
`remoted.enroll.rejected_auth`, which counts the same requests by outcome. Its outcome-shaped companion family is
[`remoted.enroll.*`](#agent-enrollment--remotedenroll).

### Request latency — `remoted.http.<endpoint>.latency`

End-to-end request time in microseconds, stamped when the auth gateway picks the request up
and observed when the response is delivered. Only the endpoints whose latency answers a tuning
question carry one; `/stats` and `/config` share `/stateful`'s downstream and would add no new
signal.

| Metric | Type | Unit | Meaning | Tuning |
|---|---|---|---|---|
| `remoted.http.stateless.latency` | histogram | microseconds | The event-ingestion hot path, gateway receipt → response delivery | [`remoted.http_worker_threads`](configuration.md#remotedhttp_worker_threads), [`remoted.http_io_threads`](configuration.md#remotedhttp_io_threads), [`remoted.downstream_post_process_threads`](configuration.md#remoteddownstream_post_process_threads), [`remoted.downstream_io_threads`](configuration.md#remoteddownstream_io_threads) |
| `remoted.http.stateful.latency` | histogram | microseconds | A sync session indexes within the request, so this is the number that sizes its dedicated deadline. The server-side half of the same span is [`sync.session.duration.*`](../inventory-sync-server/metrics.md#sync-pipeline--syncpipeline-syncshardi-syncsessionduration) on the sync server | [`remoted.downstream_stateful_response_timeout`](configuration.md#remoteddownstream_stateful_response_timeout), plus the thread settings above |

| `remoted.http.enroll.latency` | histogram | microseconds | Handler entry → response delivery, the only measurement that spans the hop to `authd`. Timed from handler entry rather than gateway receipt (`/enroll` does not go through the gateway), and it covers the answer authd's callback delivers asynchronously | [`remoted.authd_connect_timeout`](configuration.md#remotedauthd_connect_timeout), [`remoted.authd_response_timeout`](configuration.md#remotedauthd_response_timeout), [`remoted.authd_worker_threads`](configuration.md#remotedauthd_worker_threads) |

All are bounded by
[`remoted.http_request_timeout`](configuration.md#remotedhttp_request_timeout): a p99 creeping
toward that cap predicts request-cutoff failures before they happen.

### Authentication rejections — `remoted.auth.reject.*`

*Why* agents fail authentication, counted with the pre-collapse cause: on the wire the
credential failures deliberately fold into one generic 401 (so a client cannot probe which
check failed), but the operator keeps the distinction here. All counters, unit `count`.

| Metric | Meaning | Tuning |
|---|---|---|
| `remoted.auth.reject.unknown_agent` | The agent id is not in `client.keys` | diagnostic — enroll the agent |
| `remoted.auth.reject.invalid_signature` | The bearer's HS256 signature did not verify with the agent's key (wrong key, or tampering); `/enroll`'s `wazuh-enroll+jwt` failures (wrong password) also land here | diagnostic — re-enroll (agent) or check `authd.pass` (enroll); scanners/noise on exposed listeners also land here |
| `remoted.auth.reject.bad_token` | The bearer is not a well-formed token of the expected profile: size, compact grammar, base64url, JSON, header/claim sets or types, `jti`, structural time rules — including a token of the *other* profile (an agent token on `/enroll`, or vice versa) | diagnostic — a client that is not a 5.x agent, or a broken one |
| `remoted.auth.reject.identity_mismatch` | The token's `sub`/`iss` do not name the agent its `kid` names | diagnostic — a security signal: a forged or hand-assembled token |
| `remoted.auth.reject.clock_skew` | Token outside the accepted time window (too old, expired, or issued in the future) | [`remoted.jwt_max_age`](configuration.md#remotedjwt_max_age), [`remoted.jwt_clock_skew`](configuration.md#remotedjwt_clock_skew) — but fix NTP first |
| `remoted.auth.reject.unusable_key` | The agent's `client.keys` entry does not decode to a usable AES key | diagnostic — re-enroll the agent |
| `remoted.auth.reject.address_not_allowed` | The peer address does not satisfy the agent's [registered address](https-events-api.md#registered-address-ip-column) (`client.keys` `ip` column) | diagnostic — re-enroll the agent with the address it connects from, or with `any` |
| `remoted.auth.reject.enrollment_key_unavailable` | Password-mode `/enroll` could not use the enrollment password key: `etc/authd.pass` missing, unreadable, invalid, or not yet synced to this worker — or the HKDF key derivation unavailable manager-wide. **Not** an agent credential fault: no agent exists yet, so re-enrolling fixes nothing | diagnostic — fix/sync `etc/authd.pass` |
| `remoted.auth.reject.payload_mismatch` | An **authenticated** agent submitted a payload claiming another agent's id — a security signal, not a tuning problem | diagnostic — investigate the agent |
| `remoted.auth.reject.body_too_large` | Body over the authenticated cap, a zstd frame that did not fit the in-flight budget, or (on `/enroll`) a decoded body over that endpoint's own 16 KiB ceiling | [`remoted.auth_max_body_size`](configuration.md#remotedauth_max_body_size); for compressed bodies also [`remoted.max_inflight_bytes`](configuration.md#remotedmax_inflight_bytes) |
| `remoted.auth.reject.bad_encoding` | Unsupported or undecodable `Content-Encoding` (zstd) | [`remoted.http_content_encoding_enabled`](configuration.md#remotedhttp_content_encoding_enabled) |
| `remoted.auth.reject.malformed` | Missing/malformed authorization or protocol-version headers | diagnostic — agent/manager version drift or non-agent traffic |

### Agent enrollment — `remoted.enroll.*`

`POST /enroll` bridges an agent that has no credentials yet to `authd`'s local socket. These
counters say **why** each request ended the way it did; the matching **what** (HTTP status,
latency) is the `enroll` family in [Request outcomes](#request-outcomes--remotedhttpendpointresponsescode)
and [Request latency](#request-latency--remotedhttpendpointlatency). All are counters, unit
`count`, except the three queue pulls at the end.

| Metric | Meaning | Tuning |
|---|---|---|
| `remoted.enroll.accepted` | `authd` created the agent and the key was returned | — |
| `remoted.enroll.rejected_auth` | The enrollment credential check failed (Password mode: the `wazuh-enroll+jwt` bearer; mTLS mode: the listener already refused the connection) | diagnostic — the per-cause split is [`remoted.auth.reject.*`](#authentication-rejections--remotedauthreject) |
| `remoted.enroll.rejected_validation` | Rejected locally before reaching `authd`: undecodable `Content-Encoding`, malformed/invalid body, or a version this manager does not allow | [`remoted.http_content_encoding_enabled`](configuration.md#remotedhttp_content_encoding_enabled); version policy is `<allow_higher_versions>` |
| `remoted.enroll.disabled` | Enrollment is administratively off, so the request was answered `403` without touching `authd` | the manager's enrollment setting (the route always exists, so this is distinguishable from a `404`) |
| `remoted.enroll.authd_error` | `authd` answered, and refused on its own business rules (duplicate name, agent limit, cluster forwarding) | diagnostic — `authd`'s own limits; the mapped status is in the `enroll` response cells |
| `remoted.enroll.authd_unavailable` | No clean answer from `authd`: a full request queue, an unreachable socket, a timeout, or the module shutting down | see the queue metrics below to tell saturation apart from the rest |

The queue in front of `authd` (pulls, so they read as levels):

| Metric | Type | Unit | Meaning | Tuning |
|---|---|---|---|---|
| `remoted.enroll.authd.queue.depth` | gauge (pull) | requests | Enrollment requests waiting for an `authd` worker right now | [`remoted.authd_worker_threads`](configuration.md#remotedauthd_worker_threads) |
| `remoted.enroll.authd.queue.capacity` | gauge (pull) | requests | The configured cap the depth is measured against | [`remoted.authd_max_queue_size`](configuration.md#remotedauthd_max_queue_size) |
| `remoted.enroll.authd.queue.rejected.total` | counter (pull) | requests | Requests refused because that queue was full — cumulative | [`remoted.authd_max_queue_size`](configuration.md#remotedauthd_max_queue_size), [`remoted.authd_worker_threads`](configuration.md#remotedauthd_worker_threads) |

`authd_unavailable` fires for saturation, an unreachable `authd`, a timeout and shutdown alike,
which is why the queue counter exists: **`authd_unavailable` − `queue.rejected.total`** is the
share that raising the queue or the worker count could *not* have fixed. `depth` sitting near
`capacity` at peak is the signal to raise them; `depth` near zero with `authd_unavailable`
moving means `authd` itself is the problem.

### Keystore health — `remoted.auth.keystore.*`

Whether the `client.keys` hot-reload is actually working — the question behind "I re-enrolled
the agent and it still gets 401s". All pulls.

| Metric | Type | Unit | Meaning | Tuning |
|---|---|---|---|---|
| `remoted.auth.keystore.agents` | gauge (pull) | agents | Agents with a usable key after the last successful load | diagnostic — reflects `client.keys` content |
| `remoted.auth.keystore.entries_skipped` | gauge (pull) | entries | Lines that same load could **not** use: bad field count, non-numeric id, an `ip` column that does not parse, or a key that does not decode | diagnostic — each one is logged with its line number; fix the file |
| `remoted.auth.keystore.reloads.total` | counter (pull) | count | Successful loads (startup load included) | [`remoted.keyupdate_interval`](configuration.md#remotedkeyupdate_interval) sets the fallback poll cadence |
| `remoted.auth.keystore.reload_failures.total` | counter (pull) | count | Failed loads: unreadable file, or content that kept changing across every read attempt | diagnostic — fix the file/permissions |

`agents` and `entries_skipped` are **levels describing the file as it stands now**, and they
are read together: an agent that is neither authenticating nor showing up in `agents` is
usually one of the `entries_skipped` lines. Neither equals the number of lines in
`client.keys` — comments, blanks and entries marked as removed are counted by neither, by
design. A *failed* load leaves both levels untouched (the previous table stays in service),
which is why `reload_failures.total` is the metric that tells you a reload was attempted and
lost.

There is no `keystore_refresh_interval` option: the module's refresh cadence is fed by the
pre-existing [`remoted.keyupdate_interval`](configuration.md#remotedkeyupdate_interval)
(see [client.keys hot-reload](https-events-api.md#clientkeys-hot-reload)).

### Control plane — `remoted.control.*`

The `POST /control` pipeline (startup / keepalive / shutdown) and its wazuh-db and
task-manager clients.

| Metric | Type | Unit | Meaning | Tuning |
|---|---|---|---|---|
| `remoted.control.startup` | counter | count | `{"type":"startup"}` messages handled | diagnostic — fleet behavior |
| `remoted.control.notify` | counter | count | Keepalive messages handled | diagnostic — fleet size × keepalive cadence |
| `remoted.control.shutdown` | counter | count | `{"type":"shutdown"}` messages handled | diagnostic |
| `remoted.control.rejected` | counter | count | The endpoint's own 400s (invalid body/JSON/agent-id/type) — an agent/manager version-drift signal | [`agents.allow_higher_versions`](configuration.md#agentsallow_higher_versions) for version drift; otherwise diagnostic |
| `remoted.control.wdb_error` | counter | count | wazuh-db round trips that failed (connect, timeout, queue full) | [`remoted.control_wdb_roundtrip_deadline`](configuration.md#remotedcontrol_wdb_roundtrip_deadline), [`remoted.control_wdb_max_queue_size`](configuration.md#remotedcontrol_wdb_max_queue_size) |
| `remoted.control.wdb.latency` | histogram | microseconds | **Successful** wazuh-db round-trip time (timeouts are counted by `wdb_error`, never observed here — the histogram means "how long a healthy round trip takes") | [`remoted.control_wdb_roundtrip_deadline`](configuration.md#remotedcontrol_wdb_roundtrip_deadline), [`remoted.control_wdb_request_connections`](configuration.md#remotedcontrol_wdb_request_connections) |
| `remoted.control.task_fetch` | counter | count | Pending-task fetches from the task manager that succeeded | — |
| `remoted.control.task_fetch_error` | counter | count | Pending-task fetches that failed | [`remoted.control_tm_deadline`](configuration.md#remotedcontrol_tm_deadline), [`remoted.control_tm_concurrency`](configuration.md#remotedcontrol_tm_concurrency), [`remoted.control_tm_max_queue_size`](configuration.md#remotedcontrol_tm_max_queue_size) |
| `remoted.control.registry.agents` | gauge (pull) | agents | Agents currently tracked by the control registry | diagnostic — the registry TTL (6 h) and eviction cadence (5 min) are compile-time constants, not settings |

### VD scan admission — `remoted.scanvd.*`

`POST /scan/vd` is a synchronous passthrough of the Vulnerability Detection module's own
admission, so this whole family is **diagnostic from remoted's side**: every capacity knob
lives in the VD module, and what became of an accepted scan is VD's to report. All counters,
unit `count`.

| Metric | Meaning |
|---|---|
| `remoted.scanvd.requests.total` | Requests reaching the handler |
| `remoted.scanvd.accepted` | 200: VD queued the scan (it will run) |
| `remoted.scanvd.queue_full` | 503: VD's scan dispatch queue at capacity. **Not** `vd.capacity.503.total`, which the inventory sync server raises for its own VD lane on a different socket ([inventory sync server metrics](../inventory-sync-server/metrics.md#vulnerability-detection-lane--vd)) |
| `remoted.scanvd.indexer_unavailable` | 503: VD reports no healthy indexer host |
| `remoted.scanvd.vd_error` | 503 for any other reason: VD unreachable, not ready, unexpected answer |
| `remoted.scanvd.version_mismatch` | 409: requested feed offset != current offset |
| `remoted.scanvd.invalid_agent` | 400: agent id 0 reached the handler |

### Downloads — `remoted.download.*`

`POST /download` admission outcomes and started transfers. Everything is counted **before**
the streaming pump runs; the per-chunk loop is deliberately uninstrumented.

| Metric | Type | Unit | Meaning | Tuning |
|---|---|---|---|---|
| `remoted.download.rejected` | counter | count | 400: the request did not parse | diagnostic |
| `remoted.download.not_found` | counter | count | 404: the requested group/WPK does not exist — the config-drift signal behind agent retry storms | diagnostic — deploy the missing group/WPK |
| `remoted.download.open_error` | counter | count | 500: the file exists but could not be opened | diagnostic — filesystem/permissions |
| `remoted.download.started` | counter | count | Streamed transfers started | [`remoted.max_parallel_connections`](configuration.md#remotedmax_parallel_connections) is the only bound on concurrent transfers |
| `remoted.download.bytes.total` | counter | bytes | Bytes **offered** to started transfers, counted once at start (an aborted transfer overcounts) | [`remoted.http_stream_chunk_size`](configuration.md#remotedhttp_stream_chunk_size), [`remoted.http_write_timeout`](configuration.md#remotedhttp_write_timeout) |

### Admin transport — `remoted.admin.server.*`

The admin socket's own transport diagnostics (the server dogfooding itself). **Entirely
diagnostic**: its thread count, connection cap and socket path are fixed by design. Both admin
routes are liveness-class, so the budget and the data/control session lanes are structurally
zero — only `sessions.live` and `sessions.liveness` ever move; the full set is published so
every `uds_http_server` consumer reports the same vocabulary.

| Metric | Type | Unit | Meaning |
|---|---|---|---|
| `remoted.admin.server.budget.available.bytes` | gauge (pull) | bytes | Bytes the admin budget can still admit |
| `remoted.admin.server.budget.inflight.bytes` | gauge (pull) | bytes | Bytes reserved by admitted admin requests |
| `remoted.admin.server.budget.inflight.requests` | gauge (pull) | requests | Admin requests holding a reservation |
| `remoted.admin.server.sessions.live` | gauge (pull) | connections | Open admin connections, deferred replies included |
| `remoted.admin.server.sessions.data` | gauge (pull) | connections | Sessions on data-class routes |
| `remoted.admin.server.sessions.control` | gauge (pull) | connections | Sessions on control-class routes |
| `remoted.admin.server.sessions.liveness` | gauge (pull) | connections | Sessions on liveness-class routes |

## Accounting boundaries

These rules say what sums to what — read them before comparing families:

- A request shed by the **byte budget** is refused before any route runs: it appears **only**
  in `remoted.server.budget.rejected.total`, never in a `responses.*` cell. The converse also
  holds: an *admitted* compressed request whose zstd window or decoded output does not fit the
  budget is answered **413** and counted only in `remoted.auth.reject.body_too_large` —
  `budget.rejected.total` is exclusively admission sheds.
- A **deferred-limiter** shed is the endpoint's answer: it counts **both** as that endpoint's
  `responses.503` and in `remoted.forwarder.deferred.rejected.total`.
- **`/enroll` is counted twice on purpose, in two different vocabularies**: once by outcome
  (`remoted.enroll.*` — why it ended that way) and once by HTTP status and latency
  (`remoted.http.enroll.*` — what the agent got, and how long it waited). The two families are
  not summable against each other: a single request contributes exactly one cell to each. Its
  credential failures ALSO appear in `remoted.auth.reject.*`, which is the per-cause split of
  `remoted.enroll.rejected_auth`.
- **Auth-gateway rejections** (401s, 413 at authentication, bad encoding) happen before any
  endpoint handler and appear only in `remoted.auth.reject.*`. A rejection by registered
  address is deliberately indistinguishable on the wire — it collapses into the same generic
  401 as every credential failure, so a caller cannot learn that the agent id exists — which
  makes `remoted.auth.reject.address_not_allowed` the only place it can be told apart. An endpoint's own pre-forward
  rejection (empty body, payload identity) counts in its `responses.*` (the *what*) and, when
  it is an authentication error, in `remoted.auth.reject.*` too (the *why*).
- `remoted.http.<endpoint>.responses.*` therefore reads as "every response this endpoint
  sent", and `remoted.forwarder.*` as "why the forwarded ones failed".
- There are **no rates** in the dump: derive EPS by diffing counters between polls.

## See Also

- [Configuration](configuration.md#internal-options) — every `remoted.*` setting linked from
  the Tuning columns above
- [HTTPS Agent API — Diagnosing rejections and capacity problems](https-events-api.md#diagnosing-rejections-and-capacity-problems)
- [Module overview — Local admin socket](README.md#local-admin-socket)
- Developer-level detail (where each metric is counted, hot-path cost, test coverage):
  `src/remoted/remoted_module/README.md`, section *Metrics catalog* (in-repo, outside this book)

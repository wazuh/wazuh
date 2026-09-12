# Metrics

The HTTPS agent server (`remoted_module`, the C++ module inside `wazuh-manager-remoted`) keeps
its statistics in a `wazuh_metrics` registry (the shared library at
`src/shared_modules/metrics/` — the same one the inventory sync server uses) and serves a JSON
dump of the whole registry on **`GET /metrics` over the module's local admin socket**,
`queue/sockets/remote-admin-http.sock`. See the admin-socket contract in the
[module overview](README.md#local-admin-socket): the socket is local-only, optional
(a failed bind is a warning, never fatal), and none of this is ever exposed on the public
HTTPS listener.

That socket is the **authoritative** surface: it serves the whole registry, always current.
Most of it is also reported remotely through the cluster daemons-stats API, alongside the
legacy daemon counters — see [API projection](#api-projection) below and
[Monitoring](configuration.md#monitoring).

Every metric answers a concrete tuning or triage question. This page is the full catalog:
what each metric means, and — where one exists — the configuration setting to act on. The
**Tuning** column links into the [configuration reference](configuration.md); *diagnostic*
means there is deliberately no setting behind the number (the fix is elsewhere: the
downstream service, agent enrollment, deployed content, or nothing at all).

For the timeout, retry and throttle settings in particular, the number here is only half the
answer: those options pair with a deadline on the agent's side of the same hop, and moving one
alone is what produces duplicate work or stalled uploads.
[Connection timing tuning](timing-tuning.md) has the pairing rules and, in
[§8](timing-tuning.md#8-verifying-a-change), which metric on this page has to move after each
kind of change.

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
  the observation count. Percentiles are log-linear-bucket estimates (~12.5% relative error),
  clamped into the exact `[min, max]` of the same snapshot, so `min <= p50 <= p90 <= p99 <= max`
  always holds within one `summary` and a single observation reports exactly.

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

### TLS listener certificate — `remoted.server.tls.*`

The health of the certificate the HTTPS listener serves. Expiry is evaluated when the listener
starts and once every 24 hours afterwards (each evaluation also re-logs its findings); the leaf is
the certificate loaded when the listener started. `ca_matches_leaf`, on the other hand, is read
from the same place `GET /cacerts` answers from, so the two can never disagree: replacing the CA
file changes both in the next request, without waiting for the daily tick. Both read `0` while the
listener is down — so `ca_matches_leaf` at `0` with the listener **up** is the mismatch signal, and
`GET /cacerts` is answering `503` (see [CA distribution](#ca-distribution--remotedcacerts)).

| Metric | Type | Unit | Meaning | Tuning |
|---|---|---|---|---|
| `remoted.server.tls.cert_expiry_days` | gauge (pull, signed) | days | Whole days until the served certificate's `notAfter`; **negative once expired** (the first 24 h past expiry read `-1`). The only signed value in the catalog — alert on `< 30`, which is also when remoted starts logging a WARN | [`https.certificate`](configuration.md#httpscertificate) — renew the certificate |
| `remoted.server.tls.ca_matches_leaf` | gauge (pull) | flag | `1` when the configured CA signs the served certificate, `0` when it does not **or** could not be read (the log line tells which) | [`https.ca_certificate`](configuration.md#httpsca_certificate) — the CA that must sign [`https.certificate`](configuration.md#httpscertificate) |

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

A slot is held for as long as the downstream deadline allows, so this family is the check on
every timeout increase: raising a `downstream_*` timeout multiplies the occupancy of the same
cap, and a change that fixes `error.response_timeout` while pushing `deferred.rejected.total`
up has only moved the shed from one place to another
([timing tuning §6](timing-tuning.md#6-environment-decisions)).

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

`error.response_timeout` is also the counter to read against the agent's own budget. The body
has already been forwarded by the time this deadline runs, so an agent that gives up first
retries a request the downstream still completes — duplicate work with no dedup on
`/stateless`. Keep the response deadline under the agent's per-request budget for that endpoint
(`agent.https_request_timeout`, 10 s; `agent.https_stateful_timeout`, 90 s) rather than raising
it alone: [timing tuning, invariant 2](timing-tuning.md#3-invariants).

### Request outcomes — `remoted.http.<endpoint>.responses.<code>`

What each endpoint actually answered its agents. Six endpoints carry this family — `stateless`,
`stateful`, `stats`, `config`, `enroll` and `cacerts` (the only `GET` route with this family) — each with the same
closed set of eight status cells, so a scraper's columns line up across endpoints (some cells
are structurally zero for a given endpoint, e.g. `/stateless` never answers 409, and
`/cacerts`'s `404` lands in `other`). Every response is counted exactly once, at the single
place it is sent. All units are `count`; all are counters.

**`/control`, `/download` and `/scan/vd` have no `responses.*` family.** Do not read their absence
as "no traffic": each is counted by outcome instead, in its own family, where the cause is more
useful than the status —
[`remoted.control.*`](#control-plane--remotedcontrol),
[`remoted.download.*`](#downloads--remoteddownload) and
[`remoted.scanvd.*`](#vd-scan-admission--remotedscanvd).

| Cell (`remoted.http.<endpoint>.responses.` + code) | Meaning | Tuning |
|---|---|---|
| `2xx` | Success (202 for `/stateless`, 200 elsewhere) | — |
| `400` | Client fault: empty body, bad batch, payload-identity mismatch | diagnostic — agent-side content |
| `403` | Identity rejection relayed from the sync server (`/stateful` contract), or enrollment administratively disabled (`/enroll`) | diagnostic — the sync server's own view is [`sync.requests.total.*`](../inventory-sync-server/metrics.md#request-outcomes--syncrequeststotalcode); for `/enroll` see [`remoted.enroll.disabled`](#agent-enrollment--remotedenroll) |
| `409` | Checksum mismatch relayed from the sync server (`/stateful` contract) | diagnostic — same cross-reference as `403` |
| `413` | Body over the accepted size | [`remoted.auth_max_body_size`](configuration.md#remotedauth_max_body_size), [`https.max_body_size`](configuration.md#httpsmax_body_size) |
| `500` | Internal error while building the reply | diagnostic — a bug signal, report it |
| `503` | Downstream failure or a deferred-limiter shed | [`remoted.max_deferred_requests`](configuration.md#remotedmax_deferred_requests) for the limiter share; the [downstream failures](#downstream-failures--remotedforwarder) family for the rest |
| `other` | Any status outside the set above. Includes `/enroll` authentication `401`/encoding `415` responses and `/cacerts`'s `404`; other routes' gateway rejections are excluded | [`remoted.http_content_encoding_enabled`](configuration.md#remotedhttp_content_encoding_enabled) for the `415` share, which [`remoted.auth.reject.bad_encoding`](#authentication-rejections--remotedauthreject) counts by cause |

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

Two failure modes are **invisible** to these histograms, so do not read a healthy p99 as proof
the agents are being served. Both are observed at the auth gateway or later, which means:

- A request cut off while its body was still arriving never reaches the gateway. That is
  [`remoted.http_read_timeout`](configuration.md#remotedhttp_read_timeout) (10 s), a total
  deadline on the upload rather than an idle timer, and the connection is simply closed — no
  status, no observation here. On slow links it is the first thing to fail
  ([timing tuning, invariant 3](timing-tuning.md#3-invariants)).
- An agent that abandoned the request is not visible either: the manager finishes it and the
  latency is observed as a success.

### Authentication rejections — `remoted.auth.reject.*`

*Why* agents fail authentication, counted with the fine cause: on the wire a 401 names only its
agent-actionable **class** (`unknown_agent`, `stale_token`, `invalid_signature`, `invalid_request`,
the `token_*` and `enrollment_key_unavailable` of `/enroll` — see the
[HTTPS Agent API](https-events-api.md#error-responses)), which folds several causes together
(`invalid_signature` covers a bad MAC, a malformed token, an identity mismatch, an unusable key and
a disallowed peer address); the operator keeps the distinction here. All counters, unit `count`.

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
| `remoted.auth.reject.token_unknown` | `/enroll` only: an enrollment-token bearer whose `kid` is not in this node's replica of `etc/enrollment_tokens.json`, even after one forced re-read — never minted, minted without a credential, or not yet synchronized to this worker | diagnostic — check the token id the agent was given and, on a worker, that the cluster sync delivered the store ([`remoted.enroll.token_store.tokens`](#agent-enrollment--remotedenroll)) |
| `remoted.auth.reject.token_expired` | `/enroll` only: a correctly signed enrollment-token bearer whose token is past its `expires`. Distinct from `clock_skew`: the credential itself has lapsed, not this request | diagnostic — mint a new token |
| `remoted.auth.reject.token_revoked` | `/enroll` only: a correctly signed enrollment-token bearer whose token the operator revoked | diagnostic — expected after a revocation; a stream of them is an agent (or a leaked token) still trying |

`clock_skew` is the one cell in this family that a timing setting can move, and it fails
*before* any budget in the request path matters: the token profile's lifetime is a fixed 60 s,
so the whole tolerance for host clock drift is
[`jwt_max_age`](configuration.md#remotedjwt_max_age) +
[`jwt_clock_skew`](configuration.md#remotedjwt_clock_skew). A fleet whose clocks drift past it
fails every request with a generic `401` and no other symptom
([timing tuning, invariant 7](timing-tuning.md#3-invariants)).

`/enroll`'s re-enrollment bearers are judged by `authd` on the master, not by this module; its
verdicts still count here under the cause they map to — 9026 (unknown agent or no re-enrollment
credential) in `unknown_agent`, 9027 (invalid credential) in `invalid_signature`, 9028 (outside the
time window) in `clock_skew` — alongside their own `remoted.enroll.reenroll.*` cells below.

### Agent enrollment — `remoted.enroll.*`

`POST /enroll` bridges an agent that has no credentials yet — or one re-enrolling under its
existing id — to `authd`'s local socket. These counters say **why** each request ended the way it
did; the matching **what** (HTTP status, latency) is the `enroll` family in
[Request outcomes](#request-outcomes--remotedhttpendpointresponsescode) and
[Request latency](#request-latency--remotedhttpendpointlatency). All are counters, unit `count`,
except the pulls at the end (the `authd` queue and the token store).

| Metric | Meaning | Tuning |
|---|---|---|
| `remoted.enroll.accepted` | `authd` created the agent (or rotated a re-enrolling agent's credentials) and the key was returned | — |
| `remoted.enroll.rejected_auth` | The enrollment credential check failed — every `401` of the route: the shared-password `wazuh-enroll+jwt` bearer, an enrollment token this node refused (unknown, expired, revoked, bad signature), or a re-enrollment bearer `authd` refused (9026/9027/9028). mTLS failures are not here: the listener already refused the connection | diagnostic — the per-cause split is [`remoted.auth.reject.*`](#authentication-rejections--remotedauthreject); the per-credential split is `remoted.enroll.token.*` / `remoted.enroll.reenroll.*` below |
| `remoted.enroll.rejected_validation` | Rejected locally before reaching `authd`: undecodable `Content-Encoding`, malformed/invalid body, or a version this manager does not allow | [`remoted.http_content_encoding_enabled`](configuration.md#remotedhttp_content_encoding_enabled); version policy is `<allow_higher_versions>` |
| `remoted.enroll.disabled` | Enrollment is administratively off, so the request was answered `403` without touching `authd` | the manager's enrollment setting (the route always exists, so this is distinguishable from a `404`) |
| `remoted.enroll.authd_error` | `authd` answered, and refused on its own business rules (duplicate name, agent limit, cluster forwarding) — including the `403` it gives a verified enrollment token it will not consume (9022 not found or revoked, 9023 expired, 9024 uses exhausted) | diagnostic — `authd`'s own limits; the mapped status is in the `enroll` response cells |
| `remoted.enroll.authd_unavailable` | No clean answer from `authd`: a full request queue, an unreachable socket, a timeout, or the module shutting down | see the queue metrics below to tell saturation apart from the rest |

The **enrollment-token** subset — requests whose bearer's `kid` named an enrollment token — by
what happened to the token (the [HTTPS Agent API](https-events-api.md#enrollment-endpoint-post-enroll)
describes the credential):

| Metric | Meaning | Tuning |
|---|---|---|
| `remoted.enroll.token.accepted` | A `200` obtained with an enrollment token: this node verified the bearer and `authd` consumed one use | — |
| `remoted.enroll.token.rejected_unknown` | The token id is not in this node's replica of the store (never minted, minted without a credential, or not yet synchronized here) — or, rarely, `authd` answered 9022 (not found or revoked) after this node's replica had accepted it | diagnostic — the replica's size is `remoted.enroll.token_store.tokens` below; on a worker, a burst right after a mint means the cluster sync has not landed yet (the forced re-read covers a single lagging request, not a long lag) |
| `remoted.enroll.token.rejected_expired` | The token is past its expiry: decided from the replica (a correctly signed bearer only), or by `authd`'s 9023 when the replica lagged | diagnostic — mint a new token; the agent gets `401 token_expired` from this node or `403` 9023 from `authd` |
| `remoted.enroll.token.rejected_revoked` | The token was revoked: decided from the replica (a correctly signed bearer only) | diagnostic — expected after a revocation |
| `remoted.enroll.token.rejected_exhausted` | `authd` refused the use because the token has no uses left (9024, a `403`) — only `authd` counts uses, so this node cannot decide it earlier | diagnostic — mint a token with more uses, or another one |

The **re-enrollment** subset — requests whose bearer's `kid` named an agent id. This node
forwards that bearer unverified (the secret it is signed with lives only in the master's
database), so every cell is `authd`'s verdict on the master:

| Metric | Meaning | Tuning |
|---|---|---|
| `remoted.enroll.reenroll.accepted` | `authd` verified the bearer and rotated the agent's key and re-enrollment secret in place — same id, nothing removed | — |
| `remoted.enroll.reenroll.rejected_unknown` | 9026: the agent is unknown to the master, or has no re-enrollment secret on record (enrolled over legacy port 1515, or a database rebuilt from `client.keys`) — the agent gets `401 unknown_agent` | diagnostic — such an agent can only enroll anew |
| `remoted.enroll.reenroll.rejected_signature` | 9027: the bearer did not verify against the agent's re-enrollment secret (or was malformed) — the agent gets `401 invalid_signature` | diagnostic — a stale secret on the agent, or probing |
| `remoted.enroll.reenroll.rejected_stale` | 9028: correctly signed but outside the accepted time window — the agent gets `401 stale_token` | [`remoted.jwt_max_age`](configuration.md#remotedjwt_max_age), [`remoted.jwt_clock_skew`](configuration.md#remotedjwt_clock_skew) (`authd` reads the same two) — but fix NTP first |
| `remoted.enroll.reenroll.rejected_in_progress` | 9030: a rotation for that agent is already accepted and not yet persisted — the agent gets `409` and retries, its bearer was fine | — (transient; a sustained count means the writer is not draining, look at wazuh-db) |

The replica of the token store this node authenticates enrollment tokens against (pulls; present
whenever enrollment is enabled, `0` otherwise):

| Metric | Type | Unit | Meaning | Tuning |
|---|---|---|---|---|
| `remoted.enroll.token_store.tokens` | gauge (pull) | tokens | Tokens **with a credential** currently replicated from `etc/enrollment_tokens.json`; credential-less tokens are not replicated (nothing to authenticate with). `0` is the normal state of a manager that has minted no token — and of a worker that has not received the master's sync | diagnostic — a worker stuck at `0` while the master has tokens is a cluster-sync problem |
| `remoted.enroll.token_store.reloads.total` | counter (pull) | count | Successful loads of the store (the startup load included; an absent file counts as a successful, empty load). `authd` rewrites the file on every consumed use, so this moves with enrollment traffic | [`remoted.enroll_password_refresh_interval`](configuration.md#remotedenroll_password_refresh_interval) sets the fallback poll cadence (inotify reacts first) |
| `remoted.enroll.token_store.reload_failures.total` | counter (pull) | count | Loads that kept the **previous** replica: malformed content (the store is written by `authd` and must not be edited by hand), a read that kept changing across every retry, or an unreadable/oversized file | diagnostic — restore the file on the master; the previous replica keeps serving meanwhile, and `GET /status` reports `enrollment_tokens.last_reload_ok: false` |

The three subsets above are read from the admin socket dump; the
[API projection](#api-projection)'s `enrollment` group carries the six outcome counters and the
`authd` queue pulls only.

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

There is no counter for keepalives the throttle suppressed, and none is needed: on a fleet in
steady state the control plane's wazuh-db traffic is almost entirely keepalive writes, so the
ratio between the `remoted.control.notify` rate and the `remoted.control.wdb.latency`
**observation** rate is the throttle's actual suppression factor. It should come out at
[`remoted.control_keepalive_throttle`](configuration.md#remotedcontrol_keepalive_throttle) ÷ the
fleet's `<client><notify_time>` (6× at both defaults); a ratio of 1 means the throttle is at or
below the notify cadence and is suppressing nothing. Startups and shutdowns inflate the
wazuh-db side, so measure it on a fleet that is not restarting
([timing tuning §5](timing-tuning.md#5-per-goal-recipes)).

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
| `remoted.download.denied` | counter | count | 403: the agent asked for a `config` selector that is not its own, or the manager has no established group membership for it (no `/control/startup` yet, or an evicted entry) | **the only signal for a denial** — the event itself is logged at debug, so a rising count with `remoted.debug=0` is all an operator sees. Steady non-zero: an agent using a stale `config_token`, or one probing other groups. Distinct from `rejected` (a malformed request) and from `not_found` (an *entitled* request whose file is not on disk yet) |
| `remoted.download.not_found` | counter | count | 404: the requested group/WPK does not exist — the config-drift signal behind agent retry storms | diagnostic — deploy the missing group/WPK |
| `remoted.download.open_error` | counter | count | 500: the file exists but could not be opened | diagnostic — filesystem/permissions |
| `remoted.download.started` | counter | count | Streamed transfers started | [`remoted.max_parallel_connections`](configuration.md#remotedmax_parallel_connections) is the only bound on concurrent transfers |
| `remoted.download.bytes.total` | counter | bytes | Bytes **offered** to started transfers, counted once at start (an aborted transfer overcounts) | [`remoted.http_stream_chunk_size`](configuration.md#remotedhttp_stream_chunk_size), [`remoted.http_write_timeout`](configuration.md#remotedhttp_write_timeout) |

### CA distribution — `remoted.cacerts.*`

Outcomes of `GET /cacerts`, the unauthenticated route that hands agents the CA that signs the
listener certificate ([`https.ca_certificate`](configuration.md#httpsca_certificate)). The WHY
behind `remoted.http.cacerts.responses.*`; the evaluation that decides the `503` is the
[`remoted.server.tls.*`](#tls-listener-certificate--remotedservertls) pair.

| Metric | Type | Unit | Meaning | Tuning |
|---|---|---|---|---|
| `remoted.cacerts.served` | counter | count | 200: the CA PEM was handed out | — |
| `remoted.cacerts.not_found` | counter | count | 404: the CA file is missing, unreadable or carries no certificate — agents cannot bootstrap trust until it is restored | diagnostic — restore [`https.ca_certificate`](configuration.md#httpsca_certificate) |
| `remoted.cacerts.ca_mismatch` | counter | count | 503: refused because the configured CA does not sign the served certificate | diagnostic — make [`https.ca_certificate`](configuration.md#httpsca_certificate) the CA that signed [`https.certificate`](configuration.md#httpscertificate), then restart |

### Admin transport — `remoted.admin.server.*`

The admin socket's own transport diagnostics (the server dogfooding itself). **Entirely
diagnostic**: its thread count, connection cap and socket path are fixed by design. Both admin
routes are liveness-class, so the budget lanes, the data/control session lanes and
`rejected.budget` with them are structurally zero. What moves is `sessions.live`,
`sessions.liveness` and the rest of the `rejected.*` family; the full set is published so every
`uds_http_server` consumer reports the same vocabulary.

| Metric | Type | Unit | Meaning |
|---|---|---|---|
| `remoted.admin.server.budget.available.bytes` | gauge (pull) | bytes | Bytes the admin budget can still admit |
| `remoted.admin.server.budget.inflight.bytes` | gauge (pull) | bytes | Bytes reserved by admitted admin requests |
| `remoted.admin.server.budget.inflight.requests` | gauge (pull) | requests | Admin requests holding a reservation |
| `remoted.admin.server.sessions.live` | gauge (pull) | connections | Open admin connections, deferred replies included |
| `remoted.admin.server.sessions.data` | gauge (pull) | connections | Sessions on data-class routes |
| `remoted.admin.server.sessions.control` | gauge (pull) | connections | Sessions on control-class routes |
| `remoted.admin.server.sessions.liveness` | gauge (pull) | connections | Sessions on liveness-class routes |
| `remoted.admin.server.rejected.budget` | counter (pull) | requests | Answered `503`: the in-flight byte budget could not admit the request |
| `remoted.admin.server.rejected.session_cap` | counter (pull) | requests | Answered `503`: the request's class session cap was reached |
| `remoted.admin.server.rejected.shutdown` | counter (pull) | requests | Answered `503`: the server was already stopping |
| `remoted.admin.server.rejected.no_response` | counter (pull) | requests | Answered `503`: the handler returned without answering. A handler bug |

The `rejected.*` family is cumulative since start and is the only attributable record of a shed on
this transport: the answer comes from the transport rather than from a handler, so it reaches no
`responses.*` cell, and the throttled WARN in the log reports only the occurrences of its own
window. A throttled line is a floor, not a census: it reports only what is pending when it is
emitted, so a burst that starts and ends inside one window is reported as `1` and the rest is
never printed. Where a cumulative counter exists it is the figure to trust; where it does not, as
with the wazuh-db error throttles in the control plane, the line's own total is all there is and it
under-reports. Three of the four are decided before any route runs; `rejected.no_response` is the
exception, counted after a handler returned without answering.

## API projection

The catalog above is also reported through the server API, so it can be read remotely and per
cluster node without shell access to the admin socket:

```bash
GET /cluster/{node_id}/daemons/stats?daemons_list=wazuh-manager-remoted
```

The flat `remoted.*` names are projected onto a nested object, `metrics.http_server`, beside the
legacy daemon counters that same response has always carried:

```jsonc
{
  "uptime": "2026-08-19T09:12:04Z",
  "timestamp": "2026-08-19T12:00:00Z",
  "name": "wazuh-manager-remoted",
  "metrics": {
    "bytes": { "received": 0, "sent": 0 },   // legacy TCP/UDP channel — see the caveat below
    "tcp_sessions": 0,
    // ... the rest of the legacy counters ...
    "http_server": {
      "timestamp": "2026-08-19T12:00:00Z",
      "responses": {
        "stateless": { "total": 98220, "2xx": 98213, "400": 2, "403": 0, "409": 0,
                       "413": 1, "500": 0, "503": 4, "other": 0 },
        "stateful":  { "...": 0 }, "stats": { "...": 0 },
        "config":    { "...": 0 }, "enroll": { "...": 0 },
        "cacerts":   { "total": 34, "2xx": 34, "...": 0 }
      },
      "latency": {
        "stateless": { "count": 98213, "sum": 210394821, "min": 312, "max": 90210,
                       "p50": 1830, "p90": 4110, "p99": 9920 },
        "stateful": { "...": 0 }, "enroll": { "...": 0 }
      },
      "auth_rejections": { "total": 5, "unknown_agent": 3, "bad_token": 1, "...": 0 },
      "enrollment":      { "accepted": 34, "authd_queue": { "depth": 0, "capacity": 128, "...": 0 } },
      "control":         { "notify": 421337, "registry_agents": 32, "wdb_latency": { "...": 0 } },
      "keystore":        { "agents": 34, "reloads_total": 3, "...": 0 },
      "downstream":      { "errors": { "...": 0 }, "deferred": { "capacity": 512, "...": 0 } },
      "backpressure":    { "available_bytes": 67099136, "inflight_requests": 3, "...": 0 },
      "downloads":       { "started": 12, "bytes_total": 48213004, "...": 0 },
      "tls":             { "cert_expiry_days": 3649, "ca_matches_leaf": 1 },
      "cacerts":         { "served": 34, "not_found": 0, "ca_mismatch": 0 },
      "vd_scan":         { "requests_total": 8, "accepted": 8, "...": 0 }
    }
  }
}
```

The group names map onto the catalog sections above one-for-one:

| API group under `metrics.http_server` | Catalog family |
|---|---|
| `responses.<endpoint>` | [`remoted.http.<endpoint>.responses.<code>`](#request-outcomes--remotedhttpendpointresponsescode), plus a `total` rollup |
| `latency.<endpoint>` | [`remoted.http.<endpoint>.latency`](#request-latency--remotedhttpendpointlatency) |
| `auth_rejections` | [`remoted.auth.reject.*`](#authentication-rejections--remotedauthreject), plus a `total` rollup |
| `enrollment` | [`remoted.enroll.*`](#agent-enrollment--remotedenroll), with `remoted.enroll.authd.queue.*` under `authd_queue` |
| `control` | [`remoted.control.*`](#control-plane--remotedcontrol), with `registry.agents` as `registry_agents` and `wdb.latency` as `wdb_latency` |
| `keystore` | [`remoted.auth.keystore.*`](#keystore-health--remotedauthkeystore) |
| `downstream` | [`remoted.forwarder.*`](#downstream-failures--remotedforwarder), with `error.*` under `errors` and [`deferred.*`](#deferred-forwarding--remotedforwarderdeferred) under `deferred` |
| `backpressure` | [`remoted.server.budget.*`](#public-transport-backpressure--remotedserverbudget) |
| `downloads` | [`remoted.download.*`](#downloads--remoteddownload) |
| `tls` | [`remoted.server.tls.*`](#tls-listener-certificate--remotedservertls) — `cert_expiry_days` is the catalog's one signed integer |
| `cacerts` | [`remoted.cacerts.*`](#ca-distribution--remotedcacerts) |
| `vd_scan` | [`remoted.scanvd.*`](#vd-scan-admission--remotedscanvd) |

Conventions worth knowing before reading a response:

- **`remoted.admin.server.*` is deliberately not projected.** Those metrics
  ([Admin transport](#admin-transport--remotedadminserver)) describe the very socket the API
  reads the dump from; they are only meaningful when queried directly. The admin socket remains
  the only way to see them.
- **The whole `http_server` object is absent when the admin socket cannot be read.** It is
  optional by contract, so its unavailability must not fail the request: the response still
  carries the legacy counters, `total_failed_items` stays `0`, and the API log records a
  warning. An absent object means "could not read", not "nothing to report".
- **An absent field means "not reported", never zero.** Fields, sub-objects and whole groups
  are omitted when the daemon does not report the metric behind them. A zero in the response is
  therefore a real, observed zero — which is what makes the legacy caveat below detectable.
- **The legacy counters are a different channel.** Everything directly under `metrics` counts
  legacy TCP/UDP traffic and stays `0` unless `remote.legacy.enabled` is set. `metrics.bytes`
  and `metrics.tcp_sessions` in particular are **not** the HTTPS figures: the HTTPS transport
  keeps no byte or session counters, so there is nothing to project onto them.
- **Names are flattened with underscores.** A dot inside a leaf name becomes an underscore
  (`reloads.total` → `reloads_total`, `requests.total` → `requests_total`); the dots that
  separate catalog *families* become the object nesting instead.
- **Still no rates.** As with the raw dump, derive per-second figures by diffing between polls.

Field-by-field descriptions are in the API reference: the `WazuhRemotedStatsItem` schema of
`GET /cluster/{node_id}/daemons/stats`.

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
  address is not told apart on the wire — it shares the `invalid_signature` class with a bad
  MAC, a malformed token, an identity mismatch and an unusable key, since none of them is fixed
  by re-enrolling — which makes `remoted.auth.reject.address_not_allowed` the only place it can be told apart. An endpoint's own pre-forward
  rejection (empty body, payload identity) counts in its `responses.*` (the *what*) and, when
  it is an authentication error, in `remoted.auth.reject.*` too (the *why*).
- `remoted.http.<endpoint>.responses.*` therefore reads as "every response this endpoint
  sent", and `remoted.forwarder.*` as "why the forwarded ones failed".
- There are **no rates** in the dump: derive EPS by diffing counters between polls.

## See Also

- [Configuration](configuration.md#internal-options) — every `remoted.*` setting linked from
  the Tuning columns above
- [Connection timing tuning](timing-tuning.md) — how the timeout/retry/throttle settings behind
  these metrics pair with the agent's own, and which metric to watch after changing one
- [HTTPS Agent API — Diagnosing rejections and capacity problems](https-events-api.md#diagnosing-rejections-and-capacity-problems)
- [Module overview — Local admin socket](README.md#local-admin-socket)
- Developer-level detail (where each metric is counted, hot-path cost, test coverage):
  `src/remoted/remoted_module/README.md`, section *Metrics catalog* (in-repo, outside this book)

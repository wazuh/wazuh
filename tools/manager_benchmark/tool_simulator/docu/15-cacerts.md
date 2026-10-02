# 15 — The CA-distribution request (`GET /cacerts`)

`/cacerts` is how a 5.x agent bootstraps trust in its manager: before it holds any credential, it
fetches the CA that signs the manager's HTTPS listener certificate and verifies every later
connection against it. Besides the health probe (`GET /`) and `POST /enroll` (which carries its own
enrollment bearer), it is the one route on the listener that skips the agent authentication
gateway: **no agent bearer, no `protocol-version` header and no body** — by construction, since the
caller has nothing to authenticate with yet.

| | `GET /cacerts` |
|---|---|
| What it carries | Nothing (a body or an `Authorization` header, if sent, is ignored) |
| What it returns | The certificates of the file configured as `remote.https.ca_certificate`, re-serialized by remoted (anything in the file that is not a certificate, a private key included, is never served), with `Content-Type: application/x-pem-file` and a `Wazuh-CA-Generation` header (the bundle's publication generation, `0` when it is not published) |
| Manager-side path | remoted reads the file on every request (bounded to 1 MiB, the parse cached under the file's SHA-256) and judges on that same read, against the current clock, whether the served leaf chains to the bundle (`src/remoted/remoted_module/src/endpoints/cacertsEndpoint.cpp`, `src/remoted/remoted_module/src/http_server/caCertificateSource.hpp`) — no downstream service at all |
| When a real agent does it | Once, on first contact (trust on first use); never to replace a CA it already holds |
| Sender step | `kind: "cacerts"` |

Source of truth: [remoted's https-events-api.md](../../../../docs/ref/modules/remoted/https-events-api.md#ca-certificate-endpoint-get-cacerts)
and the OpenAPI `agent-api.yaml` (`/cacerts`).

## Why it is in the harness

The harness never *uses* the answer: its TLS client skips verification (docu/04), so the PEM is
checked for shape and dropped like every other body (docu/03). Two reasons it still deserves a step:

1. **Contract.** A fleet whose first contact is a `404` (no CA file on the manager) or a `503` (the
   manager refuses to hand out a CA the served certificate does not chain to) cannot bootstrap trust at
   all. `scenarios/cacerts.json` pins that a correctly provisioned manager answers every one of 200
   requests with a PEM.
2. **Cost floor.** It is the cheapest route on the listener — TLS handshake, routing, a small file
   read, no downstream — so its latency is the fixed per-request cost every other route pays on top
   of its own work. A lane of `cacerts` next to a `delta` lane separates the listener's cost from the
   pipeline's.

## Request

```http
GET /wazuh-manager/cacerts HTTP/1.1
```

Nothing else. The global prefix applies like on every route (`--global-prefix`, or the value read
from the manager's configuration); the bare path answers `404`. `Do()` still adds the bearer and
`protocol-version` in agent mode — the route ignores them, so they are harmless and keep the client
uniform. **agent mode only** —
the module's Unix socket has no such route, so a `uds` scenario carrying a `cacerts` step is refused
at load time, exactly like an `engine` or `scan_vd` step. The step takes **only** the timing fields
(`repeat_count`, `repeat_delay`, `initial_delay`); anything describing a payload is a load-time error.

## Responses

| Outcome | Status | Recorded as | Fails the run? |
|---|---|---|---|
| CA served | `200`, `application/x-pem-file`, body with a `-----BEGIN CERTIFICATE-----` block | `cacerts_200` | no |
| No CA to serve: the file was never readable since remoted started, or it now holds no certificate | `404 {"error":"not_found"}` | `cacerts_404` | no |
| The served leaf does not chain to the configured CA (judged against the clock, so an expired CA counts); the manager refuses to hand it out | `503 {"error":"ca_mismatch"}` | `cacerts_503` | no |
| The route's rate limit refused it before the CA was read (`remote.https.cacerts_rate_limit`, `50` req/s for the whole endpoint by default) | `429 {"error":"rate_limited"}` + `Retry-After` | `cacerts_429` | no |
| A `200` without the PEM media type or without a certificate block | `200` | `cacerts_other` | **yes** |
| Any other status | — | `cacerts_other` | **yes** |

`404`, `503` and `429` are **ordinary results**: they are what a real fleet meets against a
misprovisioned or a rate-limited manager, and a scenario's `expected` block decides whether they are
acceptable for the run (`scenarios/cacerts.json` pins `sent` and `s200` at 200 and `other` at 0,
which rules all three out). A file that becomes unreadable after a good read is not a `404`: remoted
keeps serving the last good bundle and logs the read failure.

The `429` deserves its own note, because it is the one an unmodified manager produces against this
scenario: the limit is **per endpoint and fleet-wide**, not per agent, so 20 agents × 10 unpaced
fetches spend the burst (twice the rate) and the rest are refused — by a perfectly healthy manager.
`prepare_manager.sh` therefore sets `cacerts_rate_limit` to `0` ("no limit") by default, so a
capacity run measures the listener's cost instead of the ceiling; `--keep-rate-limits` leaves the
shipped defaults in place to benchmark the limiter itself, and `s429` is then the counter to assert.
Its latency is deliberately **not** in `cacerts_latency_ms_p50/p99`: a refusal never reached the
handler, so its microsecond-scale samples would drag the percentiles away from what a served request
actually costs — the same reason remoted keeps a `429` out of its own histogram. The `other` bucket is different: a `200` that would not let an
agent trust anything means the sender is not talking to remoted's `/cacerts` (a proxy answered, a
prefix mismatch reached something else) and the measurement is invalid (docu/10). The step never
retries, so requests and attempts are the same number.

## Metrics

`cacerts_sent`, `cacerts_200`, `cacerts_404`, `cacerts_503`, `cacerts_429`, `cacerts_other` and
`cacerts_latency_ms_p50/p99` in `bench.csv`; the `cacerts` block of `totals`/`by_fleet`/`by_lane`
and the `cacerts` histogram in `latency_ms` in `sender_summary.json`; the `cacerts` group of
`expected` (`sent`, `s200`, `s404`, `s503`, `s429`, `other`) — see [09](09-metrics-and-output.md) and
[07](07-scenario-schema.md).

On the manager side, the matching families are `remoted.http.cacerts.responses.*` (what it answered),
`remoted.cacerts.{served,not_found,ca_mismatch,rate_limited}` (why) and the `remoted.server.tls.*`
pulls (`cert_expiry_days`, `ca_matches_leaf`) that report the listener certificate's state — all in
remoted's admin `GET /metrics` and scraped by `monitor.py`
([remoted metrics](../../../../docs/ref/modules/remoted/metrics.md#ca-distribution--remotedcacerts)).

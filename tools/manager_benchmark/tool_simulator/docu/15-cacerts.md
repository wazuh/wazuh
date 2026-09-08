# 15 — The CA-distribution request (`GET /cacerts`)

`/cacerts` is how a 5.x agent bootstraps trust in its manager: before it holds any credential, it
fetches the CA that signs the manager's HTTPS listener certificate and verifies every later
connection against it. It is the one route on the listener besides the health probe that carries
**no authentication, no `protocol-version` header and no body** — by construction, since the caller
has nothing to authenticate with yet.

| | `GET /cacerts` |
|---|---|
| What it carries | Nothing (a body or an `Authorization` header, if sent, is ignored) |
| What it returns | The PEM configured as `remote.https.ca_certificate` on the manager, byte for byte, `Content-Type: application/x-pem-file` |
| Manager-side path | remoted reads the file per request and consults the listener's start-time/daily evaluation of whether that CA signs the served certificate (`src/remoted/remoted_module/src/endpoints/cacertsEndpoint.cpp`, `src/http_server/tlsCertificateStatus.cpp`) — no downstream service at all |
| When a real agent does it | Once, on first contact (trust on first use); never to replace a CA it already holds |
| Sender step | `kind: "cacerts"` |

Source of truth: [remoted's https-events-api.md](../../../../docs/ref/modules/remoted/https-events-api.md#ca-certificate-endpoint-get-cacerts)
and the OpenAPI `agent-api.yaml` (`/cacerts`).

## Why it is in the harness

The harness never *uses* the answer: its TLS client skips verification (docu/04), so the PEM is
checked for shape and dropped like every other body (docu/03). Two reasons it still deserves a step:

1. **Contract.** A fleet whose first contact is a `404` (no CA file on the manager) or a `503` (the
   manager refuses to hand out a CA that does not sign its own certificate) cannot bootstrap trust at
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
from the manager's configuration); the bare path answers `404`. `Do()` still adds the bearer in agent
mode — the route ignores it, so it is harmless and keeps the client uniform. **agent mode only** —
the module's Unix socket has no such route, so a `uds` scenario carrying a `cacerts` step is refused
at load time, exactly like an `engine` or `scan_vd` step. The step takes **only** the timing fields
(`repeat_count`, `repeat_delay`, `initial_delay`); anything describing a payload is a load-time error.

## Responses

| Outcome | Status | Recorded as | Fails the run? |
|---|---|---|---|
| CA served | `200`, `application/x-pem-file`, body with a `-----BEGIN CERTIFICATE-----` block | `cacerts_200` | no |
| No CA file on the manager (missing, unreadable, or without a certificate block) | `404 {"error":"not_found"}` | `cacerts_404` | no |
| The configured CA does not sign the listener's certificate; the manager refuses to hand it out | `503 {"error":"ca_mismatch"}` | `cacerts_503` | no |
| A `200` without the PEM media type or without a certificate block | `200` | `cacerts_other` | **yes** |
| Any other status | — | `cacerts_other` | **yes** |

`404` and `503` are **ordinary results**: they are what a real fleet meets against a misprovisioned
manager, and a scenario's `expected` block decides whether they are acceptable for the run
(`scenarios/cacerts.json` says no). The `other` bucket is different: a `200` that would not let an
agent trust anything means the sender is not talking to remoted's `/cacerts` (a proxy answered, a
prefix mismatch reached something else) and the measurement is invalid (docu/10). The step never
retries, so requests and attempts are the same number.

## Metrics

`cacerts_sent`, `cacerts_200`, `cacerts_404`, `cacerts_503`, `cacerts_other` and
`cacerts_latency_ms_p50/p99` in `bench.csv`; the `cacerts` block of `totals`/`by_fleet`/`by_lane`
and the `cacerts` histogram in `latency_ms` in `sender_summary.json`; the `cacerts` group of
`expected` (`sent`, `s200`, `s404`, `s503`, `other`) — see [09](09-metrics-and-output.md) and
[07](07-scenario-schema.md).

On the manager side, the matching families are `remoted.http.cacerts.responses.*` (what it answered),
`remoted.cacerts.{served,not_found,ca_mismatch}` (why) and the `remoted.server.tls.*` pulls
(`cert_expiry_days`, `ca_matches_leaf`) that drive the `503` — all in remoted's admin `GET /metrics`
and scraped by `monitor.py`
([remoted metrics](../../../../docs/ref/modules/remoted/metrics.md#ca-distribution--remotedcacerts)).

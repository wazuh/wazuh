# 16 — Enrolling with an enrollment token (`POST /enroll`)

`/enroll` is how a 5.x agent that has no `client.keys` entry yet obtains one over the same HTTPS
listener it will use for everything afterwards (1517), instead of the legacy plaintext-inside-TLS
protocol on 1515. It is a **bridge to `authd`**: remoted authenticates the request and forwards it
over `authd`'s local socket; `authd` owns every enrollment rule (names, ids, keys, `client.keys`,
cluster forwarding). Three credentials exist; the harness exercises the newest one, the
**enrollment token** (issue #38993): a text the operator mints on the manager
(`wazuh-manager-authd --create-enrollment-token --address <manager>`) and pastes into the agent. It
carries the manager's address, how to trust it (the CA's SPKI pin, or the CA itself) and, unless
minted without a credential, a 16-byte id plus a 16-byte secret. The agent derives the token's
HS256 key from the secret (HKDF-SHA256, `info = "WAZUH-ENROLL-TOKEN-KEY" || 0x01`) and signs a
`wazuh-enroll+jwt` whose header names the id in `kid`; remoted resolves that `kid` in its replica of
`authd`'s token store, verifies the signature, checks the token is neither expired nor revoked, and
forwards the id as `token_id` so `authd` consumes one use.

| | `POST /enroll` (enrollment token) |
|---|---|
| What it carries | `{"name": "<fresh agent name>", "version": "<agent version>"}` and `Authorization: Bearer <wazuh-enroll+jwt with kid = token id>`, `protocol-version: 1` |
| What it returns | `200 {"id","name","ip","key","reenroll_secret"}` — the new agent's record, verbatim from `authd` |
| Manager-side path | `EnrollmentAuthenticator` (token path: `TokenKeySource` replica of `etc/enrollment_tokens.json` → `verifyWithKid` → expiry/revocation) → `AuthdClient` with `token_id` → `authd` `add` (consumes a use, writes `client.keys`) — `src/remoted/remoted_module/src/enrollment/`, `src/os_auth/src/local-server.c` |
| When a real agent does it | Once, on first contact, when the operator handed it a token instead of the shared password |
| Sender step | `kind: "enroll_https"` (measured), and the fleet's own bootstrap (`--bootstrap enroll-token`, setup) |

Source of truth: [remoted's `agent-api.yaml`](../../../../docs/ref/modules/remoted/agent-api.yaml)
(`/enroll`) and the enrollment chapter of `src/remoted/remoted_module/README.md`.

## Why it is in the harness

1. **Contract.** The token path crosses four implementations of the same key derivation and token
   format — `authd` (C), remoted (C++), the agent, and this sender (Go) — pinned by one frozen
   vector set (`internal/wire/testdata/jwt_vectors.json`, `"enroll_token"`). A fleet whose first
   contact is `401` never enrolls at all; `scenarios/enroll_https.json` pins that a token minted on
   the manager enrolls 100 fresh agents with no refusal.
2. **Cost.** Unlike every other route, `/enroll`'s answer waits on `authd`: the hop over its local
   socket, the id assignment, the key generation and the `client.keys` write. `enroll_https` is what
   a fleet's first contact costs the manager, per agent — the number a rollout plan needs.

## The bootstrap and the measured step are the same route, counted apart

This route is how the fleet itself comes into being. `--bootstrap enroll-token` (the DEFAULT, issue
#39054) enrolls every simulated agent here before the run starts and **adopts** the `200` record —
`id`, `key` and `reenroll_secret` — as that agent's identity for the rest of the scenario. That is
what lets the harness run against a manager whose `<use_password>` is the installed default: the
token bearer is verified in every mode, so no `<auth>` flip is needed and `prepare_manager.sh`
changes no policy. `--bootstrap 1515` selects the legacy authd listener instead (`wire.Enroll`,
docu/04), which carries no credential and therefore needs `prepare_manager.sh --open-1515`; it is
kept for comparing the two first-contact paths on one manager, and each run records which it used in
`meta.bootstrap`.

An `enroll_https` STEP is the same request under load, and is counted separately: each repetition
enrolls a NEW name (`<agent name>-tk-<n>`, so `bench-linux-28000-tk-1`…) and records the answer
without adopting the identity it minted — the agent keeps running under the one its bootstrap gave
it. The bootstrap's own requests are **never** recorded in `enroll_https_*`: they are setup, they
happen before the measurement clock starts, and folding one request per agent into those counters
would corrupt both the numbers and any `expected` block over them. Both paths keep the `bench-`
prefix, which is what lets `cleanup_agents.sh` remove everything a run created.

A bootstrap answered anything but `200` fails the run as a setup error (exit 2) naming the remedy:
`401` a token that is unknown, expired or revoked (or a clock outside the window), `403` a token out
of uses, `409` a previous run's agents still registered — `./cleanup_agents.sh`.

## The token is environment config, not scenario content

The token is a credential minted on the manager under test, so it never lives in a committed
scenario file. `prepare_manager.sh` mints one for the fleet and writes it to `.enrollment_token`
(gitignored) next to itself, which `run_benchmark.sh` reads by default; **`--enroll-token-file
<file>`** and the **`WAZUH_ENROLLMENT_TOKEN`** environment variable override that, in that order. A
run that needs a token and has none is refused **before any traffic** (`setup:` error, exit 2), and
so is a token minted without a credential (`--no-credential`: it can pin the CA but cannot
authenticate).

Mint it with enough uses for the run — leave `--max-uses` unset (unlimited), which is what
`prepare_manager.sh` does: the bootstrap consumes one use per agent and
`scenarios/enroll_https.json` another 100 on top. `--address` must be a SAN of the listener
certificate (authd `9025`), but the token's own `adr` is informational to the sender, which targets
`--manager`/`--port` like every other route and skips TLS verification (docu/04).

```bash
sudo ./prepare_manager.sh                     # mints it; run_benchmark.sh finds it
./run_benchmark.sh --scenario scenarios/enroll_https.json --label enroll_https
./cleanup_agents.sh

# or bring your own
sudo /var/wazuh-manager/bin/wazuh-manager-authd --create-enrollment-token --address wazuh-manager --ttl 2h > /tmp/tok.txt
./run_benchmark.sh --scenario scenarios/enroll_https.json --label enroll_https --enroll-token-file /tmp/tok.txt
```

## Request

```http
POST /wazuh-manager/enroll HTTP/1.1
protocol-version: 1
Authorization: Bearer eyJhbGciOiJIUzI1NiIsImtpZCI6IkFBRUNBd1FGQmdjSUNRb0xEQTBPRHciLCJ0eXAiOiJ3YXp1aC1lbnJvbGwrand0In0.…
Content-Type: application/json

{"name":"bench-linux-28000-tk-1","version":"5.0.0"}
```

The bearer is minted fresh per request (`internal/wire/enrolltoken.go`: `SignEnrollWithKid`), header
exactly `{alg, kid, typ}` and claims exactly `{exp, iat, jti, nbf}` — no `iss`/`sub`, there is no
identity yet. No `ip` is sent: the manager resolves it as `any` (or the peer address, if it is
configured with `use_source_ip`). The global prefix applies like on every route. **agent mode only**
— the module's Unix socket has no `/enroll`; a `uds` scenario carrying the step is refused at load
time. The step takes **only** the timing fields; anything describing a payload is a load-time error.

## Responses

| Outcome | Status | Recorded as | Fails the run? |
|---|---|---|---|
| Agent created | `200 {"id","name","ip","key","reenroll_secret"}` | `enroll_https_200` | no |
| The manager refused the bearer: unknown, expired or revoked token; wrong key; clock outside the window | `401` (generic body, `WWW-Authenticate: Bearer`) | `enroll_https_401` | no |
| `authd` refused the use of a bearer remoted had verified: no uses left (`9024`), or revoked/expired between remoted's check and `authd`'s (`9022`/`9023`) | `403 {"error":{"code":902x,…}}` | `enroll_https_403` | no |
| Duplicate name (`9008`) | `409` | `enroll_https_409` | no |
| A `200` without the agent record (or for another name) | `200` | `enroll_https_other` | **yes** |
| Any other status (`400`: the sender built a body remoted rejects; `5xx`) | — | `enroll_https_other` | **yes** |

`401`/`403`/`409` are **ordinary results**: they are what a fleet meets with a stale or exhausted
token, and a scenario's `expected` block decides whether they are acceptable
(`scenarios/enroll_https.json` says no to all three). The `other` bucket is different: the sender is
not exercising the path it claims to, and the measurement is invalid (docu/10). The step never
retries, so requests and attempts are the same number.

## Metrics

`enroll_https_sent`, `enroll_https_200`, `enroll_https_401`, `enroll_https_403`,
`enroll_https_409`, `enroll_https_other` and `enroll_https_latency_ms_p50/p99` in `bench.csv`; the
`enroll_https` block of `totals`/`by_fleet`/`by_lane` and the `enroll_https` histogram in
`latency_ms` in `sender_summary.json`; the `enroll_https` group of `expected` (`sent`, `s200`,
`s401`, `s403`, `s409`, `other`) — see [09](09-metrics-and-output.md) and [07](07-scenario-schema.md).

On the manager side, the matching families are `remoted.http.enroll.responses.*` (what it
answered), `remoted.enroll.*` (why: `accepted`, `rejected_auth`, `authd_error`…), the token
outcomes `remoted.enroll.token.{accepted,rejected_unknown,rejected_expired,rejected_revoked,rejected_exhausted}`,
the per-cause `remoted.auth.reject.token_{unknown,expired,revoked}` cells and the store replica's
health `remoted.enroll.token_store.{tokens,reloads.total,reload_failures.total}` — all in remoted's
admin `GET /metrics` and scraped by `monitor.py`
([remoted metrics](../../../../docs/ref/modules/remoted/metrics.md#agent-enrollment--remotedenroll)).

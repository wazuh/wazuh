# 09 — Metrics and output

**This document is the single source of truth for the sender's artifact formats** (`bench.csv`
and `sender_summary.json`; the rest of a results directory is the orchestration's, see
[the harness README](../../README.md)). The retired simulator
documented its CSV in one place and grew six undocumented columns in another; here the rule is: a
column or field that is not in this document does not exist, and adding one means editing this file
in the same change.

The guiding principle for what to record: **keep everything, judge nothing.** The sender does not
decide whether a run passed — it records every outcome it observed, along every dimension a run
varies (status code, request kind, lane, fleet, over time), so that the operator or F9c-4's report
can slice it however they need. A run's exit code reflects only whether the *measurement itself* is
valid (see [10](10-error-handling-and-shutdown.md)), never a success ratio.

## `bench.csv` — one row per wall-clock second

Header, in this exact order:

```text
timestamp,elapsed_s,mode,agents_active,
sessions_sent,sessions_ok,sessions_noop,sessions_409,sessions_400,sessions_401,sessions_403,sessions_413,sessions_500,sessions_503,sessions_503_retry_after,sessions_other,
stateless_sent,stateless_202,stateless_400,stateless_413,stateless_503,stateless_other,events_sent,
scan_sent,scan_200,scan_409,scan_503,scan_other,
cacerts_sent,cacerts_200,cacerts_404,cacerts_503,cacerts_429,cacerts_other,
enroll_https_sent,enroll_https_200,enroll_https_401,enroll_https_403,enroll_https_409,enroll_https_429,enroll_https_other,
retries_feed,retries_503,retries_exhausted,transport_errors,
bytes_sent,documents_sent,
control_startup_ok,control_startup_err,control_notify_ok,control_notify_err,control_shutdown_ok,control_shutdown_err,
deletes_ok,deletes_err,
session_latency_ms_p50,session_latency_ms_p99,notify_latency_ms_p50,notify_latency_ms_p99,stateless_latency_ms_p50,stateless_latency_ms_p99,
scan_latency_ms_p50,scan_latency_ms_p99,
cacerts_latency_ms_p50,cacerts_latency_ms_p99,
enroll_https_latency_ms_p50,enroll_https_latency_ms_p99
```

- `timestamp` is ISO-8601 UTC with a `Z` (second precision); `elapsed_s` is whole seconds
  (rounded) since the sender started
  (the CSV clock starts before enrollment, unlike `meta.start_time`, which restarts once the fleet
  is authenticated). A final row is written when the run ends. `mode` is the effective mode, and
  `agents_active` the number of agents admitted and not yet finished (`0` while the fleet enrolls).
- Every count column is a **cumulative** counter, monotonically non-decreasing (deltas are the
  consumer's job — that keeps rows independent of sampling jitter).
- `sessions_503_retry_after` is a **subset** of `sessions_503` (the feed-not-ready case, separated
  because it is manager bring-up, not backpressure); `retries_feed` counts the re-sends it caused.
- `retries_503` counts the re-sends of BARE 503s (backpressure), governed by the scenario's
  `defaults.retry` block ([07](07-scenario-schema.md)); `retries_exhausted` counts sessions
  abandoned with their retry budget spent while the server still answered 503. Because every
  attempt is real traffic the server answered, **`sessions_sent` counts attempts**, not logical
  sessions — the logical view is `sessions_sent - retries_feed - retries_503`.
- `sessions_noop` is a subset of `sessions_ok` (`{"status":"ok","noop":true}`).
- `stateless_*` are the engine-stream counters ([13](13-engine-event-streams.md)); `events_sent` is
  the number of `E` lines shipped, distinct from `stateless_sent` (the number of batches).
  `agent`-batching lanes add three counters to the summary's `stateless` block only (not to this
  CSV): `retries` (re-sends of the same batch), `retries_exhausted` (flushes whose try budget ran out,
  the batch staying buffered) and `events_dropped` (events refused by a full buffer); each event
  counts once in `events_sent` however many times its batch is tried.
- `scan_*` are the `POST /scan/vd` counters ([14](14-scan-vd.md)): the feed-update re-scan requests
  a `scan_vd` step sends. `scan_200` counts requests **recorded by VD as a `vd_scan` task** (the
  scan will run), not scans that ran yet — the manager answers at admission and scans afterward, so
  `scan_latency_ms_*` is admission time and NOT a scan duration. `scan_409` (a stale `feed_offset`)
  and `scan_503` (VD did not record it: pending-scan queue full / indexer unavailable / not ready /
  task not recorded / unreachable) are contract outcomes; `scan_other` holds every other status —
  a `400`/`401` there also invalidates the run, anything else is only counted. A `200` whose body is
  not JSON is counted in `scan_200` and invalidates the run. A `scan_vd` step never retries, so
  requests and attempts are the same number here.
- `cacerts_*` are the `GET /cacerts` counters ([15](15-cacerts.md)): the CA-distribution requests a
  `cacerts` step sends. `cacerts_200` counts CA PEMs handed out; `cacerts_404` (the manager has no
  CA file), `cacerts_503` (the manager refused a CA the served certificate does not chain to) and
  `cacerts_429` (the route's own rate limit, `remote.https.cacerts_rate_limit`) are the manager's
  contract outcomes; `cacerts_other` holds a status the contract does not name, which also
  invalidates the run — the `429` has a column of its own so a rate-limited manager is not mistaken
  for one answering something unexpected. A `200` without the PEM media type or without a
  certificate block is counted in `cacerts_200` and invalidates the run. `cacerts_latency_ms_*` is the cost of the
  cheapest route on the listener — TLS plus a file read, no downstream — and **excludes** the `429`s,
  which never reached the handler. A `cacerts` step never retries.
- `meta.bootstrap` is how the fleet obtained its identities: `"enroll-token"` (`POST /enroll` with
  an enrollment token, the default) or `"1515"` (authd's legacy listener) in agent mode, and `""` in
  uds mode, which enrolls nothing. The bootstrap's own requests appear in NO counter: they are setup,
  sent before the measurement clock starts ([16](16-enroll-https.md)).
- `enroll_https_*` are the `POST /enroll` counters of an `enroll_https` STEP ([16](16-enroll-https.md)):
  one fresh agent enrolled per request with the enrollment token's bearer. `enroll_https_200` counts
  agents created; `enroll_https_401` (the manager refused the bearer: unknown, expired or revoked
  token, or a clock/key problem), `enroll_https_403` (authd refused the use of a bearer remoted had
  verified — no uses left, or revoked/expired between the two checks), `enroll_https_409` (a
  duplicate name) and `enroll_https_429` (the route's rate limit,
  `remote.https.enroll_rate_limit`, refused before `authd` was contacted at all) are the manager's
  contract outcomes; `enroll_https_other` holds a status the contract does not name, which also
  invalidates the run. A `200` without the agent record (or naming another agent) is counted in
  `enroll_https_200` and invalidates the run. `enroll_https_latency_ms_*` spans remoted's
  verification, the hop to `authd` and `authd`'s `client.keys` write — a fleet's first-contact cost —
  and **excludes** the `429`s, which paid none of it. The step never retries.
  `prepare_manager.sh` clears both rate limits by default, so these two `429` columns stay at `0`
  unless you pass `--keep-rate-limits` to benchmark the limiter itself.
- `sessions_401` has its own column rather than living in `sessions_other`: a `401` means remoted has
  not loaded that fleet's keys yet, so those requests measured nothing. It also **invalidates the
  run** — a run full of unauthenticated requests must never read as a result.
- `transport_errors` counts requests whose response never arrived (connection refused or closed,
  timeout), on every route except `/control`, never folded into an HTTP bucket and never counted in
  the route's `_sent`. A transport error on a `/control` request is counted in `control_*_err`
  instead.
- `bytes_sent` and `documents_sent` cover `/stateful` sessions only, per attempt (a re-sent session
  counts again). `bytes_sent` counts the WIRE bytes: with zstd it is the compressed size (what the
  manager actually received), not the FlatBuffer's. `meta.compression` records the mode, so a
  with/without pair is comparable at a glance.
- The latency columns are percentiles **over the whole run so far**, so a row is self-contained, in
  milliseconds with one decimal. They come from a log-linear histogram (four buckets per power of
  two, each reported at its midpoint: `internal/metrics/histogram.go`), so they are accurate to
  about 12 %, and `0.0` means no sample yet.
- `control_*` and `deletes_*` count requests by outcome: `_ok` is a `200`, `_err` anything else
  (for `/control`, also a request that got no answer; a delete that got none is a
  `transport_errors`).

This top-level CSV is the aggregate. The per-lane and per-fleet breakdowns below are where a mixed
fleet's detail lives — the CSV would be unreadable with a column per (fleet × lane × status).

## `sender_summary.json`

Abbreviated (`"..."` stands for keys left out):

```json,fragment
{
  "meta": {
    "scenario_name": "mixed_fleet_windows_linux",
    "scenario_path": "/path/to/tools/manager_benchmark/scenarios/mixed_fleet_windows_linux.json",
    "mode": "agent",
    "manager": "127.0.0.1", "port": 1517, "reg_port": 1515,
    "bootstrap": "enroll-token",
    "target": "127.0.0.1:1517",
    "global_prefix": "/wazuh-manager",
    "cluster_name": "cluster01",
    "agents_requested": 100, "agents_enrolled": 100, "agents_failed": 0,
    "concurrent_agents": 0, "requests_per_second_target": 0,
    "keepalive_interval": "10s", "control_enabled": true, "connection_reuse": true,
    "compression": "zstd",
    "document_seed": 1234567,
    "start_time": "2026-08-06T18:00:00Z", "end_time": "2026-08-06T18:05:00Z", "duration_sec": 300.0,
    "sender_version": "dev", "go_version": "go1.26.2"
  },
  "totals": {
    "sessions": { "sent": 240000, "ok": 239880, "noop": 120, "s400": 0, "s403": 0, "s409": 0,
                  "s401": 0, "s413": 0, "s500": 0, "s503": 120, "s503_retry_after": 0, "other": 0,
                  "abandoned_on_drain": 0, "retries_feed": 0, "retries_503": 120,
                  "retries_exhausted": 0, "transport_errors": 0,
                  "bytes_sent": 3145728000, "documents_sent": 12000000 },
    "stateless": { "sent": 6000, "s202": 6000, "s400": 0, "s413": 0, "s503": 0, "other": 0,
                   "events_sent": 1500000, "retries": 0, "retries_exhausted": 0, "events_dropped": 0 },
    "scan": { "sent": 100, "s200": 100, "s409": 0, "s503": 0, "other": 0 },
    "cacerts": { "sent": 100, "s200": 100, "s404": 0, "s503": 0, "s429": 0, "other": 0 },
    "enroll_https": { "sent": 100, "s200": 100, "s401": 0, "s403": 0, "s409": 0, "s429": 0, "other": 0 },
    "control": { "startup_ok": 100, "startup_err": 0, "notify_ok": 1500, "notify_err": 0,
                 "shutdown_ok": 100, "shutdown_err": 0 },
    "deletes": { "ok": 0, "err": 0 },
    "latency_ms": { "session": { "count": 240000, "p50": 4.1, "p99": 31.2, "...": 0 } }
  },
  "throughput": { "sessions_per_second": 800.0, "mib_per_second": 60.0,
                  "documents_per_second": 40000.0, "events_per_second": 5000.0,
                  "achieved_vs_target": null },
  "latency_ms": {
    "session":   { "count": 240000, "p50": 4.1, "p90": 9.0, "p95": 14.0, "p99": 31.2, "max": 210.0, "avg": 6.2 },
    "stateless": { "count": 6000,   "p50": 2.0, "p90": 5.0, "p95": 8.0,  "p99": 20.0, "max": 90.0,  "avg": 3.1 },
    "notify":    { "count": 1500,   "p50": 1.2, "p90": 2.0, "p95": 3.0,  "p99": 5.5,  "max": 18.0,  "avg": 1.5 },
    "startup":   { "count": 100,    "p50": 2.0, "p90": 3.1, "p95": 4.0,  "p99": 6.0,  "max": 9.0,   "avg": 2.2 },
    "shutdown":  { "count": 100,    "p50": 1.5, "p90": 2.4, "p95": 3.0,  "p99": 4.5,  "max": 7.0,   "avg": 1.7 },
    "scan":      { "count": 100,    "p50": 1.0, "p90": 1.8, "p95": 2.2,  "p99": 3.0,  "max": 5.0,   "avg": 1.1 },
    "cacerts":   { "count": 100,    "p50": 0.8, "p90": 1.2, "p95": 1.5,  "p99": 2.0,  "max": 4.0,   "avg": 0.9 },
    "enroll_https": { "count": 100, "p50": 6.0, "p90": 9.0, "p95": 11.0, "p99": 15.0, "max": 30.0,  "avg": 6.5 }
  },
  "by_fleet": {
    "windows": { "sessions": { "sent": 120000, "ok": 119940, "s503": 60, "...": 0 },
                 "stateless": { "sent": 3000, "s202": 3000 },
                 "latency_ms": { "session": { "p50": 4.0, "p99": 30.0 } } },
    "linux":   { "sessions": { "sent": 120000, "ok": 119940, "s503": 60, "...": 0 },
                 "stateless": { "sent": 3000, "s202": 3000 },
                 "latency_ms": { "session": { "p50": 4.2, "p99": 32.0 } } }
  },
  "by_lane": {
    "fim_windows":         { "sessions": { "sent": 60000, "ok": 60000 }, "latency_ms": { "session": { "p50": 3.8, "p99": 22.0 } } },
    "vd_windows":          { "sessions": { "sent": 21000, "ok": 20940, "s503": 60 }, "latency_ms": { "session": { "p50": 5.0, "p99": 80.0 } } },
    "engine":              { "stateless": { "sent": 6000, "s202": 6000, "events_sent": 1500000 }, "latency_ms": { "stateless": { "p50": 2.0, "p99": 20.0 } } },
    "vd_linux":            { "sessions": { "sent": 100, "ok": 100 }, "scan": { "sent": 50, "s200": 50 }, "latency_ms": { "scan": { "p50": 1.0, "p99": 3.0 } } }
  }
}
```

- `totals`, `by_fleet` and `by_lane` carry the **same counter shape**, each with its own
  `latency_ms`, so a consumer parses one structure at three granularities (the example abbreviates
  `by_fleet` and `by_lane`; the real file has every counter in every bucket). Control traffic is
  recorded per fleet but under no lane, and `abandoned_on_drain` in `totals` only.
  `meta.global_prefix` is the normalized prefix (no trailing `/`), and `meta.start_time` is when
  measurement started (after enrollment and the readiness probe). `by_lane` is where the VD lane's `503`s and the engine lane's
  events show up isolated from the FIM lane's clean stream — the whole reason a mixed fleet is worth
  running.
- `latency_ms` carries one histogram per request kind, never one merged number: a notify, a
  1000-document session and an engine batch belong to different distributions. The kinds are
  `session`, `stateless`, `notify`, `startup`, `shutdown`, `scan`, `cacerts` and `enroll_https`,
  each `{count, p50, p90, p95, p99, max, avg}` in milliseconds, and a kind with no
  sample is left out of that bucket. `throughput.sessions_per_second` counts `/stateful` attempts,
  and every `throughput` rate divides by `meta.duration_sec`.
- `throughput.achieved_vs_target` is `null` when `requests_per_second: 0` (unlimited), since there
  is no target to divide by.
- There is **no verdict, no pass/fail, no expected-ratio field by default.** The one opt-in
  exception: a scenario carrying an `expected` block ([07](07-scenario-schema.md)) gets an
  `expected` section in `sender_summary.json` (`passed`, `checked`, `failures[]`) and exit code
  `3` when it fails — over final counters only, never latency or throughput, so the same scenario
  judges the same way on any hardware. Otherwise: `meta.agents_failed` and the
  `transport_errors` total are facts, not judgments; the exit code is set from run-invalidating
  conditions only ([10](10-error-handling-and-shutdown.md)), not from these numbers.
- `meta` (the `Meta` struct in `internal/metrics/summary.go`) holds exactly the keys of the example.
  Notes on a few: `target` is the socket path in `uds` mode; `bootstrap` is `""` in `uds` mode;
  `agents_enrolled` counts identities obtained (synthesized ones in `uds` mode) and
  `agents_failed` is `0` or `1`, since the first failed enrollment aborts the run;
  `keepalive_interval` is the interval the keepalive loop uses — the scenario's value, `"10s"` when
  it is absent or `0` (recorded even when no keepalive ran: see `control_enabled` and `mode`); `compression` is `"zstd"` or `""`; `sender_version` is `dev` unless the binary was built
  with `-ldflags "-X main.senderVersion=<version>"` (the Makefile's `build` target does not set
  it). `meta` does not record the VD worker count (the sender reads no server metric: state it in
  the report from the manager's configuration), `drain_timeout`, `repeat_until`, `--feed-timeout`
  or `--timeout`; the scenario copy and `params.json` that `run_benchmark.sh` writes cover the
  first two, unless `--drain-timeout` overrode the scenario's `drain_timeout`.

## `samples/metrics.ndjson` — the scrape

The sender never scrapes `GET /metrics`: `samples/metrics.ndjson` is written only by the
orchestration (`monitor.py`, or `scrape_metrics.sh` when the monitor cannot run), in the format
defined by `tools/devContainer/scripts/bench_samples.py` and documented in
[the harness README](../../README.md#samplesmetricsndjson-is-the-server-side-artifact).

## Console output

The console is never the primary artifact. The sender prints no progress lines: a header
(`=== benchmark_sender (<version>) ===`, scenario and mode), setup messages, errors on stderr
(`setup: …`, `run invalidated: …`), and a final block (`printFinal()` in
`cmd/benchmark_sender/main.go`) with whether the run was valid (not whether it "passed" — that
distinction is the point):

- `mode=… agents=<enrolled>/<requested> duration=…s` — no achieved rate;
- the session line (sent, ok, noop and each status, `503(retry_after=N)`, other);
- the stateless and `scan/vd` lines when there was any such traffic (the latter with its admission
  p50/p99);
- the control and retry lines when non-zero;
- the session p50/p99 with `transport_errors` and `abandoned`;
- the `expected` verdict (`PASS` or `FAIL` with each failure) when the scenario has one;
- `run: VALID (exit 0)`, `run: VALID, but the scenario's expected block failed (exit 3)` or
  `run: INVALID (measurement not trustworthy) (exit N)`.

There is no `/cacerts` or `/enroll` line; those counters are in the artifacts only.

## What is not measured here

Manager-side resource usage (CPU, RSS, indexer latency) is the orchestration's monitor, not the
sender. The sender **MUST NOT** read the manager's logs or metrics to infer anything: the HTTP
answers to its own requests are the only channel it interprets.

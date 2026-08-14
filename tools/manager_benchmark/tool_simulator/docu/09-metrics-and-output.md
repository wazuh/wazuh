# 09 — Metrics and output

**This document is the single source of truth for the artifact formats.** The retired simulator
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
retries_feed,retries_503,retries_exhausted,transport_errors,
bytes_sent,documents_sent,
control_startup_ok,control_startup_err,control_notify_ok,control_notify_err,control_shutdown_ok,control_shutdown_err,
deletes_ok,deletes_err,
session_latency_ms_p50,session_latency_ms_p99,notify_latency_ms_p50,notify_latency_ms_p99,stateless_latency_ms_p50,stateless_latency_ms_p99,
scan_latency_ms_p50,scan_latency_ms_p99
```

- `timestamp` is ISO-8601 UTC with a `Z`; `elapsed_s` is seconds since the run started.
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
- `scan_*` are the `POST /scan/vd` counters ([14](14-scan-vd.md)): the feed-update re-scan requests
  a `scan_vd` step sends. `scan_200` counts requests the manager **queued**, not scans it ran — it
  answers at admission and scans afterward, so `scan_latency_ms_*` is admission time and NOT a scan
  duration. `scan_409` (a stale `feed_offset`) and `scan_503` (`scan_queue_full`) are contract
  outcomes; `scan_other` holds the `400`/`401` that also invalidate the run. A `scan_vd` step never
  retries, so requests and attempts are the same number here.
- `sessions_401` has its own column rather than living in `sessions_other`: a `401` means remoted has
  not loaded that fleet's keys yet, so those requests measured nothing. It also **invalidates the
  run** — a run full of unauthenticated requests must never read as a result.
- `transport_errors` counts responses that never arrived (connection closed, read timeout), never
  folded into an HTTP bucket.
- `bytes_sent` counts the WIRE bytes: with `compression: "zstd"` it is the compressed size (what
  the manager actually received), not the FlatBuffer's. `meta.compression` records the mode, so a
  with/without pair is comparable at a glance.
- The latency columns are percentiles **over the whole run so far**, so a row is self-contained.

This top-level CSV is the aggregate. The per-lane and per-fleet breakdowns below are where a mixed
fleet's detail lives — the CSV would be unreadable with a column per (fleet × lane × status).

## `sender_summary.json`

```json
{
  "meta": {
    "scenario_name": "mixed_fleet_windows_linux",
    "scenario_path": "scenarios/mixed_fleet_windows_linux.json",
    "mode": "agent",
    "manager": "127.0.0.1", "port": 1517, "reg_port": 1515,
    "cluster_name": "cluster01",
    "agents_requested": 100, "agents_enrolled": 100, "agents_failed": 0,
    "concurrent_agents": 0, "requests_per_second_target": 0,
    "keepalive_interval": "10s", "control_enabled": true, "connection_reuse": true,
    "document_seed": 1234567,
    "server_vd_workers": 1,
    "start_time": "2026-08-06T18:00:00Z", "end_time": "2026-08-06T18:05:00Z", "duration_sec": 300.0,
    "sender_version": "<git describe>", "go_version": "go1.22.x"
  },
  "totals": {
    "sessions": { "sent": 240000, "ok": 239880, "noop": 120, "s400": 0, "s403": 0, "s409": 0,
                  "s401": 0, "s413": 0, "s500": 0, "s503": 120, "s503_retry_after": 0, "other": 0,
                  "abandoned_on_drain": 0 },
    "stateless": { "sent": 6000, "s202": 6000, "s400": 0, "s413": 0, "s503": 0, "other": 0,
                   "events_sent": 1500000 },
    "scan": { "sent": 100, "s200": 100, "s409": 0, "s503": 0, "other": 0 },
    "control": { "startup_ok": 100, "startup_err": 0, "notify_ok": 1500, "notify_err": 0,
                 "shutdown_ok": 100, "shutdown_err": 0 },
    "deletes": { "ok": 0, "err": 0 }
  },
  "throughput": { "sessions_per_second": 800.0, "mib_per_second": 60.0,
                  "documents_per_second": 40000.0, "events_per_second": 5000.0,
                  "achieved_vs_target": null },
  "latency_ms": {
    "session":   { "count": 240000, "p50": 4.1, "p90": 9.0, "p95": 14.0, "p99": 31.2, "max": 210.0, "avg": 6.2 },
    "stateless": { "count": 6000,   "p50": 2.0, "p90": 5.0, "p95": 8.0,  "p99": 20.0, "max": 90.0,  "avg": 3.1 },
    "notify":    { "count": 1500,   "p50": 1.2, "p90": 2.0, "p95": 3.0,  "p99": 5.5,  "max": 18.0,  "avg": 1.5 },
    "startup":   { "count": 100,    "p50": 2.0, "p90": 3.1, "p95": 4.0,  "p99": 6.0,  "max": 9.0,   "avg": 2.2 },
    "scan":      { "count": 100,    "p50": 1.0, "p90": 1.8, "p95": 2.2,  "p99": 3.0,  "max": 5.0,   "avg": 1.1 }
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

- `totals`, `by_fleet` and `by_lane` carry the **same counter shape**, so a consumer parses one
  structure at three granularities. `by_lane` is where the VD lane's `503`s and the engine lane's
  events show up isolated from the FIM lane's clean stream — the whole reason a mixed fleet is worth
  running.
- `latency_ms` **MUST** carry one histogram per request kind, never one merged number: a notify, a
  1000-document session and an engine batch belong to different distributions.
- `throughput.achieved_vs_target` is `null` when `requests_per_second: 0` (unlimited), since there
  is no target to divide by.
- There is **no verdict, no pass/fail, no expected-ratio field by default.** The one opt-in
  exception: a scenario carrying an `expected` block ([07](07-scenario-schema.md)) gets an
  `expected` section in `sender_summary.json` (`passed`, `checked`, `failures[]`) and exit code
  `3` when it fails — over final counters only, never latency or throughput, so the same scenario
  judges the same way on any hardware. Otherwise: `meta.agents_failed` and the
  `transport_errors` total are facts, not judgments; the exit code is set from run-invalidating
  conditions only ([10](10-error-handling-and-shutdown.md)), not from these numbers.
- `meta` **MUST** record everything needed to reproduce the run: the document seed, the effective
  pacing, `connection_reuse`, and `server_vd_workers` read from `GET /metrics` when available (the
  VD worker count changes what the lane numbers mean).

## `server_metrics.csv` — the scrape

The sender **MAY** scrape `GET /metrics` (F9a) itself in `uds` mode; in `agent` mode the socket may
not be reachable from where the sender runs, and the orchestration's monitor does it (F9c-3). One
row per scrape, long format so a new metric never breaks a parser:

```text
timestamp,elapsed_s,<metric-name>,<value>
```

Histograms contribute one row per summary field, named `<metric>.p50`, `<metric>.p99`,
`<metric>.count`, `<metric>.sum`.

## Console output

Progress lines **SHOULD** be one per second, compact, and **MUST NOT** be the primary artifact. The
final block **MUST** print: mode, achieved rate, the session, stateless and `/scan/vd` status
distributions (the last two only when the run produced any), the session p50/p99, and whether the
run was valid (not whether it "passed" — that distinction is the
point). Enough that a run can be judged from the terminal, with the files for the detail.

## What is not measured here

Manager-side resource usage (CPU, RSS, indexer latency) is the orchestration's monitor, not the
sender. The sender **MUST NOT** read the manager's logs to infer anything: the HTTP answers and
`/metrics` are the only channels it interprets.

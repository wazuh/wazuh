# 10 — Error handling and shutdown

The governing principle: **the sender never hides a problem to keep a run going, and it never judges
a run's outcome.** A benchmark that retries its way past failures reports throughput it did not
achieve, and a spurious error that gets swallowed is exactly the kind of bug this tooling is meant
to surface (F9b found a real server-side race precisely because an unexplained disconnect was
treated as a failure, not noise). At the same time, a `503` under saturation or a `409` on a
checksum is a *result to record*, not a failure — so the sender separates two ideas cleanly:

- **run-invalidating conditions** set a non-zero exit code, because they mean the measurement itself
  is not trustworthy (the sender is misconfigured, or the manager is unreachable);
- **everything else is data**: recorded in full ([09](09-metrics-and-output.md)), never turned into
  a verdict. There is no success-ratio threshold and no expected-status list; a scenario says what
  to send, not what should come back.

## Error matrix

| Condition | Classification | Sender behavior | Invalidates the run? |
|---|---|---|---|
| Enrollment refused by authd | Setup error | Report authd's own answer verbatim, abort before sending load | **Yes**, immediately |
| Scenario validation error (unknown field, bad reference) | Setup error | Refuse to start, naming the field | **Yes**, before any traffic |
| `401` on any request | Sender bug (signing/clock) | Abort with the canonical string and timestamp used, for diagnosis | **Yes**, immediately |
| `400` from `/control` (any subtype) | Sender bug | Abort naming the subtype (`invalid_json`, `invalid_version`, `invalid_host_info`, …) | **Yes**, immediately |
| `400`/`403` from `/stateful` on a normal step | Sender bug | Abort: a correct sender never produces these on a `delta`/`cleans`/`checksum` step | **Yes** |
| `400`/`403`/`413` from a `raw` or deliberately-oversized step | Expected result of that step | Count in its bucket; continue | No |
| `409` checksum mismatch (`ModuleCheck`) | Result | Count; no implicit resync | No |
| `409` version_mismatch (VDFirst/VDSync, stale `feed_offset`) | Result | Count; no implicit re-request. A normal VD scenario run with a correct `-vd-feed-offset`/learned offset never produces this — only `contract_vd_version_mismatch` deliberately does | No |
| `413` from a normal step | Result (budget contract) | Count; never split or retry | No |
| `500` | Server failure | Count and report prominently; no retry | No — recorded, not judged |
| `503` **with** `Retry-After` | Manager bring-up (feed) | Honor the header, then re-send, bounded by `--feed-timeout`; count each re-send as `retries_feed`, a spent budget as `retries_exhausted`. For a VDFirst/VDSync step this is a re-ENCODE, not a byte-identical resend: `Start.feed_offset` is refreshed from the current value first, so a feed that finishes loading mid-wait doesn't turn into a version_mismatch `409` on the attempt that would otherwise have landed `200` | No — the exhaustion is a counter (assertable via `expected`), not an abort |
| `503` **without** `Retry-After` | Backpressure | Count; re-send the same buffer per the scenario's `retry` block (default on, 500ms, 10 attempts — what a real agent does), counting `retries_503` and, on a spent budget, `retries_exhausted`. Shed-counting scenarios disable it | No |
| `202` / `400` / `413` / `503` from `/stateless` | Result | Count in the `stateless_*` buckets; `400` on a normal engine step is a sender bug and aborts | `400` normal → yes; else no |
| Connection closed with no response | Transport error | Count in `transport_errors`, never as an HTTP bucket; keep the connection's context in the log | **Yes** past the threshold (default 0 in `uds` mode; configurable) |
| Read/write timeout | Transport error | Same; the per-request timeout **MUST** exceed the server's response timeout so a slow answer is not misread as a hang | As above |
| Keepalive failure (non-`401`) | Result | Count `control_notify_err`, keep the loop running | No (unless a configured threshold is crossed) |
| Indexer down mid-run | Result | Manifests as `503`s; count and report | No |

The exit code is `0` when the run completed and nothing invalidated it — **regardless of how many
`503`s or `409`s were recorded**. It is `1`/`2` only for the "Yes" rows above, and `3` when the
measurement is valid but the scenario's opt-in `expected` block failed ([07](07-scenario-schema.md)).
This is the whole difference from a conformance checker: the sender guarantees the *numbers are
real*, not that they are *good* — unless the scenario explicitly says what "good" means.

Every retry attempt (either 503 flavor) takes a `requests_per_second` token before sending: a retry
is traffic the server must answer, so it is paced like any other request, and `sessions_sent`
counts attempts.

Any abort **MUST** still write the artifacts collected so far and print the summary: a failed run's
data is usually the most interesting.

## Timeouts

| Timeout | Default | Rule |
|---|---|---|
| Per-request (`/stateful`) | 120 s | **MUST** be greater than the server's `response_timeout` (300 s default is deliberately larger; the sender's value is a run-level choice and **MUST** be recorded) so that a slow flush reads as slow, not as a hang |
| Per-request (`/control`) | 30 s | Control answers are short; a slow one is a finding |
| Enrollment | 30 s | Per agent |
| `--feed-timeout` | 300 s | Total budget for feed-not-ready retries of one session |
| `--drain-timeout` | 60 s | See below |

## Shutdown and drain

SIGINT/SIGTERM and reaching the scenario's end both mean the same thing — drain — and the sequence
is identical:

1. **Stop admitting**: no new steps, no new agents, keepalive tickers stopped.
2. **Let in-flight land**, bounded by `--drain-timeout`. Sessions still outstanding when it expires
   are counted as `abandoned_on_drain` and reported; they are neither successes nor server failures.
3. **`shutdown` per agent** (`agent` mode), best-effort and counted. A failure here does not fail the
   run: the manager answers `200` before it updates state anyway.
4. **Flush artifacts**, print the summary, exit with the verdict's code.

A second signal during drain **MUST** abort immediately, flushing whatever is in memory: an operator
pressing Ctrl-C twice wants out, not a longer wait.

The sender **MUST NOT** clean up the enrolled fleet: removing agents is the orchestration's job
(F9c-3), and a sender that deletes agents on exit makes a crashed run impossible to inspect.

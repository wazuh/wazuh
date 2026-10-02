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
| Enrollment refused (`POST /enroll` answered other than `200`, or authd refused on 1515) | Setup error | Report the manager's own answer verbatim — with what the status calls for — and abort before sending load | **Yes**, immediately (exit `2`) |
| Scenario validation error (unknown field, bad reference) | Setup error | Refuse to start, naming the field | **Yes**, before any traffic (exit `2`) |
| No enrollment token when the run needs one, or a token without a credential | Setup error | Refuse to start, saying how to get one | **Yes**, before any traffic (exit `2`) |
| remoted still answers `401` when the readiness budget runs out | Setup error | Abort, telling the operator to raise `--enroll-settle` | **Yes** (exit `2`) |
| `401` on a `/stateful`, `/control`, `/scan/vd` or `/cacerts` request | Sender bug (signing/clock) or keys not loaded | Abort with the manager's answer. **Not implemented:** the canonical signing input and the timestamp used are not printed | **Yes**, immediately (exit `1`) |
| `401` on a measured `enroll_https` step | Result | Count `enroll_https_401` (an unknown, expired or revoked token is a contract outcome there) | No |
| Any non-`200` from `/control` `startup` or `notify` (`400` subtypes, `409 invalid_version`, a wazuh-db `503`) | Sender bug or setup error | Abort with the status and body | **Yes**, immediately (exit `1`) |
| `400`/`403` from `/stateful` on a normal step | Sender bug | Abort: a correct sender never produces these on a `delta`/`cleans`/`checksum` step. **Not implemented:** the sender counts them (`sessions_400`/`sessions_403`) and carries on; only an `expected` block can turn them into a failure | **Yes** as designed; no as implemented |
| `400`/`403`/`413` from a `raw` or deliberately-oversized step | Expected result of that step | Count in its bucket; continue | No |
| `409` checksum mismatch (`ModuleCheck`) | Result | Count; no implicit resync | No |
| `409` version_mismatch (VDFirst/VDSync, stale `feed_offset`) | Result | Count; no implicit re-request. A normal VD scenario run with a correct `-vd-feed-offset`/learned offset never produces this — only `contract_vd_version_mismatch` deliberately does | No |
| `413` from a normal step | Result (budget contract) | Count; never split or retry | No |
| `500` | Server failure | Count and report prominently; no retry | No — recorded, not judged |
| `503` **with** `Retry-After` | Manager bring-up (feed) | Honor the header, then re-send, bounded by `--feed-timeout`; count each re-send as `retries_feed`, a spent budget as `retries_exhausted`. For a VDFirst/VDSync step this is a re-ENCODE, not a byte-identical resend: `Start.feed_offset` is refreshed from the current value first, so a feed that finishes loading mid-wait doesn't turn into a version_mismatch `409` on the attempt that would otherwise have landed `200` | No — the exhaustion is a counter (assertable via `expected`), not an abort |
| `503` **without** `Retry-After` | Backpressure | Count; re-send the same buffer per the scenario's `retry` block (default on, 500ms, 10 attempts — what a real agent does), counting `retries_503` and, on a spent budget, `retries_exhausted`. Shed-counting scenarios disable it | No |
| `202` / `400` / `413` / `503` from `/stateless` | Result | Count in the `stateless_*` buckets; `400` on a normal engine step is a sender bug and aborts | `400` normal → yes; else no |
| `400` from `/scan/vd`; an answer outside the contract from `/cacerts` or a measured `/enroll` (including a `200` without a PEM or without the agent record) | Sender bug | Count in the step's `other` bucket, then abort | **Yes** (exit `1`) |
| `409`/`503` from `/scan/vd`; `404`/`503`/`429` from `/cacerts`; `403`/`409`/`429` from `/enroll` | Result | Count in the step's own bucket | No |
| Connection closed with no response | Transport error | Count in `transport_errors`, never as an HTTP bucket. **Not implemented:** the connection's context is not logged | **Yes** in `uds` mode, on any occurrence (exit `1`). In `agent` mode, no. The design's configurable threshold does not exist |
| Read/write timeout | Transport error | Same; the per-request timeout **MUST** exceed the server's response timeout so a slow answer is not misread as a hang | As above |
| Keepalive failure | Result | Count `control_notify_err`, keep the loop running. **Not implemented as written:** that holds only for a transport error; a `notify` answered with any non-`200` status aborts the run (row above) | No for a transport error |
| Indexer down mid-run | Result | Manifests as `503`s; count and report | No |

The exit code is `0` when the run completed and nothing invalidated it — **regardless of how many
`503`s or `409`s were recorded**. It is `2` for a setup error (bad flags or scenario, no token,
failed enrollment, the readiness probe) and `1` for a run invalidated while it ran (the "Yes" rows
above), and `3` when the measurement is valid but the scenario's opt-in `expected` block failed
([07](07-scenario-schema.md)). The `expected` block is evaluated only when the exit code would
otherwise be `0`.
This is the whole difference from a conformance checker: the sender guarantees the *numbers are
real*, not that they are *good* — unless the scenario explicitly says what "good" means.

Every retry attempt (either 503 flavor) takes a `requests_per_second` token before sending: a retry
is traffic the server must answer, so it is paced like any other request, and `sessions_sent`
counts attempts.

Any abort **MUST** still write the artifacts collected so far and print the summary: a failed run's
data is usually the most interesting. A run invalidated while it ran (exit `1` or `3`) does: the
CSV writer and `sender_summary.json` are written before the exit. A setup error after the CSV is
created (exit `2` from the runner) still writes both, with zero counters. A scenario or flag error
exits before either file is created.

## Timeouts

| Timeout | Default | Rule |
|---|---|---|
| Per-request (`--timeout`) | 120 s | One value for every request, enrollment included (HTTP client timeout; for the 1515 bootstrap, the dial and the connection deadline). **MUST** be greater than the server's response timeout so that a slow flush reads as slow, not as a hang. **Not met by default:** the inventory sync server's response backstop is 300 s (`response_timeout`), above the sender's 120 s. Raise `--timeout` for runs where a session can legitimately take that long. The value is not recorded in `meta` |
| Per-request (`/control`) | 30 s | Control answers are short; a slow one is a finding. **Not implemented:** `/control` uses the same `--timeout` |
| Enrollment | 30 s | Per agent. **Not implemented:** enrollment uses the same `--timeout` |
| `--feed-timeout` | 300 s | Total budget for feed-not-ready retries of one session, from its first attempt |
| Drain | 60 s | `--drain-timeout` when set (> 0), else `pacing.drain_timeout` in the scenario, else the default; see below |
| Readiness | 30 s | `--enroll-settle` (12 s default) with a 30 s floor; see [06](06-agent-state-machine.md) |

## Shutdown and drain

SIGINT/SIGTERM and reaching the scenario's end both mean the same thing — drain — and the sequence
is identical:

1. **Stop admitting**: no new steps, no new agents, keepalive tickers stopped.
2. **Let in-flight land**, bounded by the drain window (`--drain-timeout`, else
   `pacing.drain_timeout`). Requests still outstanding when it expires are counted as `abandoned_on_drain` and reported; they are neither
   successes nor server failures.
3. **`shutdown` per agent** (`agent` mode), best-effort and counted. A failure here does not fail the
   run: the manager answers `200` before it updates state anyway.
4. **Flush artifacts**, print the summary, exit with the verdict's code.

A second signal during drain **MUST** abort immediately, flushing whatever is in memory: an operator
pressing Ctrl-C twice wants out, not a longer wait. **Not implemented:** the sender catches
SIGINT/SIGTERM with `signal.NotifyContext` and keeps catching them until it returns, so a second
signal does nothing and the drain window runs to its end.

The sender **MUST NOT** clean up the enrolled fleet: removing agents is the orchestration's job
(F9c-3), and a sender that deletes agents on exit makes a crashed run impossible to inspect.

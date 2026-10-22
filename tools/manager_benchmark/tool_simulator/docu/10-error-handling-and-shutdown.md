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
  a verdict. There is no success-ratio threshold; a scenario says what to send, and only its
  optional `expected` block says what should come back ([07](07-scenario-schema.md#expected-optional-verdict)).

## Error matrix

The run-invalidating decisions are `runner.fatalf()` (first error wins, cancels the run) and the
checks at the end of `Run()` in `internal/runner/runner.go`; setup errors return `2` before any load.

| Condition | Classification | Sender behavior | Invalidates the run? |
|---|---|---|---|
| Bad flag value (`--bootstrap`, `--compression`), missing `--scenario`, unreadable `--enroll-token-file` | Setup error | Refuse to start, naming it | **Yes**, before any traffic (exit `2`) |
| Scenario validation error (unknown field, kind or `option`, bad mode/kind combination, missing referenced file, bad `expected` block) | Setup error | Refuse to start, naming the field | **Yes**, before any traffic (exit `2`) |
| No enrollment token when the run needs one, or a token that does not parse or carries no credential | Setup error | Refuse to start, saying how to get one | **Yes**, before any traffic (exit `2`) |
| Enrollment refused (`POST /enroll` answered other than `200`, a `200` without the agent record, or authd's `ERROR` on 1515) | Setup error | Report the manager's own answer — with the remedy the status calls for — and abort before sending load | **Yes**, immediately (exit `2`) |
| The readiness probe still answered `401` when its budget ran out, or answered anything else but `200` | Setup error | Abort, telling the operator to raise `--enroll-settle` (for the `401`) | **Yes** (exit `2`) |
| `401` on a `/stateful`, `/control`, `/scan/vd` or `/cacerts` request | Sender bug (signing/clock) or keys not loaded | Record it, abort with the manager's answer (the signing input and timestamp are not printed) | **Yes** (exit `1`) |
| `401` on a measured `enroll_https` step | Result | Count `enroll_https_401` (an unknown, expired or revoked token is a contract outcome there) | No |
| Any non-`200` from `/control` `startup` or `notify` (`400` subtypes, `409 invalid_version`, a wazuh-db `503`), a non-JSON `200`, or a transport error on `startup` | Sender bug or setup error | Abort with the status and body; a `startup` is counted in `control_startup_err`, a `notify` is not counted | **Yes** (exit `1`) |
| Transport error on a `notify` | Result | Count `control_notify_err`, keep the loop running | No |
| Any answer to `shutdown` | Result | Count `control_shutdown_ok`/`_err`, latency in the `shutdown` histogram | No |
| `400`/`403` from `/stateful` | Result (a sender bug on a normal step, the point of a `raw` step) | Count `sessions_400`/`sessions_403` and carry on; only an `expected` block can turn them into a failure | No |
| `409` checksum mismatch (`ModuleCheck`) | Result | Count; no implicit resync | No |
| `409` version_mismatch (VDFirst/VDSync, stale `feed_offset`) | Result | Count; no implicit re-request. A normal VD scenario run with a correct `--vd-feed-offset`/learned offset never produces this — only `contract_vd_version_mismatch` deliberately does | No |
| `413` from `/stateful` | Result (budget contract) | Count; never split or retry | No |
| `500` | Server failure | Count; no retry | No — recorded, not judged |
| `503` **with** `Retry-After` | Manager bring-up (feed) | Honor the header (1–30 s), then re-send, bounded by `--feed-timeout`; count each re-send as `retries_feed`, a spent budget as `retries_exhausted`. For a VDFirst/VDSync step this is a re-ENCODE, not a byte-identical resend: `Start.feed_offset` is refreshed from the current value first, so a feed that finishes loading mid-wait doesn't turn into a version_mismatch `409` on the attempt that would otherwise have landed `200` | No — the exhaustion is a counter (assertable via `expected`), not an abort |
| `503` **without** `Retry-After` | Backpressure | Count; re-send the same buffer per the scenario's `retry` block (default on, 500 ms, 10 attempts — what a real agent does), counting `retries_503` and, on a spent budget, `retries_exhausted`. Shed-counting scenarios disable it | No |
| Any other `/stateful` status | Sender bug or server regression | Count `sessions_other` | No |
| `400` from `/stateless` | Sender bug (no scenario sends a bad batch on purpose) | Count `stateless_400`, abort | **Yes** (exit `1`) |
| `202` / `413` / `503` / any other status from `/stateless` | Result | Count in the `stateless_*` buckets, never retry | No |
| `400` from `/scan/vd`, or a `200` whose body is not JSON | Sender bug | Count (`scan_other` / `scan_200`), then abort | **Yes** (exit `1`) |
| A `/cacerts` or measured `/enroll` status outside the contract, or a `200` without the PEM / without the agent record | Sender bug, or not talking to remoted's route | Count (`_other` / `_200`), then abort | **Yes** (exit `1`) |
| `409`/`503`/other from `/scan/vd`; `404`/`503`/`429` from `/cacerts`; `403`/`409`/`429` from `/enroll` | Result | Count in the step's own bucket | No |
| A `dump` that exists but cannot be decoded | Setup error found mid-run | Abort when a step first loads it (nothing is sent for that step) | **Yes** (exit `1`) |
| An `engine` sample file that cannot be read (or is empty) | — | The step sends nothing and nothing is reported; check `events_sent` | No |
| Connection closed with no response, or a timeout | Transport error | Count in `transport_errors`, never as an HTTP bucket and never retried (the connection's context is not logged) | **Yes** in `uds` mode, on any occurrence (exit `1`). In `agent` mode, no — assert it in `expected` |
| Indexer down mid-run | Result | Manifests as `503`s; count and report | No |

The exit code is `0` when the run completed and nothing invalidated it — **regardless of how many
`503`s or `409`s were recorded**. It is `2` for a setup error (the first five rows, plus a
`--output` file that cannot be created), `1` for a run invalidated while it ran (the other "Yes"
rows), and `3` when the measurement is valid but the scenario's opt-in `expected` block failed
([07](07-scenario-schema.md#expected-optional-verdict)). The `expected` block is evaluated only when
the exit code would otherwise be `0`. This is the whole difference from a conformance checker: the
sender guarantees the *numbers are real*, not that they are *good* — unless the scenario explicitly
says what "good" means.

Every retry attempt (either 503 flavor) takes a `requests_per_second` token before sending: a retry
is traffic the server must answer, so it is paced like any other request, and `sessions_sent`
counts attempts.

A run that got as far as creating `bench.csv` still writes both artifacts and prints the final
block whatever its exit code: an invalidated run (exit `1`), a failed `expected` block (exit `3`),
and a setup error raised by the runner (token, enrollment, readiness probe: exit `2`, with zero
counters). A flag or scenario error, or a `--output` that cannot be created, exits before either
file is written. A summary that cannot be written is a warning, not a different exit code.

## Timeouts

| Timeout | Default | Rule |
|---|---|---|
| Per-request (`--timeout`) | 120 s | One value for every request — sessions, `/stateless`, `/control`, `/scan/vd`, `/cacerts`, `/enroll`, deletes, and the 1515 bootstrap's dial and connection deadline. It should exceed the server's response time so that a slow flush reads as slow, not as a hang: the inventory sync server's own backstop is 300 s (`response_timeout`), so a `uds` run whose sessions can legitimately take that long needs a larger `--timeout`. The value is not recorded in `meta` |
| `--feed-timeout` | 300 s | Total budget for feed-not-ready retries of one session, from its first attempt |
| First-notify wait | 30 s | How long a VD session or `scan_vd` step waits for its agent's first `notify` to report an offset ([05](05-flatbuffers-messages.md#start)) |
| Drain | 60 s | `--drain-timeout` when set (> 0), else `pacing.drain_timeout` in the scenario, else the default; see below |
| Readiness | 30 s | `--enroll-settle` (12 s default) with a 30 s floor; see [06](06-agent-state-machine.md) |

## Shutdown and drain

SIGINT/SIGTERM, reaching `repeat_until`, and the first run-invalidating error all cancel the run's
context and start the same drain ([06](06-agent-state-machine.md#drain)); a one-pass run whose
agents all finish needs none:

1. **Stop starting work**: no further agent is admitted (one still waiting for a
   `concurrent_agents` slot never starts), and every lane stops at its next step, repetition or
   delay; requests already on the wire finish with their answer or `--timeout`.
2. **`shutdown` per agent** (`agent` mode with control), sent by each agent once its lanes have
   returned, after its keepalive loop stops; best-effort and counted. A failure here does not fail
   the run: the manager answers `200` before it updates state anyway.
3. **Let in-flight land**, bounded by the drain window. Requests (other than `/control`) still
   outstanding when it expires are counted as `abandoned_on_drain` and reported; they are neither
   successes nor server failures.
4. **Flush artifacts**, print the final block, exit with the code above.

The signals are caught with `signal.NotifyContext` for the whole run, so a second SIGINT during the
drain has no further effect: the drain window runs to its end.

The sender **MUST NOT** clean up the enrolled fleet: removing agents is the orchestration's job
(F9c-3), and a sender that deletes agents on exit makes a crashed run impossible to inspect.

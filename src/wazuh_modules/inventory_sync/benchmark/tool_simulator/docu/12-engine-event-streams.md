# 12 — Engine event streams

A second payload type the Go sender supports (the Python sender does not).
Where inventory_sync sessions push FlatBuffer messages prefixed with
`s:<module_id>:`, an **engine event stream** reads a text file line by
line and emits one frame per line, prefixed with `1:<location>:`.

The transport is identical (same TCP socket to remoted, same AES + zlib
+ length-prefix wrap, same per-agent enrolment and AES key derivation).
Only the inner identifier blob changes.

## When to use

- Generating load against the manager's event ingestion path
  (`wazuh-engine`, formerly `analysisd`) without spinning up real
  agents.
- Stressing the manager's decoder/rule pipeline with a known corpus of
  log lines (apache, syslog, sshd, etc.).
- Mixed workloads: an agent can run an inventory_sync lane AND an engine
  stream lane in parallel from the same socket.

## Wire format

```
identifier_blob = "1:" + <location> + ":" + <line>
```

`<line>` is the file's line with the trailing `\n` stripped. The blob is
fed to `wire.EncodeText(aesKey, agentID, identifier_blob)` — the rest of
the stack (MD5 + zlib + Wazuh pad + PKCS#7 + AES + length prefix) is the
same as inventory_sync. See [05-wire-protocol.md](./05-wire-protocol.md).

The leading `1` is the queue byte — what the manager's
[eventParser.cpp](../../../../../engine/source/base/src/eventParser.cpp)
extracts as `/wazuh/protocol/queue` (ASCII 49 = `'1'`). It is hard-coded;
exposing it as a per-step setting is a follow-up.

## Scenario schema

A step with an `engine` key is mutually exclusive with `kind` and `dump`:

```json
{
  "engine":   "sample_payloads/engine/syslog.log",
  "location": "syslog",
  "max_eps":  500,
  "loop":     true,
  "duration": 5.0,
  "run_while_siblings_active": true
}
```

| Field                       | Required | Default                         | Description                                                                                 |
| --------------------------- | -------- | ------------------------------- | ------------------------------------------------------------------------------------------- |
| `engine`                    | yes      | —                               | Path to the input text file. Resolved relative to the scenario file, then the benchmark dir. |
| `max_eps`                   | yes      | —                               | Per-stream rate cap. `0` is rejected for engine streams (there is no point in unbounded).   |
| `location`                  | no       | basename(`engine`) sans ext     | Logical location string sent as the `<location>` field of the frame.                        |
| `loop`                      | no       | `true`                          | At EOF: rewind and continue (`true`) or end the iteration (`false`).                        |
| `duration`                  | no       | `0` (no limit)                  | Upper bound on the engine step's wall-clock runtime, in seconds. `0` = no limit. See termination semantics below. |
| `run_while_siblings_active` | no       | `false`                         | When `true`, the engine source terminates as soon as every non-engine lane on the same agent finishes. Requires at least one non-engine lane in the fleet — see Validation. |

`initial_delay` and `repeat_delay` apply the same way as inventory_sync
steps. **`repeat_count` is restricted to `1` for engine steps** — the engine
controls its own iteration through `loop` + `duration`, and nesting both
mechanisms would produce ambiguous deadlines.

### Termination semantics

An engine step's `Run()` returns once **any** of the following fires
(whichever-first composition). The exit reason is recorded in a one-line
info log at the end of the step:

```
engine step terminated: file=<basename> location=<loc> reason=<reason> events_sent=<N> elapsed=<T>s
```

| reason       | Trigger                                                                                          |
| ------------ | ------------------------------------------------------------------------------------------------ |
| `eof`        | End-of-file was hit and `loop=false`.                                                            |
| `duration`   | The `duration` deadline elapsed (only set if `duration > 0`).                                    |
| `siblings`   | The per-agent non-engine sibling counter dropped to 0 (only set if `run_while_siblings_active`). |
| `ctx`        | The outer context (SIGINT / `repeat_until` / orchestrator cancel) was cancelled.                 |

The two new terminators are designed to compose: a step can set both
`duration` and `run_while_siblings_active` — `duration` then acts as a
safety upper bound in case siblings somehow never finish. When neither is
set and `loop=true`, the step runs until `ctx` is cancelled (the legacy
behavior).

The sibling counter is **per-agent, per-iteration**: a lane is counted
as a sibling iff it contains at least one non-engine step. The runner
pre-increments the counter before launching any lane goroutine, and
each non-engine lane decrements it on exit via `defer`. Engine sources
that opted in poll the counter every 20 events (cheap atomic load).

### Forbidden fields (per-step)

These are inventory-sync-only and the loader rejects them when `engine`
is set explicitly on the step itself:

`session_type`, `sync_mode`, `data_size`, `use_databatch`, `retransmit`,
`payload_size`, `pad_field`, `modulecheck_checksum`, `auto_resync`,
`module`, `index`, `option`.

### Defaults inheritance

The scenario-wide `defaults` block is merged into every step before
loading. To make mixed scenarios (engine + inventory lanes) ergonomic,
the loader **strips inventory-only fields from `defaults` before merging
into an engine step**. The stripped set is the union of the forbidden
fields above plus the inventory-only retry/timeout knobs
(`offline_retry`, `offline_retry_delay`, `start_ack_timeout`,
`end_ack_processing_timeout`, `end_ack_timeout`, `ack_timeout_retry`,
`ack_timeout_retry_delay`, `post_data_delay`).

The result: a scenario can keep one rich `defaults` block that applies
to its inventory lanes, and the engine lanes ignore the inapplicable
keys silently. Step-local overrides on an engine step still win over
defaults (because they ride in the step's own map, not the filtered
defaults).

### Validation

In addition to the field-level rules above, the loader rejects:

- `repeat_count > 1` on an engine step (use `loop` + `duration` instead).
- `duration < 0`.
- A fleet that uses an engine step with `run_while_siblings_active=true`
  but contains no lane with at least one non-engine step. Without a
  sibling, the counter would either start at 0 (engine exits before
  emitting anything) or never decrement, neither of which is useful.

## Concurrency model

- One goroutine per `engine` step per agent. Multiple lanes on the same
  agent can each run their own engine source concurrently.
- The agent's `sendMu` serialises socket writes — engine events and
  inventory_sync writes can intermix in any order; the AES+framing layer
  is atomic per `WriteFrame` call.
- EPS pacing is per-stream (one `golang.org/x/time/rate.Limiter`
  per source instance, burst=1).
- SIGINT / `ctx.Done()` interrupts the read loop, the limiter's `Wait`,
  and the write at every iteration boundary.
- Each agent's `runIteration` owns one `atomic.Int32` siblings counter.
  Lane goroutines that include at least one non-engine step increment
  the counter before launching and decrement it on exit. Engine sources
  with `run_while_siblings_active` receive a pointer to that counter and
  read it every 20 events.

## Metrics

Three columns are added to `bench.csv` (opt-in via `--report-engine`,
default `true`). They appear after the standard Python column set, so
`result_summary.py` keeps working unchanged.

| Column                  | Semantics                                                                |
| ----------------------- | ------------------------------------------------------------------------ |
| `engine_events_sent`    | One line successfully written as a frame. Also bumps `messages_sent`.     |
| `engine_files_eof_wrap` | Stream with `loop=true` rewound at EOF.                                  |
| `engine_send_errors`    | Write error during `SendText` (socket dead, framing failure).            |

`sender_summary.json.messages.engine_*` reflects the same cumulative
totals.

## Acceptance criteria (additions to [11-acceptance-criteria.md](./11-acceptance-criteria.md))

- **AC-K (smoke)**: `scenarios/engine_smoke.json` against a local manager
  produces `engine_events_sent ≥ 4000` over ~10 s @ 500 EPS, with no
  `Decoding error` lines in the manager log for the `bench-*` agent ID.
- **AC-L (mixed)**: `scenarios/engine_burst_mixed.json` over 30 s with 5
  agents produces both `sessions_completed > 0` and
  `engine_events_sent > 200 000`, no decoder errors. tcpdump capture
  decoded out-of-band shows engine frames and inventory_sync frames
  interleaved on the same TCP stream without corruption.
- **AC-M (duration)**: `scenarios/engine_duration_only.json` finishes in
  `5 ± 0.5 s` with `engine_events_sent ≈ 2500` (500 EPS × 5 s) and exactly
  one `engine step terminated: ... reason=duration ...` log line per
  agent.
- **AC-N (eof)**: `scenarios/engine_eof_short_file.json` finishes in
  `< 1 s` with `engine_events_sent = 50` (matches `short.log` line
  count), `engine_files_eof_wrap = 0` (loop=false), and `reason=eof`.
- **AC-O (siblings)**: `scenarios/engine_while_siblings_inventory.json`
  finishes when the FIM lane completes (≈ 3–4 s); the engine source
  logs `reason=siblings` and `engine_events_sent` is consistent with
  500 EPS × elapsed.
- **AC-P (whichever-first)**:
  `scenarios/engine_duration_AND_siblings.json` finishes with
  `reason=siblings` (siblings beats the 30 s `duration` safety net);
  `scenarios/engine_duration_safety_net.json` finishes with
  `reason=duration` at ≈ 20 s while the FIM lane keeps streaming
  afterwards (overall run lasts ≈ FIM duration).
- **AC-Q (load)**: `scenarios/engine_fleet_load.json` (50 agents, 1
  engine + 3 inventory lanes each) completes all 150 inventory
  sessions, no `sessions_failed`, `engine_events_sent` proportional to
  per-agent inventory elapsed × 200 EPS, and every engine step logs a
  termination line (one per agent per iteration).
- **AC-R (validation)**:
  `scenarios/engine_invalid_all_engine.json` is rejected at load time
  with the substring `run_while_siblings_active` in the error message.
  Likewise, a scenario with `repeat_count > 1` on an engine step is
  rejected with the substring `repeat_count must be 1`.

## Example: end-to-end frame chain

Input file line: `Jun  1 00:00:01 host01 sshd[1234]: Accepted password for root`

With `location = "syslog"` and the standard test fixture
`(name = "bench-0001-aaaaaaaaaaaa", id = "001", manager_key = "deadbeef…")`:

```
identifier_blob :  "1:syslog:Jun  1 00:00:01 host01 sshd[1234]: Accepted password for root"
inner_event     :  MD5_hex(routing_prefix || identifier_blob) || routing_prefix || identifier_blob
                  (where routing_prefix = "55555" + "1234567891" + ":" + "5555" + ":")
zlib_compressed :  zlib.compress(inner_event, level=6)
wazuh_padded    :  ('!' × N) || zlib_compressed     (N = 8 - len%8, or 8 if already aligned)
aes_padded      :  PKCS#7 pad to 16-byte alignment
encrypted       :  AES_256_CBC(aesKey, IV = "FEDCBA0987654321", aes_padded)
frame           :  "!001!#AES:" || encrypted
wire            :  uint32_le(len(frame)) || frame
```

See `tool_simulator/internal/wire/parity_test.go` for the test that asserts
a Go round-trip with this exact payload semantic-matches the Python sender.

## Files

| Path                                                                | Role                                                                  |
| ------------------------------------------------------------------- | --------------------------------------------------------------------- |
| [`internal/engine/source.go`](../internal/engine/source.go)          | `engine.Source` — file reader + EPS loop + frame writer + terminators |
| [`internal/engine/engine_test.go`](../internal/engine/engine_test.go)| Integration test against a fake remoted server                       |
| [`internal/runner/runner.go`](../internal/runner/runner.go)          | Sibling counter wiring (`runIteration` → `runLane` → `engine.New`)    |
| [`sample_payloads/engine/syslog.log`](../../sample_payloads/engine/syslog.log) | 1 000-line fixture used by smoke scenarios                       |
| [`sample_payloads/engine/short.log`](../../sample_payloads/engine/short.log)   | 50-line fixture for the EOF-before-duration test                 |
| [`scenarios/engine_smoke.json`](../../scenarios/engine_smoke.json)      | Minimal 1-agent / 10-second test (no terminators set)                 |
| [`scenarios/engine_burst_mixed.json`](../../scenarios/engine_burst_mixed.json) | Mixed engine+inventory_sync workload                            |
| [`scenarios/engine_duration_only.json`](../../scenarios/engine_duration_only.json) | Duration-only test (Mode A in isolation)                          |
| [`scenarios/engine_eof_short_file.json`](../../scenarios/engine_eof_short_file.json) | EOF wins over `duration` upper bound                            |
| [`scenarios/engine_while_siblings_inventory.json`](../../scenarios/engine_while_siblings_inventory.json) | Mode B in isolation: engine stops when single inventory lane finishes |
| [`scenarios/engine_duration_AND_siblings.json`](../../scenarios/engine_duration_AND_siblings.json) | Both terminators set; whichever-first: siblings win              |
| [`scenarios/engine_duration_safety_net.json`](../../scenarios/engine_duration_safety_net.json) | Both terminators; duration trips first to cap engine while inventory keeps running |
| [`scenarios/engine_invalid_all_engine.json`](../../scenarios/engine_invalid_all_engine.json) | Negative scenario: loader must reject (all-engine fleet + run_while_siblings_active) |
| [`scenarios/engine_fleet_load.json`](../../scenarios/engine_fleet_load.json) | Mode B at scale: 50 agents × engine + 3 inventory lanes each       |

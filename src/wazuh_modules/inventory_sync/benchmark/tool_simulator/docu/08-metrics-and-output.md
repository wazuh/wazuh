# 08 — Metrics and output

The Go sender MUST produce `bench.csv` and (optionally) `sender_summary.json`
with the **exact** schemas that the Python sender produces.
[`result_summary.py`](../../result_summary.py) and the chart generator consume
both files and MUST keep working unchanged.

## `bench.csv`

- One header row.
- One row per wall-clock second, written as soon as the stats collector
  ticks. **No batched flush at end-of-run.** Use `bufio.Writer` with an
  explicit `Flush()` per row, or a CSV writer that flushes per write.
- Timestamp format: ISO-8601 UTC with seconds precision, e.g.
  `2026-06-02T14:23:45Z`.

### Header row (exact order, matches Python's `COUNTER_FIELDS`)

```
timestamp,elapsed_s,
messages_sent,
sessions_started,sessions_completed,sessions_failed,
start_ack_ok,start_ack_offline,start_ack_error,
end_ack_ok,end_ack_offline,end_ack_error,end_ack_processing,
reqret,missing_ranges_total,messages_dropped,start_retries
```

This is `COUNTER_FIELDS` in `benchmark_sender.py`. The Go port MUST emit
exactly these columns in this order so that `result_summary.py` keeps
working unchanged.

**Go-only addendum** (opt-in via `--report-engine`, default `true`): three
more columns appended at the end:

```
engine_events_sent,engine_files_eof_wrap,engine_send_errors
```

These cover the engine event stream feature (see
[12-engine-event-streams.md](./12-engine-event-streams.md)). They are
optional — `result_summary.py` ignores any column it does not know.

### Column semantics

| Column                          | Incremented when                                                                                                |
| ------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| `timestamp`                     | The collector tick that produced this row.                                                                      |
| `elapsed_s`                     | Seconds since `t0_run` (the moment `agents_registered == total_agents` and lanes started).                      |
| `sessions_started`              | A session-runner sends its `Start` message.                                                                     |
| `sessions_completed`            | An `EndAck` with `Status_Ok` is observed.                                                                       |
| `sessions_failed`               | A session aborts for any non-Ok terminal reason (Error/Offline at End, timeout, ReqRet budget exhausted).        |
| `start_sent`                    | One `Start` message was written to the socket.                                                                  |
| `start_ack_ok`                  | A `StartAck` with `Status_Ok` was matched to its runner.                                                        |
| `start_ack_error`               | Same, `Status_Error`.                                                                                            |
| `start_ack_offline`             | Same, `Status_Offline`.                                                                                          |
| `start_ack_checksum_mismatch`   | Same, `Status_ChecksumMismatch` (only valid for `Mode_ModuleCheck` etc).                                         |
| `start_ack_timeout`             | 15-second window elapsed before a StartAck arrived.                                                              |
| `end_sent`                      | One `End` message was written.                                                                                   |
| `end_ack_ok`                    | `EndAck` with `Status_Ok`.                                                                                       |
| `end_ack_error`                 | `EndAck` with `Status_Error`.                                                                                    |
| `end_ack_offline`               | `EndAck` with `Status_Offline`.                                                                                  |
| `end_ack_processing`            | `EndAck` with `Status_Processing` (intermediate, the runner keeps waiting).                                      |
| `end_ack_timeout`               | 60-second window elapsed before a terminal EndAck.                                                               |
| `data_values_sent`              | Each `DataValue` message sent. Inside a `DataBatch`, every item counts as 1.                                     |
| `data_batches_sent`             | Each `DataBatch` envelope sent (regardless of item count).                                                       |
| `data_contexts_sent`            | Each `DataContext` message sent.                                                                                 |
| `data_cleans_sent`              | Each `DataClean` message sent.                                                                                   |
| `checksum_modules_sent`         | Each `ChecksumModule` message sent.                                                                              |
| `data_values_retransmitted`     | Each DataValue resent in response to a `ReqRet`. (Also counts toward `data_values_sent`.)                        |
| `reqret`                        | One `ReqRet` was received and acted on.                                                                          |
| `missing_ranges_total`          | Increment by `len(ranges)` for each `ReqRet` consumed.                                                           |
| `messages_dropped`              | ReqRet budget exhausted → `+= len(remaining_missing)`; OR sender-side queue overflow if you ever add one.        |

### Reset policy

All counters are **per-tick deltas**: the collector calls `atomic.SwapInt64(&c, 0)`
to read-and-zero. The cumulative totals for `sender_summary.json` are
maintained separately as a sum of those deltas.

### Empty rows

If a tick happens before any agent has started (the registration phase),
write a row with `elapsed_s=0` and all zeros — do not omit the row. The
chart generator relies on continuous time series.

## `sender_summary.json`

Written once, at the end of the run, after the drain phase completes. The
file location comes from `--summary-json`. If the flag is not set, the
summary is not written (Python uses this for ad-hoc runs without the full
orchestrator).

### Top-level shape

```json
{
  "meta": {
    "scenario_name":    "string",
    "scenario_path":    "string",
    "manager":          "string",
    "port":             1514,
    "reg_port":         1515,
    "total_agents":     2000,
    "agents_registered": 2000,
    "parallel_agents":  0,
    "repeat_until":     180,
    "drain_timeout":    60,
    "start_time":       "2026-06-02T14:00:00Z",
    "end_time":         "2026-06-02T14:03:21Z",
    "duration_sec":     201.4,
    "sender":           "python",          // or "go"; tagged at runtime
    "version":          "1.0.0"
  },
  "messages": {
    "sessions_started":       12345,
    "sessions_completed":     12300,
    "sessions_failed":        45,
    "start_sent":             12345,
    "start_ack_ok":           12300,
    "start_ack_error":        12,
    "start_ack_offline":      33,
    "start_ack_checksum_mismatch": 0,
    "start_ack_timeout":      0,
    "end_sent":               12300,
    "end_ack_ok":             12300,
    "end_ack_error":          0,
    "end_ack_offline":        0,
    "end_ack_processing":     1500,
    "end_ack_timeout":        0,
    "data_values_sent":       7654321,
    "data_batches_sent":      120000,
    "data_contexts_sent":     12300,
    "data_cleans_sent":       0,
    "checksum_modules_sent":  0,
    "data_values_retransmitted": 23,
    "reqret":                 5,
    "missing_ranges_total":   12,
    "messages_dropped":       0
  },
  "latency_ms": {
    "start_ack":    { "count": 12345, "p50": 4.1, "p90": 12.0, "p95": 18.5, "p99": 55.0, "max": 312.0, "avg": 8.2 },
    "end_ack":      { "count": 12300, "p50": 9.0, "p90": 27.5, "p95": 41.0, "p99": 110.0,"max": 880.0, "avg": 18.4 },
    "session_full": { "count": 12300, "p50": 23.4,"p90": 71.5, "p95": 99.0, "p99": 240.0,"max": 1430.0,"avg": 41.2 }
  }
}
```

### Field-by-field

- `meta.sender`: `"python"` for the legacy script, `"go"` for the new
  binary. `result_summary.py` does not branch on this, but it goes into the
  final report — keep it accurate.
- `meta.duration_sec`: wall time between the first agent's Start and the
  collector's last tick (after drain). Floating point with 3 decimals.
- `meta.scenario_name`: the `name` field from the scenario JSON, or the
  basename if absent.
- `messages.*`: cumulative totals, matching `bench.csv` column sums.
- `latency_ms.*`: see below.

### Latency events

Three latency series are tracked. Each observation is a positive float in
milliseconds.

| Series          | `t0` recorded when                          | `t1` recorded when                                  | Excluded                          |
| --------------- | ------------------------------------------- | --------------------------------------------------- | --------------------------------- |
| `start_ack`     | Start message hits the wire (after encrypt) | Matched StartAck is dispatched to the runner        | Sessions whose StartAck timed out |
| `end_ack`       | End message hits the wire                   | Terminal EndAck arrives (NOT `Status_Processing`)   | Sessions whose EndAck timed out   |
| `session_full`  | Start message hits the wire                 | Terminal EndAck arrives                             | Failed sessions                   |

Percentiles: `p50`, `p90`, `p95`, `p99` plus `max`, `avg`, `count`. Use
unweighted percentiles over the full set of observations (no streaming
estimator — sessions counts are small enough to store all values; 2000
agents × ~5 sessions/iter × 60 iters ≈ 600 000 floats is fine).

Sample-collection rule: append on every successful observation; if the
budget is busted, fall back to a reservoir sampler of size 100 000 (Python
does not but the Go port MAY).

## Stdout

The collector also emits a human-readable line every 5 seconds:

```
[+00:05] sess started=234 completed=12 failed=0  eps=1480  in_flight=222
[+00:10] sess started=512 completed=68 failed=0  eps=1532  in_flight=444
```

This is for the developer watching the terminal — not parsed by any tool.
The Go port SHOULD emit equivalent lines.

## Compatibility checks

- `result_summary.py`'s `aggregate_bench()` reads `bench.csv` with
  `pandas.read_csv` and references columns by name; missing columns crash.
  Therefore: every column listed above MUST be present, in any order
  (pandas reorders by name). The Python sender writes them in the order
  above for human readability — keep that.
- The chart generator (`monitor_graphics_generator.py`) reads
  `sender_summary.json` and looks for `meta.scenario_name`, `duration_sec`,
  `messages.sessions_completed`, `latency_ms.session_full.p99`. Renaming
  any of those breaks the charts.

Do NOT add new columns or new JSON fields in the Go port. If new telemetry
is needed, plumb it through a separate file and update the consumers in a
follow-up.

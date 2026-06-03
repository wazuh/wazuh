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
  "loop":     true
}
```

| Field      | Required | Default                         | Description                                                                             |
| ---------- | -------- | ------------------------------- | --------------------------------------------------------------------------------------- |
| `engine`   | yes      | —                               | Path to the input text file. Resolved relative to the scenario file, then the benchmark dir. |
| `max_eps`  | yes      | —                               | Per-stream rate cap. `0` is rejected for engine streams (there is no point in unbounded). |
| `location` | no       | basename(`engine`) sans ext     | Logical location string sent as the `<location>` field of the frame.                    |
| `loop`     | no       | `true`                          | At EOF: rewind and continue (`true`) or end the iteration (`false`).                    |

Repeat controls (`repeat_count`, `initial_delay`, `repeat_delay`) apply the
same way as inventory_sync steps.

### Forbidden fields

These are inventory-sync-only and the loader rejects them when `engine`
is set:

`session_type`, `sync_mode`, `data_size`, `use_databatch`, `retransmit`,
`payload_size`, `pad_field`, `modulecheck_checksum`, `auto_resync`,
`module`, `index`, `option`.

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
| [`internal/engine/source.go`](../internal/engine/source.go)          | `engine.Source` — file reader + EPS loop + frame writer               |
| [`internal/engine/engine_test.go`](../internal/engine/engine_test.go)| Integration test against a fake remoted server                       |
| [`sample_payloads/engine/syslog.log`](../../sample_payloads/engine/syslog.log) | 1 000-line fixture used by smoke scenarios                       |
| [`scenarios/engine_smoke.json`](../../scenarios/engine_smoke.json)      | Minimal 1-agent / 10-second test                                      |
| [`scenarios/engine_burst_mixed.json`](../../scenarios/engine_burst_mixed.json) | Mixed engine+inventory_sync workload                            |

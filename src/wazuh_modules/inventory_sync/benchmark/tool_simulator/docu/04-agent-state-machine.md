# 04 — Agent and session state machines

Each simulated agent walks an outer state machine. Inside each iteration it
spawns one session-runner per lane; each runner walks an inner state machine
that depends on `session_type`. This document fixes both.

## Outer: agent lifecycle

```
                       +-----------+
                       |  Created  |
                       +-----+-----+
                             |
                             v
                      +-------------+
                      | Registering |   authd TCP+TLS, OSSEC A: name
                      +------+------+
                             |
                             v
                      +-------------+
                      |  Registered |   has (id, name, key)
                      +------+------+
                             |  optional --key-wait sleep
                             v
                      +-------------+
                      | Connecting  |   remoted TCP
                      +------+------+
                             |
                             v
                      +-------------+   #!-agent startup control msg
                      |  Connected  |   reader goroutine running
                      +------+------+
                             |
                +------------v-------------+
                |    IterationLoop         | <----+ next iteration
                | (run all lanes once)     |      |
                +------------+-------------+      |
                             |                    |
                  yes  +-----+--------+ no        |
        more passes?-->|  Done?       |-----------+
                       +-----+--------+
                             |
                             v
                      +-------------+   close socket
                      | Disconnecting|
                      +------+------+
                             |
                             v
                       +-----+-----+
                       |   Done    |
                       +-----------+
```

### Transition rules

| From         | To             | Trigger                                           | Failure → action                                                  |
| ------------ | -------------- | ------------------------------------------------- | ----------------------------------------------------------------- |
| Created      | Registering    | Worker pool picks up the agent                    | n/a                                                               |
| Registering  | Registered     | `OSSEC K:'…'` parsed; key derived                 | Retry up to 3× with 1 s sleep; then mark agent failed, exit       |
| Registered   | Connecting     | `--key-wait` elapsed                              | n/a                                                               |
| Connecting   | Connected      | TCP connect + startup control message sent        | Retry up to 3× with 1 s sleep; on exhaustion: agent failed        |
| Connected    | IterationLoop  | Reader goroutine ready                            | n/a                                                               |
| IterationLoop| IterationLoop  | Iteration done, `repeat_until` not elapsed; close socket; sleep 1 s; reconnect | If reconnect fails: count remaining sessions as failed, agent exits |
| IterationLoop| Disconnecting  | `repeat_until` elapsed OR single-pass scenario    | n/a                                                               |
| Disconnecting| Done           | Socket closed; reader goroutine joined            | n/a                                                               |

### Concurrency notes

- Lanes inside one iteration run in parallel (one goroutine per lane).
- Steps inside one lane run sequentially.
- `parallel_agents>0`: the outer transition `Created → Registering` is gated
  by a semaphore of that size. An agent slot is released when the agent
  reaches `Done`.

### Keepalive + shutdown (control conversation)

Independent of the session work above, every agent maintains a small
side conversation with the manager during its lifetime — mirroring the
real Wazuh agent ([`client-agent/src/notify.c`](../../../../client-agent/src/notify.c)):

1. **On `Connected`**: spawn a `StartKeepalive` goroutine that ticks at
   `--keepalive-interval` (default 20 s, matches `NOTIFY_TIME`). Every
   tick emits `#!-<JSON>` with a minimal payload
   `{"version":"1.0","agent":{"id,name,version,merged_sum,groups}}`. The
   first keepalive carries `merged_sum=""`, prompting the manager to
   push us the shared file `merged.mg` via `#!-up file <md5> merged.mg`.
2. **On `#!-up file` arrival** (the reader, [`agent/conn.go`](../internal/agent/conn.go#L237)
   handles the prefix BEFORE the FB parser): extract the MD5, cache it
   on the `Conn`, fire the optional `MergedSumObserver` so the supervisor
   can bump `merged_sum_updates`. Subsequent keepalives report this hash
   → manager logs the agent as `synced`, stops resending the file.
3. **On `Disconnecting`**: stop the keepalive ticker, then send a
   `#!-agent shutdown ` frame (no payload), then close the socket. This
   mirrors `send_agent_stopped_message()` and lets the manager mark the
   agent disconnected immediately instead of waiting for the inactivity
   timeout.

The keepalive and shutdown frames go through the same `Conn.SendText` →
`sendMu` path as inventory_sync writes, so they interleave atomically
with whatever session work is in flight.

Counters added (opt-in via `--report-engine`):
`keepalives_sent`, `keepalive_errors`, `shutdowns_sent`,
`merged_sum_updates`.

## Inner: per-session state machine by `session_type`

Three session types exist. They differ only between `AwaitStartAck` and
`SendEnd`.

### Common preamble — all session types

```
   +--------------+    Build Message{type=Start}    +-----------+
   |  Build Start |--------------------------------> SendStart |
   +--------------+                                 +-----+-----+
                                                          |
                                                          v
                                                  +---------------+
                                                  | AwaitStartAck |
                                                  +-------+-------+
                                                          |
              +--------------+--------------+------+------+
              |              |              |      |      |
         Status_Ok      Status_Error  Status_Offline Status_  timeout
                                                  ChecksumMismatch
              |              |              |      |      |
              v              v              v      v      v
         <session-     ABORT runner    ABORT runner   special  ABORT runner
          specific     (count          (count         (handled (count failed)
          body>         failed)         offline)       below)
```

### `delta` session body

`(sync_mode = ModuleFull|ModuleDelta or any data-producing mode)`

```
  +-------------+
  | SendData*   |  one of:
  +------+------+    - N × DataValue (default)
         |           - groups of DataValue inside DataBatch (if use_databatch)
         |           - 1 × DataContext per metadata key (if applicable)
         |    EPS pacing enforced here
         v
  +-------------+
  |   SendEnd   |
  +------+------+
         |
         v
  +-------------+
  | AwaitEndAck |---- Status_Processing → keep waiting (record latency, do not exit)
  +-------+-----+---- Status_Ok → success
          |
   ReqRet received   ┐
          v          │   only if `retransmit=true`; up to 5 rounds
  +-------------+    │   compute set of missing seq IDs from ReqRet ranges
  | ResendMissing|---┘   resend the items, then keep awaiting EndAck
  +-------------+
```

Notes:
- `ReqRet` can arrive before or after `End`. The runner MUST keep the reader
  alive throughout `AwaitEndAck`.
- After 5 ReqRet rounds without progress, mark the session failed
  (`sessions_failed++`, `messages_dropped += missing.size`).

### `modulecheck` session body

`(sync_mode = ModuleCheck or MetadataCheck or GroupCheck)`

```
  +-------------------+
  | SendChecksumModule|   one Message{type=ChecksumModule} with hash
  +---------+---------+
            |
            v
  +-------------+
  |   SendEnd   |
  +------+------+
         |
         v
  +-------------+
  | AwaitEndAck |
  +-------+-----+
          |
  +---+---+-------------------------+
  |       |                         |
Status   Status                Status_
_Ok     _ChecksumMismatch     Error/Offline/Processing
  |       |                         |
  v       v                         v
 done   auto_resync?               handle per common rules
         yes → enqueue a delta session for the same module
              with sync_mode=ModuleFull, same step otherwise.
         no  → count as completed-with-mismatch
```

### `dataclean` session body

`(sync_mode = ModuleDelta with empty payload, or explicit DataClean op)`

```
  +-------------+
  | SendDataClean|   one Message{type=DataClean} carrying the per-index map
  +------+-------+
         |
         v
  +-------------+
  |   SendEnd   |
  +------+------+
         |
         v
  +-------------+
  | AwaitEndAck |
  +-------+-----+
          |
   Status_Ok / Status_Processing → success / continue
   Status_Error / Status_Offline → count failed/offline, abort runner
```

## Timeouts

These are constants in the Python script; the Go port MUST reuse them
(absolute time budgets, not relative).

| Event                        | Budget    | On expiry                                                                |
| ---------------------------- | --------- | ------------------------------------------------------------------------ |
| StartAck                     | 15 s      | `start_ack_timeout++`, abort runner (pre-StartAck → no further messages) |
| EndAck (final)               | 60 s      | `end_ack_timeout++`, session counted failed                              |
| EndAck (intermediate `Status_Processing` → next ack) | 60 s | Same as above                                                            |
| ReqRet round (resend + await any Status update)      | 30 s | Treat as a missed ack; counts against the 5-round budget                 |
| Reconnect retry (per attempt)| 1 s sleep, 3 attempts | Mark agent failed                                                 |

## Status code reaction (recap)

| Status code (StartAck or EndAck)   | Counter incremented           | Runner reacts                                                                                 |
| ---------------------------------- | ----------------------------- | --------------------------------------------------------------------------------------------- |
| `Status_Ok (0)`                    | `*_ack_ok`                    | Proceed                                                                                       |
| `Status_Error (1)`                 | `*_ack_error`                 | Abort runner immediately; no End is sent if it was a Start                                    |
| `Status_Offline (2)`               | `*_ack_offline`               | **StartAck**: depends on the step's `offline_retry` policy — `-1` (default) aborts the runner; `0` retries indefinitely; `N>0` retries up to N total attempts (waiting `offline_retry_delay` between each). Each retry also bumps `start_retries`. **EndAck**: always aborts (no retry path for End). |
| `Status_ChecksumMismatch (3)`      | `start_ack_checksum_mismatch` | Only in `modulecheck`. If `auto_resync=true`, enqueue a delta resync after End                |
| `Status_Processing (4)`            | `end_ack_processing`          | Keep waiting for the next ack; record latency only on the first occurrence                    |

## Side effects on transition

Every transition writes one of:

- An entry into the **counters** array (incremented once per transition).
- A latency observation (paired `t0`/`t1` recorded into the
  `latency_ms.{start_ack|end_ack|session_full}` histogram).

Mapping of transitions to counters:

| Transition                          | Counter                                            |
| ----------------------------------- | -------------------------------------------------- |
| `Build Start` → `SendStart`         | `start_sent`                                       |
| `AwaitStartAck` → success branch    | `start_ack_ok`                                     |
| `AwaitStartAck` → Status_Error      | `start_ack_error`                                  |
| `AwaitStartAck` → Status_Offline    | `start_ack_offline`                                |
| `AwaitStartAck` → Status_ChecksumMismatch | `start_ack_checksum_mismatch`                |
| `AwaitStartAck` → timeout           | `start_ack_timeout`                                |
| Each DataValue / Item in DataBatch  | `data_values_sent`                                 |
| Each DataBatch envelope             | `data_batches_sent`                                |
| Each DataContext                    | `data_contexts_sent`                               |
| Each DataClean                      | `data_cleans_sent`                                 |
| Each ChecksumModule                 | `checksum_modules_sent`                            |
| `SendEnd`                           | `end_sent`                                         |
| `AwaitEndAck` → Status_Ok           | `end_ack_ok`, `sessions_completed`                 |
| `AwaitEndAck` → Status_Error        | `end_ack_error`, `sessions_failed`                 |
| `AwaitEndAck` → Status_Offline      | `end_ack_offline`                                  |
| `AwaitEndAck` → Status_Processing   | `end_ack_processing`                               |
| `AwaitEndAck` → timeout             | `end_ack_timeout`, `sessions_failed`               |
| ReqRet entered                      | `reqret`, `missing_ranges_total += len(ranges)`    |
| ResendMissing item                  | `data_values_retransmitted++`                      |
| ReqRet budget exhausted             | `messages_dropped += len(missing)`, `sessions_failed` |

The full counter list with semantics is in
[08-metrics-and-output.md](./08-metrics-and-output.md).

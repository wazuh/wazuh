# 09 — Error handling and shutdown

This document fixes how the sender reacts to errors, signals, and the
drain phase.

## Error matrix

Each row says: when this happens, increment counter X, scope it to Y, and
react with Z. "Scope" answers "what does this kill?" — the step, the
session, the agent, or the whole sender.

| Error                                           | Counter                          | Scope          | Reaction                                                                                                       |
| ----------------------------------------------- | -------------------------------- | -------------- | -------------------------------------------------------------------------------------------------------------- |
| Scenario JSON malformed                         | n/a                              | sender         | Print error to stderr, exit with code 2 BEFORE opening any socket.                                              |
| Authd handshake fails (TLS)                     | n/a                              | agent          | Retry up to 3× with 1 s sleep; on exhaustion, mark agent failed and skip its lanes.                            |
| Authd refuses (`OSSEC E:` or unexpected reply)  | n/a                              | agent          | Same as above.                                                                                                  |
| Remoted TCP connect fails                       | n/a                              | agent          | Same retry policy.                                                                                              |
| Send error mid-frame (socket dead)              | `sessions_failed += in_flight`   | agent          | Stop reader, close socket, exit agent loop. Remaining iterations counted as failed.                            |
| Read error / EOF                                | (depends on in-flight state)     | agent          | Same as above.                                                                                                  |
| StartAck timeout (15 s)                         | `start_ack_timeout`              | runner         | Abort runner; do NOT send End. Sibling runners continue.                                                       |
| EndAck timeout (60 s)                           | `end_ack_timeout`, `sessions_failed` | runner     | Abort runner. Sibling runners continue.                                                                        |
| StartAck `Status_Error`                         | `start_ack_error`                | runner         | Abort runner.                                                                                                  |
| StartAck `Status_Offline`                       | `start_ack_offline`              | runner         | Abort runner. Do NOT retry inside the runner — the scenario decides via `repeat_count`.                        |
| EndAck `Status_Error`                           | `end_ack_error`, `sessions_failed` | runner       | Treated as session failure.                                                                                    |
| EndAck `Status_Offline`                         | `end_ack_offline`                | runner         | Treated as session failure (not retried internally).                                                            |
| `StartAck Status_ChecksumMismatch` (non-modulecheck) | `start_ack_checksum_mismatch` | runner         | Log + abort. Should not happen against a healthy manager.                                                      |
| `StartAck Status_ChecksumMismatch` (modulecheck, `auto_resync=true`) | `start_ack_checksum_mismatch` | runner | Enqueue a follow-up delta session for the same module. The current session still completes normally.        |
| ReqRet for an unknown session                   | n/a                              | log only       | Drop. Logged at debug level only.                                                                              |
| ReqRet budget exhausted (>5 rounds)             | `messages_dropped += len(missing)`, `sessions_failed` | runner | Abort runner.                                                                                                  |
| Reconnect failure between iterations            | `sessions_failed += remaining`   | agent          | Exit agent loop early.                                                                                          |
| FlatBuffer parse error on inbound frame         | n/a                              | log only       | Drop the frame, increment a debug counter, keep reader alive.                                                  |
| zlib/AES decryption failure                     | n/a                              | log only       | Same: log + drop. Persistent failures imply the agent is using the wrong key — the supervisor MAY mark it failed after N consecutive drops. |

**"Abort runner"** means: stop sending more messages for this session, do
not record an EndAck observation, leave the session id in
`atomic.AddInt64(&inFlight, -1)` so drain counts down correctly.

## Signal handling

The sender installs a handler for `SIGINT` and `SIGTERM`.

### First signal — graceful drain

1. Cancel the root `context.Context`. This propagates everywhere; all
   `select { case <-ctx.Done(): … }` arms fire.
2. Each agent's lane loop exits between iterations. Lane runners with an
   in-flight session **complete** that session (or hit a per-session
   timeout); they do NOT abandon mid-Start.
3. The supervisor enters the **drain** phase (see below).

### Second signal within 2 s — force exit

1. Skip drain.
2. Flush whatever is buffered in `bench.csv` (the writer is already
   line-buffered so usually nothing extra to do).
3. `os.Exit(130)`.

The 2-second window is a simple `time.Now().Sub(firstSignalAt) < 2*time.Second`
check at the moment of the second signal.

Go implementation:

```go
ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
defer cancel()

sigs := make(chan os.Signal, 1)
signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
go func() {
    first := <-sigs
    firstAt := time.Now()
    cancel() // graceful
    for s := range sigs {
        if time.Since(firstAt) < 2*time.Second {
            _ = s
            os.Exit(130)
        }
    }
}()
```

(Or use `signal.NotifyContext` for the first signal and a separate channel
for the second — same effect.)

## Drain semantics

The drain phase is the window between "the last agent finishes its outer
loop" and "the sender exits".

```
                                     drain_timeout (default 60 s)
                                   ┌──────────────────┐
                                   │                  │
─ agent loops still running ─┬─ all agent loops done ─┴─ exit ─
                             │
                          drain start
```

Rules:

1. The collector goroutine keeps ticking 1 Hz and writing `bench.csv` rows.
   Drain counts (responses still coming in late) ARE reflected in those
   rows.
2. The supervisor reads `inFlight` (atomic counter incremented on Start
   send, decremented on terminal ack or runner abort). Exit when
   `inFlight == 0` OR `drain_timeout` elapses.
3. On timeout, sessions still in-flight are counted as `sessions_failed`
   with `end_ack_timeout` reason. The implementation MUST do this so
   summary numbers reconcile.

### Drain budget interaction with `--drain-timeout`

The CLI flag overrides the scenario's `drain_timeout`. Both default to 60.
Order of precedence: CLI > scenario > built-in default.

## Reconnect between iterations

When `repeat_until > 0`, after every iteration each agent:

```
close socket
sleep 1 s                             # canceled if ctx canceled
attempt to reconnect (up to 3 tries, 1 s back-off)
if reconnect fails:
    sessions_failed += remaining_session_count_for_this_agent
    exit agent loop
else:
    continue with the next iteration
```

The 1-second sleep before reconnect mirrors Python and gives the manager's
keys-reload a moment to settle.

## Panic handling

Every long-lived goroutine MUST defer a recover that:

1. Logs the panic + stack trace.
2. Sends a `runtime error` event to the supervisor (close a `chan error` or
   call `errgroup.Group.Go`'s error path).
3. Allows the supervisor to either degrade gracefully (mark this agent
   failed) or trigger a global cancel for unrecoverable errors.

A panic in the supervisor itself: log, drain, `os.Exit(1)`.

## Logging

- Default log level: INFO. Per-second counter snapshots, transitions in/out
  of drain, agent registration progress.
- `--debug`: enables DEBUG. Per-frame logs are NOT acceptable at this level
  (too noisy); use TRACE if you add one.
- Critical errors (registration failed, all-agents-failed) go to stderr.
- Counter snapshots and progress go to stdout.

The sender uses one logger per component (`agent`, `runner`, `collector`);
`log/slog` is the implementation.

## Exit codes

| Exit | When                                                            |
| ---- | --------------------------------------------------------------- |
| `0`  | Normal completion (all agents finished or `repeat_until` elapsed) and drain succeeded. |
| `1`  | Unrecoverable error during run (panic in supervisor, indexer-side reject of all sessions, etc.). |
| `2`  | Configuration / scenario error before the run started.          |
| `130`| Second SIGINT received within 2 s of the first.                 |

`result_summary.py` does not look at exit codes; the orchestrator
`run_benchmark.sh` does (`set -e` somewhere).

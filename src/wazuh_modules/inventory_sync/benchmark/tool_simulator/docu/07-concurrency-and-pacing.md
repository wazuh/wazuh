# 07 — Concurrency and pacing

This document describes the Go concurrency model and EPS pacing semantics
used by the benchmark sender.

## Concurrency primitive mapping

| Concept                                           | Go implementation                                          | Notes |
| ------------------------------------------------- | ---------------------------------------------------------- | ----- |
| Per-agent execution unit                          | `goroutine` + `context.Context`                            | One per agent. |
| Per-agent frame reader                            | One goroutine per agent that reads frames and demuxes      | Does not parse FlatBuffers; routes raw payloads to per-session channels and to the per-agent StartAck FIFO. |
| Per-session inbox                                 | `chan inboundFrame` (buffered, capacity 16)                | Closed by the runner when it leaves `AwaitEndAck`. |
| Per-agent send lock                               | `sync.Mutex` per agent                                     | Serialises wire writes for one agent — the manager requires intra-agent order. |
| Pending-starts FIFO                               | `container/list.List` guarded by the send mutex            | StartAck FIFO; see 06-flatbuffers-messages.md. |
| Concurrency limiter (`parallel_agents`)           | Buffered `chan struct{}` of capacity N                     | Acquire on agent entry, release on agent exit. |
| All-agents-ready barrier                          | `sync.WaitGroup` + `chan struct{}` signal                  | Used when `parallel_agents == 0` to launch all agents together. |
| Per-session EPS throttle                          | `golang.org/x/time/rate.Limiter` per runner                | Leaky-bucket semantics; see §3. |
| Stats collector                                   | One goroutine driven by `time.Ticker(1s)`                  | Owns the CSV writer; no other goroutine writes to bench.csv. |
| SIGINT handler                                    | `signal.Notify(ch, syscall.SIGINT)` consumed by the supervisor goroutine | Cancels the root context on first signal. |

## Goroutine map

```
supervisor                                   (1)  parses CLI/scenario, registers agents, owns root ctx
└─ stats_collector                           (1)  ticks 1 Hz, flushes bench.csv, accumulates latency hist
└─ for each agent:
   ├─ agent_main                             (N)  walks the outer state machine
   │  └─ reader                              (N)  pulls frames, demuxes to session inboxes / StartAck FIFO
   │  └─ for each lane (in parallel):
   │     └─ lane_runner                      (Σ lanes)  walks steps sequentially; spawns one session_runner per step
   │        └─ session_runner                (Σ sessions in-flight) drives one session's inner state machine
```

At full load with 2000 agents × 4 lanes, that's ~16 000 goroutines steady
state — well within Go's comfort zone. Memory budget: ~2 MB/agent at peak
(NFR-6).

## Send-side ordering

Per-agent writes MUST be strictly serialised. There is one TCP socket per
agent, and the AES-CBC stream + framing has no concept of message
interleaving. Use:

```go
type AgentConn struct {
    sendMu sync.Mutex
    conn   net.Conn
    ...
}

func (a *AgentConn) Write(payload []byte) error {
    a.sendMu.Lock()
    defer a.sendMu.Unlock()
    return a.writeFrame(payload)   // length-prefix + encrypt + frame
}
```

The same mutex protects the StartAck FIFO push — see FR-20: enqueue the
pending runner **inside the locked region** so the reader's `pop front` on
StartAck always sees the matching runner.

## Read-side fan-out

```go
func (a *AgentConn) readLoop(ctx context.Context) {
    for {
        select { case <-ctx.Done(): return; default: }
        f, err := a.readFrame()
        if err != nil { /* signal failure, exit */ }
        msg := parseMessage(f)
        switch msg.Type {
        case StartAck:
            r := a.pendingStarts.PopFront()
            r.resolveStart(msg.Session, msg.Status)
        case EndAck, ReqRet:
            r := a.sessions.Get(msg.Session)
            if r == nil { /* log + drop */ continue }
            select {
            case r.inbox <- msg:
            case <-ctx.Done(): return
            }
        default:
            /* drop unexpected types */
        }
    }
}
```

Channel capacity 16 matches manager batch sizes; under sustained ReqRet
floods, larger may be warranted — measure first.

## Pacing — per-session EPS

Per-session `max_eps` is enforced by a leaky bucket:

```
t0   = time.monotonic()           # captured once per session
cap  = step.max_eps               # events per second
sent = 0                          # incremented after each Message sent

for each Message to send:
    sent  += 1
    target = t0 + sent / cap
    now    = time.monotonic()
    if now < target:
        sleep(target - now)
```

This produces a *steady* EPS — bursts are not allowed. The Go implementation:

```go
limiter := rate.NewLimiter(rate.Limit(step.MaxEPS), 1)  // burst=1

for ... {
    if err := limiter.Wait(ctx); err != nil { return err }   // ctx cancellation OK
    send(msg)
}
```

`burst=1` enforces strict leaky-bucket semantics. `burst > 1` allows short
bursts and diverges — do not change without test evidence.

Notes:

- When `max_eps == 0`, no limiter is used (uncapped).
- The limiter is per-session, NOT per-agent and NOT global.
- For dumps with `use_databatch=true`, the EPS cap applies to the **logical
  items** (each `DataValue` inside a `DataBatch` counts as 1), not the batch
  envelopes. The counter increments per item, not per batch.

## Pacing — scenario-level cadence

| Knob                     | Where applied                          | Cancellable on SIGINT?                                   |
| ------------------------ | -------------------------------------- | -------------------------------------------------------- |
| `initial_delay` (step)   | Before the first iteration of a step   | Yes — `select { case <-time.After(d): case <-ctx.Done(): }` |
| `repeat_delay`  (step)   | Between iterations of the same step    | Yes — same pattern                                       |
| `repeat_until`  (scenario) | Outer agent loop                     | Yes — checked at each iteration boundary                 |
| `--key-wait`    (CLI)    | Between authd success and remoted dial | Yes                                                      |

Never call `time.Sleep` for any of these — always use the
`select`-with-context pattern so SIGINT cancels promptly.

## `parallel_agents` semantics

- `parallel_agents == 0` (most scenarios): use a barrier. All agents enrol
  + connect, then wait on a shared `chan struct{}`, then the supervisor
  closes the channel and they all start their lane work simultaneously.
- `parallel_agents > 0`: use a buffered channel of capacity N as a
  semaphore. Each agent acquires before entering `IterationLoop` and
  releases when leaving it (i.e. between iterations, the slot is held).

**Semantics**: an agent holds its semaphore slot for the *entire* set of
iterations. If `repeat_until > 0`, that behaviour caps the number of
agents looping at once, not the number of agents performing a single
iteration. Do NOT release between iterations.

## Cancellation

A single root `context.Context` is created in `main`. All goroutines accept
either the root context or a child derived from it. SIGINT → first signal
cancels the root context; agents finish their in-flight session naturally,
then drain.

```go
ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
defer cancel()
```

Second-signal-within-2s force exit: implement with a `sync/atomic` counter
or a separate `signal.Notify` channel that triggers `os.Exit(130)`.

## Memory & GC

- Pre-allocate one builder per goroutine that emits FlatBuffers; call
  `builder.Reset()` between messages.
- Pool small buffers with `sync.Pool` for the `[]byte` slices used in
  encryption (one per agent send loop is enough).
- Avoid `bytes.Buffer.ReadFrom` for variable-size reads — use exact-length
  `io.ReadFull` since the wire framing tells you the length up front.
- The hot path is: build → MD5 → zlib → pad → AES → write. Every step
  should reuse buffers; do not allocate slices in the inner loop.

## Why a single reader per agent is sufficient

Each reader runs on its own goroutine and the runtime schedules them across
cores without contention. In a 2000-agent run on a 16-core box there are
2000 reader goroutines, each typically idle (blocking on `recv`);
decryption and decode work runs in parallel across all available cores —
exactly the throughput target of NFR-7.

## Counters and the stats collector

- All counters are `int64` atomics (`atomic.AddInt64`, `atomic.LoadInt64`).
- The collector ticks every 1 s. On each tick it:
  1. Reads (and resets) the per-tick counters via `atomic.SwapInt64`.
  2. Writes one CSV row.
  3. Accumulates the read values into a cumulative copy used to populate
     `sender_summary.json` at the end.
- Latency histograms use a write-side ring buffer (1 obs per write) and a
  read-side flush every tick. See [08-metrics-and-output.md](./08-metrics-and-output.md).

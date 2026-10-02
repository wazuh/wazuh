# 06 — Agent and session state machines

## The simulated agent

An agent goes through enrollment and startup once, then runs its lanes and its keepalive loop
concurrently until drain. In `uds` mode enrollment, startup, keepalives and shutdown are all
skipped — there is no remoted in the path, and the agent id is assigned by the scenario.

Two timing rules the transitions depend on, both learned against a real manager:

- **After enrolling, the fleet waits until remoted accepts its signature.** remoted reloads
  `client.keys` on its own schedule (`remoted.keyupdate_interval` is 10 s, but gaps of well over a
  minute were measured), so an agent that signs a request the instant it enrolls is answered `401`:
  its key is simply not in the transport's keystore yet. The sender does not sleep a guessed
  interval. Once the whole fleet is enrolled it probes with the first agent's `POST /control`
  `startup`, every 2 s, until it is not a `401`. The budget is `--enroll-settle` with a 30 s floor
  (the 12 s default therefore means 30 s). Each agent's own `startup` retries a `401` the same way
  within the same budget. The run clock restarts after the probe: enrollment and settling are setup,
  not load, and counting them would deflate every throughput figure.
- **The keepalive loop ends when the lanes do.** It is periodic and has no end of its own, so it is
  bound to a context cancelled once that agent's lanes finish. Otherwise a one-pass run
  (`repeat_until: 0`) would never return on its own and its measured duration would only reflect
  whatever external timeout killed it.

```mermaid
stateDiagram-v2
    [*] --> Created
    Created --> Enrolled: agent mode, POST /enroll with an enrollment token (or authd 1515)
    Created --> Active: uds mode, synthetic id, skip control
    Enrolled --> Active: startup, POST /control (when control is enabled)

    state Active {
        [*] --> Running
        Running --> Running: keepalive loop, notify then discard response
        --
        [*] --> Lanes
        Lanes --> Lanes: lane goroutines run in parallel
    }

    Active --> Draining: lanes done, repeat_until reached, or SIGINT/SIGTERM
    Draining --> Done: agent mode, shutdown POST /control
    Draining --> Done: uds mode, just stop
    Done --> [*]
```

The `Active` state has two concurrent regions on purpose: the keepalive loop and the lanes are
independent, so a notify never waits behind a session and the lanes never wait behind a notify.

Rules:

- **The lanes run in parallel with each other**, one goroutine per lane (see
  [07](07-scenario-schema.md) and [08](08-concurrency-and-pacing.md)). An agent in the mixed fleet
  runs its FIM, SCA, syscollector, VD and engine lanes simultaneously — the realistic shape.
- **`startup` failure is fatal for the run** (`400`/`409 invalid_version` or `401` means the run
  is misconfigured — a malformed version, a version above the manager's `allow_higher_versions`
  policy, or bad signing); it **MUST** be reported as failed, not silently kept sending. As
  implemented, any non-`200` `startup` (after the `401` retries above) invalidates the run.
- **A keepalive failure is not fatal**: it is counted (`control_notify_err`) and the loop continues,
  because a manager that starts failing keepalives under load is precisely a thing to observe.
  **Not implemented as written:** only a transport error is counted and survived. Any `notify`
  answered with a status other than `200`, a wazuh-db `503` included, invalidates the run (exit `1`)
  and stops that agent's keepalive loop.
- **`notify` without `startup` is legal** on the manager side, so a scenario **MAY** model
  keepalive-only fleets; when it does it **MUST** say so, since the response contents differ even
  though the sender ignores them.

## A lane

Each lane is one goroutine walking its steps in order. A step may repeat with delays
([07](07-scenario-schema.md)); a session step is a single request/response (a `full_resync` is two,
`Cleans` then `Delta`), an engine step ships the whole sample file as one or more H/E batches
([13](13-engine-event-streams.md)). With `pacing.repeat_until` set, the lane starts over from its
first step until that deadline; otherwise it walks its steps once.

```mermaid
flowchart TD
    A[lane start] --> B{more steps?}
    B -- no --> Z[lane done]
    B -- yes --> C[wait initial_delay]
    C --> D["build request<br/>Message FullSession, or H/E batch"]
    D --> E[send one request]
    E --> F[read one response]
    F --> I["record status, latency, size<br/>by lane and fleet"]
    I --> G{session answered 503?}
    G -- with Retry-After, within feed-timeout --> H[wait Retry-After] --> D
    G -- bare, retry on and attempts left --> R[wait retry.interval] --> E
    G -- no --> J{repeat_count left?}
    J -- yes --> K[wait repeat_delay] --> D
    J -- no --> B
```

Only `/stateful` sessions re-send, on two branches. A `503` carrying `Retry-After` (FR-11) means the
CVE feed is not ready, so the buffer goes back through `build request` after the delay (bounded by
`--feed-timeout`) rather than straight to `send`. A bare `503` (backpressure) re-sends the same
bytes after `defaults.retry.interval`, up to `max_attempts` sends (see
[07](07-scenario-schema.md#retry-defaultsretry)); scenarios that count sheds set
`retry.enabled: false`. Every attempt is recorded before the decision. Every other status, and
every answer to the other step kinds, ends the step.

For a VDFirst/VDSync step specifically, that trip back through `build request` is not a no-op:
`Start.feed_offset` is re-read from the sender's own tracked value (step override, `-vd-feed-offset`,
or whatever the keepalive loop has learned by then — [05](05-flatbuffers-messages.md)) before
re-encoding, since the feed can finish loading, and the server's current offset can therefore
change, during a wait this long. Every OTHER field of the rebuilt buffer is identical to the first
attempt — the documents are a deterministic function of `(seed, docKey, spec)`, not regenerated
differently each time.

## The session itself has no state

There is no session state machine beyond "one request, one response": no acknowledgments, no
sequence numbers, no session id. Re-POSTing an identical buffer is idempotent, and that is the whole
retry story for the bare-`503` path. The feed-not-ready path re-encodes instead, and does not
reintroduce session state either, since `feed_offset` is the SENDER's own tracked knowledge, not
anything learned from or about this particular session ([05](05-flatbuffers-messages.md)).

Two properties the sender **MUST** preserve so scenarios mean what they claim:

- **Sequential steps of one lane are sequential on the wire.** The full-resync step (Cleans then
  Delta) is a test of ordering only if the second request is not sent before the first response
  arrives. There is no concurrency within a lane at all: an agent that must have two sessions in
  flight at once runs two lanes (`session_fifo_concurrent`). The loader refuses the retired
  `parallel` step kind.
- **Agents are independent**, and so are the lanes of one agent: the run's concurrency is the fleet
  size × lanes × pacing, not a barrier between steps.

## Drain

Drain is bounded by `pacing.drain_timeout` (60 s when unset; the `--drain-timeout` flag is parsed
but not used):

1. stop starting new steps and stop the keepalive loops;
2. wait for in-flight responses, up to the timeout;
3. in `agent` mode send `shutdown` per agent (best-effort, counted);
4. flush the artifacts and print the summary.

Requests still in flight when the timeout expires are counted as `abandoned_on_drain` (in the
global totals only: at that point the sender knows how many are left, not whose they were) and
reported — not failures of the manager, but a signal the window was shorter than intended. Cleanup
of the enrolled fleet is the orchestration's job (F9c-3), not the sender's. An agent's keepalive
loop and `shutdown` wait for **all** of its lanes, engine lanes included, so a long-running engine
lane keeps its agent connected (which is how `real_inspect_fleet` stays visible in the dashboard).

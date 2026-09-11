# Architecture

Three mechanisms carry the design: an asynchronous request pipeline with deferred
responses, a two-phase shutdown with named guarantees, and route classes that let one
server host a sheddable data plane without starving control traffic.

*Diagram source of truth: `src/shared_modules/uds_http_server/README.md`.*

## Request pipeline

One connection, from accept to reply — the deferred path included. A handler may return
without answering, keep its responder, and `send()` minutes later from any thread;
`send()` is exactly-once and is a defined no-op after `stop()`.

```mermaid
sequenceDiagram
    participant P as Peer (UDS client)
    participant A as Acceptor (own strand)
    participant S as Session (own strand)
    participant H as RouteHandler (inline, non-blocking)
    participant W as Consumer executor
    P->>A: connect
    A->>S: accept (liveSessions++, over maxConnections ⇒ 503+close)
    S->>S: header timer armed, doRead
    P->>S: request head
    Note over S: parser PAUSES at headers-complete
    S->>S: match route (404/405) → reserve budget (503 / 413)
    S->>S: resume, read body (chunks of bufferSize)
    S->>H: dispatch(request, responder)
    H->>W: enqueue work, return immediately
    Note over S: read buffer shrunk. response timer armed (504 backstop).<br/>1-byte peer-gone watch armed
    W-->>S: responder->send(response)  [any thread, any time]
    S->>P: response head+body, then close
    Note over S: dropping the REQUEST releases payload+reservation.<br/>a responder dropped unanswered ⇒ 503
```

## Two-phase shutdown (S1/S2/S3)

Designed to fit a daemon's 30-second stop window: `stopAccepting()` first (S1 — no
handler will ever run again; S2 — the runtime still runs, so deferred replies remain
deliverable), the consumer tears down its own pipelines, then `stop()` (S3 — `send()`
on any responder is a no-op forever after).

```mermaid
sequenceDiagram
    participant C as Consumer stop()
    participant Srv as Server
    participant IO as I/O runtime (co-owned by responders)
    C->>Srv: stopAccepting()
    Srv->>Srv: close acceptor (bounded wait), 503 every pre-handler session
    Srv->>Srv: wait for running dispatches to RETURN
    Note over Srv: S1 no handler will ever run again<br/>S2 the runtime still RUNS — deferred replies still deliverable
    C->>C: finish in-flight work, tear down pipelines the handlers used
    C->>Srv: stop()
    Srv->>Srv: drain deferred replies (drainTimeoutSec), then force-close (peer sees EOF)
    Srv->>IO: release work guard, join threads
    Note over IO: S3 send() on ANY responder is a no-op forever after —<br/>responders co-own the runtime, nothing dangles
```

## Route classes (QoS)

```mermaid
flowchart LR
    A[accept] -->|liveSessions <= maxConnections,<br/>else 503+close| H[read head]
    H --> M{match route}
    M -->|none| R404[404 / 405+Allow]
    M --> B{declared length <=<br/>class body cap?}
    B -->|no| R413[413 — the peer is wrong]
    B --> C{class session cap<br/>Data: maxConnections − reserved<br/>Control: 256 · Liveness: 64}
    C -->|over| R503c[503 — class confined]
    C --> G{charge byte budget?<br/>only Data}
    G -->|exhausted| R503b[503 — shed]
    G --> D[read body → dispatch]
```

The decisive mechanism is `reservedControlConnections`: the Data class's session cap
resolves to `maxConnections − reserved`, so the data plane alone can never drive
occupancy up to the accept-time cap — Control and Liveness always find a slot. The
honest residual: class membership is unknowable before the request head is read, so
connections racing between accept and classification occupy global slots class-blind;
the hard "control always answers" guarantee holds while the concurrency of new data
connects stays below the reserve. A Control route that does real work still sheds its
own capacity module-side (bounded queue → 503); the class only guarantees the data
plane cannot starve it.

# 08 — Concurrency and pacing

## Goroutine model

```mermaid
flowchart TD
    R[runner] -->|admits per concurrent_agents| A1[agent 1]
    R --> A2[agent 2]
    R --> An[agent N]
    W["metrics writer<br/>1 Hz snapshot to bench.csv"]
    S["signal watcher<br/>SIGINT to drain"]

    subgraph one_agent [one agent]
      direction TB
      K["keepalive loop<br/>notify every interval"]
      L1[lane fim]
      L2[lane vd]
      L3[lane engine]
    end
    A1 --- K
    A1 --- L1
    A1 --- L2
    A1 --- L3

    L1 -->|session bucket| RL[(shared EPS limiter)]
    L2 -->|session bucket| RL
    L3 -->|events_per_second (own budget)| LE[(per-agent limiter)]
```

Per run: one `runner`, one `metrics writer`, one `signal watcher`, and per active agent one
`keepalive loop` plus **one goroutine per lane the fleet lists**. A mixed-fleet agent with five
lanes is five lane goroutines plus a keepalive; 100 such agents is ~600 goroutines — still an order
of magnitude below the retired simulator, which needed a reader goroutine per agent for the ack
protocol. Nothing here needs a reader: one request, one response, on the lane's own goroutine.

The sender **MUST NOT** share an HTTP client's connection between two agents: their identities
differ per request, and connection reuse across identities makes connection cost unattributable. One
client (and one keep-alive pool) **per agent** is the model; lanes of one agent **MAY** share that
client, since they share the identity.

## Pacing

Load shape comes from independent knobs, and confusing them is the classic benchmark mistake:

- **`concurrent_agents`** bounds how many agents are Active at once — the *concurrency*.
- **`requests_per_second`** bounds the aggregate **session** rate through one shared leaky bucket
  (`golang.org/x/time/rate`) — the *throughput target*. One session = one token no matter how many
  documents it carries (a 500-document VD full sync is still one request); 503-retry attempts take
  a token each, so retries are paced traffic, never a bypass of the target.
- **An engine lane's `events_per_second`** bounds *that lane's* EVENT rate independently, so a
  syslog engine lane at 250 events/s can run beside paced inventory lanes without either starving
  the other. The unit is real events: the limiter charges each `/stateless` batch its size in
  events (`events_per_batch` groups them), so the cap holds however events are grouped into
  requests. The rate is EACH AGENT'S OWN independent budget, not a shared aggregate — the knob
  shapes what one agent produces, so N agents running the lane in parallel deliver up to
  N × `events_per_second` to the manager in total.

A run **MUST** report the target and the *achieved* rate: below target, the manager is the limit and
the number is a result; at target, the sender was the limit and the run measured its own ceiling.
`requests_per_second: 0` means unlimited — correct for saturation, wrong for latency.

The keepalive loops are **not** subject to the session bucket: their rate is the fleet size divided
by the interval, by construction, and throttling them would misrepresent a real fleet's traffic.
They are counted separately in the artifacts for the same reason.

## Deliberate saturation

Three scenarios exist to find limits rather than to be fast:

| Target | How | What to watch (scraped `/metrics`) |
|---|---|---|
| Pipeline queue (`503` shed) | Many agents, large sessions, `requests_per_second: 0` | `sync.pipeline.shed.total`, per-shard depth |
| In-flight byte budget (`413`) | One session declaring more than the total budget | `413` count (a single request, not a rate) |
| VD scan lane (`503` capacity) | A fleet of `VDFirst` sessions | `vd.capacity.503.total`, `vd.lane.depth`, `vd.lane.time` |

The VD case is sharpest: with `vd_workers = 1` (today's default, because the scanner serializes
internally — subplan F9d) a modest fleet saturates the lane, so this measures *queue behavior*, not
scan throughput. F9c-4 **MUST** state the worker count, or the numbers are not comparable against a
post-F9d run.

## Fairness and shard skew

Sessions land on `hash(agentId) % workers`, so a fleet with sequential ids does not guarantee an
even spread. A run **SHOULD** report the per-shard depth spread from `/metrics`: a fleet that
saturates one shard while others idle is a property of the fleet, not the server, and must not be
reported as a server limit.

## Interleaving lanes within one agent

The mixed fleet exists to stress the *cross-lane* paths: one agent's FIM delta, VD scan and engine
stream in flight at once exercise the pipeline's per-agent FIFO, the scan lane's cross-lane registry
(one agent never has two sessions applied at once, whichever lane they took), and the engine ingress
— simultaneously. A sender that serialized an agent's lanes would never produce that contention, so
the parallel-lanes model is not a convenience, it is the point.

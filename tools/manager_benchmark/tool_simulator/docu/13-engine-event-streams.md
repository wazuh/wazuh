# 13 — Engine event streams (`POST /stateless`)

An agent does not only synchronize inventory; it also ships a continuous stream of log-collector
events. Those go through a **different** remoted route than sessions — `POST /stateless` — and end
up in the engine, not in `inventory_sync_server`. The sender models this as a second kind of load a
lane can produce, so that a scenario can put realistic event pressure on remoted at the same time as
inventory sessions, exactly as a real fleet does (see the mixed-fleet scenario in
[07-scenario-schema.md](07-scenario-schema.md)).

Source of truth: `src/remoted/remoted_module/src/endpoints/statelessEndpoint.{hpp,cpp}`.

## The route

`POST /stateless`, HTTPS/1517, authenticated by the same gateway as everything else (see
[04-wire-protocol.md](04-wire-protocol.md)): `protocol-version: 1` plus the AES-CMAC
`Authorization`, signed over the target `/stateless` and the exact body. It exists **only in
`agent` mode** — there is no Unix-socket equivalent, because the engine ingress is remoted's own
downstream, not this module's.

## The body: an H/E batch

The body is a text batch, not FlatBuffers and not JSON: one header line, then one or more event
lines.

```text
H {"wazuh":{"agent":{"id":"1001"}}}
E 1:/var/log/syslog:Oct  6 14:02:11 host sshd[2211]: Accepted publickey for root
E 1:/var/log/syslog:Oct  6 14:02:12 host sudo: pam_unix(sudo:session): session opened
```

- The **`H ` line** carries a JSON object whose `/wazuh/agent/id` remoted cross-checks against the
  authenticated identity: a mismatch is `400`, exactly like a `/stateful` identity mismatch is
  `403`. The sender **MUST** put the agent's own id there, or the batch is rejected before it
  reaches the engine.
- Each **`E ` line** is one event: `E <location-id>:<location>:<raw log line>`. The `<location>` is
  the source path the events belong to (`/var/log/syslog`, a Windows channel name, …), and the
  remainder is the raw line verbatim. A lane's engine source (a sample log file) provides these
  lines; the sender frames each into an `E` line.

## Response mapping

remoted forwards the batch to the engine and maps the downstream result back, so the sender sees a
smaller set of codes than `/stateful`:

| Status | Meaning | Sender behavior |
|---|---|---|
| `202` | The engine enqueued the batch (empty body). NOT "fully processed" | Count as success; record latency and byte size |
| `400` | Invalid batch (missing/malformed `H` line, identity mismatch) | Count; a sender bug outside a deliberate scenario |
| `413` | Batch over the body cap | Count; the sender **MUST** size batches under the cap (10 MiB default) |
| `503` | Engine unreachable, downstream timeout, or a 5xx from it | Count as backpressure; **MUST NOT** retry |

Note the success code is **`202`**, not `200`: the engine ingest is fire-and-forget from the agent's
point of view, so a `202` says "accepted", and the sender **MUST** count it as its own success
bucket rather than folding it into the session `200`s.

## As a lane

An engine stream is a lane kind (see [07](07-scenario-schema.md)): the lane names a sample log file,
a `location`, its own event rate and its batch size. Because event lanes and session lanes run on
independent goroutines within one agent (see [08](08-concurrency-and-pacing.md)), a mixed scenario
produces the real thing — one agent simultaneously syncing FIM/SCA/syscollector inventory and
streaming syslog — and the artifacts count the two independently (`stateless_*` columns in
[09](09-metrics-and-output.md)).

Three rules keep an event lane honest:

- Its rate is the lane's own `events_per_second`, separate from the session rate limiter: log
  volume and inventory volume stress different paths (the engine vs the sync pipeline) and must be
  dialed independently. The unit is real events — the limiter charges each batch its size — and the
  rate is EACH agent's own independent budget: every agent running the lane paces itself against
  `events_per_second`, so the manager-side total scales with the fleet size
  (`events_per_second × agents running the lane`), not a fixed aggregate.
- `events_per_batch` sets how many events ride one `/stateless` request (0 = the whole sample file
  as a single batch). One pass always ships the entire file, split into as many requests as the
  batch size implies, so `stateless_sent` counts requests and `events_sent` counts events.
- Sustained pressure comes from the run's own repetition (`repeat_count` on the step or the run's
  `repeat_until`), the same mechanism every other lane uses; the stream stops at drain with
  everything else.

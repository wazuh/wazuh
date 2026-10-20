# 13 — Engine event streams (`POST /stateless`)

An agent does not only synchronize inventory; it also ships a continuous stream of log-collector
events. Those go through a **different** remoted route than sessions — `POST /stateless` — and end
up in the engine, not in `inventory_sync_server`. The sender models this as a second kind of load a
lane can produce, so that a scenario can put realistic event pressure on remoted at the same time as
inventory sessions, exactly as a real fleet does (see the mixed-fleet scenario in
[07-scenario-schema.md](07-scenario-schema.md)).

Source of truth: `src/remoted/remoted_module/src/endpoints/statelessEndpoint.{hpp,cpp}`.

## The route

In **agent** mode: `POST /stateless`, HTTPS/1517, authenticated by the same gateway as everything
else (see [04-wire-protocol.md](04-wire-protocol.md)): `protocol-version: 1` plus the
`wazuh-agent+jwt` bearer `Authorization` (identity only; the body is not part of authentication).
This exercises the whole relay: JWT, the identity check, forwarding and the engine.

In **uds** mode the sender skips remoted and is itself an engine producer: it posts the same batch
to the engine's own `POST /events/enriched` on `--socket` (the engine ingest socket,
`<WAZUH_HOME>/queue/sockets/engine-ingest-http.sock`) with `Content-Type: application/x-ndjson` and
`X-Wazuh-Agent-Id: <agent id>`, the header remoted adds for the agent it authenticated. Synthesized
ids are canonical (`"001"`), so the header and the H line carry the same spelling. Nothing has to be
enrolled, which is what makes a distinct-id flood (`engine_direct_flood`) cheap. The engine answers
`200` where remoted answers `202`, and both count in the same success bucket (`s202`). With
`run_benchmark.sh`, pass the engine ingest socket as `--socket`. The engine's own counters
(`agent.cache.*`, `server.*`) come from the monitor's `analysisd` source (`POST /metrics/dump` on the
engine API socket), not from `--socket`. A uds run has a single `--socket`, so it cannot mix
inventory lanes and engine lanes: a `404` on an engine batch (the inventory-sync socket, the default)
invalidates the run instead of losing every batch.

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
  lines; the sender frames each into an `E` line, always with location id `1` and the step's
  `location` (`internal/engine/batch.go`).

## Response mapping

remoted forwards the batch to the engine and maps the downstream result back, so the sender sees a
smaller set of codes than `/stateful`:

| Status | Meaning | Sender behavior |
|---|---|---|
| `202` | The engine enqueued the batch (empty body). NOT "fully processed" | Count as success; record latency and the event count (`stateless_*` has no byte counter) |
| `400` | Invalid batch (missing/malformed `H` line, identity mismatch) | Count, then invalidate the run: no scenario sends a deliberately invalid batch, so it is a sender bug |
| `413` | Batch over the body cap | Count; the sender **MUST** size batches under the cap: remoted's authenticated-body cap, `remoted.auth_max_body_size` (5 MiB default). Past the 10 MiB transport cap there is no `413`, only a closed connection (a transport error) |
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

## Shaping the header

By default the `H ` line is the minimal one above. An optional `header` block on the step shapes it,
so a run can measure how header size and layout drive remoted's identity check and the engine's
agent metadata cache:

| Field | Effect |
|---|---|
| `pad_bytes` | Exact size of the H-line JSON (the text after `H `), reached by growing a `bench_pad` member under `wazuh.agent`. The loader refuses a size some agent cannot reach and, in agent mode, anything over remoted's 8192-byte cap (every batch would be `400`) |
| `extra_fields` | That many `bench_field_<n>` string members under `wazuh.agent` |
| `off_path_fields` | That many members under a root `bench` object, outside `wazuh` |
| `id_position` | `first` (default) or `last`: where `id` sits among the members of `wazuh.agent` |
| `change_every` | Change the header every N batches the agent sends, through a `wazuh.agent.bench_seq` counter (`0` = never). The counter belongs to the agent and survives repeated passes, so the header keeps changing for the whole run |

The identity path (`wazuh`, `wazuh.agent`, `wazuh.agent.id`) always appears exactly once, and the
same inputs always give the same bytes, so a stable header is a byte-identical repeat.
`engine_header_shapes` puts the shapes side by side.

The step needs `engine` (the sample file, relative to the scenario file) and `location`;
`events_per_second` and `events_per_batch` default to `0` (unlimited, and the whole file in one
batch). A sample file that cannot be read sends nothing and is not reported, so check `events_sent`
(`--validate` does catch a path that does not exist).

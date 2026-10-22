# 07 — Scenario schema

A scenario is one JSON file: it fully determines a run, so a run is reproducible from the file plus
the CLI overrides recorded with the artifacts. The sender validates it up front
(`internal/scenario/loader.go`, plus `internal/verdict` for `expected`) and refuses to start (exit
`2`) on an unknown field, an unknown step kind, an unknown `option`, an unknown `expected` counter
or operator, or a referenced file that does not exist — a typo must not silently produce a
different measurement. Values of the free-text fields (`module`, `checksum`, `raw`) are not checked;
what an unrecognized one builds is said below.

The model is **lanes and fleets**, so that a single run can put *heterogeneous* load on the manager
at once — the realistic case, where a Windows fleet and a Linux fleet each run several modules in
parallel and stream logs, all simultaneously. This is the structure the retired simulator's
`mixed_fleet_windows_linux_full` scenario used, kept because it is the only way to reproduce
production-shaped pressure.

```json
{
  "name": "mixed_fleet_windows_linux",
  "description": "Two fleets, each running FIM and VD inventory lanes and a syslog engine lane in parallel.",
  "mode": "agent",
  "defaults": {
    "module": "syscollector",
    "option": "Sync",
    "cluster_name": "cluster01",
    "control": { "enabled": true, "keepalive_interval": "10s", "send_host_info": true, "startup_version": "5.0.0" },
    "retry": { "enabled": true, "interval": "500ms", "max_attempts": 10 }
  },
  "lanes": {
    "fim_windows": [
      { "kind": "full_resync", "module": "fim", "indices": ["wazuh-states-fim-files"],
        "documents": { "count": 500, "size_bytes": 512 } },
      { "kind": "delta", "module": "fim", "indices": ["wazuh-states-fim-files"],
        "documents": { "count": 20 }, "repeat_count": 10, "repeat_delay": "3s", "initial_delay": "0s" }
    ],
    "vd_windows": [
      { "kind": "delta", "module": "syscollector", "option": "VDFirst",
        "indices": ["wazuh-states-inventory-packages"], "documents": { "count": 300 } },
      { "kind": "delta", "option": "VDSync", "documents": { "count": 30 },
        "repeat_count": 20, "repeat_delay": "5s", "initial_delay": "10s" }
    ],
    "fim_linux": [
      { "kind": "full_resync", "module": "fim", "indices": ["wazuh-states-fim-files"],
        "documents": { "count": 300, "size_bytes": 512 } }
    ],
    "vd_linux": [
      { "kind": "delta", "module": "syscollector", "option": "VDFirst",
        "indices": ["wazuh-states-inventory-packages"], "documents": { "count": 300 } }
    ],
    "engine": [
      { "kind": "engine", "engine": "../sample_payloads/engine/syslog.log", "location": "syslog",
        "events_per_second": 250, "events_per_batch": 100 }
    ]
  },
  "fleets": [
    { "name": "windows", "agents": 50, "first_id": 1000, "lanes": ["fim_windows", "vd_windows", "engine"],
      "start": { "osname": "Windows 11", "osplatform": "windows", "ostype": "windows", "architecture": "x86_64" } },
    { "name": "linux", "agents": 50, "first_id": 2000, "lanes": ["fim_linux", "vd_linux", "engine"],
      "start": { "osname": "Ubuntu", "osplatform": "ubuntu", "ostype": "linux", "osversion": "22.04" } }
  ],
  "pacing": { "concurrent_agents": 0, "requests_per_second": 0, "repeat_until": "0", "drain_timeout": "90s" }
}
```

## Blocks

| Block | Meaning |
|---|---|
| `name`, `description` | Free text; `name` is echoed by `--validate` and recorded as `meta.scenario_name` |
| `mode` | `uds` or `agent` (required: anything else is refused). **MAY** be omitted from the file only when `--mode` supplies it per run, which is how the relay overhead is measured on one file. `engine`, `scan_vd`, `cacerts` and `enroll_https` steps are `agent`-mode only, `delete_agent` `uds`-mode only |
| `defaults` | Inherited by every lane step unless overridden (below) |
| `lanes` | A named map of **lane definitions**. A lane is an ordered list of steps one agent walks (see below). Lanes are the reusable unit — many fleets reference the same lane |
| `fleets` | One or more fleets (none is refused), below |
| `pacing` | Run-level load shape: concurrency, request rate, how long to run, drain window |
| `expected` | **Optional** contract assertions on the run's final counters (below). Absent = the run is never judged |

### `defaults`

| Field | Meaning |
|---|---|
| `module`, `option` | Fallbacks for a step that leaves them unset ([05](05-flatbuffers-messages.md#start)). `option`, here and on a step, is `Sync`, `VDFirst` or `VDSync` (lower case accepted) or absent; any other value is refused |
| `cluster_name` | The cluster every session declares, unless `--cluster` overrides it (see the conventions) |
| `documents` | `{count, size_bytes}` fallback for a step with no `documents` |
| `control` | The `/control` traffic (agent mode only), below |
| `retry` | The bare-`503` retry policy, [below](#retry-defaultsretry) |
| `compression` | Encoding of the `/stateful` session bodies ([04](04-wire-protocol.md#content-encoding-zstd-agent-mode-only)): `""`/absent = **the per-transport default — zstd in agent mode** (what a real 5.x agent does), plain in uds mode (its ingress has no decoder); `"none"` = explicitly off; `"zstd"` = forced (agent mode only; refused in uds). Any other value is refused. `--compression zstd\|none` overrides it per run, which makes the with/without A/B one scenario instead of two |

`defaults.control` ([03](03-control-protocol.md)):

| Field | Default | Meaning |
|---|---|---|
| `enabled` | `false` | Send `startup`, the `notify` keepalives and `shutdown` per agent. Off, an agent-mode run sends no control traffic beyond the readiness probe ([06](06-agent-state-machine.md)) |
| `keepalive_interval` | `10s` (also for `0`) | Interval between one agent's notifies; the effective value is what `meta.keepalive_interval` records ([09](09-metrics-and-output.md)) |
| `send_host_info` | `false` | Add the `host` block to every notify (the expensive variant a real agent sends) |
| `startup_version` | `5.0.0` | `version` of `startup`, and `agent.version` of every notify |

### `fleets`

| Field | Meaning |
|---|---|
| `name` | Fleet name: the `by_fleet` key and part of each agent's name, `bench-<name>-<NNNN>` (`bench` when empty) |
| `agents` | Agent count; must be > 0 |
| `first_id` | Default `0`. Numbers the fleet's agents `first_id + i`: their names, and in `uds` mode their ids. In `agent` mode the manager assigns the ids at enrollment, so it only names them |
| `lanes` | The lanes every agent of the fleet runs in parallel; at least one, each a key of `lanes` |
| `start` | Per-fleet metadata stamped onto the fleet's sessions (and its notifies' `host` block): `architecture`, `osname`, `osplatform`, `ostype`, `osversion`, `agentversion` (also the version an enrollment claims). An unset one falls back to the built-in value of [05](05-flatbuffers-messages.md#start) (`x86_64`, `Ubuntu`, `ubuntu`, `linux`, `22.04`, `5.0.0`), not to `defaults` |

This layering (built-in → `defaults` → fleet/step) is what lets one file carry a Windows fleet and a
Linux fleet with different metadata but shared lane logic.

The step rules (kind, mode, field combinations) are checked only on the lanes some fleet
references: a lane no fleet lists is never run and its steps are never checked, though the files
its `engine`/`dump` fields name must still exist.

## Lanes run in parallel

Within one agent, **every lane the fleet lists runs concurrently**, each on its own goroutine
([08](08-concurrency-and-pacing.md)). A `windows` agent above runs `fim_windows`, `vd_windows` and
`engine` at the same time — first-scan bursts, VD deltas and a syslog stream overlapping — which is
what a real agent does and what stresses the manager's cross-lane paths (the sync pipeline and the
scan lane sharing one agent's ordering, plus the engine ingress).

Steps **within** a lane are sequential; lanes **within** an agent are parallel; agents are
independent.

## Step kinds

| `kind` | Session built | Notes |
|---|---|---|
| `delta` | `ModuleDelta` + `SyncData` | `documents` (or `defaults.documents`) controls count and size, or a `dump` replays a capture (below); `checksum.hash.sha1` is always present — see the conventions; `contexts` **MAY** add VD context items; `option` picks `Sync`/`VDFirst`/`VDSync` (any other value is refused at load); for `VDFirst`/`VDSync`, `feed_offset` **MAY** override `Start.feed_offset` (see [05](05-flatbuffers-messages.md)) |
| `cleans` | `ModuleDelta` + `Cleans` | Cleans the step's `indices`, else `wazuh-states-inventory-packages` |
| `checksum` | `ModuleCheck` + `ChecksumModule` | On the step's first index (`wazuh-states-inventory-packages` by default). `checksum` is `"correct"` or absent (the aggregate over the documents a `delta` of the same lane, module and `documents` spec generates — so it matches when that is what the agent sent), `"mismatch"` (40 zeros), or any other string sent as is |
| `metadata` / `groups` | `MetadataDelta` / `GroupDelta` | Start-only; the loader requires `indices`. Set `global_version` too: the server needs it for these modes, but the loader does not check it. The `*Check` variants cannot be built from a scenario |
| `full_resync` | Expands to `cleans` + `delta` | The D19 composition, as two sequential sessions on the same lane (one repetition sends both) |
| `delete_agent` | `POST /_internal/agents/delete` | `uds` mode only; body `{"agent_id":"<id>"}` |
| `engine` | An H/E event batch to `POST /stateless` | `agent` mode only; see [13](13-engine-event-streams.md) |
| `scan_vd` | A feed-update re-scan request to `POST /scan/vd` | `agent` mode only; takes ONLY `feed_offset` and the timing fields — no payload; see [14](14-scan-vd.md) |
| `cacerts` | A body-less `GET /cacerts` (the CA that signs the listener certificate) | `agent` mode only; takes ONLY the timing fields (`repeat_count`, `repeat_delay`, `initial_delay`); see [15](15-cacerts.md) |
| `enroll_https` | A `POST /enroll` of a FRESH agent name with the `wazuh-enroll+jwt` bearer of an enrollment token | `agent` mode only; takes ONLY the timing fields; the token comes from `--enroll-token-file` / `WAZUH_ENROLLMENT_TOKEN`, never from the scenario; see [16](16-enroll-https.md) |
| `raw` | A deliberately invalid `/stateful` body, never compressed | `raw` picks the body: `garbage` or absent → `this is not a flatbuffer at all`; `empty` → an empty body; `oversized` → a single byte (it does not trip a size limit; use a large `documents` spec for the `413`); `not_full_session` or any other value → `not a full session message`. None of them is a FlatBuffer, so every one exercises the verifier's rejection, not a valid non-`FullSession` message |

Concurrency is expressed with lanes, never with a step kind: an agent that must POST two sessions
at once runs two lanes (the FIFO-ordering scenario). An earlier `parallel` kind was accepted
without an implementation and silently degraded to a `delta`; it is refused now.

## Replaying real payloads

A `delta` or `full_resync` step **MAY** carry a `dump` instead of a `documents` spec (any other
kind with a `dump` is refused): a path to a captured-session file (`sample_payloads/dumps/`, JSON
`{"metadata": {module, option, indices, …}, "items": [{operation, id, index, version, data}]}`)
whose recorded items are sent verbatim, so the wire bytes match production shapes rather than a
generator's. The dump's `module` and `option` are used only when neither the step nor `defaults`
sets one, and its `indices` when the step has none; the fleet's OS/host metadata still comes from
the `start` block. Document ids are prefixed with the agent id, so a fleet replaying one dump does
not have every agent overwrite the same `_id`. A `full_resync` with a `dump` cleans the dump's own
indices before replaying it. Paths are resolved relative to the scenario file's own directory, so
from `scenarios/` a payload is `../sample_payloads/...`. Every load (not only `--validate`) stats
every referenced `dump` and `engine` file, so a typo is a load-time error; a dump that exists but
cannot be decoded invalidates the run when a step first uses it (exit `1`).

A dump path ending in `.zst` is decompressed transparently at load. The `dumps/first_connect/`
corpus is stored that way: the FULL-fidelity first-connection captures (the Windows FIM first sync
alone is 27,726 items / ~27 MB of JSON — 21,091 registry-values + 6,625 registry-keys + 10 files)
would otherwise put ~32 MB of JSON in the repo; compressed they are ~2.6 MB. The plain `dumps/*.json`
files keep the representative truncated slices the per-module `real_*` scenarios use.

## Per-step timing

A lane step **MAY** carry:

| Field | Meaning |
|---|---|
| `repeat_count` | Send the step this many times (0, negative or absent = once). A steady delta stream is `delta` with a high `repeat_count` |
| `repeat_delay` | Wait this long between repeats (not after the last) |
| `initial_delay` | Wait this long before the step's first send — how lanes are staggered (VD starting after FIM has seeded, say), and how a `scan_vd` step waits for the inventory it re-scans to reach the indexer |

Durations are Go duration strings (`"3s"`, `"5m"`, `"500ms"`); `""` means zero, and anything else
that does not parse is refused at load.

## Pacing

| Field | Meaning |
|---|---|
| `concurrent_agents` | How many agents are Active at once. `0` (or a value ≥ the fleet total) = all of them |
| `requests_per_second` | Aggregate session rate through a shared leaky bucket. `0` = unlimited (correct for saturation, wrong for latency) |
| `repeat_until` | Keep replaying every fleet's lanes until this duration elapses (`"0"` = one pass of each lane's steps) |
| `drain_timeout` | The bounded shutdown window (see [10](10-error-handling-and-shutdown.md)); `60s` when unset. The sender's `--drain-timeout` flag, when set (> 0), overrides it |

**What `requests_per_second` counts**: `/stateful` sessions, `POST /_internal/agents/delete`,
`POST /scan/vd`, `GET /cacerts` and measured `POST /enroll` requests, one token each (not
`/control`, not `/stateless`, not the bootstrap enrollment). A session's document count does NOT weigh against it — a VD full sync of 500 documents is one
FlatBuffer, one request, one token. Session *volume* is shaped with `documents.count`/`size_bytes`
and observed in the summary's `documents_per_second`; the rate knob shapes how often the server sees
a session. Engine lanes have their own knob in real event units (`events_per_second`, [13](13-engine-event-streams.md)),
applied per agent — the manager-side total scales with how many agents run the lane. Both targets
are recorded with the artifacts.

## Retry (defaults.retry)

| Field | Meaning |
|---|---|
| `enabled` | Re-send a `/stateful` session answered a bare `503` (backpressure shed). Default `true` — it is what a real agent does. Scenarios whose object is to COUNT sheds set it to `false` |
| `interval` | Delay between attempts (default `"500ms"`, also for `"0"`; negative is refused) |
| `max_attempts` | Total send attempts per session, feed-not-ready ones included (default `10`; `0` or negative = unbounded, cut only by drain) |

The `503` **with** `Retry-After` (the CVE feed still downloading) keeps its own contract: the header
dictates the delay (clamped to 1–30 s) and `--feed-timeout` bounds the budget, regardless of
`enabled`. `/stateless`
event batches are never retried — an agent's events are lost the same way. Every attempt consumes a
`requests_per_second` token and is recorded (`sessions_sent` counts attempts; `retries_feed` /
`retries_503` tell the re-sends apart, and `retries_exhausted` counts sessions abandoned with the
budget spent).

## Expected (optional verdict)

```json,fragment
{
  "expected": {
    "sessions":  { "ok": { "eq": 48 }, "s5xx": { "eq": 0 }, "s503_retry_after": { "gte": 1 } },
    "stateless": { "s202": { "gte": 1 } },
    "scan":      { "sent": { "eq": 100 }, "other": { "eq": 0 } },
    "cacerts":   { "sent": { "eq": 200 }, "s200": { "eq": 200 }, "other": { "eq": 0 } },
    "enroll_https": { "sent": { "eq": 100 }, "s200": { "eq": 100 }, "s401": { "eq": 0 }, "other": { "eq": 0 } },
    "control":   { "startup_err": { "eq": 0 } },
    "deletes":   { "err": { "eq": 0 } },
    "transport_errors": { "eq": 0 },
    "retries_exhausted": { "eq": 0 }
  }
}
```

Assertions run against the run's **final total counters** (the summary's `totals` section, same
names; `s5xx` is the derived `s500 + s503`). The group keys and their counters are the tables in
`internal/verdict/verdict.go`: `sessions` (every `totals.sessions` key except `bytes_sent`, plus
`s5xx`), `stateless`, `control`, `scan`, `cacerts`, `enroll_https`, `deletes` (each with exactly
the keys of its `totals` block), and the two top-level counters `transport_errors` and
`retries_exhausted`. Operators are `eq`, `gte` and `lte`; several on one counter form a
conjunction, and an empty assertion (`{}`) is refused. **Counters only, by design**: statuses and counts are properties of the
protocol contract and hold on any hardware, while latency and throughput belong to the machine that
produced them — a committed threshold from one laptop would fail on the next. Counts that depend on
load shedding are asserted with `gte`/`lte` or left out.

A failed expectation exits `3` and writes the verdict into `sender_summary.json` (`expected.passed`,
`expected.checked`, `expected.failures[]`, each failure reading
`<group>.<counter>: expected <op> <value>, got <actual>`); the measurement itself is still VALID. The block is strict-checked at load
time (unknown counter or operator = refused), and evaluation is skipped entirely when the run is
already invalid — judging counters produced by an unauthenticated fleet would be judging noise.

## Conventions

- `documents.size_bytes` is the length of the filler in one generated document (its serialized
  size is that plus the fixed fields); the filler rides in a mapped field of a realistic shape
  rather than in one giant string, because document count and document size stress different parts
  of the pipeline (per-document overlay vs bulk bytes). `count: 0` sends an empty `values` vector.
- **Every generated document carries `checksum.hash.sha1`, and there is no knob to omit it.** A real
  agent has no checksum-less mode: syscollector writes `/checksum/hash/sha1` into every item it emits
  (`syscollectorImp.cpp`), SCA computes one per check (`sca_event_handler.cpp`), FIM keeps it as a
  column of its own, and every one of the ~34,000 documents of the captured corpus in
  `sample_payloads/dumps/` has one. It is also what the `ModuleCheck` aggregate is computed over, so a document without it is a
  document the integrity path could never reconcile. The former `documents.with_checksum` field was
  **retired**, not defaulted to `true`: a scenario that still sets it is refused at load time, like
  every other retired knob, rather than reading as a choice the sender does not have.
- **Generated documents MUST satisfy the target index's mapping.** The real state indices are
  `dynamic: strict`, so a field that is not in the mapping makes the indexer reject the whole bulk
  with `400` and the session answer `500` — the load never reaches the pipeline being measured. The
  generator therefore uses only mapped fields and rides the size filler in one of them rather than
  in a synthetic `pad`. It has three shapes, chosen by the step's first index
  (`internal/source/documents.go`): `file` (filler in `file.path`) for `wazuh-states-fim-files`,
  `check` (filler in `check.description`) for `wazuh-states-sca`, and `package` (filler in
  `package.description`) for every other index. A generated step on any other state index (the
  FIM registry indices, the other inventory indices) therefore sends package-shaped documents the
  mapping refuses; for those, and for realistic VD load, use the `dump` replay of real captured
  payloads, which is mapping-valid by construction.
- **The cluster name is environment config, not scenario content.** The server answers `403` to a
  session whose `cluster_name` is not its own, so the value in the file is only a default:
  `--cluster` overrides it per run, which is what makes one scenario library usable against any
  manager. There is **no cluster node**: `defaults.cluster_node` was retired (a file that still
  declares it is refused at load time), and `Start` no longer has such a field — see
  [05](05-flatbuffers-messages.md).
- Document generation is deterministic from the seed (`--seed`, or a random one when `0`),
  recorded in `meta.document_seed`: two runs of one scenario with the same seed send byte-identical
  payloads, or the comparison is not one.
- **There is no pass/fail gate unless the scenario opts in.** A scenario declares *what to send*;
  the sender records every outcome (every status code, every latency, per lane and per fleet) and
  reports it. A saturation run that is *supposed* to produce `503`s is not mislabeled a failure.
  The one opt-in exception is the `expected` block above — counter-only contract assertions, exit
  `3` on failure. What the sender always fails on is a broken run (a `401`, a non-`200` answer to a
  `/control` `startup` or `notify`, a `400` from `/stateless`, an answer outside the contract of
  `/scan/vd`, `/cacerts` or a measured `/enroll`, a dump that cannot be decoded, any transport error
  in `uds` mode), because those mean the measurement itself is invalid — see
  [10](10-error-handling-and-shutdown.md).
- The scenario file used **MUST** be copied into the run's artifacts verbatim (F9c-3), together with
  the effective CLI parameters.

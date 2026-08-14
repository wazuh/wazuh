# 07 — Scenario schema

A scenario is one JSON file: it fully determines a run, so a run is reproducible from the file plus
the CLI overrides recorded with the artifacts. The sender **MUST** validate it up front and refuse
to start on an unknown field — a typo must not silently produce a different measurement.

The model is **lanes and fleets**, so that a single run can put *heterogeneous* load on the manager
at once — the realistic case, where a Windows fleet and a Linux fleet each run several modules in
parallel and stream logs, all simultaneously. This is the structure the retired simulator's
`mixed_fleet_windows_linux_full` scenario used, kept because it is the only way to reproduce
production-shaped pressure.

```json
{
  "name": "mixed_fleet_windows_linux",
  "description": "Two fleets, each running FIM + SCA + syscollector + VD inventory lanes and a syslog engine lane in parallel.",
  "mode": "agent",
  "defaults": {
    "module": "syscollector",
    "option": "Sync",
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
| `mode` | `uds` or `agent`. **MAY** be omitted and supplied per run by the orchestration, which is how the relay overhead is measured. `engine` lanes are `agent`-mode only (see [13](13-engine-event-streams.md)) |
| `defaults` | Inherited by every lane step and every fleet unless overridden. Includes the default `control` block and the `retry` policy (below) |
| `lanes` | A named map of **lane definitions**. A lane is an ordered list of steps one agent walks (see below). Lanes are the reusable unit — many fleets reference the same lane |
| `fleets` | One or more fleets. Each names its agent count, id range, the lanes its agents run in parallel, and a `start` block of per-fleet metadata (OS, arch) stamped onto that fleet's sessions |
| `pacing` | Run-level load shape: concurrency, request rate, how long to run, drain window |
| `expected` | **Optional** contract assertions on the run's final counters (below). Absent = the run is never judged |

`defaults` also carries `compression` for the `/stateful` session bodies (see
[04](04-wire-protocol.md)): `""`/absent = **the per-transport default — zstd in agent mode** (what
a real 5.x agent does), plain in uds mode (its ingress has no decoder); `"none"` = explicitly off;
`"zstd"` = forced (agent mode only). The `--compression zstd|none` CLI flag overrides it per run,
which makes the with/without A/B one scenario instead of two.

Anything a fleet or a step does not set is taken from `defaults`; anything `defaults` does not set
has a built-in default. This three-level inheritance (built-in → `defaults` → fleet/step) is what
lets one file carry a Windows fleet and a Linux fleet with different metadata but shared lane logic.

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
| `delta` | `ModuleDelta` + `SyncData` | `documents` controls count and size (`checksum.hash.sha1` is always present — see the conventions); `contexts` **MAY** add VD context items; `option` picks `Sync`/`VDFirst`/`VDSync`; for `VDFirst`/`VDSync`, `feed_offset` **MAY** override `Start.feed_offset` (see [05](05-flatbuffers-messages.md)) |
| `cleans` | `ModuleDelta` + `Cleans` | `indices` overrides the defaults |
| `checksum` | `ModuleCheck` + `ChecksumModule` | `checksum` is `"correct"` (computed from what this agent sent), `"mismatch"`, or a literal |
| `metadata` / `groups` | `MetadataDelta` / `GroupDelta` (or `*Check`) | Start-only; needs `indices` and `global_version` |
| `full_resync` | Expands to `cleans` + `delta` | The D19 composition, as two sequential sessions on the same lane |
| `delete_agent` | `DELETE /agents` | `uds` mode only |
| `engine` | An H/E event batch to `POST /stateless` | `agent` mode only; see [13](13-engine-event-streams.md) |
| `scan_vd` | A feed-update re-scan request to `POST /scan/vd` | `agent` mode only; takes ONLY `feed_offset` and the timing fields — no payload; see [14](14-scan-vd.md) |
| `raw` | A deliberately invalid body | Rejection paths: `not_full_session`, `garbage`, `empty`, `oversized` |

Concurrency is expressed with lanes, never with a step kind: an agent that must POST two sessions
at once runs two lanes (the FIFO-ordering scenario). An earlier `parallel` kind was accepted
without an implementation and silently degraded to a `delta`; it is refused now.

## Replaying real payloads

A `delta` or `full_resync` step **MAY** carry a `dump` instead of a `documents` spec: a path to a
captured-session file (`sample_payloads/dumps/`) whose recorded items are sent verbatim, so the wire
bytes match production shapes rather than a generator's. Its `module`, `option` and `indices` fill
whatever the scenario left unset (a dump is self-describing), while the fleet's OS/host metadata still
comes from the `start` block. Document ids are namespaced per agent, exactly as generated documents
are, so a fleet replaying one dump does not have every agent overwrite the same `_id`. A `full_resync`
with a `dump` cleans the dump's own indices before replaying it. Paths are resolved relative to the
scenario file's own directory, so from `scenarios/` a payload is `../sample_payloads/...`; a typo is a
load-time error (`--validate` stats every referenced file).

A dump path ending in `.zst` is decompressed transparently at load. The `dumps/first_connect/`
corpus is stored that way: the FULL-fidelity first-connection captures (the Windows FIM first sync
alone is 27,726 items / ~27 MB of JSON — 21,091 registry-values + 6,625 registry-keys + 10 files)
would otherwise put ~30 MB of JSON in the repo; compressed they are ~2.6 MB. The plain `dumps/*.json`
files keep the representative truncated slices the per-module `real_*` scenarios use.

## Per-step timing

A lane step **MAY** carry:

| Field | Meaning |
|---|---|
| `repeat_count` | Send the step this many times (0 or absent = once). A steady delta stream is `delta` with a high `repeat_count` |
| `repeat_delay` | Wait this long between repeats |
| `initial_delay` | Wait this long before the step's first send — how lanes are staggered (VD starting after FIM has seeded, say), and how a `scan_vd` step waits for the inventory it re-scans to reach the indexer |

Durations are Go duration strings (`"3s"`, `"5m"`).

## Pacing

| Field | Meaning |
|---|---|
| `concurrent_agents` | How many agents are Active at once. `0` = all of them |
| `requests_per_second` | Aggregate session rate through a shared leaky bucket. `0` = unlimited (correct for saturation, wrong for latency) |
| `repeat_until` | Keep replaying every fleet's lanes until this duration elapses (`"0"` = one pass of each lane's steps) |
| `drain_timeout` | The bounded shutdown window (see [10](10-error-handling-and-shutdown.md)) |

**What `requests_per_second` counts**: `/stateful` sessions, `DELETE /agents` and `POST /scan/vd`
requests, one token each. A session's document count does NOT weigh against it — a VD full sync of 500 documents is one
FlatBuffer, one request, one token. Session *volume* is shaped with `documents.count`/`size_bytes`
and observed in the summary's `documents_per_second`; the rate knob shapes how often the server sees
a session. Engine lanes have their own knob in real event units (`events_per_second`, [13](13-engine-event-streams.md)),
applied per agent — the manager-side total scales with how many agents run the lane. Both targets
are recorded with the artifacts.

## Retry (defaults.retry)

| Field | Meaning |
|---|---|
| `enabled` | Re-send a `/stateful` session answered a bare `503` (backpressure shed). Default `true` — it is what a real agent does. Scenarios whose object is to COUNT sheds set it to `false` |
| `interval` | Delay between attempts (default `"500ms"`) |
| `max_attempts` | Total send attempts per session (default `10`; `0` = unbounded, cut only by drain) |

The `503` **with** `Retry-After` (the CVE feed still downloading) keeps its own contract: the header
dictates the delay and `--feed-timeout` bounds the budget, regardless of this block. `/stateless`
event batches are never retried — an agent's events are lost the same way. Every attempt consumes a
`requests_per_second` token and is recorded (`sessions_sent` counts attempts; `retries_feed` /
`retries_503` tell the re-sends apart, and `retries_exhausted` counts sessions abandoned with the
budget spent).

## Expected (optional verdict)

```json
"expected": {
  "sessions":  { "ok": { "eq": 48 }, "s5xx": { "eq": 0 }, "s503_retry_after": { "gte": 1 } },
  "stateless": { "s202": { "gte": 1 } },
  "scan":      { "sent": { "eq": 100 }, "other": { "eq": 0 } },
  "control":   { "startup_err": { "eq": 0 } },
  "deletes":   { "err": { "eq": 0 } },
  "transport_errors": { "eq": 0 },
  "retries_exhausted": { "eq": 0 }
}
```

Assertions run against the run's **final total counters** (the summary's `totals` section, same
names; `s5xx` is the derived `s500 + s503`). Operators are `eq`, `gte` and `lte`; several on one
counter form a conjunction. **Counters only, by design**: statuses and counts are properties of the
protocol contract and hold on any hardware, while latency and throughput belong to the machine that
produced them — a committed threshold from one laptop would fail on the next. Counts that depend on
load shedding are asserted with `gte`/`lte` or left out.

A failed expectation exits `3` and writes the verdict into `sender_summary.json` (`expected.passed`,
`expected.failures[]`); the measurement itself is still VALID. The block is strict-checked at load
time (unknown counter or operator = refused), and evaluation is skipped entirely when the run is
already invalid — judging counters produced by an unauthenticated fleet would be judging noise.

## Conventions

- `documents.size_bytes` is the approximate serialized size of one document; the generator pads a
  realistic shape rather than one giant string, because document count and document size stress
  different parts of the pipeline (per-document overlay vs bulk bytes).
- **Every generated document carries `checksum.hash.sha1`, and there is no knob to omit it.** A real
  agent has no checksum-less mode: syscollector writes `/checksum/hash/sha1` into every item it emits
  (`syscollectorImp.cpp`), SCA computes one per check (`sca_event_handler.cpp`), FIM keeps it as a
  column of its own, and all 32,000 documents of the captured corpus in `sample_payloads/dumps/` have
  one. It is also what the `ModuleCheck` aggregate is computed over, so a document without it is a
  document the integrity path could never reconcile. The former `documents.with_checksum` field was
  **retired**, not defaulted to `true`: a scenario that still sets it is refused at load time, like
  every other retired knob, rather than reading as a choice the sender does not have.
- **Generated documents MUST satisfy the target index's mapping.** The real state indices are
  `dynamic: strict`, so a field that is not in the mapping makes the indexer reject the whole bulk
  with `400` and the session answer `500` — the load never reaches the pipeline being measured. The
  generator therefore uses only mapped fields and rides the size filler in `package.description`
  rather than a synthetic `pad`. Its shape is packages-flavoured, so a generated-document step
  belongs on `wazuh-states-inventory-packages`; for FIM/SCA/VD load use the `dump` replay of real
  captured payloads, which is mapping-valid by construction.
- **The cluster name is environment config, not scenario content.** The server answers `403` to a
  session whose `cluster_name` is not its own, so the value in the file is only a default:
  `--cluster` overrides it per run, which is what makes one scenario library usable against any
  manager. There is **no cluster node**: `defaults.cluster_node` was retired (a file that still
  declares it is refused at load time) and no session sets `Start.cluster_node`, because the manager
  never validated it and the tool was only echoing back a value it had read from the manager's own
  configuration — see [05](05-flatbuffers-messages.md).
- Document generation is deterministic from a seed recorded in the run metadata: two runs of one
  scenario send byte-identical payloads, or the comparison is not one.
- **There is no pass/fail gate unless the scenario opts in.** A scenario declares *what to send*;
  the sender records every outcome (every status code, every latency, per lane and per fleet) and
  reports it. A saturation run that is *supposed* to produce `503`s is not mislabeled a failure.
  The one opt-in exception is the `expected` block above — counter-only contract assertions, exit
  `3` on failure. What the sender always fails on is a broken run (a `401`, a `400 invalid_json` to
  `/control`, transport errors past the threshold), because those mean the measurement itself is
  invalid — see [10](10-error-handling-and-shutdown.md).
- The scenario file used **MUST** be copied into the run's artifacts verbatim (F9c-3), together with
  the effective CLI parameters.

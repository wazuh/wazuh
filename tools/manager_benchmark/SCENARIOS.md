# Scenario library

Every file in [`scenarios/`](scenarios/) is a self-contained run description in the lanes-and-fleets
model ([`docu/07-scenario-schema.md`](tool_simulator/docu/07-scenario-schema.md)). This is the map of
what each one exercises and which manager code path it is aimed at. The whole library is kept
`--validate`-green (unknown field / unknown step kind is a hard load-time error).

A note on the port: these are **not** copies of any earlier tool's scenarios. The earlier design fed
recorded payload dumps over a stream protocol with acknowledgements and retransmission requests; here
one session is one self-contained `Message{FullSession}` and documents are generated deterministically
from a seed. So each scenario was re-expressed against the current wire, and the ones that only made
sense under retransmission (sequence gaps, out-of-range sequence numbers, ack timeouts) have no
equivalent and were dropped rather than faked.

## Baseline / per-module (uds)

These put one module's traffic on the socket in isolation — the cleanest read on a single path.

| Scenario | Exercises |
|---|---|
| `fim_first_sync_ubuntu` / `fim_first_sync_windows` | A FIM first scan (`full_resync` = `Cleans` + `ModuleDelta`) — the large single-session upsert path |
| `fim_delta_stream_ubuntu` | A steady FIM delta stream (a `delta` with a high repeat count) |
| `sca_base_ubuntu` / `sca_base_centos` | An SCA full sync |
| `sca_delta_ubuntu` | An SCA delta stream |
| `syscollector_init_debian` / `syscollector_init_windows` | A syscollector first scan followed by a `ModuleCheck` checksum reconcile |
| `checksum_reconcile` | The checksum path both ways: a `"correct"` checksum (matches what the agent sent) and a `"mismatch"` (forces a resync) |
| `vd_first_then_sync_debian` / `vd_first_then_sync_windows` | The VD lane: a `VDFirst` first scan then a `VDSync` delta stream (the feed gate → scan lane path) |
| `dump_replay_syscollector_full_debian` | A large-dataset first scan + delta (bulk bytes, group commit). Despite the name it GENERATES 2000 synthetic documents — for real captured payloads see the `real_*` scenarios |
| `mega_burst` | A big single fleet, unpaced, one delta lane — maximum session rate |

## Mixed fleet (the flagship pair)

| Scenario | Exercises |
|---|---|
| `mixed_fleet_windows_linux` (agent) | Two fleets, each agent running FIM + SCA + syscollector + VD **and** a syslog engine lane in parallel, with `/control` keepalives — production-shaped, heterogeneous, simultaneous load |
| `mixed_fleet_windows_linux_uds` (uds) | The same inventory lanes straight to the socket, no engine, no control. Run as a pair, the difference isolates the remoted relay cost (F9c-4) |

## Engine event streams (agent)

| Scenario | Exercises |
|---|---|
| `engine_smoke` | One small fleet streaming a short syslog file to `POST /stateless` |
| `engine_fleet_load` | A larger fleet looping a syslog file at a sustained EPS |
| `engine_with_inventory` | An engine lane running **while** inventory lanes are active on the same agents — the cross-path case |

## Control (agent)

| Scenario | Exercises |
|---|---|
| `control_notify_storm` | A large fleet with an aggressive keepalive interval and a token session lane — the `/control` `notify` path under fan-out |
| `control_notify_storm_with_sessions` | The same keepalive storm combined with a realistic stateful load |

## Contract under pressure

These aim at a specific response contract. Where the outcome is deterministic on ANY manager, the
scenario carries an `expected` block (counter assertions; a failure exits `3` — see
`tool_simulator/docu/07-scenario-schema.md`); where it depends on server config or live load, it
deliberately does not. Two footnotes from running these against a real manager:

- `contract_oversized_413` has **no** `expected`: the default `max_body_size` is unlimited, so on a
  default manager the sessions are simply accepted — the `413` only appears when the server is
  configured with a cap (F9c-4 measured exactly that).
- The shed-measuring scenarios (`contract_ramp_503`, `contract_vd_saturation`, plus `session_storm`
  and `mega_burst`) set `retry: {"enabled": false}`: the agent-like default retry would convert the
  `503`s they exist to count into eventual `200`s.
- `contract_ramp_503` was recalibrated against a live 32-core manager (2026-08-10): its original
  fixed-count design (`repeat_count`, no duration) finished before any backlog could build and
  produced **zero** `503`s on fast hardware. Two findings from that calibration, verified with a
  mid-run `GET /metrics` probe of `sync.pipeline.shed.total`:
  - **Duration alone does not fix it.** Switching to a fixed-duration unpaced flood (like
    `session_storm`) at the original 80 agents / moderate document size still produced zero
    shedding at both 20s and 60s — with only 80 agents blocking one request each, the pipeline's
    admission queue never accumulates enough concurrent bytes regardless of how long the flood runs.
  - **`session_storm`'s own description is imprecise.** Its massive shedding was confirmed (via the
    same probe) to come from the indexer-availability path (`!indexer->isAvailable()`), not the
    pipeline byte-queue gate its description names — and that path is noisy: identical 500-agent /
    60s runs of a scaled-up `contract_ramp_503` variant produced anywhere from 0% to 82% shed
    across repeats, with 1000 agents additionally triggering `transport_errors` (uds accept-path
    saturation) that invalidate the run. Not calibratable to a reliable threshold this way.
  - The fix that reproduced cleanly (5/5 runs, 79-90% shed) keeps the **original 80 agents**, sizes
    each session enough (`150 docs × 16 KiB ≈ 2.4 MiB`) that even 80 concurrent in-flight sessions
    approach the pipeline's 64 MiB admission cap directly, and runs for a fixed 60s so a faster
    manager simply admits more sessions before any one drains — both self-scaling with hardware,
    unlike the retired fixed-count design.

| Scenario | Aimed at | `expected` |
|---|---|---|
| `contract_oversized_413` | The body-size limit (`413`): an intentionally huge single session | none (server-config dependent) |
| `contract_invalid_bodies` | The `400` rejection paths: `garbage`, `empty`, `not_full_session` raw bodies | all 12 answered `400` |
| `contract_delete_under_load` | `DELETE /agents` (uds) while a delta lane is mid-load | 120 sessions + 4 deletes all OK |
| `contract_feed_not_ready_retry` | `503` + `Retry-After` when the VD feed is still downloading; the sender re-encodes `Start.feed_offset` on each retry rather than resending the original buffer, bounded by `--feed-timeout` (**uds mode needs `-vd-feed-offset` set to the target's real offset once it settles, or this ends `409` instead** — see [05](tool_simulator/docu/05-flatbuffers-messages.md)) | all 8 logical sessions end `200`, no budget exhausted (holds cold or warm) |
| `contract_ramp_503` | The pipeline's own admission queue (`sync_queue_bytes`, 64 MiB default) — an 80-agent unpaced fleet of large (~2.4 MiB) sessions for a fixed 60s, retry off. `503`s here are expected backpressure, not a failure | `sessions.s503 >= 1`, no transport errors |
| `contract_vd_saturation` | The VD scan lane ceiling (`D22`): a large fleet firing `VDFirst` back to back, retry off. The lane is single-worker until F9d, so this measures that limit. Needs `-vd-feed-offset` set correctly (uds mode) or sessions fast-reject with `409` before reaching the scanner instead of measuring real scan-lane pressure | none (load dependent) |
| `contract_vd_version_mismatch` | The `feed_offset` gate itself (`vdScanLane.cpp`): a deliberately wrong `feed_offset` (1) on every `VDFirst` session, pinning the `409 {"error":"version_mismatch","current_version":N}` contract — distinct from `checksum_reconcile`'s `409 checksum_mismatch` | all 4 sessions end `409`, none `200` |

## Real captured payloads

These replay **real** captured sessions from [`sample_payloads/dumps/`](sample_payloads/dumps/)
instead of generated documents, so the wire bytes match production shapes. The dumps were adapted
from real FIM, SCA, syscollector and VD captures: each keeps its metadata and a representative,
stride-sampled slice of its items (the multi-MB first-scans were truncated — the shapes are what
matter, and volume is reached with `repeat_count` and fleet size). A step names one with `dump`
(see [`docu/07`](tool_simulator/docu/07-scenario-schema.md#replaying-real-payloads)).

| Scenario | Real payload replayed |
|---|---|
| `real_fim_first_sync_ubuntu` (uds) | A real Ubuntu FIM first scan (`full_resync`) + FIM delta stream |
| `real_syscollector_debian` (uds) | A real Debian syscollector session spanning seven inventory indices, first scan + delta |
| `real_vd_debian` (uds) | Real VDFirst + VDSync sessions on the VD lane |
| `real_sca_full` (uds) | Real SCA full syncs for Ubuntu, CentOS and Windows at once (large check documents → bulk-bytes path) |
| `real_mixed_fleet` (agent) | The production-shaped flagship: Windows and Linux fleets each replaying real FIM + SCA + syscollector + VD sessions in parallel, plus an engine lane and `/control` keepalives |
| `real_first_connect_uds` (uds) | **A freshly connected Windows agent + Linux agent at FULL fidelity**: FIM first sync (Windows: the whole 27,726-item registry corpus — 21,091 registry-values + 6,625 registry-keys — in ONE ~26 MB session), syscollector, SCA full and VDFirst, each as its first-connection shape. `expected` pins all 14 sessions OK and the exact 31,950 documents |
| `real_first_connect` (agent) | The same first connection over remoted, **with zstd riding the agent-mode default**: uncompressed, the Windows FIM session exceeds remoted's 10 MiB body cap — this payload is the use case remoted's `Content-Encoding: zstd` exists for (~2 MB on the wire). Paired with the uds twin it isolates relay + decompression cost |
| `real_vd_rescan_storm` (agent) | **100 agents (50 Windows + 50 Linux) that sync their whole inventory and only then all ask for a re-scan at once**: real FIM + syscollector + SCA `full_resync`es plus a `syscollector_vd` VDFirst delta, then one `scan_vd` step per agent 90 s later — the `POST /scan/vd` feed-update path, a DIFFERENT manager path from the scan a VDFirst session triggers (see the note below). `expected` pins 700 sessions OK, ≥92,850 documents, no exhausted retry budget, and 100 re-scan requests with no malformed one |
| `real_inspect_fleet` (agent) | A **dashboard-inspection showcase, not a measurement**: the same `real_first_connect` full-fidelity payload (1 Windows + 1 Linux agent, all 31,950 documents across FIM/syscollector/SCA/VD) plus a basic syslog `engine` lane, kept connected on `/control` keepalives for several extra minutes after the inventory sessions finish — see the note below |

**Keeping a fleet connected without replaying its dumps.** `real_inspect_fleet` wants the two agents
to stay visibly connected long enough to go look at `wazuh-states-*` in the indexer dashboard, but
`pacing.repeat_until` is the wrong knob for that: set to a duration, it replays **every** lane's full
step list (agent.go's `laneLoop`) — including each `full_resync`'s `Cleans`, which would wipe and
re-populate the real dumps' indices on every loop instead of leaving them alone. An agent's keepalive
loop is tied to `lanes.Wait()` and only stops once **all** of that agent's lanes finish, so the fix is
a per-step `repeat_count`/`repeat_delay` on just the `engine` lane (the same mechanism
[13-engine-event-streams.md](tool_simulator/docu/13-engine-event-streams.md) documents for sustained
event pressure): the heavy FIM/SCA/syscollector/VD dumps send once and are done in seconds, while the
still-repeating `engine` lane keeps that agent's keepalive ticking for several more minutes, `pacing.
repeat_until` itself staying `"0"`.

**Two scans, two paths, one order.** `real_vd_rescan_storm` is the only scenario that walks both VD
scan entry points, in the order a real agent does. Its `vd_*` lane first sends the inventory (a
`delta` of a `VDFirst` dump), which the `inventory_sync_server`'s **VD scan lane** scans inline — one
`option=VDFirst` scan per agent in modulesd's log. Then, after `initial_delay: "90s"`
(the gap that lets the documents actually land in the indexer), the `scan_vd` step sends
`POST /scan/vd {"type":"feed_update","feed_offset":N}` with the offset the agent learned from
`/control`, and **remoted's** own worker pool dispatches a re-scan of that already-indexed inventory
— one `reason=feed_update` scan per agent. Two things to keep in mind when reading a run:

- **`200` means queued, not scanned.** The manager answers at admission and scans afterward, one
  agent at a time (`ScanOrchestrator::runScanAfterFeedUpdate()` holds an exclusive lock), so the
  sender's `scan_latency_ms_*` is admission time. remoted's own `/scan/vd` counters are not exposed
  on any metrics endpoint, which leaves modulesd's log as the only evidence the scans ran:
  `grep -c "reason=feed_update" /var/wazuh-manager/logs/wazuh-manager.log`.
- **The feed must be loaded**, or every request answers `409 version_mismatch` against offset 0.
  Check with `curl --unix-socket queue/sockets/modulesd http://localhost/vulnerability-detector/offset`
  and wait for `CVE feed fully loaded — per-agent scans unblocked` in the log.

- **The VD scan lane, not `/scan/vd`, is what 100 simultaneous first connections hit first.** The
  inventory phase produced thousands of bare `503`s from `vd.capacity.503.total` (one indexer
  connector, one scan at a time), which is why the scenario raises `retry.max_attempts` to 120 and
  why its VD lane is a bare `delta`: a VDFirst `Cleans` session is `isVD` too, so it queues in that
  same lane and waits its turn **without scanning anything** — with the `full_resync` shape it
  doubled the lane's pressure for zero inventory, and 85 sessions then never landed at all. When a
  VDFirst never lands, its agent's later re-scan is *correctly* skipped (`no package inventory
  available`), so the storm reads as 100 × `200` with only a third of the scans actually running.
  `retries_exhausted: 0` in the `expected` block is what guards that.

100 agents also need enrollment room: run it with `--enroll-settle 300s` (remoted reloads
`client.keys` on its own cadence, and that grows with fleet size — 100 keys took ~200 s and 100
probes here). Full contract in [`docu/14-scan-vd.md`](tool_simulator/docu/14-scan-vd.md).

## First-id ranges

Each scenario uses a distinct `first_id` block so a single run never collides agent ids. Runs are one
scenario at a time, but the blocks are kept disjoint for tidiness and so ad-hoc combinations do not
overlap.

# Scenario library

Every file in [`scenarios/`](scenarios/) is a self-contained run description in the lanes-and-fleets
model ([`docu/07-scenario-schema.md`](tool_simulator/docu/07-scenario-schema.md)). This is the map of
what each one exercises and which manager code path it is aimed at. The whole library is kept
`--validate`-green (unknown field / unknown step kind is a hard load-time error). One session is one
self-contained `Message{FullSession}`; documents are generated deterministically from a seed unless
a step replays a captured dump ([Real captured payloads](#real-captured-payloads)).

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
| `mega_burst` | A big single fleet, unpaced, one delta lane — maximum session rate (retry off) |
| `session_storm` | 50 agents replaying a one-document syscollector delta as fast as the manager answers, for a fixed 60 s, retry off — the sustained flood that makes the server shed (see the `contract_ramp_503` note below for which gate that shedding comes from) |
| `session_fifo_concurrent` | Each of 8 agents runs a small syscollector lane and a large FIM lane **concurrently**, 40 sessions each, so two sessions of one agent are in flight at once on the same shard. `expected` pins all 640 sessions `200`, no `5xx`, no transport errors — the per-agent FIFO and the no-crossed-documents guarantee |

## Mixed fleet (the flagship pair)

| Scenario | Exercises |
|---|---|
| `mixed_fleet_windows_linux` (agent) | Two fleets, each agent running FIM + SCA + syscollector + VD **and** a syslog engine lane in parallel, with `/control` keepalives — production-shaped, heterogeneous, simultaneous load |
| `mixed_fleet_windows_linux_uds` (uds) | The same inventory lanes straight to the socket, no engine, no control. Run as a pair, the difference isolates the remoted relay cost |
| `mixed_fleet_windows_linux_only_stateful` (agent) | The flagship without the engine lane, scaled from 20 + 20 to 50 + 50 agents: the stateful sync path alone under `/control` keepalives |
| `mixed_fleet_windows_linux_only_stateless` (agent) | The flagship's engine lane alone (50 + 50 agents at 250 events/s each), repeated for 20 min (`repeat_until`) under `/control` keepalives |

## Engine event streams (agent)

| Scenario | Exercises |
|---|---|
| `engine_smoke` | One small fleet streaming a short syslog file to `POST /stateless` |
| `engine_fleet_load` | A larger fleet looping a syslog file at a sustained EPS |
| `engine_with_inventory` | An engine lane running **while** inventory lanes are active on the same agents — the cross-path case |

## Control (agent)

| Scenario | Exercises |
|---|---|
| `control_notify_storm` | A 50-agent fleet with an aggressive 2 s keepalive interval and host-info reporting; its single inventory lane is deliberately tiny and spaced so the measured pressure is the `/control` `notify` traffic itself |
| `control_notify_storm_with_sessions` | The same 2 s keepalive storm paired with a realistic sustained syscollector delta stream — combined control + stateful pressure |

## Contract under pressure

These aim at a specific response contract. Where the outcome is deterministic on ANY manager, the
scenario carries an `expected` block (counter assertions; a failure exits `3` — see
`tool_simulator/docu/07-scenario-schema.md`); where it depends on server config or live load, it
deliberately does not. Four footnotes from running these against a real manager:

- `contract_oversized_413` has **no** `expected`. With the default
  `wazuh_modules.inventory_sync_server_max_body_size=0`, the body cap is derived from the 256 MiB
  in-flight budget (`max_inflight_bytes`). Its ~13 MB sessions are therefore simply accepted on a
  default manager. The `413` appears only when the server is configured with a smaller cap.
- The shed-measuring scenarios (`contract_ramp_503`, `contract_vd_saturation`, plus `session_storm`
  and `mega_burst`) set `retry: {"enabled": false}`: the agent-like default retry would convert the
  `503`s they exist to count into eventual `200`s.
- `contract_ramp_503` aims at the pipeline's admission queue
  (`wazuh_modules.inventory_sync_server_sync_queue_bytes`, 64 MiB by default) and reads its sheds
  in `sync.pipeline.shed.total`. Each of its 80 agents sends sessions of
  `150 docs × 16 KiB ≈ 2.4 MiB`, so 80 concurrent in-flight sessions approach the 64 MiB cap
  directly, and it runs for a fixed 60 s rather than a fixed session count, so a faster manager
  admits more sessions before any one drains. A fixed session count, or 80 agents with small
  documents, finishes without a single `503` on fast hardware.
- `session_storm`'s `503`s come from the indexer-availability check
  (`!indexer->isAvailable()` in `syncEndpoint.cpp`), not the byte-queue gate. That path is noisy:
  scaled-up runs (500 agents, 60 s) shed anywhere from 0 % to 82 % across repeats, and 1000 agents
  also produce `transport_errors` (uds accept-path saturation) that invalidate the run, so it is
  not a reliable `503` threshold.

| Scenario | Aimed at | `expected` |
|---|---|---|
| `contract_oversized_413` | The body-size limit (`413`): an intentionally huge single session | none (server-config dependent) |
| `contract_invalid_bodies` | The `400` rejection paths: `garbage`, `empty`, `not_full_session` raw bodies | all 12 answered `400` |
| `contract_delete_under_load` | `POST /_internal/agents/delete` (uds) while a delta lane is mid-load | 120 sessions + 4 deletes all OK |
| `contract_feed_not_ready_retry` | `503` + `Retry-After` when the VD feed is still downloading; the sender re-encodes `Start.feed_offset` on each retry rather than resending the original buffer, bounded by `--feed-timeout` (**uds mode needs `--vd-feed-offset` set to the target's real offset once it settles, or this ends `409` instead** — see [05](tool_simulator/docu/05-flatbuffers-messages.md)) | all 8 logical sessions end `200`, no budget exhausted (holds cold or warm) |
| `contract_ramp_503` | The pipeline's own admission queue (`sync_queue_bytes`, 64 MiB default) — an 80-agent unpaced fleet of large (~2.4 MiB) sessions for a fixed 60s, retry off. `503`s here are expected backpressure, not a failure | `sessions.s503 >= 1`, no transport errors |
| `contract_vd_saturation` | The VD scan lane ceiling (`D22`): 40 agents firing `VDFirst` back to back, retry off. The lane's worker count is `wazuh_modules.inventory_sync_server_vd_workers`, whose default `0` resolves to half the host's cores (at least one), so the ceiling scales with the host and the report must state it. Needs `--vd-feed-offset` set correctly (uds mode) or sessions fast-reject with `409` before reaching the scanner instead of measuring real scan-lane pressure | none (load dependent) |
| `contract_vd_version_mismatch` | The `feed_offset` gate itself (`src/wazuh_modules/inventory_sync_server/src/vd/vdScanLane.cpp`): a deliberately wrong `feed_offset` (1) on every `VDFirst` session, pinning the `409 {"error":"version_mismatch","current_version":N}` contract — distinct from `checksum_reconcile`'s `409 checksum_mismatch` | all 4 sessions end `409`, none `200` |
| `cacerts` | `GET /cacerts`, the unauthenticated CA-distribution route: 20 agents × 10 fetches of the manager's CA PEM over the HTTPS listener — the trust-bootstrap contract, and the floor of the listener's fixed per-request cost (no downstream). `agent` mode only; needs the manager's `remote.https.ca_certificate` in place, and its 200 unpaced requests only stay under the route's rate limit because `prepare_manager.sh` clears it — with the shipped `cacerts_rate_limit` of 50 req/s (counted for the endpoint as a whole, burst twice that) roughly half would be answered `429` | all 200 answered `200` with an `application/x-pem-file` body, none `429`/`other`, no transport errors |
| `enroll_https` | `POST /enroll` with an **enrollment token**: 20 agents × 5 fresh agent names, each request carrying the `wazuh-enroll+jwt` bearer minted from the token — remoted's replica of the token store, the signature, authd consuming a use and writing `client.keys`. `agent` mode only; needs the same enrollment token the fleet's own bootstrap uses (`prepare_manager.sh` mints it; `--enroll-token-file` / `WAZUH_ENROLLMENT_TOKEN` override), and its 100 uses are on top of the one per agent the bootstrap spent; run `cleanup_agents.sh` afterwards (the names carry the `bench-` prefix). Its 100 requests fit inside the default `enroll_rate_limit` burst, and `prepare_manager.sh` clears the limit anyway | all 100 answered `200` with the agent record, none `401`/`403`/`409`/`429`/`other`, no transport errors |

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
| `real_first_connect_uds` (uds) | **A freshly connected Windows agent + Linux agent at FULL fidelity**: FIM first sync (Windows: all 27,726 items — 21,091 registry values, 6,625 registry keys and 10 files, a 27 MB dump — in ONE session), syscollector, SCA full and VDFirst, each as its first-connection shape. `expected` pins all 14 sessions OK and the exact 31,950 documents |
| `real_first_connect` (agent) | The same first connection over remoted, **with zstd riding the agent-mode default**. Uncompressed, the Windows FIM session exceeds both of remoted's caps: the 5 MiB authenticated-body cap (`remoted.auth_max_body_size`, a `413`) and the 10 MiB transport cap (`<remote><https><max_body_size>`, where the connection closes with no response). This payload is the use case remoted's `Content-Encoding: zstd` exists for (~2 MB on the wire). Paired with the uds twin it isolates relay + decompression cost |
| `real_vd_rescan_storm` (agent) | **100 agents (50 Windows + 50 Linux) that sync their whole inventory and only then all ask for a re-scan at once**: real FIM + syscollector + SCA `full_resync`es plus a `syscollector_vd` VDFirst delta, then one `scan_vd` step per agent 90 s later — the `POST /scan/vd` feed-update path, a DIFFERENT manager path from the scan a VDFirst session triggers (see the note below). `expected` pins 700 sessions OK, ≥92,850 documents, no exhausted retry budget, and 100 re-scan requests with no malformed one |
| `vd_rescan_storm_isolated` (agent) | `real_vd_rescan_storm` with only its VD lanes (a VDFirst `delta`, then `scan_vd` 90 s later), so the re-scan path is measured without the FIM/syscollector/SCA ingest storm competing for modulesd. `expected` pins 100 re-scan requests with no malformed one |
| `storm_160` (agent) | `real_vd_rescan_storm` scaled to 160 agents (80 Windows + 80 Linux), same lanes. `expected` is the base one scaled by 1.6: 1,120 sessions OK, ≥148,560 documents, no exhausted retry budget, and 160 re-scan requests (one `scan_vd` per agent) with no malformed one |
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
`/control`. **remoted relays VD's admission** of a re-scan of that already-indexed inventory: VD
records a durable `vd_scan` task in the Task Manager, whose dispatcher later runs it through the
inventory sync server's `POST /_internal/vd/scan`, one `reason=on_demand` scan per agent. Two
things to keep in mind when reading a run:

- **`200` means recorded, not scanned.** VD answers at admission, once the task row exists, and
  the scan runs afterward. The `vd_scan` task type runs one task at a time (its concurrency group
  is capped at 1) and keeps one pending task per agent, so 100 requests are 100 serialized scans
  and the sender's `scan_latency_ms_*` is admission time. remoted's admin socket exposes the
  `remoted.scanvd.*` admission counters over `GET /metrics`, and modulesd's log is the evidence the
  scans ran: `grep -c "reason=on_demand" /var/wazuh-manager/logs/wazuh-manager.log`.
- **The feed must be loaded**, or every request answers `409 version_mismatch` against offset 0.
  Check with `curl --unix-socket queue/sockets/vd-http.sock http://localhost/vulnerability-detector/offset`
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

`first_id` sets the ids a scenario's agents get in `uds` mode and the numbers in their `bench-*`
names in both modes (in agent mode the manager assigns the real ids). The agent-mode entries of
`run_matrix.sh` use disjoint blocks, so one pass of the matrix never re-enrolls a name; two of its
uds entries, `session_storm` and `real_first_connect_uds`, share 46000 (see below for what that
means). The rest of the library does **not** keep them disjoint either. Several pairs share a block: `cacerts` and
`contract_oversized_413` (27000), `enroll_https` and `contract_invalid_bodies` (28000),
`control_notify_storm_with_sessions` and `contract_vd_version_mismatch` (26000), `session_storm` and
`real_first_connect_uds` (46000), `storm_160` and `real_vd_rescan_storm` (48000 / 48100), and the
four `mixed_fleet_windows_linux*` files (1000 / 2000). Where both scenarios of a pair run in agent
mode with the same fleet names (`storm_160` / `real_vd_rescan_storm`, and the three agent-mode
`mixed_fleet_*` files), running them back to back with `--keep-agents` fails enrollment with a
duplicate name (`409`), so clean up with `./cleanup_agents.sh` between them. Where both are uds
runs, the synthetic agent ids coincide and the second run writes over the first one's documents.

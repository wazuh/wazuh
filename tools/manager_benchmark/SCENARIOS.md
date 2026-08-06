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
| `dump_replay_syscollector_full_debian` | A large-dataset first scan + delta replay (bulk bytes, group commit) |
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

These aim at a specific response contract. There is no pass/fail gate — a scenario declares *what to
send*; whether the target status actually appears depends on the server's configured limits and the
live load, and that is the measurement F9c-4 reports. The exact trigger points (max body size,
in-flight byte budget, scan-lane capacity) are server config, noted in each file's description.

| Scenario | Aimed at |
|---|---|
| `contract_oversized_413` | The body-size limit (`413`): an intentionally huge single session |
| `contract_invalid_bodies` | The `400` rejection paths: `garbage`, `empty`, `not_full_session` raw bodies |
| `contract_delete_under_load` | `DELETE /agents` (uds) while a delta lane is mid-load |
| `contract_feed_not_ready_retry` | `503` + `Retry-After` when the VD feed is still downloading; the sender re-sends the same buffer bounded by `--feed-timeout` |
| `contract_ramp_503` | The in-flight byte budget (`503` + shed): a big unpaced fleet. `503`s here are expected backpressure, not a failure |
| `contract_vd_saturation` | The VD scan lane ceiling (`D22`): a large fleet firing `VDFirst` back to back. The lane is single-worker until F9d, so this measures that limit |

## First-id ranges

Each scenario uses a distinct `first_id` block so a single run never collides agent ids. Runs are one
scenario at a time, but the blocks are kept disjoint for tidiness and so ad-hoc combinations do not
overlap.

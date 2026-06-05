# 03 — Scenario file schema

The sender's only structured input is a scenario JSON. This document is the
canonical schema reference. The Python implementation reads it in
`load_scenario()` in [`benchmark_sender.py`](../../benchmark_sender.py) (~line
1833); the Go implementation MUST accept exactly the same inputs.

## Top-level object

```jsonc
{
  // Human-readable identifier (used for the results directory label and
  // chart titles). Optional but recommended.
  "name": "string",

  // Free-form prose. Optional.
  "description": "string",

  // Defaults merged into every step before per-step overrides. Optional.
  // Same shape as a step (see "Step object" below) but typically holds
  // the cross-step keys: session_type, max_eps, use_databatch, retransmit.
  "defaults": { ... },

  // REQUIRED. Map of lane-name → array of steps. At least one lane.
  "lanes": {
    "fim":          [ /* steps */ ],
    "syscollector": [ /* steps */ ]
  },

  // Either total_agents OR fleets, never both.
  "total_agents":     1,             // implicit single fleet running ALL lanes
  "fleets": [                        // explicit fleet assignment
    { "name": "windows", "agents": 20, "lanes": ["fim", "syscollector"] },
    { "name": "linux",   "agents": 30, "lanes": ["sca"] }
  ],

  // Concurrency cap. 0 = launch all agents at a barrier, then go. >0 = sliding
  // window: at most N agents running their iteration at any moment.
  "parallel_agents": 0,

  // Loop the lanes for N seconds. 0 = single pass.
  "repeat_until":    0,

  // Sender-side: how many seconds the stats collector keeps sampling
  // bench.csv after the last agent finishes. Default 60.
  "drain_timeout":   60,

  // Orchestrator-side: how many seconds run_benchmark.sh keeps monitor.py
  // alive after the sender exits, so RSS/disk graphs settle. Default 0.
  // Not consumed by the sender itself; documented here for completeness.
  "post_run_grace":  0
}
```

### Required vs optional

| Key                 | Required?                                       |
| ------------------- | ----------------------------------------------- |
| `lanes`             | Yes                                             |
| `total_agents`      | Yes if `fleets` not set; mutually exclusive     |
| `fleets`            | Yes if `total_agents` not set                   |
| `name`              | Recommended (used as label); defaults to filename |
| `description`       | No                                              |
| `defaults`          | No (treated as `{}`)                            |
| `parallel_agents`   | No (default `0`)                                |
| `repeat_until`      | No (default `0`)                                |
| `drain_timeout`     | No (default `60`)                               |
| `post_run_grace`    | No (default `0`)                                |

## Step object

Each entry inside `lanes["<lane-name>"]` is a step. Exactly ONE of `dump`
XOR `kind` XOR `engine` is set; the rest of the keys are overrides over
`defaults`. The Go sender also accepts `engine` (a third type that streams
log lines as engine events — see [12-engine-event-streams.md](./12-engine-event-streams.md)).

```jsonc
{
  // EITHER: replay a recorded session.
  // Path is resolved relative to the scenario directory first, then the
  // benchmark directory.
  "dump": "sample_payloads/dump-syscollector/session_vd_first_windows.json",

  // OR: build a synthetic session from a template under sample_payloads/.
  // See "kind" table below.
  "kind": "fim_file",

  // Optional. Default "delta".
  "session_type": "delta" | "modulecheck" | "dataclean",

  // Optional. Default 1. Mapped to FlatBuffer Mode enum (see 06-).
  "sync_mode":    0 | 1 | 2 | 3 | 4 | 5 | 6,

  // Optional. Synthetic only: number of generated items. Ignored for dumps
  // (the dump's metadata dictates size).
  "data_size":    0,

  // Optional. Per-session EPS cap. 0 = unlimited.
  "max_eps":      0,

  // Optional. Pack DataValues into DataBatch messages (60 KB target). Default false.
  "use_databatch": false,

  // Optional. Respond to ReqRet by retransmitting missing items. Default true.
  "retransmit":   true,

  // Optional. Synthetic only: pad the template to this many bytes JSON-serialised.
  "payload_size": 0,

  // Optional. Synthetic only: dotted-path field to expand with padding.
  // Defaults per kind: see PAD_FIELD_BY_KIND in benchmark_sender.py.
  "pad_field":    "file.path",

  // Optional. session_type=modulecheck only.
  "modulecheck_checksum": "0000…0000",   // 40-char hex; mismatched on purpose
  "auto_resync":          false,         // if checksum mismatches → launch a full sync delta

  // Optional overrides for the manifest pulled from the dump/kind.
  "module":  "string",
  "index":   "string",
  "option":  "Sync" | "VDFirst" | "VDSync",

  // Repetition controls.
  "repeat_count":  1,    // ≥ 1
  "initial_delay": 0.0,  // seconds before the first run
  "repeat_delay":  0.0,  // seconds between repeats

  // Retry policy when the manager replies to Start with Status_Offline
  // (typically: inventory_sync_data_value_quota exhausted, or agent
  // locked by a concurrent Metadata/Group session). Only Status_Offline
  // triggers retries — Status_Error and timeouts still abort.
  "offline_retry":       -1,   // -1 = abort on first Offline (default,
                               //      historical behavior)
                               //  0 = retry indefinitely until Ok or ctx cancels
                               // N>0 = up to N total attempts; if all return
                               //      Offline, the iteration fails
  "offline_retry_delay": 1.0,  // seconds to wait between retry attempts
                               // (ignored when offline_retry == -1)

  // Per-step ack timeout overrides. These knobs live ONLY in the
  // scenario — there are no equivalent CLI flags. All default to 0 =
  // "use the inventory package default" (15s start, 5s end-processing,
  // 120s end-final). Set them per-step or under `defaults:` to apply
  // to every step in the scenario.
  //
  // The End→EndAck wait is two-phase: a SHORT window between End and
  // the first Status_Processing (manager queue ack — should be fast),
  // and a LONG window between Status_Processing and the terminal
  // Status_Ok (covers indexer flush, can legitimately be 40+ s). When
  // the short window elapses without any Processing, the End frame
  // was almost certainly dropped by the manager's input queue → the
  // ack_timeout_retry budget resends it. The long window is reset on
  // every subsequent Status_Processing.
  "start_ack_timeout":            0, // seconds (float). 0 = package default (15s)
  "end_ack_processing_timeout":   0, // seconds (float). SHORT phase, 0 = package default (5s)
  "end_ack_timeout":              0, // seconds (float). LONG phase,  0 = package default (120s)

  // Pause inserted between the last DataValue of a session and EVERY
  // End frame (initial + every End that follows a ReqRet round). Lets
  // the manager drain its handleData queue so the End hits the
  // gap-empty branch instead of triggering an extra ReqRet round.
  // Sentinel:
  //   -1 = use the inventory package default (1 s) — DEFAULT.
  //    0 = no pause (back-to-back DataValue → End).
  //   N>0 = wait N seconds.
  // Scenario-only; no CLI flag.
  "post_data_delay":         -1,

  // Retry on ack timeout (independent budget for Start and End). The
  // manager's input queue is bounded — under pressure a Start or End
  // frame can be silently dropped. Resending the frame gives the
  // manager another chance. Mirrors offline_retry semantics:
  //   -1 = no retry; the timeout fails the iteration (default).
  //    0 = retry indefinitely until ack arrives or ctx cancels.
  //   N>0 = up to N total attempts per ack (Start and End budgets
  //         are independent).
  "ack_timeout_retry":       -1,
  "ack_timeout_retry_delay": 1.0
}
```

### Fleet object

```jsonc
{
  "name":   "string",       // required; used in logs
  "agents": 1,              // required; number of simulated agents in this fleet
  "lanes":  ["fim", "..."] // required; must reference defined lane names
}
```

## Step `kind` table

When `kind` is set instead of `dump`, the sender loads a template JSON from
[`sample_payloads/`](../../sample_payloads/). The mapping (from
`benchmark_sender.py`, `PAYLOAD_KINDS`):

| `kind`                | Template file                    | Default module           | Default index                       |
| --------------------- | -------------------------------- | ------------------------ | ----------------------------------- |
| `package`             | `syscollector_package.json`      | `syscollector_packages`  | `wazuh-states-inventory-packages`   |
| `system`              | `syscollector_system.json`       | `syscollector_system`    | `wazuh-states-inventory-system`     |
| `hotfix`              | `syscollector_hotfix.json`       | `syscollector_hotfixes`  | `wazuh-states-inventory-hotfixes`   |
| `fim_file`            | `fim_file.json`                  | `fim_files`              | `wazuh-states-fim-files`            |
| `fim_file_windows`    | `fim_file_windows.json`          | `fim_files`              | `wazuh-states-fim-files`            |
| `fim_registry_key`    | `fim_registry_key.json`          | `fim_registries_keys`    | `wazuh-states-fim-registries-keys`  |
| `fim_registry_value`  | `fim_registry_value.json`        | `fim_registries_values`  | `wazuh-states-fim-registries-values`|
| `sca_check`           | `sca_check.json`                 | `sca`                    | `wazuh-states-sca`                  |

The default `pad_field` per kind matches the field that scales nicely
(`file.path` for FIM, `package.description` for packages, etc.).

## Dump file shape

A dump is a JSON file with this structure:

```json
{
  "metadata": {
    "module":  "syscollector_packages",
    "mode":    "ModuleFull" | "ModuleDelta" | "ModuleCheck" | ... ,
    "option":  "Sync" | "VDFirst" | "VDSync",
    "indices": ["wazuh-states-inventory-packages", "..."]
  },
  "items": [
    {
      "seq": 0,
      "operation": "Upsert" | "Delete",
      "id":    "doc-id-1",
      "index": "wazuh-states-inventory-packages",
      "data":  { /* arbitrary JSON, becomes DataValue.data */ }
    },
    ...
  ]
}
```

The sender preserves the per-item `index`, allowing one session to touch
multiple OpenSearch indices. The `metadata.indices` array is used for the
`Start` message; `metadata.module`/`mode`/`option` drive the enums.

## Canonical examples

### A) Minimal: 1 agent, 1 lane, dump replay

[`scenarios/base_init_debian_syscollector.json`](../../scenarios/base_init_debian_syscollector.json)

```json
{
  "name": "Syscollector, both sessions with/without VD, single agent, single pass",
  "lanes": {
    "syscollector_sync_debian10": [
      { "dump": "sample_payloads/dump-syscollector/session_syscollector_sync_debian10.json" }
    ],
    "vd_first_debian10": [
      { "dump": "sample_payloads/dump-syscollector/session_vd_first_debian10.json" }
    ]
  },
  "total_agents": 1,
  "parallel_agents": 1,
  "repeat_until": 0,
  "drain_timeout": 30,
  "post_run_grace": 30
}
```

### B) Stress: 2000 agents, synthetic, looped 180 s

[`scenarios/mega_burst.json`](../../scenarios/mega_burst.json)

```json
{
  "name": "mega_burst",
  "description": "Saturates the m_workersQueue producer ...",
  "lanes": {
    "fim_file": [ { "kind": "fim_file", "data_size": 100 } ]
  },
  "total_agents": 2000,
  "parallel_agents": 0,
  "repeat_until": 180
}
```

### C) Replay with throttle + DataBatch

[`scenarios/dump_replay_syscollector_vd_windows_full.json`](../../scenarios/dump_replay_syscollector_vd_windows_full.json)

```json
{
  "name": "dump_replay_syscollector_vd_windows_full",
  "lanes": {
    "vd_first_windows": [
      {
        "dump": "sample_payloads/dump-syscollector/session_vd_first_windows.json",
        "max_eps": 75,
        "use_databatch": true
      }
    ]
  },
  "total_agents": 4,
  "parallel_agents": 0,
  "repeat_until": 60
}
```

### D) Two fleets, disjoint lanes

[`scenarios/mixed_fleet_windows_linux.json`](../../scenarios/mixed_fleet_windows_linux.json) (excerpt):

```json
{
  "name": "mixed_fleet_windows_linux",
  "lanes": {
    "syscollector_windows": [ /* steps */ ],
    "syscollector_linux":   [ /* steps */ ],
    "fim_windows":          [ /* steps */ ],
    "fim_linux":            [ /* steps */ ]
  },
  "fleets": [
    { "name": "windows", "agents": 1, "lanes": ["syscollector_windows", "fim_windows"] },
    { "name": "linux",   "agents": 1, "lanes": ["syscollector_linux",   "fim_linux"]   }
  ],
  "parallel_agents": 0,
  "repeat_until":    0,
  "drain_timeout":   30
}
```

## Validation rules the loader MUST enforce

Run at startup, before any socket is opened:

1. `lanes` is present, is a non-empty object, and every value is a non-empty array of steps.
2. Exactly one of `total_agents` or `fleets` is present. `total_agents ≥ 1`. Every fleet has `name`, `agents ≥ 1`, and `lanes` is a non-empty subset of the lane names defined above.
3. Every step has exactly one of `dump` XOR `kind`.
4. `repeat_count ≥ 1`, `initial_delay ≥ 0`, `repeat_delay ≥ 0`, `max_eps ≥ 0`, `payload_size ≥ 0`, `data_size ≥ 0`, `offline_retry ≥ -1`, `offline_retry_delay ≥ 0`, `start_ack_timeout ≥ 0`, `end_ack_processing_timeout ≥ 0`, `end_ack_timeout ≥ 0`, `post_data_delay ≥ -1`, `ack_timeout_retry ≥ -1`, `ack_timeout_retry_delay ≥ 0`.
   - **Engine-only**: `repeat_count` must be exactly `1` (engine controls its own iteration via `loop` + `duration`). `duration ≥ 0` (`0` = no time limit).
5. `repeat_until ≥ 0`, `drain_timeout ≥ 0`, `post_run_grace ≥ 0`, `parallel_agents ≥ 0`.
6. `session_type ∈ {delta, modulecheck, dataclean}` if set; default is the value from `defaults.session_type`, fallback `delta`.
7. `option ∈ {Sync, VDFirst, VDSync}` if set.
8. Dump path resolution order: relative to the scenario file's directory, then relative to the benchmark directory. Reject with a clear error if neither exists.
9. `auto_resync` is meaningful only when `session_type == "modulecheck"`. Other combinations SHOULD warn but not abort.
10. Reject scenarios that define `total_agents` and `fleets` simultaneously (no implicit override).
11. **Engine sibling check** (cross-fleet): if a fleet uses an engine step with `run_while_siblings_active: true`, at least one lane assigned to that fleet must contain at least one non-engine step. Otherwise the engine source would never see a sibling decrement and could only exit on `duration` or `ctx`. See [12-engine-event-streams.md](./12-engine-event-streams.md#validation) for the rationale.

## Typical ranges observed in committed scenarios

| Field             | Min | Max  | Notes                                    |
| ----------------- | --- | ---- | ---------------------------------------- |
| `total_agents`    | 1   | 2000 | `mega_burst` is the upper bound          |
| `parallel_agents` | 0   | 0    | All current scenarios use the barrier mode |
| `repeat_until`    | 0   | 180  | `mega_burst`                             |
| `drain_timeout`   | 30  | 60   | The sender's own default is 60           |
| `post_run_grace`  | 0   | 30   | Optional; used by orchestrator only      |
| `max_eps`         | 0   | 75   | `vd_*` dumps use 75                      |

These are guides for sanity, not enforced bounds.

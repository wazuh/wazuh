# Inventory Sync Benchmark Tools

Tools for measuring the memory, CPU, disk, and throughput impact of the
`inventory_sync` module under load. The benchmark uses real simulated agents:
each agent registers through `authd`, connects to `remoted`, and sends
Inventory Sync FlatBuffers over the normal manager path.

The canonical workflow is scenario-driven:

```bash
./run_benchmark.sh --scenario scenarios/windows11_fim_first_sync.json
```

`run_benchmark.sh` orchestrates the whole run. `benchmark_sender.py` is the
Python sender used by the orchestrator and can also be run directly for focused
debugging.

## Layout

```text
inventory_sync/
├── shared/                      # FlatBuffers and agent-controller helpers
├── qa/                          # Integration tests
└── benchmark/
    ├── run_benchmark.sh         # Orchestrator: monitor + sender + summary + charts
    ├── benchmark_sender.py      # Scenario-driven multi-agent sender
    ├── result_summary.py        # Descriptive summary aggregator
    ├── run_monitor_only.sh      # Monitor-only companion for real-agent runs
    ├── cleanup_agents.sh        # Deletes bench-* agents via the manager API
    ├── indexer_control.sh       # Convenience wrapper for wazuh-indexer
    ├── generate_payloads.py     # Builds synthetic payload templates
    ├── migrate_scenarios.py     # One-shot helper for old-format scenarios
    ├── scenarios/               # Current scenario JSON files
    └── sample_payloads/         # Synthetic templates and recorded session dumps
```

`run_benchmark.sh` uses monitor and chart helpers from
`engine/tools/devContainer/scripts/`.

## Setup

```bash
cd src/wazuh_modules/inventory_sync/benchmark
pip install -r requirements.txt
pip install -r ../shared/requirements.txt
python3 ../shared/generate_flatbuffers.py
```

## Quick Start

Run one scenario locally:

```bash
./run_benchmark.sh --scenario scenarios/windows11_fim_first_sync.json
```

Run a mixed fleet scenario:

```bash
./run_benchmark.sh --scenario scenarios/mixed_fleet_windows_linux.json --label mixed_fleet
```

Keep monitoring after the sender exits:

```bash
./run_benchmark.sh --scenario scenarios/windows11_fim_first_sync.json --post-run-grace 30
```

Compare previous runs:

```bash
./run_benchmark.sh --compare results_before results_after
```

Direct sender invocation, useful when you only need `bench.csv` and
`sender_summary.json`:

```bash
python3 benchmark_sender.py \
  --scenario scenarios/windows11_fim_first_sync.json \
  --manager 127.0.0.1 \
  -o bench.csv \
  --summary-json sender_summary.json
```

## Orchestrator

`run_benchmark.sh` is a pure pass-through for load definition: all load shape
is in the scenario file. Its main runtime flags are operational knobs:

| Flag | Meaning |
|---|---|
| `--scenario FILE` | Scenario JSON to run. Required in benchmark mode. |
| `--label LABEL` | Results directory suffix. Defaults to scenario name, then timestamp. |
| `--manager HOST` | Manager address. Non-localhost enables remote-monitor mode. |
| `--port PORT` | Manager remoted port. Default: `1514`. |
| `--drain-timeout N` | Sender-side grace while waiting for late EndAcks after agents finish. Can be overridden by scenario `drain_timeout`. |
| `--post-run-grace N` | Script-side grace: keep monitor sampling after the sender exits. Overrides scenario `post_run_grace`. |
| `--cleanup-after` | Delete `bench-*` agents at the end. By default they are kept so indexed docs remain inspectable. |
| `--compare DIR...` | Generate comparison charts from previous result directories. |
| `--format FMT` | Chart format for comparison or normal chart generation. Default: `png`. |

Remote-manager options are available with `--manager <remote-host>`:
`--ssh-key`, `--ssh-port`, `--ssh-password`, `--indexer-port`, and `--grace`.
The sender itself talks to a local reverse tunnel in remote mode.

## Run Artifacts

Each run writes `results_<label>/`:

| File | Source | Contents |
|---|---|---|
| `bench.csv` | `benchmark_sender.py` | Per-second sender counters: messages, sessions, ACKs, ReqRet, retries. |
| `sender_summary.json` | `benchmark_sender.py` | Totals, latency percentiles, normalized scenario metadata. |
| `monitor/` | `monitor.py` | Process and disk CSVs, including `wazuh-manager-modulesd.csv` and `disk_usage.csv`. |
| `scenario.json` | `run_benchmark.sh` | Exact scenario file copied for reproducibility. |
| `params.json` | `run_benchmark.sh` | Run metadata: label, scenario path/name, manager, process, timestamp. |
| `system_info.txt` | `run_benchmark.sh` | Host, kernel, CPU, cores, memory. |
| `summary.json` | `result_summary.py` | Descriptive aggregate. No PASS/FAIL policy is applied. |
| `charts/` | `monitor_graphics_generator.py` | PNG/SVG/PDF charts for the run. |

If `monitor/logs.csv` exists, `result_summary.py` includes log counters too.

## Scenario Schema

A scenario defines lanes, optional defaults, and agent/fleet execution knobs.
Lanes run in parallel inside an agent over that agent's single socket. Steps
inside one lane run sequentially.

```json
{
  "name": "windows11_fim_sysc_init_then_fim_deltas",
  "description": "FIM first sync + periodic deltas with syscollector init.",

  "defaults": {
    "session_type": "delta",
    "max_eps": 75,
    "use_databatch": true,
    "retransmit": true
  },

  "lanes": {
    "fim_windows": [
      { "dump": "sample_payloads/fim/windows11_fim_first_sync.json" },
      {
        "dump": "sample_payloads/fim/windows11_fim_delta_modify.json",
        "repeat_count": 20,
        "initial_delay": 0,
        "repeat_delay": 3
      }
    ],
    "syscollector": [
      { "dump": "sample_payloads/dump-syscollector/session_syscollector_sync_windows.json" }
    ]
  },

  "total_agents": 1,
  "parallel_agents": 1,
  "repeat_until": 0,
  "drain_timeout": 30,
  "post_run_grace": 0
}
```

Top-level fields:

| Field | Meaning |
|---|---|
| `defaults` | Optional fields merged into every step unless the step overrides them. |
| `lanes` | Required object: `lane_name -> [step, ...]`. |
| `total_agents` | Single-fleet shorthand. Use only when `fleets` is omitted. |
| `fleets` | Optional split of agents into groups that run different lane subsets. |
| `parallel_agents` | Global agent concurrency cap. `0` means all registered agents run together. |
| `repeat_until` | `0` means one pass. `>0` loops the lanes until the time budget expires. |
| `drain_timeout` | Optional sender-side post-finish drain window. |
| `post_run_grace` | Optional monitor-side grace read by `run_benchmark.sh`. |

Fleet example:

```json
"fleets": [
  { "name": "windows", "agents": 5, "lanes": ["syscollector_windows", "fim_windows"] },
  { "name": "linux",   "agents": 3, "lanes": ["syscollector_linux", "fim_linux"] }
]
```

Step fields:

| Field | Meaning |
|---|---|
| `dump` | Recorded session dump. Path is resolved relative to the scenario file, then benchmark dir. |
| `kind` | Synthetic payload kind. Use exactly one of `dump` or `kind`. |
| `session_type` | `delta`, `modulecheck`, or `dataclean`. Default: `delta`. |
| `sync_mode` | Start mode for delta sessions: `0=ModuleFull`, `1=ModuleDelta`. |
| `max_eps` | Sender-side throttle for this step. `0` means unlimited. |
| `use_databatch` | Send items as `DataBatch` instead of individual `DataValue` messages. |
| `retransmit` | Whether the sender responds to `ReqRet` with missing sequences. |
| `payload_size` / `pad_field` | Synthetic payload inflation controls for `kind` steps. |
| `modulecheck_checksum` / `auto_resync` | ModuleCheck flow controls. |
| `module` / `index` / `option` | Overrides for synthetic steps or specialized dump replay. |
| `repeat_count` | Number of times to run the step back-to-back. Default: `1`. |
| `initial_delay` | Seconds to wait before the first run of the step. Default: `0`. |
| `repeat_delay` | Seconds to wait between step repeats. Default: `0`. |

Legacy pacing names `repeat`, `delay`, and `every` are rejected with an error
that points to `repeat_count`, `initial_delay`, and `repeat_delay`.

## Payload Dumps

Recorded dumps have this shape:

```json
{
  "metadata": {
    "agentid": "001",
    "module": "fim",
    "mode": "ModuleDelta",
    "option": "Sync",
    "indices": ["wazuh-states-fim-files"]
  },
  "items": [
    {
      "seq": 0,
      "operation": "Upsert",
      "id": "...",
      "index": "wazuh-states-fim-files",
      "data": { }
    }
  ]
}
```

Each item maps to one `DataValue`. When `use_databatch=true`, a batch simply
contains multiple `DataValue` items.

## Available Scenarios

Current scenarios live under `scenarios/`:

| Scenario | Purpose |
|---|---|
| `windows11_fim_first_sync.json` | Windows FIM first sync replay. |
| `windows11_fim_delta_create.json` | Windows FIM create delta replay. |
| `windows11_fim_delta_modify.json` | Windows FIM modify delta replay. |
| `ubuntu22_fim_first_sync.json` | Ubuntu FIM first sync replay. |
| `ubuntu22_fim_delta_create.json` | Ubuntu FIM create delta replay. |
| `ubuntu22_fim_delta_modify.json` | Ubuntu FIM modify delta replay. |
| `windows11_fim_sysc_init_then_fim_deltas.json` | Parallel syscollector init plus repeated FIM deltas. |
| `mixed_fleet_windows_linux.json` | Two fleets with different lane subsets. |
| `dump_replay_syscollector_windows_full.json` | Windows syscollector full dump replay. |
| `dump_replay_syscollector_debian_full.json` | Debian syscollector full dump replay. |
| `dump_replay_syscollector_vd_windows_full.json` | Windows vulnerability-detector syscollector dump replay. |
| `dump_replay_syscollector_vd_debian_full.json` | Debian vulnerability-detector syscollector dump replay. |
| `base_init_windows_syscollector.json` | Windows syscollector init baseline. |
| `base_init_debian_syscollector.json` | Debian syscollector init baseline. |
| `base_windows_sca.json` | Windows SCA base replay. |
| `base_windows_sca_delta.json` | Windows SCA delta replay. |
| `sca_base_Ubuntu.json` / `sca_base_CentOS.json` | Linux SCA base scenarios. |
| `sca_delta_Ubuntu.json` / `sca_delta_CentOS.json` | Linux SCA delta scenarios. |
| `mega_burst.json` | High-agent burst stress scenario. |

## Agent Cleanup

Before each benchmark run, `run_benchmark.sh` tries to delete old `bench-*`
agents. Post-run cleanup is opt-in:

```bash
./run_benchmark.sh --scenario scenarios/windows11_fim_first_sync.json --cleanup-after
```

By default agents remain registered after the run so their indexed documents
remain available in the indexer and IT Hygiene views.

## Indexer Control

`indexer_control.sh` is a small wrapper around the local `wazuh-indexer`
service. It is useful before a run to make sure the indexer is available, and
for manual failure tests where you intentionally stop the indexer while the
sender is running.

```bash
# First-time bootstrap only.
./indexer_control.sh init-security

# Day-to-day benchmark setup.
./indexer_control.sh start
./indexer_control.sh wait-healthy 90
./indexer_control.sh status

# Manual failure injection.
./indexer_control.sh stop
./indexer_control.sh restart
```

The wrapper uses `INDEXER_HOST`, `INDEXER_PORT`, `INDEXER_USER`, and
`INDEXER_PASS` when polling cluster health. Service control still requires root
or sudo privileges, just like calling `service wazuh-indexer ...` directly.

## Reprocess a Run

The CSVs are the source of truth. To regenerate `summary.json`:

```bash
python3 result_summary.py \
  --bench results_my_run/bench.csv \
  --monitor results_my_run/monitor/wazuh-manager-modulesd.csv \
  --disk-csv results_my_run/monitor/disk_usage.csv \
  --sender-json results_my_run/sender_summary.json \
  --params results_my_run/params.json \
  --out results_my_run/summary.json
```

## Payload Templates and Generation

`sample_payloads/` contains two kinds of files:

- recorded session dumps under `sample_payloads/fim/`, `dump-sca/`, and
  `dump-syscollector/`;
- synthetic templates such as `syscollector_package.json`, `fim_file.json`,
  and `sca_check.json` for `kind`-based steps.

`generate_payloads.py` can build larger synthetic templates from those mapping
safe shapes:

```bash
python3 generate_payloads.py --kind fim_file --size 8192 -o big_fim.json
```

For dump replay scenarios, prefer `dump` steps. For synthetic traffic, use
`kind`, `data_size`, and optional `payload_size` / `pad_field`.

## Notes

- The benchmark exercises the real manager path: registration on `1515`,
  encrypted remoted traffic on `1514`, and normal inventory-sync processing.
- `parallel_agents=0` starts all registered agents together. A positive value
  creates a sliding-window cap across all fleets.
- `repeat_until=0` is single-pass mode; the sender exits after all agent loops
  finish and then drains late EndAcks for `drain_timeout` seconds.
- `results_*/` directories are run artifacts and should normally stay out of
  git.

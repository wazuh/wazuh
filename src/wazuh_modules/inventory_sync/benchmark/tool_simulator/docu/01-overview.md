# 01 — Overview and motivation

## What the sender is

[`benchmark_sender.py`](../../benchmark_sender.py) (~2400 LOC) simulates a fleet
of Wazuh agents talking to a real `wazuh-manager`. Each simulated agent:

1. Enrols itself against `wazuh-authd` on port `1515` (TLS, no client cert).
2. Opens a TCP socket to `wazuh-remoted` on port `1514`.
3. Sends a startup control message and then runs one or more **lanes**.
4. Each lane drives a sequence of inventory-sync **sessions** — `Start`,
   payload messages (`DataValue` / `DataBatch` / `DataContext` / `DataClean`
   / `ChecksumModule`), `End` — and reads the corresponding acks.
5. On request, retransmits missing sequences (`ReqRet` handling).
6. Records per-second counters and per-message latencies.

The script is invoked from [`run_benchmark.sh`](../../run_benchmark.sh) once the
resource monitor is in place; it writes `bench.csv` and an optional
`sender_summary.json`, and exits when either `repeat_until` elapses or all
agents finish their pass — followed by a configurable `drain_timeout`.

## Why move to Go

Python is the wrong tool for this workload:

- **GIL**: even with N OS threads, only one runs Python bytecode at a time.
  At ~2000 simulated agents (see [scenarios/mega_burst.json](../../scenarios/mega_burst.json))
  the sender stops scaling well before the manager does.
- **Per-agent reader thread bottleneck**: the architecture has 1 reader
  thread per agent doing a blocking `recv()`. Decoding AES + zlib + the
  inner framing all happens under the GIL, so the readers serialise.
- **Memory churn**: every message creates Python objects + a FlatBuffer
  builder; GC pressure scales with throughput.

Go does not magically remove the cost of crypto and zlib, but:

- Goroutines run concurrently across cores without a GIL.
- `crypto/aes`, `compress/zlib`, `crypto/md5` are stdlib, no FFI.
- `sync.Pool` and pre-allocated buffers keep allocations bounded.
- A `select`-based reader fan-out is cleaner than a queue per session id.

The goal is **a 2× or better sustained-EPS improvement** under the
`mega_burst` scenario on the same hardware, while preserving exact wire
compatibility and output format.

## Scope of this migration

**In scope**: replace `benchmark_sender.py` with a Go binary that exposes
the same CLI flags and produces the same CSV/JSON outputs.

**Out of scope** (everything else in
[`benchmark/`](../../) stays as-is):

- [`run_benchmark.sh`](../../run_benchmark.sh) — orchestrator. Calls the sender
  with the same flags.
- [`monitor.py`](../../../../../engine/tools/devContainer/scripts/monitor.py),
  [`monitor_graphics_generator.py`](../../../../../engine/tools/devContainer/scripts/monitor_graphics_generator.py),
  [`result_summary.py`](../../result_summary.py),
  [`cleanup_agents.sh`](../../cleanup_agents.sh),
  [`indexer_control.sh`](../../indexer_control.sh): unchanged.
- [`generate_payloads.py`](../../generate_payloads.py): generates fixture JSONs
  offline, not coupled to the sender at runtime.
- Manager-side code (`inventorySyncFacade.hpp`, …): outside this folder.
- The patch in [`patches/dbsync_metrics/`](../../patches/): benchmark-only
  instrumentation for the manager; orthogonal.

## End-to-end pipeline

```
+----------------------+
| run_benchmark.sh     |
|   --scenario FILE    |
+----------+-----------+
           |
           v
    1) cleanup_agents.sh  (delete old bench-* agents via API)
           |
           v
    2) monitor.py &       (sample wazuh-manager-modulesd CPU/RSS/FDs/disk)
           |
           v
    3) ===== sender =====
        benchmark_sender.py    <-- REPLACED BY GO BINARY
           --scenario FILE
           --manager HOST
           --port 1514 --reg-port 1515
           --drain-timeout 60
           --summary-json sender_summary.json
           -o bench.csv
           |
           v
    4) kill monitor + post_run_grace sleep
           |
           v
    5) result_summary.py        (merge bench.csv + monitor csvs → summary.json)
           |
           v
    6) monitor_graphics_generator.py  (render charts/*.png)
```

The Go sender slots into step 3 with no changes to steps 1, 2, 4, 5, 6.

## I/O contract in one page

### Inputs

- `--scenario PATH` — JSON file in
  [`scenarios/`](../../scenarios/). Schema in
  [03-scenario-schema.md](./03-scenario-schema.md).
- The scenario may reference [`sample_payloads/`](../../sample_payloads/) dump
  files (relative to either the scenario directory or the benchmark
  directory — see resolution rules in 03).
- Runtime config from CLI flags (`--manager`, `--port`, `--reg-port`,
  `--drain-timeout`, `--key-wait`, `--debug`).

### Outputs

- `bench.csv` (path from `-o`/`--output`, default `bench.csv`): one header
  row + one row per second of wall-clock time, with counters of events
  observed in that second. Columns documented in
  [08-metrics-and-output.md](./08-metrics-and-output.md).
- `sender_summary.json` (path from `--summary-json`, optional): cumulative
  counters + latency percentiles + run metadata. Consumed by
  [`result_summary.py`](../../result_summary.py).
- Stdout: human-readable progress (start, periodic snapshots, drain, final
  report).
- Manager-visible side effects: ~`total_agents` `bench-XXXX-…` agents are
  registered on the manager (cleanup is a separate step).

### Process exit

- `0` on a normal run that hit `repeat_until` or finished all agents and
  drained successfully.
- `130` on a forceful SIGINT-twice.
- Non-zero on configuration errors before the run starts.

## Performance target

Pick one canonical workload as the gating benchmark: `mega_burst.json` with
2000 agents and `repeat_until=180` on a fixed reference host (e.g. the CI
runner spec). Record Python's sustained EPS and peak memory; the Go
implementation must equal-or-exceed EPS by ≥2× and stay within a comparable
memory envelope (no GC thrash). See
[11-acceptance-criteria.md](./11-acceptance-criteria.md) for the full
verification protocol.

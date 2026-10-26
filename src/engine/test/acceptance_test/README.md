# Engine Benchmark Suite

Automated benchmark harness for the Wazuh Engine (`wazuh-manager-analysisd`).  
Measures how resource usage and event throughput scale across different orchestrator thread counts.

It runs against an **installed manager** (default home `/var/wazuh-manager`, overridable with the
`WAZUH_HOME` environment variable), stops and starts its analysisd, and therefore needs root. It is run by
hand; no CI workflow runs it.

## Directory Structure

```
acceptance_test/
├── acceptance_test.sh          # Main orchestration script
├── setup_dependencies.sh       # Installs Go, curl, Python and the venv (Amazon Linux 2023, Ubuntu 24.04)
├── requirements.txt            # Python dependencies
├── README.md
├── results/                    # Generated after a run
│   ├── system_report.txt       # Hardware & test parameters snapshot
│   ├── monitor-1T.csv          # Resource samples (1 thread)
│   ├── bench-1T.csv            # EPS / processed events (1 thread)
│   ├── monitor-4T.csv
│   ├── bench-4T.csv
│   └── ...
└── utils/
    ├── benchmark_tool.go       # Event sender (Go)
    ├── monitor.py              # Process resource monitor (Python)
    ├── graphics_generator.py   # Chart generator (Python)
    ├── hardware_comparison.py  # Compares results directories from different hosts
    └── version_comparison.py   # Compares results directories from different code versions
```

## How It Works

For each requested thread count, `acceptance_test.sh` executes the following steps:

1. **Stop** the manager (`wazuh-manager-control stop`, if analysisd is running) and remove stale RocksDB
   `LOCK` files under `<home>/engine` and `<home>/queue`.
2. **Launch** `<home>/bin/wazuh-manager-analysisd` with `WAZUH_ORCHESTRATOR_THREADS=N`, after truncating
   `<home>/logs/wazuh-manager.log`.
3. **Wait** until the engine is ready: a line ending in `Engine started` (or `Engine started in standalone mode`) in
   `wazuh-manager.log`, then
   `POST /_internal/router/route/get` for the route (`--route`) on `engine-api-http.sock` via `curl`.
4. **Start** `monitor.py` to sample CPU, memory, FDs and disk I/O every second.
5. **Grace period** before the benchmark.
6. **Run** `benchmark_tool.go` twice — a warmup run (`bench-NT-warmup.csv`) and the measured run
   (`bench-NT.csv`), with a grace period between them. Each sends events at the configured rate and records
   throughput; a failed run is logged and the loop continues.
7. **Grace period** after the benchmark.
8. **Stop** the monitor and analysisd (`wazuh-manager-control stop`).

A `trap` ensures that child processes (monitor, analysisd) are cleaned up on any exit.

Before the test loop starts, the script also:
- Activates the Python virtual environment `.venv` next to the script (or `VENV_DIR`) when it exists.
- Verifies that `python3` and `go` are available.
- Checks / installs Python dependencies from `requirements.txt`.
- Generates `system_report.txt` with CPU model, cores, RAM, OS version and test parameters.

## Requirements

| Tool | Purpose |
|------|---------|
| **Python 3** | `monitor.py`, `graphics_generator.py` |
| **Go** | `benchmark_tool.go` |
| **curl** | Engine route verification |
| **psutil** (pip) | Process resource sampling |
| **matplotlib, seaborn, pandas, numpy** (pip) | Chart generation |

Python packages are auto-installed by the script if missing. `setup_dependencies.sh` (as root) installs
everything, Go included, on Amazon Linux 2023 and Ubuntu 24.04.

The input directory (`--input`) must hold `.txt` / `.log` files; the default `utils/test_logs` is not
shipped in the repository.

## Usage

### Running the Benchmark

```bash
# Minimal — single thread, 10 s, unlimited rate
./acceptance_test.sh

# Full example — sweep 1, 2, 4, 8 threads
./acceptance_test.sh \
    --threads 1,2,4,8 \
    --time 60 \
    --rate 0 \
    --batch 100 \
    --input /path/to/log/files \
    --grace 5 \
    --results ./results
```

### CLI Options

| Flag | Default | Description |
|------|---------|-------------|
| `--threads LIST` | `1` | Comma-separated thread counts to test |
| `--time SECS` | `10` | Benchmark sending duration |
| `--rate EPS` | `0` | Target EPS (`0` = unlimited) |
| `--batch SIZE` | `50` | Events per HTTP request |
| `--input DIR` | `utils/test_logs` | Directory with `.txt` / `.log` input files (not shipped) |
| `--output FILE` | `$WAZUH_HOME/logs/standard-wazuh-events-v5/standard-wazuh-events-v5.json` | Output file to watch for processed events |
| `--grace SECS` | `5` | Grace period before & after benchmark |
| `--monitor-interval SECS` | `1` | Monitor sampling interval |
| `--results DIR` | `results/` next to the script | Directory for output CSVs |
| `--route NAME` | `cmsync_standard` | Engine route to verify on startup |
| `--timeout SECS` | `120` | Max wait for engine readiness |

Each default can also be set through an environment variable read by the script (`THREAD_LIST`, `BT_TIME`,
`BT_RATE`, `BT_BATCH`, `BT_INPUT`, `BT_OUTPUT`, `GRACE_SECS`, `MONITOR_INTERVAL`, `RESULTS_DIR`, `ROUTE_NAME`,
`READY_TIMEOUT`). The `--output` default is the latest-file link of the `standard` space's
`wazuh-events-v5` file output (`ruleset/outputs/file-output-integrations.yml`).

### Generating Charts

After a run completes, generate comparison charts from the results directory:

```bash
python3 utils/graphics_generator.py -r ./results -o ./charts
```

| Flag | Default | Description |
|------|---------|-------------|
| `-r, --results DIR` | *(required)* | Results directory |
| `-o, --output DIR` | `./charts` | Output directory for images |
| `--format FMT` | `png` | Image format (`png`, `svg`, `pdf`) |

Generated charts include:
- **Time-series overlays** — CPU %, RSS, VMS, FDs, I/O ops, disk %, sent and processed events, all aligned by elapsed time and grouped by thread count.
- **Sent vs Processed detail** — Per-thread subplot showing both curves.
- **Scaling summary** — Bar charts for total processed events, average EPS and loss %.
- **Resource scaling** — Bar charts for average/peak CPU and average/peak RSS across thread counts.

## Output Files

### CSV Formats

**`monitor-NT.csv`** — one row per sample:

| Column | Description |
|--------|-------------|
| `timestamp` | ISO-8601 timestamp |
| `cpu_pct` | CPU usage (%; 100 = one full core) |
| `rss_mb` | Resident Set Size (MB) |
| `vms_mb` | Virtual Memory Size (MB) |
| `fds` | Open file descriptors |
| `read_ops` / `write_ops` | Cumulative I/O operations |
| `read_bytes` / `write_bytes` | Cumulative I/O bytes |
| `disk_pct` | Process I/O as a percentage of total disk I/O |

**`bench-NT.csv`** — one row per second:

| Column | Description |
|--------|-------------|
| `timestamp` | ISO-8601 timestamp |
| `sent` | Cumulative events sent |
| `processed` | Cumulative events processed (output file lines) |

**`system_report.txt`** — hardware snapshot: date, kernel, CPU model/cores/MHz, RAM total/available/speed, and all test parameters used for the run.

## Utilities Reference

### `utils/benchmark_tool.go`

Sends events with `POST /events/enriched` to the engine's event socket
(`/var/wazuh-manager/queue/sockets/engine-ingest-http.sock`) and tracks throughput by counting the lines of
the watched output file.

```bash
go run utils/benchmark_tool.go -h
```

| Flag | Default | Description |
|------|---------|-------------|
| `-t` | `60` | Sending duration (seconds) |
| `-r` | `1000` | Target EPS (`0` = unlimited) |
| `-b` | `50` | Batch size (events per request) |
| `-i` | `./test_logs` | Input directory with log files |
| `-o` | `/var/wazuh-manager/logs/standard-wazuh-events-v5/standard-wazuh-events-v5.json` | Output file to watch |
| `-T` | `false` | Truncate output file before test |
| `-csv` | *(none)* | Path to CSV report output |

### `utils/monitor.py`

Monitors a process and writes resource samples to CSV.

```bash
python3 utils/monitor.py -h
```

| Flag | Default | Description |
|------|---------|-------------|
| `-p, --pid PID` | | Monitor by PID (one of `-p`/`-n` is required) |
| `-n, --name NAME` | | Monitor by process name |
| `-o, --output FILE` | *(required)* | CSV output file |
| `-s, --interval SECS` | `1` | Sampling interval |
| `--pidfile FILE` | `monitor.pid` | Write monitor PID to file |
| `-d, --debug` | | Enable debug logging |

### `utils/graphics_generator.py`

Reads a results directory and produces comparison charts.

```bash
python3 utils/graphics_generator.py -h
```

### `utils/hardware_comparison.py` and `utils/version_comparison.py`

Compare several results directories, from different hosts or from different code versions, for the thread
counts they have in common.

```bash
python3 utils/hardware_comparison.py -r ./results_amd::AMD -r ./results_arm::ARM -o ./hw_charts
python3 utils/version_comparison.py -r ./results_v1::Baseline -r ./results_v2::Optimised -o ./version_charts
```

| Flag | Default | Description |
|------|---------|-------------|
| `-r, --results DIR[::LABEL]` | | A results directory, optionally labelled; repeatable |
| `--scan PARENT_DIR` | | `hardware_comparison.py` only: compare every `results_*` subdirectory |
| `-o, --output DIR` | `./hw_charts` / `./version_charts` | Output directory for images |
| `--format FMT` | `png` | Image format (`png`, `svg`, `pdf`) |

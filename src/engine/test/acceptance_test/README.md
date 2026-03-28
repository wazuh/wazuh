# Engine Benchmark Suite

Automated benchmark harness for the Wazuh Engine (`wazuh-manager-analysisd`).  
Measures how resource usage and event throughput scale across different orchestrator thread counts.

## Directory Structure

```
acceptance_test/
├── acceptance_test.sh          # Main orchestration script
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
    └── graphics_generator.py   # Chart generator (Python)
```

## How It Works

For each requested thread count, `acceptance_test.sh` executes the following steps:

1. **Stop** the manager (if running) and clean stale KVDB locks.
2. **Launch** `wazuh-manager-analysisd` with `WAZUH_ORCHESTRATOR_THREADS=N`.
3. **Wait** until the engine is ready (log line detection + route verification via `curl`).
4. **Start** `monitor.py` to sample CPU, memory, FDs and disk I/O every second.
5. **Grace period** before the benchmark.
6. **Run** `benchmark_tool.go` — sends events at the configured rate and records throughput.
7. **Grace period** after the benchmark.
8. **Stop** the monitor and analysisd.

A `trap` ensures that child processes (monitor, analysisd) are cleaned up on any exit.

Before the test loop starts, the script also:
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
| **matplotlib, pandas, numpy** (pip) | Chart generation |

Python packages are auto-installed by the script if missing.

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
| `--input DIR` | `utils/test_logs` | Directory with `.txt` / `.log` input files |
| `--output FILE` | `$WAZUH_HOME/logs/standard-wazuh-events-v5/standard-wazuh-events-v5.json` | Output file to watch for processed events |
| `--grace SECS` | `5` | Grace period before & after benchmark |
| `--monitor-interval SECS` | `1` | Monitor sampling interval |
| `--results DIR` | `./results` | Directory for output CSVs |
| `--route NAME` | `cmsync_standard` | Engine route to verify on startup |
| `--timeout SECS` | `120` | Max wait for engine readiness |

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
| `cpu_pct` | CPU usage (%) |
| `rss_mb` | Resident Set Size (MB) |
| `vms_mb` | Virtual Memory Size (MB) |
| `fds` | Open file descriptors |
| `read_ops` / `write_ops` | Cumulative I/O operations |
| `read_bytes` / `write_bytes` | Cumulative I/O bytes |
| `disk_pct` | Disk usage (%) |

**`bench-NT.csv`** — one row per second:

| Column | Description |
|--------|-------------|
| `timestamp` | ISO-8601 timestamp |
| `sent` | Cumulative events sent |
| `processed` | Cumulative events processed (output file lines) |

**`system_report.txt`** — hardware snapshot: date, kernel, CPU model/cores/MHz, RAM total/available/speed, and all test parameters used for the run.

## Utilities Reference

### `utils/benchmark_tool.go`

Sends events to the engine via Unix socket and tracks throughput.

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
| `-p, --pid PID` | | Monitor by PID |
| `-n, --name NAME` | | Monitor by process name |
| `-o, --output FILE` | `stdout` | CSV output file |
| `-s, --interval SECS` | `1` | Sampling interval |
| `--pidfile FILE` | | Write monitor PID to file |
| `-d, --debug` | | Enable debug logging |

### `utils/graphics_generator.py`

Reads a results directory and produces comparison charts.

```bash
python3 utils/graphics_generator.py -h
```

# engine-metrics

Real-time metrics dashboard and CLI tools for Wazuh Engine.

## Installation

```bash
pip install -e tools/engine-metrics
```

## Usage

### Dashboard (real-time web UI)

Starts a web dashboard that reads metrics from the log directory and displays
live charts with global and per-space metrics. Shows a rolling window of the
last 300 data points (approximately 5 minutes at 1-second intervals).

```bash
engine-metrics dashboard
engine-metrics dashboard --log-dir /var/wazuh-manager/logs/metrics --port 5000
```

| Option       | Default                            | Description                  |
|--------------|------------------------------------|------------------------------|
| `--log-dir`  | `/var/wazuh-manager/logs/metrics`  | Metrics log directory        |
| `--port`     | `5000`                             | Dashboard HTTP port          |

### Plot (static report server)

Reads a metrics log file and serves an HTML report with charts for all
metrics across the entire file. Useful for post-mortem analysis.

```bash
engine-metrics plot                                    # latest file in default log dir
engine-metrics plot /var/wazuh-manager/logs/metrics/2026-04-08.json
engine-metrics plot --port 5001
```

| Option       | Default                            | Description                          |
|--------------|------------------------------------|--------------------------------------|
| `file`       | *(latest in --log-dir)*            | Path to NDJSON metrics log file      |
| `--log-dir`  | `/var/wazuh-manager/logs/metrics`  | Fallback directory if no file given  |
| `--port`     | `5001`                             | Port to serve the report             |

### Dump (one-shot metrics dump via API)

```bash
engine-metrics dump
engine-metrics dump -s /var/wazuh-manager/queue/sockets/analysis
```

### List (list all registered metric names)

```bash
engine-metrics list
engine-metrics list --space wazuh
```

### Get (get a single metric value)

```bash
engine-metrics get router.events.processed
engine-metrics get events.discarded --space wazuh
```

### Enable

```bash
engine-metrics enable router.events.processed
engine-metrics enable events.discarded --space wazuh
```

### Disable

```bash
engine-metrics disable router.eps.1m
engine-metrics disable events.unclassified --space wazuh
```

## Common options

All API subcommands (`dump`, `list`, `get`, `enable`, `disable`) accept:

| Option              | Default                                              | Description          |
|---------------------|------------------------------------------------------|----------------------|
| `-s`, `--api-socket`| `/var/wazuh-manager/queue/sockets/analysis`          | Engine API socket    |
| `--space`           | *(none)*                                             | Per-space scope      |

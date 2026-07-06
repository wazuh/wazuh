# engine-metrics

Real-time metrics dashboard and CLI tools for Wazuh Engine.

## Installation

```bash
pip install -e tools/engine-metrics
```

## Usage

### Dashboard (real-time web UI)

Starts a web server that polls the engine API every second and displays live charts
with global and per-space metrics.  Shows a rolling window of the last 300 data
points (approximately 5 minutes at 1-second intervals).

```bash
engine-metrics dashboard
engine-metrics dashboard -s /var/wazuh-manager/queue/sockets/analysis --port 5000 --interval 1.0
```

| Option              | Default                                       | Description                     |
|---------------------|-----------------------------------------------|---------------------------------|
| `-s`, `--api-socket`| `/var/wazuh-manager/queue/sockets/analysis`   | Engine API socket path          |
| `--port`            | `5000`                                        | Dashboard HTTP port             |
| `--interval`        | `1.0`                                         | Poll interval in seconds        |

The dashboard organises global metrics into sections automatically:

- **Events** — metrics whose `category` is `"events"` in `metrics_meta.json`
- **Bytes** — metrics whose `category` is `"bytes"` in `metrics_meta.json`
- Any other category creates its own section on the fly.
- Per-space metrics always get their own section, one per space.

Unknown metrics (not listed in `metrics_meta.json`) fall back to name heuristics
and appear in the Events section by default.

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

### Enable / Disable

```bash
engine-metrics enable router.events.processed
engine-metrics disable router.eps.1m
```

## Common options

All API subcommands (`dump`, `list`, `get`, `enable`, `disable`) accept:

| Option              | Default                                             | Description       |
|---------------------|-----------------------------------------------------|-------------------|
| `-s`, `--api-socket`| `/var/wazuh-manager/queue/sockets/analysis`         | Engine API socket |
| `--space`           | *(none)*                                            | Per-space scope   |

## Adding or changing a metric

The dashboard reads `src/engine_metrics/metrics_meta.json` to determine how each
metric is displayed.  **When a new global metric is added to the engine, only this
file needs to be updated — no Python or JS changes are required.**

### File format

```json
{
  "metric.name": { "category": "events", "unit": "count" }
}
```

| Field      | Values                                        | Effect                                      |
|------------|-----------------------------------------------|---------------------------------------------|
| `category` | `"events"`, `"bytes"`, or any custom string   | Dashboard section the metric appears in     |
| `unit`     | `"count"`, `"bytes"`, `"percent"`, `"eps"`, `"items"` | Y-axis label and scale              |

Unit details:

| Unit      | Y-axis label  | Notes                              |
|-----------|---------------|------------------------------------|
| `count`   | Delta/poll    | Intended for `counter` type metrics |
| `bytes`   | Bytes         |                                    |
| `percent` | Usage %       | Y-axis fixed to 0–100              |
| `eps`     | Events/sec    |                                    |
| `items`   | Items         | Queue sizes, etc.                  |

### Example — adding a new metric

1. Register the metric in the engine C++ code (e.g. with `FASTMETRICS_PULL`).
2. Add one line to `metrics_meta.json`:

```json
"router.queue.new_metric": { "category": "events", "unit": "count" }
```

3. Restart the dashboard — the new chart appears automatically.

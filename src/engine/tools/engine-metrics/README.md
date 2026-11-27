# engine-metrics

Real-time metrics dashboard and CLI tools for Wazuh Engine.

## Installation

From `src/engine/`, after its dependency `tools/api-communication` (not published):

```bash
pip install tools/api-communication
pip install -e tools/engine-metrics
```

Install it in editable mode: `setup.cfg` lists only `templates/*.html` as package data and there is no
`MANIFEST.in`, so a regular install, such as the one in the `wazuh-internal-tools` package, leaves
`metrics_meta.json` behind, and the dashboard logs `Could not load metrics_meta.json` and lays out every chart
by the fallback rules below.

`engine-metrics -v` prints the version. Every subcommand talks to the engine's `metrics/*` API endpoints
(`metrics/dump`, `metrics/list`, `metrics/get`, `metrics/enable`) on the API socket.

## Usage

### Dashboard (real-time web UI)

Starts a web server, listening on all interfaces (`0.0.0.0`), that polls `metrics/dump` every `--interval`
seconds and pushes each snapshot to the browser, which draws one live chart per enabled metric, global and
per-space, keeping the last 300 points of each (about 5 minutes at the default interval). A `counter` is drawn
as its increase since the previous poll. The page loads Socket.IO and Plotly from their CDNs, so the browser
needs Internet access.

```bash
engine-metrics dashboard
engine-metrics dashboard -s /var/wazuh-manager/queue/sockets/engine-api-http.sock --port 5000 --interval 1.0
```

| Option              | Default                                       | Description                     |
|---------------------|-----------------------------------------------|---------------------------------|
| `-s`, `--api-socket`| `/var/wazuh-manager/queue/sockets/engine-api-http.sock`   | Engine API socket path          |
| `--port`            | `5000`                                        | Dashboard HTTP port             |
| `--interval`        | `1.0`                                         | Poll interval in seconds        |

The dashboard organises global metrics into sections by the `category` of their `metrics_meta.json` line:

- **Events** — `"events"`
- **Bytes** — `"bytes"`
- Any other category creates its own section on the fly.
- Per-space metrics always get their own section, one per space, whatever their metadata.

A metric with no line in `metrics_meta.json` is still charted. Its section is **Bytes** when its name contains
`.bytes` and **Events** otherwise, and its y-axis follows its name and type: `Usage %` (0–100) for a name
ending in `.percent`, `Bytes` for `.bytes`, `Events/sec` for `.eps`, `Items` for a name ending in `.size`,
`Delta/poll` for any other `counter`, and `Value` for the rest.

### Dump (one-shot metrics dump via API)

```bash
engine-metrics dump
engine-metrics dump -s /var/wazuh-manager/queue/sockets/engine-api-http.sock
```

### List (list all registered metric names)

```bash
engine-metrics list
engine-metrics list --space standard
```

### Get (get a single metric value)

```bash
engine-metrics get router.events.processed
engine-metrics get events.discarded --space standard
```

### Enable / Disable

```bash
engine-metrics enable router.events.processed
engine-metrics disable router.eps.1m
```

## Common options

The API subcommands accept:

| Option              | Default                                             | Description       |
|---------------------|-----------------------------------------------------|-------------------|
| `-s`, `--api-socket`| `/var/wazuh-manager/queue/sockets/engine-api-http.sock`         | Engine API socket |
| `--space`           | *(none)*                                            | Per-space scope (`list`, `get`, `enable`, `disable`); the engine prefixes the name with `space.<space>.` |

## Adding or changing a metric

The dashboard reads `src/engine_metrics/metrics_meta.json` once, at start-up, to choose the section and the
y-axis of each metric; the metrics themselves come from the engine's dump. A new metric therefore needs no
Python or JS change: its chart appears without a metadata line, and the line is only needed when the fallback
rules above pick the wrong section or axis. Per-space metrics are looked up by their name without the
`space.<space>.` prefix (for example `events.discarded`).

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

1. Register the metric in the engine C++ code, with its name in the catalog header
   `src/engine/source/fastmetrics/interface/fastmetrics/metric_names.hpp` (e.g. with `FASTMETRICS_PULL`).
2. Add one line to `metrics_meta.json` when the fallback section or axis is not the right one:

```json,fragment
"router.queue.new_metric": { "category": "events", "unit": "count" }
```

3. Restart the dashboard to reload the metadata.

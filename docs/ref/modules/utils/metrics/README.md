# Metrics Library

`wazuh_metrics` (`src/shared_modules/metrics/`) is the shared lock-free metrics library
for manager daemons **outside the engine**: counters, gauges, histograms (128
log-linear buckets, p50/p90/p99 with ~12.5% bounded error), pull metrics and a
sliding-window rate, behind a thread-safe registry (`Manager`) and a JSON dump.

It is derived from the engine's `fastmetrics` (same metric semantics, same hot-path
discipline) with deliberate differences: **no singleton** (each daemon instantiates its
own `Manager` and injects it), histograms, and a rapidjson-based `dumpJson()`. Scalar
entries carry the same `{name, type, enabled, value}` shape as the engine's `/metrics`
dump, so tooling treats both alike. The planned unification is the engine aliasing
`namespace fastmetrics = wazuh::metrics;` and dropping its copy.

## Who uses it

| Module | Daemon | Serves the dump on |
|---|---|---|
| [Inventory Sync Server](../../inventory-sync-server/metrics.md) | wazuh-manager-modulesd | `queue/sockets/inventory-sync-http.sock` |
| [Remoted module](../../remoted/metrics.md) | wazuh-manager-remoted | `queue/sockets/remote-admin-http.sock` |

Each module documents its own metric catalog (with the option that tunes each metric)
in its `metrics.md` — this page is about the library and how to query any module.

## Querying a module's metrics

One `GET /metrics` per module socket, served over HTTP-on-UDS by the
[UDS HTTP Server](../uds-http-server/README.md):

```bash
curl -s --unix-socket /var/wazuh-manager/queue/sockets/inventory-sync-http.sock  http://localhost/metrics
curl -s --unix-socket /var/wazuh-manager/queue/sockets/remote-admin-http.sock  http://localhost/metrics
```

Properties that matter to an operator:

- The route is **budget-exempt** (Liveness class): it keeps answering exactly while the
  module is shedding data-plane load.
- It is **UDS-local**: no agent can reach it, and remoted forwards nothing to it.
- Counters are **cumulative since module start**, not per run.
- The dump is one deterministic JSON document — entries sorted by name; a histogram's
  `value` is its observation count and its `summary` carries count/sum/min/max/p50/p90/p99:

```json
{
  "name": "inventory_sync_server",
  "timestamp": "2026-08-06T12:00:00Z",
  "metrics": [
    {"name": "sync.bulk.flushes", "type": "counter", "enabled": true, "value": 41,
     "description": "Group-commit flushes", "unit": "count"},
    {"name": "sync.session.duration", "type": "histogram", "enabled": true, "value": 41,
     "unit": "microseconds",
     "summary": {"count": 41, "sum": 5150000, "min": 900, "max": 410000,
                  "p50": 98304, "p90": 229376, "p99": 393216}}
  ]
}
```

## Related

- [Integration Guide](integration-guide.md) — instrumenting a module with the library.
- [UDS HTTP Server](../uds-http-server/README.md) — the transport that serves the dumps.

## Development

Developer documentation: `src/shared_modules/metrics/README.md` in the repository.

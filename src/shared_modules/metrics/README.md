# wazuh_metrics — shared lock-free metrics

A small, dependency-free metric library for manager daemons: counters, gauges,
histograms, pull metrics and a sliding-window rate, behind a thread-safe
registry (`Manager`) and a rapidjson-based JSON dump. C++17, STL-only core.

Derived from the engine's `fastmetrics` (same metric semantics, same hot-path
discipline) with three deliberate differences:

- **No singleton.** Each daemon instantiates a `Manager` and injects it
  (`shared_ptr`) wherever instrumentation lives — the dependency-injection
  style of `inventory_sync_server` and `remoted_module`. Nothing here touches
  the engine's `base` utilities.
- **Histograms.** `AtomicHistogram` records value distributions over 128
  log-linear buckets (~1.1 KiB each) and answers p50/p90/p99 snapshots with a
  bounded ~12.5% relative error — cheap enough for per-request durations.
- **JSON dump with rapidjson.** `dumpJson()` serializes the whole registry;
  rapidjson exists only inside `src/jsonDump.cpp`, never in a public header.
  Scalar entries carry the same `{name, type, enabled, value}` shape the
  engine's `/metrics` dump emits, so tooling can treat both alike.

The distinct target (`wazuh_metrics`) and namespace (`wazuh::metrics`) are
load-bearing: the engine's `fastmetrics` targets live in the same build tree,
and a second `Manager` under the same name would be a silent ODR trap. The
planned unification is the engine aliasing `namespace fastmetrics =
wazuh::metrics;` and dropping its copy — additive API changes only.

## Usage contract

**Resolve once, mutate lock-free.** `getOrCreate*` costs a shared lock and a
hash lookup; call it in constructors (cold path) and cache the returned
`shared_ptr`. Every subsequent update is one relaxed atomic op:

```cpp
class Worker
{
    std::shared_ptr<wazuh::metrics::ICounter> m_processed;

public:
    explicit Worker(wazuh::metrics::IManager& metrics)
        : m_processed(metrics.getOrCreateCounter("module.worker.processed",
                                                 "Items processed", "count"))
    {
    }

    void onItem()
    {
        m_processed->add(); // hot path: one relaxed fetch_add
    }
};
```

**No labels.** Dimensions are encoded in the metric name
(`sync.requests.total.200`). For a closed set (HTTP codes, worker ids),
pre-create one metric per member and select with a `switch` — never format a
name per event.

**Pull metrics capture lifetimes.** There is no `remove()`: a pull metric's
getter must outlive the manager, so never register one over an object that is
torn down earlier (a worker, a pipeline). Use a gauge the object updates
instead — that is why shard depths in `inventory_sync_server` are gauges.

**Durations are histograms of integers.** Pick a unit (microseconds, bytes),
say it in the registration `unit`, and `observe()` raw integers. `snapshot()`
computes percentiles only when asked (a dump), never per event.

## Dump format

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

Entries are sorted by name (deterministic output), counters and histogram
counts are exact unsigned integers, `description`/`unit` appear only when
registered, and a histogram's `value` is its observation count.

## Layout

```
metrics/
├── include/wazuh_metrics/     # public headers (STL-only)
│   ├── iMetric.hpp            # IMetric, ICounter, IGaugeInt, IHistogram, MetricType
│   ├── iManager.hpp           # IManager (+ Metadata)
│   ├── atomicCounter.hpp      # relaxed fetch_add counter
│   ├── atomicGauge.hpp        # relaxed set/add/sub gauge
│   ├── atomicHistogram.hpp    # 128 log-linear buckets, percentile snapshots
│   ├── pullMetric.hpp         # callback-backed read-only metric
│   ├── slidingWindowRate.hpp  # per-second EPS over a 31-minute ring
│   ├── manager.hpp            # the registry (double-checked getOrCreate)
│   └── jsonDump.hpp           # dumpJson() declaration -- no rapidjson types
├── src/
│   ├── manager.cpp
│   └── jsonDump.cpp           # the ONE translation unit that includes rapidjson
└── test/                      # wazuh_metrics_utest (GTest) + mocks/wazuh_metrics/
```

Consumers link the `wazuh_metrics` target; their tests take the mocks by
adding `shared_modules/metrics/test/mocks` to their include path.

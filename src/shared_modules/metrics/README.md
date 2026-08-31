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

## Requirements

### Functional

| # | Requirement | Status |
|---|---|---|
| RF-1 | Counter / gauge / histogram / pull / sliding-window-rate types behind `IMetric` interfaces, each registered with optional `description`/`unit` metadata | kept |
| RF-2 | Thread-safe registry: `getOrCreate*` is idempotent (same name → same instance); re-registering a name under a **different type** throws | kept |
| RF-3 | Histograms answer p50/p90/p99 snapshots with bounded relative error (~12.5%, 128 log-linear buckets); min/max are exact; percentiles are computed only on `snapshot()` | kept |
| RF-4 | `dumpJson()` is deterministic: entries sorted by name, exact unsigned integers for counters/counts, `description`/`unit` omitted when not registered, envelope with daemon name + ISO-8601 UTC timestamp | kept |
| RF-5 | Scalar entries carry the engine-compatible `{name, type, enabled, value}` shape so tooling treats both dumps alike | kept |

### Non-functional

| # | Requirement | Status |
|---|---|---|
| RNF-1 | No singleton — the manager is injected (`shared_ptr<IManager>`); nothing touches the engine's `base` utilities | kept |
| RNF-2 | Hot path is one relaxed atomic op on a cached pointer; `getOrCreate*` (shared lock + hash) is cold-path only | kept |
| RNF-3 | Public headers are STL-only; rapidjson exists in exactly one TU (`src/jsonDump.cpp`) | kept |
| RNF-4 | C++17 | kept |

## Design decisions

| Decision | Rationale |
|---|---|
| No labels | Dimensions live in the name; closed sets are pre-created and picked with a `switch` — keeps the hot path a single atomic and the registry scan trivial |
| No `remove()` for pull metrics | An unregisterable getter forces the lifetime question to the consumer (gauge, or `weak_ptr` resolved under the consumer's lock) instead of hiding a use-after-free |
| rapidjson confined to `src/jsonDump.cpp` | Consumers never inherit the dependency; public headers stay STL-only |
| Distinct target/namespace from `fastmetrics` | Both live in one build tree; a same-name `Manager` would be a silent ODR trap |
| 128 log-linear buckets (~1.1 KiB/histogram) | Cheap enough for per-request durations; ~12.5% relative error is fine for tuning/triage percentiles |
| Deterministic dump (sorted by name) | Diffable dumps; scrapers (`monitor.py`) key columns by name |

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

## Tests

`test/unit/` builds `wazuh_metrics_utest` (GTest) under
`cmake -S src -B src/build -DUNIT_TEST=ON`. CI runs it on every PR touching
`src/shared_modules/metrics/**` via `.github/workflows/5_testunit_metrics.yml`: a
coverage job (line coverage over `src/` + `include/`; function coverage is not gated,
since the pure-interface headers dominate the function count) and an ASAN/UBSAN job.
Valgrind is deliberately off — the rate tests assert over wall-clock windows and the
concurrency tests are 16 threads x 100k atomic adds.

| File | Pins |
|---|---|
| `counter_test.cpp` | add/reset/enable-disable semantics; exact counts under concurrent mixed operations |
| `gauge_test.cpp` | set/add/sub incl. negative values; reset; enable-disable |
| `histogram_test.cpp` | percentile round-trips on known distributions; exact min/max; upper-bound clamping; reset not leaking the min sentinel; disabled `observe()` is a no-op |
| `manager_test.cpp` | `getOrCreate*` idempotence (same name → same instance); cross-type re-registration throws in every direction |
| `jsonDump_test.cpp` | envelope shape; verbatim vs fallback timestamp; alphabetical order; exact integers beyond double precision; signed gauges; metadata omitted when unregistered |
| `pullMetric_test.cpp` | callback-backed reads, typed access, exception handling, enable-disable, push+pull mixes |
| `slidingWindowRate_test.cpp` | window averaging, old-event expiry, bursty and concurrent increments |
| `realisticScenarios_test.cpp` | end-to-end consumer patterns: pipeline, worker pool, dynamic creation, high-frequency updates, mixed types under concurrency |

## Docs

Operator/integrator documentation: `docs/ref/modules/utils/metrics/` (how to query a
module's `/metrics`, integration guide). Per-module metric catalogs live in each
consumer's `docs/ref/modules/<mod>/metrics.md`.

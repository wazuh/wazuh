# Integration guide

How a manager module instruments itself with `wazuh_metrics`. This distills the
**Usage contract** of the dev README (`src/shared_modules/metrics/README.md`) — when in
doubt, that file is authoritative. Reference consumers:
`src/wazuh_modules/inventory_sync_server/` (centralized `metricNames.hpp` catalog) and
`src/remoted/remoted_module/`.

## Wire by dependency injection

There is no singleton: each daemon owns a `wazuh::metrics::Manager` and injects it as
`std::shared_ptr<IManager>` wherever instrumentation lives.

## Resolve once, mutate lock-free

`getOrCreate*` costs a shared lock and a hash lookup: call it in constructors (cold
path) and cache the returned `shared_ptr`. Every subsequent update is one relaxed
atomic operation:

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

## No labels

Dimensions are encoded in the metric name (`sync.requests.total.200`). For a closed set
(HTTP status codes, worker ids), pre-create one metric per member and select with a
`switch` — never format a metric name per event. Keep the whole catalog in one
`metricNames.hpp` per module.

## Pull metrics capture lifetimes

There is no `remove()`: a pull metric's getter must outlive the manager. Never register
one over an object that is torn down earlier (a worker, a pipeline) — use a gauge the
object updates instead. For long-lived-but-restartable sources (e.g. a transport's
`diagnostics()`), capture a `weak_ptr` resolved under your own lock and let an expired
target read as zeros (reference: `registerTransportDiagnostics()` in inventory sync's
facade).

## Durations are histograms of integers

Pick a unit (microseconds, bytes), declare it in the registration `unit`, and
`observe()` raw integers. Percentiles are computed only on `snapshot()` (a dump), never
per event.

## Testing your consumer

Reusable GMock mocks live in `src/shared_modules/metrics/test/mocks/wazuh_metrics/`
(`mockManager.hpp`, `mockCounter.hpp`, `mockGauge.hpp`, `mockHistogram.hpp`): add
`shared_modules/metrics/test/mocks` to your test include path. Library semantics are
pinned by `wazuh_metrics_utest`.

## Documenting

Every metric a module registers gets a row in that module's
`docs/ref/modules/<mod>/metrics.md` catalog, with a **Tuning** column linking the
configuration option that sizes it (or *diagnostic* when there is deliberately none).

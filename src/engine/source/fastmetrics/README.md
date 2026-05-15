# FastMetrics Module

## Overview

The **fastmetrics** module provides a high-performance, lock-free metrics system for the Wazuh engine. It is designed for ultra-low-overhead instrumentation of hot paths (event processing loops, queue operations) using `std::atomic` with `memory_order_relaxed`. Metrics are registered in a thread-safe registry and accessed globally via a singleton pattern (`SingletonLocator`).

The module supports three metric types: **counters** (monotonically increasing), **gauges** (bidirectional integers), and **pull metrics** (on-demand callbacks). All metrics are periodically serialized as JSON lines and written to rotating log files via the `streamlog` subsystem.

## Architecture

```
                    ┌─────────────────────────────────────────────────────┐
                    │                  Producers                          │
                    │                                                     │
                    │  router/worker:    counter.add(1)    (hot path)     │
                    │  router/orch:      FASTMETRICS_PULL(...)            │
                    │  api/event:        counter.add(bytes) (hot path)    │
                    │  builder/policy:   counter.add(1)                   │
                    │  main.cpp:         FASTMETRICS_PULL(...)            │
                    └───────────────┬─────────────────────────────────────┘
                                    │
                         lock-free atomic ops
                                    │
                    ┌───────────────▼─────────────────────────────────────┐
                    │              IManager (singleton)                    │
                    │                                                     │
                    │  getOrCreateCounter(name)  → shared_ptr<ICounter>   │
                    │  getOrCreateGaugeInt(name) → shared_ptr<IGaugeInt>  │
                    │  registerPullMetric(name, getter)                   │
                    │                                                     │
                    │  ┌────────────────────────────────────────────────┐ │
                    │  │         Manager (registry)                     │ │
                    │  │  m_metrics: unordered_map<string, IMetric>     │ │
                    │  │                                                │ │
                    │  │  Registration: unique_lock    (cold path)      │ │
                    │  │  Lookup:       shared_lock    (warm path)      │ │
                    │  │  Update:       lock-free      (hot path)       │ │
                    │  └────────────────────────────────────────────────┘ │
                    └───────────────┬─────────────────────────────────────┘
                                    │
                          writeAllMetrics(writer)
                           (scheduled task)
                                    │
                    ┌───────────────▼──────────────────┐
                    │   streamlog::WriterEvent          │
                    │   channel: "engine-metrics"       │
                    │   → JSON lines to rotating files  │
                    └──────────────────────────────────┘

                    ┌──────────────────────────────────┐
                    │   API Endpoints (api/metrics)     │
                    │                                   │
                    │   GET  /metrics/{name}             │
                    │   GET  /metrics                    │
                    │   POST /metrics/enable             │
                    │   POST /metrics/dump               │
                    └──────────────────────────────────┘
```

## Key Concepts

### Metric Types

| Type | Interface | Implementation | Storage | Use Case |
|------|-----------|---------------|---------|----------|
| `COUNTER` | `ICounter` | `AtomicCounter` | `atomic<uint64_t>` | Monotonically increasing values (events processed, bytes received) |
| `GAUGE_INT` | `IGaugeInt` | `AtomicGaugeInt` | `atomic<int64_t>` | Values that go up/down (queue sizes, active connections) |
| `PULL` | `IMetric` | `PullMetric<T>` | `std::function<T()>` | On-demand callbacks that read existing state (queue usage %, EPS rates) |

### Performance Model

The module is designed around three performance tiers:

1. **Hot path** (lock-free): `counter.add()`, `gauge.set()`, `gauge.add()`, `gauge.sub()` — all use `atomic::fetch_add` / `atomic::store` with `memory_order_relaxed`. Zero contention.
2. **Warm path** (shared lock): `manager().get()`, `manager().exists()`, `manager().getAllNames()` — read-only lookups on the registry map with `shared_lock`.
3. **Cold path** (unique lock): `getOrCreateCounter()`, `getOrCreateGaugeInt()`, `registerPullMetric()` — registration with double-checked locking pattern.

### Enable/Disable

Each metric has an individual `m_enabled` atomic flag. When disabled, all mutation operations (`add`, `set`, `sub`) become no-ops and `value()` returns 0.0. The manager provides `enableAll()` / `disableAll()` to toggle all metrics globally via `m_globalEnabled`.

### Singleton Access Pattern

The manager is registered once via `fastmetrics::registerManager()` and accessed globally through `fastmetrics::manager()`, which resolves to `SingletonLocator::instance<IManager>()`. This avoids passing the manager through dependency injection in hot paths.

```cpp
// Registration (once in main.cpp)
fastmetrics::registerManager();

// Access from anywhere
auto counter = fastmetrics::manager().getOrCreateCounter("router.events.processed");
counter->add(1);  // lock-free, hot path
```

### Pull Metrics and the `FASTMETRICS_PULL` Macro

Pull metrics avoid state duplication by executing a callback on read:

```cpp
FASTMETRICS_PULL(uint64_t, "indexer.queue.size", [wIndexer]() { return wIndexer->queueSize(); });
FASTMETRICS_PULL(double, "router.eps.1m", [rate]() { return rate->getRate(std::chrono::seconds(60)); });
```

The macro expands to `fastmetrics::registerPullMetric(name, std::function<type()>(getter))`.

### Sliding Window Rate (`SlidingWindowRate`)

A lock-free circular buffer for computing events-per-second (EPS) over configurable time windows (up to 31 minutes). Used by the router to compute `router.eps.1m`, `router.eps.5m`, and `router.eps.30m`.

- Resolution: 1 second per bucket.
- Buffer size: 1860 buckets (31 × 60 seconds).
- Each bucket has an atomic timestamp and atomic count.
- Bucket recycling uses a CAS-based protocol with a sentinel timestamp (`RECYCLING_TS`) to prevent data races.
- Reads use a double-check pattern (read timestamp, read count, re-read timestamp) for consistency.

### Metric Output Format

`writeAllMetrics()` serializes all metrics as JSON lines:

```json
{"timestamp":1715270400000,"name":"router.events.processed","value":42}
{"timestamp":1715270400000,"name":"indexer.queue.size","value":100}
```

Timestamp is milliseconds since epoch. Value is always `double`.

## Registered Metric Names

Predefined names in `metric_names.hpp`:

| Name | Type | Source |
|------|------|--------|
| `indexer.queue.size` | PULL | main.cpp (indexer connector) |
| `indexer.queue.usage.percent` | PULL | main.cpp (indexer connector) |
| `indexer.events.dropped` | PULL | main.cpp (indexer connector) |
| `router.queue.size` | PULL | router/orchestrator |
| `router.queue.usage.percent` | PULL | router/orchestrator |
| `router.events.processed` | COUNTER | router/worker |
| `router.events.dropped` | COUNTER | router/orchestrator |
| `router.eps.1m` | PULL | router/orchestrator (SlidingWindowRate) |
| `router.eps.5m` | PULL | router/orchestrator (SlidingWindowRate) |
| `router.eps.30m` | PULL | router/orchestrator (SlidingWindowRate) |
| `server.bytes.received` | COUNTER | api/event |
| `server.events.received` | COUNTER | api/event |
| `space.{name}.events.unclassified` | COUNTER | builder/policy (per-space) |
| `space.{name}.events.discarded` | COUNTER | builder/policy (per-space) |
| `space.{name}.events.discarded.prefilter` | COUNTER | builder/policy (per-space) |
| `space.{name}.events.discarded.postfilter` | COUNTER | builder/policy (per-space) |

## Dependencies

| Dependency | CMake Target | Role |
|------------|-------------|------|
| `base` | `base` | `SingletonLocator`, logging |
| `streamlog` | `streamlogger::streamlogger` | `WriterEvent` and `ILogManager` for `writeAllMetrics()` |

## Integration in `main.cpp`

```cpp
// 1. Register singleton manager (early startup)
fastmetrics::registerManager();

// 2. Register pull metrics for indexer
FASTMETRICS_PULL(uint64_t, fastmetrics::names::INDEXER_QUEUE_SIZE, [wIndexer]() { ... });
FASTMETRICS_PULL(double, fastmetrics::names::INDEXER_QUEUE_USAGE_PERCENT, indexerQueueUsageGetter);

// 3. Wrap singleton as shared_ptr for API handlers
metricsManager = std::shared_ptr<fastmetrics::IManager>(&fastmetrics::manager(), [](auto*) {});

// 4. Register API endpoints
api::metrics::handlers::registerHandlers(metricsManager, apiServer, ...);

// 5. Schedule periodic metrics dump to streamlog
scheduler->scheduleTask("MetricsLogger", {
    .interval = metricsLogInterval,
    .taskFunction = [metricsWriter, metricsManager]() {
        metricsManager->writeAllMetrics(metricsWriter);
    }
});
```

## Consumers

| Module | What it does |
|--------|-------------|
| **router** | Creates counters for processed/dropped events, registers EPS pull metrics via `SlidingWindowRate`, increments counters in the worker event loop |
| **builder** | Creates per-space counters for unclassified/discarded events in policy pipelines |
| **api/event** | Creates counters for bytes/events received on the ingest endpoint |
| **api/metrics** | Exposes metrics via HTTP API (get, list, enable/disable, dump) |
| **main.cpp** | Registers indexer pull metrics, schedules periodic JSON dump to `streamlog` |

## Thread Safety

- **Registry (`Manager`)**: `std::shared_mutex` — shared lock for reads, unique lock for registration. Double-checked locking on `getOrCreate*` methods.
- **Counters/Gauges**: Lock-free via `std::atomic` with `memory_order_relaxed`. No contention on the hot path.
- **Pull Metrics**: Callback is invoked under no lock. The caller must ensure captured references remain valid.
- **SlidingWindowRate**: Lock-free with CAS-based bucket recycling. Reads are best-effort (consistent enough for metrics, not exact accounting).
- **Global enable**: `std::atomic<bool>` with relaxed ordering.

## File Structure

```
fastmetrics/
├── CMakeLists.txt                                          # Build: ifastmetrics (INTERFACE), fastmetrics (STATIC)
├── interface/fastmetrics/
│   ├── iMetric.hpp                                         # IMetric, ICounter, IGaugeInt interfaces
│   ├── iManager.hpp                                        # IManager interface (registry + writeAllMetrics)
│   ├── registry.hpp                                        # Singleton access: manager(), registerManager(), FASTMETRICS_PULL
│   ├── metric_names.hpp                                    # Predefined metric name constants and formatters
│   └── slidingWindowRate.hpp                               # Lock-free EPS calculator (circular buffer)
├── include/fastmetrics/
│   ├── atomicCounter.hpp                                   # AtomicCounter (ICounter implementation)
│   ├── atomicGauge.hpp                                     # AtomicGaugeInt (IGaugeInt implementation)
│   ├── pullMetric.hpp                                      # PullMetric<T> (callback-based IMetric)
│   └── manager.hpp                                         # Manager class (IManager implementation)
├── src/
│   ├── manager.cpp                                         # Manager methods (get, exists, writeAllMetrics, etc.)
│   └── registry.cpp                                        # registerManager() — SingletonLocator wiring
├── test/
│   ├── mocks/fastmetrics/
│   │   ├── mockCounter.hpp                                 # GMock mock for ICounter
│   │   ├── mockGauge.hpp                                   # GMock mock for IGaugeInt
│   │   └── mockManager.hpp                                 # GMock mock for IManager
│   └── src/
│       ├── unit/
│       │   ├── main.cpp                                    # Test main (registers singleton for tests)
│       │   ├── counter_test.cpp                            # AtomicCounter tests
│       │   ├── gauge_test.cpp                              # AtomicGaugeInt tests
│       │   ├── pullMetric_test.cpp                         # PullMetric tests
│       │   ├── registry_test.cpp                           # Manager/registry tests
│       │   └── slidingWindowRate_test.cpp                  # SlidingWindowRate tests
│       └── component/
│           └── realistic_scenarios_test.cpp                # End-to-end realistic workload tests
```

## Testing

### Unit Tests (`fastmetrics_utest`)

| Test File | Covers |
|-----------|--------|
| `counter_test.cpp` | AtomicCounter: add, increment, reset, enable/disable, concurrent access |
| `gauge_test.cpp` | AtomicGaugeInt: set, add, sub, reset, enable/disable |
| `pullMetric_test.cpp` | PullMetric: callback invocation, disable behavior, exception safety |
| `registry_test.cpp` | Manager: getOrCreate, type conflicts, exists, getAllNames, count, clear, enableAll/disableAll |
| `slidingWindowRate_test.cpp` | SlidingWindowRate: increment, getRate over windows, bucket recycling |

### Component Tests (`fastmetrics_ctest`)

| Test File | Covers |
|-----------|--------|
| `realistic_scenarios_test.cpp` | Realistic multi-threaded workloads with counters, gauges, and pull metrics |

Build and run:

```bash
make --directory=$WAZUH_REPO/src -j TARGET=manager ENGINE_TEST=y DEBUG=yes
$ENGINE_BUILD/source/fastmetrics/fastmetrics_utest
$ENGINE_BUILD/source/fastmetrics/fastmetrics_ctest
```

## Mocks

Available at `test/mocks/fastmetrics/` (CMake target: `fastmetrics::mocks`):

| Mock | Class |
|------|-------|
| `mockCounter.hpp` | `fastmetrics::mocks::MockCounter` — mocks `ICounter` |
| `mockGauge.hpp` | `fastmetrics::mocks::MockGauge` — mocks `IGaugeInt` |
| `mockManager.hpp` | `fastmetrics::mocks::MockManager` — mocks `IManager` |

Used by `router` and `builder` test targets.

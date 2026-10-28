# FastMetrics Module

## Overview

The **fastmetrics** module provides a high-performance, lock-free metrics system for the Wazuh engine. It is designed for ultra-low-overhead instrumentation of hot paths (event processing loops, queue operations) using `std::atomic` with `memory_order_relaxed`. Metrics are registered in a thread-safe registry and accessed globally via a singleton pattern (`SingletonLocator`).

The module supports three metric types: **counters** (monotonically increasing), **gauges** (bidirectional integers), and **pull metrics** (on-demand callbacks). Metrics are not written to a file: they are read on demand through the engine API (`api/metrics`).

This is the engine's metrics library; the rest of the manager uses `wazuh_metrics`
(`src/shared_modules/metrics/`). The operator-facing catalog (what each metric means) and the
`/metrics/*` request and response shapes live in the engine book:
[Metrics](../../../../docs/ref/modules/engine/README.md#metrics) and the
[public API reference](../../../../docs/ref/modules/engine/public-api-reference.md).

## Architecture

```
                    ┌─────────────────────────────────────────────────────┐
                    │                  Producers                          │
                    │                                                     │
                    │  router/worker:    counter.add(1)    (hot path)     │
                    │  router/orch:      FASTMETRICS_PULL(...)            │
                    │  api/event:        counter.add(bytes) (hot path)    │
                    │  builder/policy:   counter.add(1)                   │
                    │  agentcache:       counter.add(1), FASTMETRICS_PULL │
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
                           get() / getAllNames()
                                    │
                    ┌───────────────▼──────────────────┐
                    │   API Endpoints (api/metrics)     │
                    │                                   │
                    │   POST /metrics/get               │
                    │   POST /metrics/list              │
                    │   POST /metrics/enable            │
                    │   POST /metrics/dump              │
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
3. **Cold path** (unique lock): `getOrCreateCounter()`, `getOrCreateGaugeInt()`, `registerPullMetric()` / `registerPullMetricDouble()` — registration with double-checked locking pattern.

### Registration semantics

- `getOrCreateCounter()` / `getOrCreateGaugeInt()` return the existing metric when the name is
  already registered with the same interface, and throw `std::invalid_argument` ("already exists with
  a different type") when it is registered as another type (`include/fastmetrics/manager.hpp`,
  `getOrCreate()`).
- Registering a pull metric under a name that already exists is a **silent no-op**: the first getter
  stays (`registerPullMetricImpl()`). A pull metric has no `remove()`; its getter must stay safe to call
  for the life of the process: the indexer (`main.cpp`) and agent-cache getters capture a `weak_ptr`,
  the router's EPS getters own a `shared_ptr` to their `SlidingWindowRate`.
- The `description` and `unit` parameters of `IManager` are accepted and ignored by `Manager`.

### Enable/Disable

Each metric has an individual `m_enabled` atomic flag. When disabled, all mutation operations (`add`, `set`, `sub`) become no-ops and `value()` returns 0.0 (`reset()` and `get()` are not gated). The manager provides `enableAll()` / `disableAll()`, which set `m_globalEnabled` and toggle every registered metric; a metric created while `m_globalEnabled` is false starts disabled.

### Singleton Access Pattern

The manager is registered once via `fastmetrics::registerManager()` and accessed globally through `fastmetrics::manager()`, which resolves to `SingletonLocator::instance<IManager>()`. This avoids passing the manager through dependency injection in hot paths.

```cpp
// Registration (once in main.cpp)
fastmetrics::registerManager();

// Access from anywhere (cache the pointer outside the hot loop, as router/src/worker.cpp does)
auto counter = fastmetrics::manager().getOrCreateCounter(fastmetrics::names::ROUTER_EVENTS_PROCESSED);
counter->add(1);  // lock-free, hot path
```

Names are never spelled at the call site: they come from the constants and per-space formatters in
`interface/fastmetrics/metric_names.hpp`.

### Pull Metrics and the `FASTMETRICS_PULL` Macro

Pull metrics avoid state duplication by executing a callback on read (from `main.cpp`):

```cpp
std::weak_ptr<wiconnector::WIndexerConnector> wIndexer = indexerConnector;
FASTMETRICS_PULL(uint64_t,
                 fastmetrics::names::INDEXER_QUEUE_SIZE,
                 [wIndexer]()
                 {
                     auto connector = wIndexer.lock();
                     return connector ? connector->getQueueSize() : 0;
                 });
```

The macro expands to `fastmetrics::registerPullMetric(name, std::function<type()>(getter))`, which
calls `registerPullMetric()` for an unsigned integer getter and `registerPullMetricDouble()` for a
`double` one. A getter that throws reads as `0.0` (`PullMetric::value()`).

### Sliding Window Rate (`SlidingWindowRate`)

A lock-free circular buffer for computing events-per-second (EPS) over configurable time windows (up to 31 minutes). Used by the router to compute `router.eps.1m`, `router.eps.5m`, and `router.eps.30m`.

- Resolution: 1 second per bucket.
- Buffer size: 1860 buckets (31 × 60 seconds).
- Each bucket has an atomic timestamp and atomic count.
- Bucket recycling uses a CAS-based protocol with a sentinel timestamp (`RECYCLING_TS`) to prevent data races.
- Reads use a double-check pattern (read timestamp, read count, re-read timestamp) for consistency.

### Metric Output Format

The four `/metrics/*` routes are registered by `api/metrics` (`registerHandlers()` in
`api/metrics/include/api/metrics/handlers.hpp`); their request and response shapes, including the
`global` / `spaces` split of `POST /metrics/dump`, are owned by the engine's public API
([public-api-reference.md](../../../../docs/ref/modules/engine/public-api-reference.md)). Two facts come
from this module: `type` is the `MetricType` rendered as `counter`, `gauge_int` or `pull`
(`metricTypeToString()` in `api/metrics/src/handlers.cpp`), and `value` is always `IMetric::value()`, a
`double`.

## Registered Metric Names

Constants and per-space formatters in `interface/fastmetrics/metric_names.hpp`, and who registers each
(the meaning of each metric is documented in the engine book's
[Available metric names](../../../../docs/ref/modules/engine/README.md#available-metric-names)):

| Name | Type | Source |
|------|------|--------|
| `indexer.queue.size` | PULL | `main.cpp` (only when the indexer connector is enabled) |
| `indexer.queue.usage.percent` | PULL | `main.cpp` (only when the indexer connector is enabled) |
| `indexer.events.dropped` | PULL | `main.cpp` (only when the indexer connector is enabled) |
| `router.queue.size` | PULL | `router/src/orchestrator.cpp` |
| `router.queue.usage.percent` | PULL | `router/src/orchestrator.cpp` |
| `router.queue.bytes.used` | PULL | `router/src/orchestrator.cpp` |
| `router.queue.bytes.usage.percent` | PULL | `router/src/orchestrator.cpp` |
| `router.events.processed` | COUNTER | `router/src/worker.cpp` |
| `router.events.dropped` | COUNTER | `router/src/orchestrator.cpp` |
| `router.events.malformed` | COUNTER | `router/src/worker.cpp` |
| `router.eps.1m` | PULL | `router/src/orchestrator.cpp` (`SlidingWindowRate`, 60 s) |
| `router.eps.5m` | PULL | `router/src/orchestrator.cpp` (`SlidingWindowRate`, 300 s) |
| `router.eps.30m` | PULL | `router/src/orchestrator.cpp` (`SlidingWindowRate`, 1800 s) |
| `agent.cache.entries` | PULL | `agentcache` (`registerCacheMetrics()`, called from `main.cpp`) |
| `agent.cache.hits` | COUNTER | `agentcache` (`AgentMetadataCache`) |
| `agent.cache.insertions` | COUNTER | `agentcache` (`AgentMetadataCache`) |
| `agent.cache.updates` | COUNTER | `agentcache` (`AgentMetadataCache`) |
| `agent.cache.evictions` | COUNTER | `agentcache` (`AgentMetadataCache`) |
| `server.bytes.received` | COUNTER | `api/event` |
| `server.events.received` | COUNTER | `api/event` |
| `space.{name}.events.unclassified` | COUNTER | `builder/src/policy/policy.cpp` (per-space) |
| `space.{name}.events.discarded` | COUNTER | `builder/src/policy/policy.cpp` (per-space) |
| `space.{name}.events.discarded.prefilter` | COUNTER | `builder/src/policy/policy.cpp` (per-space) |
| `space.{name}.events.discarded.postfilter` | COUNTER | `builder/src/policy/policy.cpp` (per-space) |

No engine module registers a `GAUGE_INT` today; the type is exercised only by the tests.

## Dependencies

| Dependency | CMake Target | Role |
|------------|-------------|------|
| `base` | `base` | `SingletonLocator`, logging |

## Integration in `main.cpp`

```cpp
// 1. Register singleton manager (early startup)
fastmetrics::registerManager();

// 2. Register pull metrics for the indexer (only when the indexer connector is enabled)
FASTMETRICS_PULL(uint64_t, fastmetrics::names::INDEXER_QUEUE_SIZE, [wIndexer]() { ... });
FASTMETRICS_PULL(double, fastmetrics::names::INDEXER_QUEUE_USAGE_PERCENT, indexerQueueUsageGetter);

// 3. Wrap singleton as shared_ptr for API handlers
metricsManager = std::shared_ptr<fastmetrics::IManager>(&fastmetrics::manager(), [](fastmetrics::IManager*) {});

// 4. Register API endpoints
api::metrics::handlers::registerHandlers(metricsManager, apiServer, "wazuh-manager-analysisd", engineUptimeISO);
```

## Consumers

| Module | What it does |
|--------|-------------|
| **router** | Creates counters for processed/dropped events, registers queue and EPS pull metrics via `SlidingWindowRate`, increments counters in the worker event loop |
| **agentcache** | Creates hit/insertion/update/eviction counters and the `agent.cache.entries` pull metric |
| **builder** | Creates per-space counters for unclassified/discarded events in policy pipelines |
| **api/event** | Creates counters for bytes/events received on the ingest endpoint |
| **api/metrics** | Exposes metrics via HTTP API (get, list, enable/disable, dump) |
| **main.cpp** | Registers indexer pull metrics and the `api/metrics` handlers |

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
│   ├── iManager.hpp                                        # IManager interface (registry, enable/disable)
│   ├── registry.hpp                                        # Singleton access: manager(), registerManager(), FASTMETRICS_PULL
│   ├── metric_names.hpp                                    # Predefined metric name constants and formatters
│   └── slidingWindowRate.hpp                               # Lock-free EPS calculator (circular buffer)
├── include/fastmetrics/
│   ├── atomicCounter.hpp                                   # AtomicCounter (ICounter implementation)
│   ├── atomicGauge.hpp                                     # AtomicGaugeInt (IGaugeInt implementation)
│   ├── pullMetric.hpp                                      # PullMetric<T> (callback-based IMetric)
│   └── manager.hpp                                         # Manager class (IManager implementation)
├── src/
│   ├── manager.cpp                                         # Manager methods (get, exists, getAllNames, etc.)
│   └── registry.cpp                                        # registerManager() — SingletonLocator wiring
├── test/
│   ├── mocks/fastmetrics/
│   │   ├── mockCounter.hpp                                 # GMock mock for ICounter
│   │   ├── mockGauge.hpp                                   # GMock mock for IGaugeInt
│   │   └── mockManager.hpp                                 # GMock mock for IManager
│   └── src/
│       ├── unit/
│       │   ├── main.cpp                                    # GoogleTest main (no singleton registration)
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
| `gauge_test.cpp` | AtomicGaugeInt: set, add, sub, negative values, reset, enable/disable |
| `pullMetric_test.cpp` | PullMetric: callback invocation, disable behavior, exception safety |
| `registry_test.cpp` | Manager: getOrCreate (returns existing), get, exists, getAllNames, count, clear, enableAll/disableAll, concurrent registration |
| `slidingWindowRate_test.cpp` | SlidingWindowRate: increment, getRate over windows, zero window, old events leaving the window, window clamped to 31 min, concurrent increments |

### Component Tests (`fastmetrics_ctest`)

| Test File | Covers |
|-----------|--------|
| `realistic_scenarios_test.cpp` | Realistic multi-threaded counter workloads: event pipeline, worker pool, dynamic metric creation, high-frequency updates |

Build and run:

```bash
make -C src -j TARGET=manager ENGINE_TEST=y      # from the repository root; ENGINE_TEST sticks in the cache
src/build/engine/source/fastmetrics/fastmetrics_utest
src/build/engine/source/fastmetrics/fastmetrics_ctest
```

Both executables register their cases with `gtest_discover_tests`, so `ctest` sees them under the
GoogleTest names (`CounterTest.*`, `RegistryTest.*`, `RealisticScenariosTest.*`, …), not under
`fastmetrics`.

## Mocks

Available at `test/mocks/fastmetrics/` (CMake target: `fastmetrics::mocks`), all in namespace `fastmetrics`:

| Mock | Class |
|------|-------|
| `mockCounter.hpp` | `fastmetrics::MockCounter` — mocks `ICounter` |
| `mockGauge.hpp` | `fastmetrics::MockGaugeInt` — mocks `IGaugeInt` |
| `mockManager.hpp` | `fastmetrics::MockManager` — mocks `IManager` |

Used by `router` and `builder` test targets.

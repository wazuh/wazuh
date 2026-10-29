# wazuh_metrics — shared lock-free metrics

A small metric library for manager daemons: counters, gauges, histograms and
pull metrics behind a thread-safe registry (`Manager`), a rapidjson-based JSON
dump, and a standalone sliding-window rate helper. STL-only public headers;
rapidjson is a private dependency of one translation unit.

Consumers (each links the `wazuh_metrics` STATIC archive and serves the dump on
its own UDS socket): `inventory_sync_server`, `task_manager` and
`vulnerability_scanner` (all in modulesd), and `remoted_module`.

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
| RF-1 | Counter / gauge / histogram / pull types behind `IMetric` interfaces, each registered through `IManager` with optional `description`/`unit` metadata. `SlidingWindowRate` is a standalone helper: not an `IMetric`, never in the registry or the dump | kept |
| RF-2 | Thread-safe registry: `getOrCreate*` is idempotent (same name → same instance); re-registering a name under a **different type** throws | kept |
| RF-3 | Histograms answer p50/p90/p99 snapshots with bounded relative error (~12.5%, 128 log-linear buckets: 32 octaves × 4 sub-buckets, so an observation of 2^32 or more lands in the last bucket and only the exact `max` still reports it); min/max are exact and the percentiles are clamped into `[min, max]`, so `min <= p50 <= p90 <= p99 <= max` always holds within a snapshot; percentiles are computed only on `snapshot()` | kept |
| RF-4 | `dumpJson()` is deterministic: entries sorted by name, exact unsigned integers for counters/counts, `description`/`unit` omitted when not registered, envelope with daemon name + ISO-8601 UTC timestamp | kept |
| RF-5 | Scalar entries carry the engine-compatible `{name, type, enabled, value}` shape so tooling treats both dumps alike | kept |

### Non-functional

| # | Requirement | Status |
|---|---|---|
| RNF-1 | No singleton — the manager is injected (`shared_ptr<IManager>`); nothing touches the engine's `base` utilities | kept |
| RNF-2 | Hot path is one relaxed atomic op on a cached pointer; `getOrCreate*` (shared lock + hash) is cold-path only | kept |
| RNF-3 | Public headers are STL-only; rapidjson exists in exactly one TU (`src/jsonDump.cpp`) | kept |
| RNF-4 | C++17 floor: `target_compile_features(wazuh_metrics PUBLIC cxx_std_17)`. Nothing pins the archive or `wazuh_metrics_utest` to 17, so both compile at the tree default C++20 and a C++20-ism is not caught by this module's CI (`5_testunit_metrics.yml` says so) | kept, not enforced |

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

How a consumer instruments itself — resolve once and mutate lock-free, no labels, names in a
catalog header beside the owning subsystem, pull-metric lifetimes, durations as integer
histograms, serving and documenting the dump — is published as the
[integration guide](../../../docs/ref/modules/utils/metrics/integration-guide.md), and the dump
format an operator reads as the
[Metrics Library page](../../../docs/ref/modules/utils/metrics/README.md#querying-a-modules-metrics).
They are the single copy; the requirements and decisions above say why. Two details of the dump
that only a developer needs: the envelope `name` is `DumpOptions::daemonName`, and an empty
`DumpOptions::timestampISO` means the current UTC time, formatted `%Y-%m-%dT%H:%M:%SZ`
(`DumpOptions::pretty` switches the compact default to a pretty-printed document).

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
│   ├── slidingWindowRate.hpp  # per-second EPS over a 31-minute ring (standalone, not an IMetric)
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

`test/unit/` builds `wazuh_metrics_utest` (GTest, ctest label `wazuh_metrics_utest`)
under `cmake -S src -B src/build -DUNIT_TEST=ON`. CI runs it on every PR touching
`src/shared_modules/metrics/**` via `.github/workflows/5_testunit_metrics.yml`: a
coverage job (line coverage over `src/` + `include/`; function coverage is not gated,
since the pure-interface headers dominate the function count) and an ASAN/UBSAN/LSan job.
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

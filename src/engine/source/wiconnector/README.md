# wiconnector

## Overview

The **wiconnector** module is the Engine's **writer** to the wazuh-indexer (OpenSearch), plus the one
read the remote configuration needs, and the owner of the Engine's `indexer_client` runtime. It exposes:

- **Indexing events** — posting processed / raw-event JSON documents to data-stream indices.
- **Remote engine configuration** — pulling runtime engine settings from `.wazuh-settings`.
- **Metrics** — the queued bytes, their share of the capacity and the events not indexed (the three `indexer.*`
  metrics), every metric of the two buckets and the runtime's, published through fastmetrics by
  `registerIndexerMetrics()`.

**One connection.** Writes and reads go through the Engine's `indexer_client` `Client` `analysisd` (the
v1 connector is no longer used here). The writes use its two buckets, `events` and `raw`; the reads
are the remote configuration here and the content downloads of [`cmcontent`](../cmcontent/README.md), which the
content manager makes through that same Client. An indexer outage is reported once.

## Architecture

```
 ┌──────────┐ ┌──────────────┐ ┌──────────┐
 │ builder  │ │rawevtindexer │ │confremote│
 └────┬─────┘ └──────┬───────┘ └────┬─────┘
      └──────────────┼──────────────┘
                     │  IWIndexerConnector
                     ▼
          ┌──────────────────────────────┐
          │  WIndexerConnector           │
          │  • index(): IWriter::post    │
          │    (no lock, fixed writers)  │
          │  • metrics: 1 snapshot / s   │
          │    (3 getters + per bucket)  │
          └─────────┬────────────────────┘
                    │  buckets `events` (weight 2) and `raw` (weight 1); IQuery for the reads
                    ▼
          ┌──────────────────────────────┐
          │ indexer_client Client        │──►  wazuh-indexer
          │ `analysisd`                  │
          └──────────────────────────────┘
```

The Client is created by `EngineIndexerRuntime` with both buckets, shared with the content topics and handed to
`WIndexerConnector`.

## Key Concepts

### Hot path and thread safety

`index(index, data)` takes both strings by value and moves them into an `Op{IndexDataStream}` that it posts with
`IWriter::post` (no ticket, no callback) to `raw` when the index is `RAW_EVENTS_INDEX` (`wazuh-events-raw-v5`, declared
next to the interface and shared with `rawevtindexer`) and to `events` otherwise: no copy of the body and no lock. The two
writers are fixed in the constructor. A refused post (`payload_too_large`, `invalid_argument`, `client_closed`, ...)
never throws: it is logged on the edge (one WARN until a post is accepted again, then one INFO) and counted only by
the library, in the bucket's `rejected` counters.

`shutdown()` sets an atomic flag and releases the writers and the Client (a mutex guards only the Client pointer,
which the reads and the metrics copy out before calling it). **Precondition**: no `index()` runs concurrently with
`shutdown()` — the router and tester workers are joined before the indexer's exit handler runs. After
`shutdown()`, `index()` discards the event and counts it (the module's only local counter), the queue size and usage
read 0, and `getEngineRemoteConfig()` throws `std::runtime_error`. The Engine calls `shutdown()` after the Client's
`requestClose()`, so a remote configuration read in flight returns `ClientClosed`.

### Buckets (`engineBucketSpecs`)

`EngineIndexerRuntime::start(process, source, EngineWriteOptions, warnings)` builds the two buckets from the v1 keys
that `main.cpp` reads (`EngineWriteOptions`) and the validated `RuntimeConfig` (it needs `global_quota_bytes`):

| Bucket field | Value |
|---|---|
| `weight` | `events` 2, `raw` 1 |
| `quotaBytes` | `analysisd.indexer_queue_max_bytes` for **both**; `0` ⇒ `global_quota_bytes`; above it ⇒ `global_quota_bytes` + WARN |
| `bulk.maxBytes` | `analysisd.indexer_bulk_max_bytes`, clipped to `quota − RESULT_RESERVE_BYTES` (2048) + WARN when it does not fit |
| `bulk.maxAge` | `analysisd.indexer_flush_interval` |
| `bulk.maxDocs` | `SIZE_MAX`: as in the v1, a bulk is cut only by bytes and by age (the library's default is 10 000) |
| `retry` | unlimited attempts and duration; `cap` = `analysisd.indexer_max_retry_delay` (the base is lowered to the cap if needed) |
| `overflow` | `DropNewest` (the router never waits) |
| `onAmbiguous5xx` | `Fail` (data streams without `_id`: a resend would duplicate); it also covers a `_bulk` answer over `max_response_bytes`, never split nor resent |
| `trustedBodies` | `true` (the Engine only sends compact `json::Json::str()` output) |

A quota that cannot hold a 64 KiB bulk and its reserve fails the start (`InvalidConfig`, no runtime); the error names
the key the quota came from (`analysisd.indexer_client_global_quota_bytes` when `indexer_queue_max_bytes` is `0` or
above it).
`analysisd.indexer_logger_queue_size` and `analysisd.indexer_logger_threads` are ignored, with a WARN when not at
their default (8 and 1). The warnings are returned to `main.cpp`, which logs them. `queueCapacityBytes()` =
min(Σ quotas, `global_quota_bytes`). Every queued op also reserves `RESULT_RESERVE_BYTES` of the quota, so a v2 quota
holds fewer small events than a v1 queue of the same size.

### Metrics

The three getters and `getBucketMetric()` read one cached `Client::metrics()` snapshot, refreshed at most once per
second (one scrape of every indexer metric takes one snapshot):

| Getter | Value |
|---|---|
| `getQueueSize()` | Σ `retainedBytes` of `events` and `raw` |
| `getQueueUsagePercent()` | max(the fullest bucket, the shared budget) × 100, capped at 100: max over `events` and `raw` of `charge` / `quotaBytes`, and Σ `charge` / `queueCapacityBytes`. 100 = a bucket or the global budget is full, i.e. new events are dropped (`QueueFull` or `GlobalFull`): the second term only matters when 2 × quota > global (a quota of `0` or above half the global quota). A bucket with quota 0 is skipped; 0.0 with no capacity or once shut down |
| `getDroppedEvents()` | Σ `dropped` + `failed` + `rejected` (every cause) of both buckets, plus the events discarded after `shutdown()`; after it the bucket part is the last snapshot taken before it (up to `METRICS_TTL`, 1 s, older than the close; zeros if nothing read the metrics before), so what the runtime's stop drops later (`Dropped(Shutdown)`) is not in it |

`getBucketMetric(name)` serves the library's catalog for the two buckets from that snapshot:
`indexer_client.bucket.analysisd.{events,raw}.<field>`, 52 names per bucket (`accepted`, `ok`, `deduplicated`, `late_results`,
`rejected.*`, `dropped.*`, `failed.*`, `retries.*` by cause, `retained_bytes`, `charge_bytes`, `quota_bytes`,
`bulk_requests`, `bulk_bytes` and the cumulative `latency.*` histogram). `bucketMetricNames()` lists them, with their
kind, from a snapshot with no values, so the set is known before any metrics() call. The client-wide
`indexer_client.client.analysisd.*` metrics are not served (the engine registers no callbacks). After `shutdown()` the
values are those of the last snapshot, as the bucket part of `getDroppedEvents()`; any other name reads 0.

`registerIndexerMetrics(manager, connector, runtime)` (`indexerMetrics.hpp`) registers them all as fastmetrics pull
metrics, once, from `main.cpp`: the three `indexer.*` names over the getters, every `bucketMetricNames()` name over
`getBucketMetric()` (as integers), and, given the `RuntimeRef` (`EngineIndexerRuntime::runtime()`), the runtime's
`indexer_client.{runtime,query,pit}.*` and `indexer_client.node.<i>.*` metrics through an
`indexer_client::MetricsSlot` holding only the runtime and refreshed at most once per `METRICS_TTL` (counters as
integers, gauges as doubles; the node family is sized by the snapshot taken at registration, which is fixed for the life
of the runtime). The getters hold the connector weakly: once it is gone the bucket metrics read 0. These are the names
the manager's modulesd consumers publish for their own buckets and runtime; the engine's runtime is its own process's.
The operator catalog is in
[engine metrics § Indexer client metrics](../../../../docs/ref/modules/engine/README.md#indexer-client-metrics).

The snapshot lags the `index()` calls: the library stages the `post()` of each producer thread and admits it in
batches (64 ops, ~1 ms, or the close), so `retainedBytes`, `charge` and the queue-full drops move up to 64 ops per
stripe behind; staged ops are outside the quota until then (at most `quotaBytes / 2` per bucket, `quotaBytes`
being the effective quota, see
[Staged admission of `post`](../../../shared_modules/indexer_client/README.md#staged-admission-of-post)).
Worst case with the defaults: min(2 × 64 MiB, 256 MiB global) charged plus 2 × 32 MiB staged, about 192 MiB, against
the single 64 MiB queue of the v1; with `indexer_queue_max_bytes` = 0 (quota = global), 256 + 2 × 128 = 512 MiB.

### Runtime and two-phase stop (`EngineIndexerRuntime`)

`EngineIndexerRuntime` (`engineIndexerRuntime.hpp`) owns the process's `indexer_client` runtime and the one Client
(`analysisd`). `start(process, source, options, warnings)` validates the configuration, builds the buckets, starts the
runtime and creates the Client; `start(process, source)` creates it without buckets and remains for tests.
`runtime()` returns the `RuntimeRef` of a successful start (empty before), for the runtime's metrics; after
`finishStop()` the reference is no longer valid and its snapshot keeps only the process-wide query and PIT counters. Every
call must come from the thread that started it (the runtime's owner: the Engine's main thread). The stop is in two
phases that `main.cpp` places around the scheduler's stop:

1. `beginStop()`, before the scheduler stops: fixes the shutdown deadline (now + 3 s, `STOP_BUDGET`) and closes the
   Client's admission (`requestClose()`), so a read in flight returns `ClientClosed`. `WIndexerConnector::shutdown()` follows.
2. `finishStop()`, after the scheduler has stopped: joins the runtime (`RuntimeOwner::shutdown()`) with the Client still
   registered, then `awaitClosed` without a drain and releases the Client.

Nothing waits for the queue to drain (as the v1): `finishStop()` does not wait for the buckets, and what is still queued when the runtime closes is discarded. Between `beginStop()` (which closes the Client's admission) and `finishStop()` the library may still send what is already queued while the scheduler stops; the whole stop fits in 3 s. The discarded events are
not counted in `getDroppedEvents()` (its bucket part is the snapshot from before `shutdown()`), but they are logged:
the runtime's stop resolves them `Dropped(Shutdown)` and its last summary, which only sees the clients still registered
(`awaitClosed` releases the consumer name, hence the order), emits the engine's buckets with them (`... unsuccessful
operations in the last <n> s: shutdown=<count>.` and `... <count> dropped.`). `finishStop()` without a
previous `beginStop()` runs both phases; each phase runs once.

### Configuration

`Config` is the standalone `<indexer>` section (`hosts`, `ssl`); `toJson()` serialises it as the indexer client reads
it, always with `ssl.verify_certificates` (`analysisd.indexer_ssl_verify_certificates`, env
`WAZUH_INDEXER_SSL_VERIFY_CERTIFICATES`, default `true`). Credentials are not part of it: the Client's credentials come from the keystore (`indexer` / `username`,
`password`) through `keystoreCredentials()` (an injectable `CredentialsProvider`; `Keystore::get` comes from
`keystore_core`, the `keystore` archive without its `Log::GLOBAL_LOG_FUNCTION`: the engine defines and assigns its own,
so what the keystore logs reaches the engine's sink), and the runtime's local copy of the password is erased after
`start` (the keystore keeps its own). `keystore_core` is compiled with the keystore's own flags (C++20, `-fPIC`), not the
engine's: an engine sanitizer build does not instrument it.

#### `EngineConfigSource` (the Client's configuration)

`EngineConfigSource` implements `indexer_client::IConfigSource` for the Engine. Keys are the full names under
`analysisd.indexer_client_` (the Engine's prefix, in standalone too). Each key resolves from the environment variable
`WAZUH_<key without "analysisd.", upper case>` (the convention of `conf`), then, in manager mode only, from the internal
options file; otherwise it is unset and the library default applies. Standalone never reads the file. `keysWithPrefix` also
enumerates the environment, so an unknown `WAZUH_INDEXER_CLIENT_*` variable is rejected like an unknown file key. The `<indexer>`
section is the manager's (`hosts`, `ssl`); standalone builds it from `analysisd.indexer_hosts|ssl_*` (including `ssl_verify_certificates`) through the environment only.

Two v1 keys feed their v2 equivalent when that one is not set: `analysisd.indexer_request_timeout` (s) →
`indexer_client_request_timeout_ms` and `analysisd.indexer_monitoring_interval` (s) → `indexer_client_probe_interval_ms`.
"Set" means an environment variable or a file entry, never a `conf` default. Both set and different in ms is reported by
`problem()` on the v2 key (the start fails); a v1 value of `0` leaves the v2 key unset and is reported once by `warnings()`
(logged as WARN). The operator-facing list is in
[engine configuration reference § Indexer client settings](../../../../docs/ref/modules/engine/configuration.md#indexer-client-settings).

The write keys of the v1 still come from the same `conf` mechanism (env var, `wazuh-manager-internal-options.conf`, or
default — env var wins); `main.cpp` validates their ranges first (an out-of-range value aborts startup) and passes them
in `EngineWriteOptions` to the runtime. They are documented in the
[engine configuration reference § Indexer connector settings](../../../../docs/ref/modules/engine/configuration.md#indexer-connector-settings);
the keys, env vars and defaults (`conf.cpp`) are:

| Internal option | Env Override | Default |
|-----------------|--------------|---------|
| `analysisd.indexer_queue_max_bytes` | `WAZUH_INDEXER_QUEUE_MAX_BYTES` | `67108864` (64 MB) |
| `analysisd.indexer_bulk_max_bytes` | `WAZUH_INDEXER_BULK_MAX_BYTES` | `8388608` (8 MB) |
| `analysisd.indexer_flush_interval` | `WAZUH_INDEXER_FLUSH_INTERVAL` | `20` |
| `analysisd.indexer_logger_queue_size` | `WAZUH_INDEXER_LOGGER_QUEUE_SIZE` | `8` |
| `analysisd.indexer_logger_threads` | `WAZUH_INDEXER_LOGGER_THREADS` | `1` |
| `analysisd.indexer_max_retry_delay` | `WAZUH_INDEXER_MAX_RETRY_DELAY` | `15` |
| `analysisd.indexer_request_timeout` | `WAZUH_INDEXER_REQUEST_TIMEOUT` | `60` |
| `analysisd.indexer_monitoring_interval` | `WAZUH_INDEXER_MONITORING_INTERVAL` | `10` |

## Directory Structure

```
wiconnector/
├── CMakeLists.txt
├── README.md
├── interface/wiconnector/
│   └── iwindexerconnector.hpp        # IWIndexerConnector, RAW_EVENTS_INDEX
├── include/wiconnector/
│   ├── windexerconnector.hpp         # WIndexerConnector + Config
│   ├── engineConfigSource.hpp        # EngineConfigSource, keystoreCredentials
│   ├── engineIndexerRuntime.hpp      # EngineIndexerRuntime, EngineWriteOptions, engineBucketSpecs
│   └── indexerMetrics.hpp            # registerIndexerMetrics
├── src/
│   ├── windexerconnector.cpp
│   ├── engineConfigSource.cpp
│   ├── engineIndexerRuntime.cpp
│   └── indexerMetrics.cpp
└── test/
    ├── mocks/wiconnector/
    │   └── mockswindexerconnector.hpp     # MockWIndexerConnector
    └── src/unit/
        ├── wic_test.cpp
        ├── engineConfigSource_test.cpp
        ├── engineIndexerRuntime_test.cpp
        └── indexerMetrics_test.cpp
```

## Public Interface

```cpp
namespace wiconnector
{
constexpr std::string_view RAW_EVENTS_INDEX {"wazuh-events-raw-v5"}; // → the `raw` bucket

class IWIndexerConnector
{
public:
    virtual ~IWIndexerConnector() = default;
    virtual void index(std::string index, std::string data) = 0; // both moved into the operation
    virtual json::Json getEngineRemoteConfig() = 0;
    virtual uint64_t getQueueSize() = 0;     // bytes pending
    virtual uint64_t getDroppedEvents() = 0;
    virtual double getQueueUsagePercent() = 0;
};

class WIndexerConnector : public IWIndexerConnector
{
public:
    WIndexerConnector(std::shared_ptr<indexer_client::IClient> client,  // with the `events` and `raw` buckets
                      std::chrono::milliseconds requestTimeout,         // remote configuration reads
                      std::uint64_t queueCapacityBytes);                // EngineIndexerRuntime::queueCapacityBytes()
    void shutdown(); // releases the writers and the Client; never concurrent with index()

    static std::vector<std::pair<std::string, indexer_client::MetricKind>> bucketMetricNames(); // both buckets
    double getBucketMetric(const std::string& name); // same cached snapshot as the three getters
};

// The three indexer.* metrics, the buckets' catalog and, with a runtime, the runtime/node/query/PIT metrics.
void registerIndexerMetrics(fastmetrics::IManager& manager,
                            const std::weak_ptr<WIndexerConnector>& connector,
                            const std::optional<indexer_client::RuntimeRef>& runtime);
}
```

## Key Flows

- **`index(index, data)`** — after `shutdown()`: discard and count. Otherwise `post(Op{IndexDataStream, index, data})`
  on `raw` (`RAW_EVENTS_INDEX`) or `events`, without a lock; a refusal is logged on the edge, never thrown.
- **`getEngineRemoteConfig()`** — searches `.wazuh-settings` for exactly one document through the Client's `IQuery::search`
  (same body as the v1: `match_all`, `size=1`, source `engine` only; unwrapping the v2 `hits`), extracts `_source.engine`,
  checks it is an object and returns it (for example `{ "index_raw_events": false }`, consumed by `confremote`). One
  attempt (`maxAttempts = 1`: the retry is the caller's), a page deadline of the runtime's `request_timeout_ms` and a call
  deadline a margin above it. Once every node has been probed and none is usable it fails at once; before
  the first probe round it waits for a node to be probed, bounded by the probe deadline. A null `query()` is `ClientClosed`, which throws like every other failure (it is
  never read as "no config"); 0 or more than one hit, or no `_source.engine`, throw. Every failure is a
  `wiconnector::RemoteConfigError` (a `std::runtime_error`; callers catch `std::exception`), with the v1's messages; the
  "no usable node" check is `HealthView::noUsableAfterProbes()` of the client library, shared with the content manager.

## CMake Targets

| Target | Type | Alias | Links |
|---|---|---|---|
| `wIndexerConnector_iwIndexerConnector` | INTERFACE | `wIndexerConnector::iwIndexerConnector` | `base` |
| `wIndexerConnector_wIndexerConnector` | STATIC | `wIndexerConnector::wIndexerConnector` | `base`, `wIndexerConnector::iwIndexerConnector`, `indexer_client`, `fastmetrics::ifastmetrics` (public); `keystore_core` (**private**, `Keystore::get`) |
| `wIndexerConnector_mocks` | INTERFACE | `wIndexerConnector::mocks` | `GTest::gmock`, `wIndexerConnector::iwIndexerConnector` (test builds only) |
| `wIndexerConnector_utest` | Executable | — | `GTest::gtest_main`, `GTest::gmock`, `wIndexerConnector::wIndexerConnector`, `wIndexerConnector::mocks`, `fastmetrics::fastmetrics`; discovered tests hold the `rocks_db_lock` resource lock (test builds only) |

## Testing

- **Unit tests** (`test/src/unit/wic_test.cpp`) — `Config::toJson()`, the bucket of each index, the moved body (a
  hand-written `FakeWriter` checks the buffer reaches `Op::body`), refusals counted once, the metrics (sums, the fullest
  bucket's percent, the global budget when it binds (quota = global, both buckets at 50 % ⇒ 100), quota 0, every cause, one snapshot per second, the refresh), `shutdown()` (the writers expire, later events are discarded and
  counted), concurrent indexing, and `getEngineRemoteConfig()` against the library's `MockClient`/`MockQuery`.
- **`engineIndexerRuntime_test.cpp`** — `engineBucketSpecs` (`EngineBucketSpecsTest.*`) and the runtime against the
  library's in-process fake indexer: start with and without buckets, the capacity, the failed start, the stop phases.
- **`indexerMetrics_test.cpp`** — `bucketMetricNames()` (52 names per bucket, nothing client-wide) and
  `registerIndexerMetrics()` on a local `fastmetrics::Manager`: the three `indexer.*` names and every bucket metric from
  one `metrics()` call, the last snapshot after `shutdown()` and 0 without a connector, and, on a runtime started
  against the library's fake indexer, the runtime, node, query and PIT families (one node set per host).
- **Mock** (`test/mocks/wiconnector/mockswindexerconnector.hpp`) — `MockWIndexerConnector`.

## Consumers

| Module | Dependency | Role |
|---|---|---|
| `builder` | `wIndexerConnector::iwIndexerConnector` | Pushes indexed events via the `indexerOutput` stage |
| `rawevtindexer` | `wIndexerConnector::iwIndexerConnector` | Indexes raw events |
| `confremote` | `wIndexerConnector::iwIndexerConnector` | Reads the remote engine configuration |
| `main.cpp` | `wIndexerConnector::wIndexerConnector` | Starts `EngineIndexerRuntime` with the buckets (when event processing is enabled), builds the connector and injects it, registers the two stop phases and the indexer metrics (`registerIndexerMetrics()`) |

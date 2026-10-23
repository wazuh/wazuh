# wiconnector

## Overview

The **wiconnector** module provides the **Wazuh Indexer Connector** — a thread-safe client that the engine uses to communicate with the wazuh-indexer (OpenSearch). It exposes a unified interface for:

- **Indexing events** — pushing processed / raw-event JSON documents into data-stream indices.
- **Retrieving policy resources** — fetching the full content of a policy space (KVDBs, decoders, filters, integrations, policy definition) for content synchronization.
- **Policy metadata queries** — checking policy existence, retrieving the SHA-256 hash and enabled status.
- **IOC operations** — checking whether the IOC index exists (`false` only on a 404; any other failure throws), reading hash manifests, and streaming IOC records by type with batched pagination.
- **CTI consumer readiness** — a pre-flight check on `.wazuh-cti-consumers`.
- **Remote engine configuration** — pulling runtime engine settings from `.wazuh-settings`.
- **Queue introspection** — reporting the pending-queue size in bytes and the dropped-event count (exported by `main.cpp` as indexer metrics).

Internally the module wraps an asynchronous `IndexerConnectorAsync` instance (from the shared `indexer_connector` library in `src/shared_modules/indexer_connector/`; operator page [indexer_connector](../../../../docs/ref/modules/indexer_connector/README.md)) behind the internal `IIndexerConnectorAsync` interface (`IndexerConnectorAsyncAdapter`, so tests can inject a mock), and protects every operation with a `std::shared_mutex` for concurrent access.

## Architecture

```
 ┌──────────┐ ┌─────────┐ ┌──────────┐ ┌──────────────┐ ┌──────────┐ ┌──────────┐
 │ builder  │ │ cmsync  │ │ iocsync  │ │rawevtindexer │ │confremote│ │ main.cpp │
 └────┬─────┘ └────┬────┘ └────┬─────┘ └──────┬───────┘ └────┬─────┘ └────┬─────┘
      │            │           │               │              │   metrics  │
      └────────────┴─────┬─────┴───────────────┴──────────────┴────────────┘
                         │  IWIndexerConnector
                         ▼
              ┌─────────────────────┐
              │  WIndexerConnector  │
              │                     │
              │  • shared_mutex     │
              │  • queryByBatches() │
              │  • PIT pagination   │
              └─────────┬───────────┘
                        │  IIndexerConnectorAsync → IndexerConnectorAsync
                        ▼
              ┌─────────────────────┐
              │  indexer_connector   │
              │  (OpenSearch client) │
              └─────────────────────┘
                        │
                        ▼
              ┌─────────────────────┐
              │   wazuh-indexer     │
              │   (OpenSearch)      │
              └─────────────────────┘
```

## Key Concepts

### Consumer Validation via Point-In-Time (PIT)

To prevent **TOCTOU (time-of-check time-of-use) races** between policy/IOC hash validation and subsequent data download, the connector implements **consumer validation within a PIT snapshot**. When downstream modules (`cmsync`, `iocsync`) pass a `consumerIdToValidate` parameter:

1. A **multi-index PIT** is created that includes both the data index AND `.wazuh-cti-consumers`.
2. Within the same PIT snapshot, the consumer document is queried and validated to be in the `ready` status.
3. If the consumer is not ready, the method returns `std::nullopt` (graceful skip — data download is deferred). A missing consumer document, or one without a `status`, inside the PIT is an error (`IndexerConnectorException`).
4. If the consumer is ready, data retrieval proceeds within the same PIT, guaranteeing consistency.

Before the PIT, `isConsumerReadyForSync(consumerId)` is a cheap pre-flight check. It reads the consumer document directly (no PIT) and returns `true` only for `status == "ready"` and `local_offset != 0`.
- It returns `false` when the document or the `.wazuh-cti-consumers` index is missing; the index answers 404 `index_not_found_exception`, which `IndexerConnectorException::statusCode()` identifies.
- It throws on any other error (transport, 429, 5xx, 401/403), so the caller's retry covers it.

This pattern is used by:
- `getPolicy()` — validates `STANDARD_RULESET_CONSUMER_ID` before fetching policy resources.
- `getPolicyHashAndEnabled()` — validates consumer before checking hash.
- `getIocTypeHashes()` → `queryByBatches()` — validates `IOC_ENRICHMENT_CONSUMER_ID` before reading hashes.
- `streamIocsByType()` → `queryByBatches()` — validates consumer before pagination.

The consumer IDs are passed by the callers (`cmsync`, `iocsync`); the connector only validates the one it is given.

### Well-Known Consumer IDs

| Constant | Value | Used By | Purpose |
|---|---|---|---|
| `STANDARD_RULESET_CONSUMER_ID` | `"cti:catalog:consumer:ruleset"` | cmsync | Validates policy consumer before sync |
| `IOC_ENRICHMENT_CONSUMER_ID` | `"cti:catalog:consumer:iocs"` | iocsync | Validates IOC consumer before sync |

### Thread Safety

Every public method except `requestShutdown()` acquires either a **shared lock** (read operations, indexing) or an **exclusive lock** (`shutdown`). After `shutdown()` resets the internal connector, subsequent calls degrade: `index()` returns (debug log), `getQueueSize()`/`getDroppedEvents()` return `0`, `isConsumerReadyForSync()` returns `false`, and the other query methods throw `std::runtime_error` (`IndexerConnectorAsync is not initialized`).

### Graceful Shutdown

`WIndexerConnector` supports a two-phase shutdown for responsive process termination:

1. **`requestShutdown()`** — sets an `std::atomic<bool> m_shutdownRequested` flag (non-destructive, idempotent, no lock). This flag is checked between batches in the two pagination loops (`getPolicy()` and `queryByBatches()`). When set, both loops throw `IndexerConnectorException` to abort the current operation. This is critical for preventing promotion of partial datasets (e.g. IocSync would otherwise hot-swap a half-downloaded IOC database).

2. **`shutdown()`** — also sets the flag (defense in depth), then acquires the exclusive lock and destroys the underlying `IndexerConnectorAsync`.

In `main.cpp`, the exit handler registers both: `requestShutdown()` executes first (LIFO) so in-flight pagination loops release their shared locks quickly, then `shutdown()` acquires the exclusive lock without blocking.

### Point-In-Time (PIT) Pagination

For large result sets (`getPolicy`, `queryByBatches`), the connector always opens a **Point-In-Time** snapshot on the wazuh-indexer with a keep-alive of `5m` (`PIT_KEEP_ALIVE`). Results are retrieved in pages sorted by `_shard_doc`, `_id` using `search_after` cursors, guaranteeing a consistent view even if the index is being concurrently updated. The PIT is automatically deleted via an RAII guard (a failed delete is logged, not thrown). `getPolicy` pages by `maxHitsPerRequest` (the constructor argument; `main.cpp` passes `analysisd.cmsync_indexer_connector_sync_batch_size`; `0` is replaced by `1` with a warning).

### Batched Query Abstraction with Consumer Validation

The private `queryByBatches()` method provides the pagination loop used by `getIocTypeHashes()` and `streamIocsByType()`. It accepts:

- An index name, query body, and batch size (clamped to `[1, SAFE_STREAM_PAGE_SIZE = 1000]`).
- An `onDocument` callback invoked for each hit's `_source` (plus its `_id`); a hit without `_source` or a callback exception is logged as a warning and skipped.
- An optional source filter for field-level projection.
- An **optional `consumerIdToValidate`** parameter:
  - When provided: PIT is created over both the data index AND `.wazuh-cti-consumers`; consumer is validated to be `ready` before pagination begins.
  - When not provided: PIT is created over the data index only; no consumer validation.
  - **Returns `std::optional<std::size_t>`**: `std::nullopt` if consumer not ready, otherwise the number of documents processed.

### Well-Known Indices

| Constant | Index Name | Purpose |
|---|---|---|
| `POLICY_INDEX` | `wazuh-threatintel-policies` | Policy metadata (hash, enabled, integrations) |
| `POLICY_ALIASES` | `wazuh-threatintel-kvdbs`, `wazuh-threatintel-decoders`, `wazuh-threatintel-filters`, `wazuh-threatintel-integrations`, `wazuh-threatintel-policies` | Full policy resource retrieval |
| `IOC_INDEX` | `wazuh-threatintel-enrichments` | Indicators of Compromise (and the `__ioc_type_hashes__` manifest) |
| `REMOTE_CONF_INDEX` | `.wazuh-settings` | Remote engine runtime configuration |
| `CTI_CONSUMERS_INDEX` | `.wazuh-cti-consumers` | CTI consumer state (readiness checks) |

### Configuration

The `Config` struct encapsulates connection parameters. `main.cpp` builds it only in standalone mode (from the `analysisd.indexer_hosts` / `analysisd.indexer_ssl_*` options); on a manager the base JSON is the `indexer` section of `wazuh-manager.conf` (`base::managerConfig::sectionJson("indexer")`):

```cpp
struct Config
{
    std::vector<std::string> hosts;    // e.g. ["https://localhost:9200"]
    size_t maxQueueBytes {0};          // 0 = unlimited (bytes)
    size_t maxRetryDelaySeconds {15};  // Upper bound of the retry backoff

    struct {
        std::vector<std::string> cacert; // CA bundle paths
        std::string cert;                // Client certificate
        std::string key;                 // Client private key
    } ssl;

    std::string toJson() const;      // Serialises to JSON for IndexerConnectorAsync
};
```

Credentials are not part of `Config`: the shared `indexer_connector` library reads them from the keystore (`indexer` / `username`, `password`).

`main.cpp` uses the JSON-string constructor in both modes: it takes the base JSON above and folds in eight more settings
from the same `conf` mechanism (env var, `wazuh-manager-internal-options.conf`, or
default — env var wins), validating their ranges first (an out-of-range value aborts startup). They are documented in the
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
│   └── iwindexerconnector.hpp        # IWIndexerConnector pure-virtual interface, PolicyResources, consumer IDs
├── include/wiconnector/
│   ├── windexerconnector.hpp         # WIndexerConnector concrete implementation + Config
│   └── iindexerConnectorAsync.hpp    # IIndexerConnectorAsync seam over the shared library
├── src/
│   ├── windexerconnector.cpp         # Implementation
│   └── indexerConnectorAsyncAdapter.hpp # Adapter: IIndexerConnectorAsync → IndexerConnectorAsync
└── test/
    ├── mocks/wiconnector/
    │   ├── mockswindexerconnector.hpp     # GMock mock (MockWIndexerConnector)
    │   └── mockIndexerConnectorAsync.hpp  # GMock mock of IIndexerConnectorAsync
    └── src/unit/
        └── wic_test.cpp              # Unit tests
```

## Public Interface

### `IWIndexerConnector` (namespace `wiconnector`)

```cpp
class IWIndexerConnector
{
public:
    using IocRecordCallback = std::function<void(const std::string&, const std::string&)>;

    virtual ~IWIndexerConnector() = default;

    // ── Indexing ───────────────────────────────────────────
    virtual void index(std::string_view index, std::string_view data) = 0;

    // ── Policy retrieval ──────────────────────────────────
    virtual std::optional<PolicyResources>
    getPolicy(std::string_view space, const std::optional<std::string_view>& consumerIdToValidate = std::nullopt) = 0;
    virtual std::optional<std::pair<std::string, bool>>
    getPolicyHashAndEnabled(std::string_view space,
                            const std::optional<std::string_view>& consumerIdToValidate = std::nullopt) = 0;
    virtual bool existsPolicy(std::string_view space) = 0;

    // ── IOC operations ────────────────────────────────────
    virtual bool existsIocDataIndex() = 0;
    virtual std::optional<std::unordered_map<std::string, std::string>>
    getIocTypeHashes(const std::optional<std::string_view>& consumerIdToValidate = std::nullopt) = 0;
    virtual std::optional<std::size_t>
    streamIocsByType(std::string_view iocType,
                     std::size_t batchSize,
                     const IocRecordCallback& onIoc,
                     const std::optional<std::string_view>& consumerIdToValidate = std::nullopt) = 0;

    // ── CTI consumer pre-flight ───────────────────────────
    virtual bool isConsumerReadyForSync(std::string_view consumerId) = 0;

    // ── Remote configuration ──────────────────────────────
    virtual json::Json getEngineRemoteConfig() = 0;

    // ── Queue introspection ───────────────────────────────
    virtual uint64_t getQueueSize() = 0;     // bytes pending
    virtual uint64_t getDroppedEvents() = 0;
};
```

### `PolicyResources`

```cpp
struct PolicyResources
{
    std::vector<json::Json> kvdbs {};       // List of KVDB definitions
    std::vector<json::Json> decoders {};    // List of decoder definitions
    std::vector<json::Json> filters {};     // List of filter definitions
    std::vector<json::Json> integration {}; // List of integration definitions
    json::Json policy {};                   // The policy document
};
```

## Implementation Details

### `WIndexerConnector`

```cpp
class WIndexerConnector : public IWIndexerConnector
{
public:
    WIndexerConnector(const Config&, const LogFunctionType& logFunction, const std::size_t maxHitsPerRequest);
    WIndexerConnector(std::string_view jsonOssecConfig, const std::size_t maxHitsPerRequest); // used by main.cpp
    WIndexerConnector(std::unique_ptr<IIndexerConnectorAsync> async, const std::size_t maxHitsPerRequest); // tests

    void shutdown();          // Destructive: resets the async connector under exclusive lock
    void requestShutdown();   // Non-destructive: sets abort flag for in-flight pagination loops
    // ... all IWIndexerConnector overrides ...

private:
    std::unique_ptr<IIndexerConnectorAsync> m_indexerConnectorAsync;
    std::shared_mutex m_mutex;
    std::size_t m_maxHitsPerRequest;
    std::atomic<bool> m_shutdownRequested {false}; // Checked between pagination batches

    std::optional<std::size_t>
    queryByBatches(std::string_view indexName,
                   std::string_view query,
                   std::size_t batchSize,
                   const std::function<void(const json::Json&)>& onDocument,
                   const std::optional<std::string_view>& sourceFilter = std::nullopt,
                   const std::optional<std::string_view>& consumerIdToValidate = std::nullopt);
    bool existsIndex(std::string_view indexName);
};
```

### Anonymous-Namespace Helpers

| Helper | Purpose |
|---|---|
| `fromIndexName(indexName)` | Maps an index name (substring `kvdbs`, `decoders`, `filters`, `integrations`, `policies`) to the `IndexResourceType` enum (`KVDB`, `DECODER`, `FILTER`, `INTEGRATION_DECODER`, `POLICY`); throws `IndexerConnectorException` otherwise |
| `getQueryFilter(space)` | Builds a `bool/filter/term` query filtering by `space.name` |
| `getSortCriteria()` | Returns `[{"_shard_doc": "asc"}, {"_id": "asc"}]` for deterministic pagination |
| `getSearchAfter(hits)` | Extracts the `sort` array from the last hit for cursor-based pagination |
| `getTotalHits(hits)` | Extracts total hit count from the response, handling both object and numeric formats |
| `extractDocumentFromHit(hit)` | Extracts `_source.document` field as `json::Json` |
| `parseIocHashesDocument(doc)` | Parses the `__ioc_type_hashes__` manifest into a `map<type, sha256>` |
| `buildIocSourceFilter()` | Builds a JSON source filter with the 12 IOC field projections (`IOC_SOURCE_FILTER_INCLUDES`) |
| `makePitGuard(pit, async)` | RAII guard that deletes the PIT |
| `buildPitIndices(base, consumerId)` | Appends `.wazuh-cti-consumers` to the PIT indices when a consumer is to be validated |
| `validateConsumerReadyInPit(async, pit, consumerId)` | Reads the consumer's `status` inside the PIT; `true` only for `ready` |

### Key Flows

#### `index(index, data)`

Acquires shared lock, delegates to `indexDataStream()`. Exceptions are caught and logged as warnings (`Error indexing data: …`) — indexing failures do not propagate to callers.

#### `getPolicy(space, consumerIdToValidate?)`

1. **When `consumerIdToValidate` is provided** (typically `STANDARD_RULESET_CONSUMER_ID`):
   - Opens a **multi-index PIT** including all 5 policy aliases AND `.wazuh-cti-consumers`.
   - Validates consumer is `ready` within the PIT snapshot.
   - Returns `std::nullopt` if consumer not ready (cmsync skips sync cycle).
2. **Otherwise** (no consumer validation):
   - Opens a PIT across all 5 policy aliases only.
3. Filters by `space.name`, paginates through results using `search_after` cursors (aborting with `IndexerConnectorException` if `requestShutdown()` was called).
4. Classifies each hit by index name into `IndexResourceType`; the policy document gets `/hash` from `space.hash.sha256` (missing → `IndexerConnectorException`).
5. Accumulates resources into `PolicyResources` vectors (with pre-reserved capacity).
6. Sets `/origin_space` on a non-empty policy.
7. PIT is automatically cleaned up via RAII guard.

#### `getPolicyHashAndEnabled(space, consumerIdToValidate?)`

**When `consumerIdToValidate` is provided** (typically `STANDARD_RULESET_CONSUMER_ID`):
- Creates a multi-index PIT including both `wazuh-threatintel-policies` AND `.wazuh-cti-consumers`.
- Validates consumer is `ready` within the PIT snapshot.
- Queries policy within the same PIT to guarantee consistency.
- Returns `std::nullopt` if consumer not ready.

**Otherwise** (no consumer validation):
- Performs a direct search without PIT.

Exactly one policy must match the space (zero or several → `IndexerConnectorException`), and it must carry `space.hash.sha256`, `document.enabled` and `document.integrations`. Returns the hash and `enabled && hasIntegrations && hasRootDecoder`: a policy with no integrations or no root decoder has
nothing to build, so it is reported as disabled. `document.root_decoder` counts as present only when it is a non-empty
string; a missing field, `null`, `""` or any other type counts as no root decoder and never throws.

#### `streamIocsByType(iocType, batchSize, onIoc, consumerIdToValidate?)`

Throws `std::runtime_error` for an empty `iocType` or callback. Uses `queryByBatches()` (always a PIT) with a `term` query on `document.type`, projecting only the 12 IOC source fields. For each hit, extracts `document.name` as key and the serialised `document` as value, invoking the callback; a hit without either is logged and skipped. Returns the number of records delivered.

**With consumer validation**:
- If `consumerIdToValidate` is provided (typically `IOC_ENRICHMENT_CONSUMER_ID`), validates the consumer is ready before streaming.
- Returns `std::nullopt` if the consumer is not ready (allowing `iocsync` to skip the sync cycle).
- Exceptions from the PIT, the validation or the search propagate to the caller.

**Without consumer validation**:
- Streams IOCs without any consumer checks.

#### `getIocTypeHashes(consumerIdToValidate?)`

Uses `queryByBatches()` (always a PIT over `wazuh-threatintel-enrichments`) with an `ids` query for `__ioc_type_hashes__`.

**When `consumerIdToValidate` is provided** (typically `IOC_ENRICHMENT_CONSUMER_ID`):
- The PIT also includes `.wazuh-cti-consumers`; the consumer is validated to be `ready` within the snapshot.
- Returns `std::nullopt` if consumer not ready (iocsync skips sync cycle).

Parses the `__ioc_type_hashes__` manifest into a `map<type, sha256>` (an invalid manifest → `IndexerConnectorException`). When the manifest document is absent (a fresh indexer), the code also returns `std::nullopt`, although the interface comment says it throws.

#### `getEngineRemoteConfig()`

Searches `.wazuh-settings` (`match_all`, `size=1`, source `engine` only); exactly one document must exist (zero or several → `IndexerConnectorException`). Extracts `_source.engine`, validates it is an object, and returns it as `json::Json` (for example `{ "index_raw_events": false }`, consumed by `confremote`).

## CMake Targets

| Target | Type | Alias | Links |
|---|---|---|---|
| `wIndexerConnector_iwIndexerConnector` | INTERFACE | `wIndexerConnector::iwIndexerConnector` | `base` |
| `wIndexerConnector_wIndexerConnector` | STATIC | `wIndexerConnector::wIndexerConnector` | `base`, `wIndexerConnector::iwIndexerConnector`, `indexer_connector` (all public) |
| `wIndexerConnector_mocks` | INTERFACE | `wIndexerConnector::mocks` | `GTest::gmock`, `wIndexerConnector::iwIndexerConnector` (test builds only) |
| `wIndexerConnector_utest` | Executable | — | `GTest::gtest_main`, `GTest::gmock`, `wIndexerConnector::wIndexerConnector`, `wIndexerConnector::mocks`; discovered tests hold the `rocks_db_lock` resource lock (test builds only) |

## Testing

- **Unit tests** (`test/src/unit/wic_test.cpp`) — `ConfigTest` (`Config::toJson()` serialisation), `WIndexerConnectorTest` (constructor validation: empty/invalid JSON, zero `maxHitsPerRequest`; `index()` graceful handling; `shutdown()` / `requestShutdown()` semantics; concurrent indexing and shutdown) and `WIndexerConnectorMockTest`, which drives every query path (policy, hashes, IOC streaming, PIT and consumer validation, remote config, readiness, shutdown during pagination) through `MockIndexerConnectorAsync`.
- **Mocks** — `MockWIndexerConnector` (`test/mocks/wiconnector/mockswindexerconnector.hpp`, namespace `wiconnector::mocks`) implements all `IWIndexerConnector` methods for downstream consumers; `MockIndexerConnectorAsync` (`mockIndexerConnectorAsync.hpp`) mocks the internal async seam.

## Consumers

| Module | Dependency | Role |
|---|---|---|
| `builder` | `wIndexerConnector::iwIndexerConnector` | Uses the connector to push indexed events via the `indexerOutput` stage builder |
| `cmsync` | `wIndexerConnector::iwIndexerConnector` | Fetches policy resources and hashes from the indexer for content synchronization |
| `iocsync` | `wIndexerConnector::iwIndexerConnector` | Reads IOC type hashes and streams IOC records for local KVDB synchronization |
| `rawevtindexer` | `wIndexerConnector::iwIndexerConnector` | Indexes raw events into the wazuh-indexer |
| `confremote` | `wIndexerConnector::iwIndexerConnector` | Retrieves remote engine configuration from `.wazuh-settings` |
| `main.cpp` | `wIndexerConnector::wIndexerConnector` | Creates the `WIndexerConnector` (only when event processing is enabled), injects it into consuming modules, exports `getQueueSize()`/`getDroppedEvents()` as metrics, and registers `requestShutdown()`/`shutdown()` on exit |

# wiconnector

## Overview

The **wiconnector** module provides the **Wazuh Indexer Connector** — a thread-safe client that the engine uses to communicate with the wazuh-indexer (OpenSearch). It exposes a unified interface for:

- **Indexing events** — pushing alert / raw-event JSON documents into data-stream indices.
- **Retrieving policy resources** — fetching the full content of a policy space (KVDBs, decoders, integrations, policy definition) for content synchronization.
- **Policy metadata queries** — checking policy existence, retrieving the SHA-256 hash and enabled status.
- **IOC operations** — checking whether the IOC index exists, reading hash manifests, and streaming IOC records by type with batched pagination.
- **Remote engine configuration** — pulling runtime engine settings from `.wazuh-settings`.
- **Queue introspection** — reporting the current size of the pending-event queue.

Internally the module wraps an asynchronous `IndexerConnectorAsync` instance (from the shared `indexer_connector` library) and protects every operation with a `std::shared_mutex` for concurrent access.

## Architecture

```
 ┌──────────┐ ┌─────────┐ ┌──────────┐ ┌──────────────┐ ┌──────────┐
 │ builder  │ │ cmsync  │ │ iocsync  │ │rawevtindexer │ │confremote│
 └────┬─────┘ └────┬────┘ └────┬─────┘ └──────┬───────┘ └────┬─────┘
      │            │           │               │              │
      └────────────┴─────┬─────┴───────────────┴──────────────┘
                         │  IWIndexerConnector
                         ▼
              ┌─────────────────────┐
              │  WIndexerConnector  │
              │                     │
              │  • shared_mutex     │
              │  • queryByBatches() │
              │  • PIT pagination   │
              └─────────┬───────────┘
                        │  IndexerConnectorAsync
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
2. Within the same PIT snapshot, the consumer document is queried and validated to be in the `idle` status.
3. If the consumer is not idle, the method returns `std::nullopt` (graceful skip — data download is deferred).
4. If the consumer is idle, data retrieval proceeds within the same PIT, guaranteeing consistency.

This pattern is used by:
- `getPolicy()` — validates `STANDARD_RULESET_CONSUMER_ID` before fetching policy resources.
- `getPolicyHashAndEnabled()` — validates consumer before checking hash.
- `getIocTypeHashes()` — validates `IOC_ENRICHMENT_CONSUMER_ID` before reading hashes.
- `streamIocsByType()` → `queryByBatches()` — validates consumer before pagination.

### Well-Known Consumer IDs

| Constant | Value | Used By | Purpose |
|---|---|---|---|
| `STANDARD_RULESET_CONSUMER_ID` | `"cti:catalog:consumer:ruleset"` | cmsync | Validates policy consumer before sync |
| `IOC_ENRICHMENT_CONSUMER_ID` | `"cti:catalog:consumer:iocs"` | iocsync | Validates IOC consumer before sync |

### Thread Safety

Every public method acquires either a **shared lock** (read operations, indexing) or an **exclusive lock** (`shutdown`). After `shutdown()` resets the internal `IndexerConnectorAsync`, subsequent calls degrade gracefully — `index()` silently returns, while query methods throw `std::runtime_error`.

### Graceful Shutdown

`WIndexerConnector` supports a two-phase shutdown for responsive process termination:

1. **`requestShutdown()`** — sets an `std::atomic<bool> m_shutdownRequested` flag (non-destructive, idempotent). This flag is checked between batches in the two pagination loops (`getPolicy()` and `queryByBatches()`). When set, both loops throw `IndexerConnectorException` to abort the current operation. This is critical for preventing promotion of partial datasets (e.g. IocSync would otherwise hot-swap a half-downloaded IOC database).

2. **`shutdown()`** — also sets the flag (defense in depth), then acquires the exclusive lock and destroys the underlying `IndexerConnectorAsync`.

In `main.cpp`, the exit handler registers both: `requestShutdown()` executes first (LIFO) so in-flight pagination loops release their shared locks quickly, then `shutdown()` acquires the exclusive lock without blocking.

### Point-In-Time (PIT) Pagination

For large result sets (`getPolicy`, `queryByBatches`), the connector opens a **Point-In-Time** snapshot on the wazuh-indexer with a keep-alive of 5 minutes. Results are retrieved in pages using `search_after` cursors, guaranteeing a consistent view even if the index is being concurrently updated. The PIT is automatically deleted via an RAII guard.

### Batched Query Abstraction with Consumer Validation

The private `queryByBatches()` method provides a reusable pagination loop used by `getIocTypeHashes()`, `streamIocsByType()`, and potentially other query paths. It accepts:

- An index name, query body, and batch size (capped at `SAFE_STREAM_PAGE_SIZE = 1000`).
- An `onDocument` callback invoked for each hit.
- An optional source filter for field-level projection.
- An **optional `consumerIdToValidate`** parameter:
  - When provided: PIT is created over both the data index AND `.wazuh-cti-consumers`; consumer is validated to be `idle` before pagination begins.
  - When not provided: PIT is created over the data index only; no consumer validation.
  - **Returns `std::optional<std::size_t>`**: `std::nullopt` if consumer not idle, otherwise the number of documents processed.

### Well-Known Indices

| Constant | Index Name | Purpose |
|---|---|---|
| `POLICY_INDEX` | `wazuh-threatintel-policies` | Policy metadata (hash, enabled, integrations) |
| `POLICY_ALIASES` | `wazuh-threatintel-kvdbs`, `wazuh-threatintel-decoders`, `wazuh-threatintel-integrations`, `wazuh-threatintel-policies` | Full policy resource retrieval |
| `IOC_INDEX` | `wazuh-threatintel-enrichments` | Indicators of Compromise |
| `REMOTE_CONF_INDEX` | `.wazuh-settings` | Remote engine runtime configuration |

### Configuration

The `Config` struct encapsulates connection parameters:

```cpp
struct Config
{
    std::vector<std::string> hosts;  // e.g. ["https://localhost:9200"]
    std::string username;            // OpenSearch username
    std::string password;            // OpenSearch password
    size_t maxQueueBytes {0};        // 0 = unlimited (bytes)

    struct {
        std::vector<std::string> cacert; // CA bundle paths
        std::string cert;                // Client certificate
        std::string key;                 // Client private key
    } ssl;

    std::string toJson() const;      // Serialises to JSON for IndexerConnectorAsync
};
```

An alternative constructor accepts a raw JSON OSSEC configuration string directly.

## Directory Structure

```
wiconnector/
├── CMakeLists.txt
├── README.md
├── interface/wiconnector/
│   └── iwindexerconnector.hpp        # IWIndexerConnector pure-virtual interface + PolicyResources
├── include/wiconnector/
│   └── windexerconnector.hpp         # WIndexerConnector concrete implementation + Config
├── src/
│   └── windexerconnector.cpp         # Full implementation (~830 lines)
└── test/
    ├── mocks/wiconnector/
    │   └── mockswindexerconnector.hpp # GMock mock (MockWIndexerConnector)
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
    virtual PolicyResources getPolicy(std::string_view space) = 0;
    virtual std::pair<std::string, bool> getPolicyHashAndEnabled(std::string_view space) = 0;
    virtual bool existsPolicy(std::string_view space) = 0;

    // ── IOC operations ────────────────────────────────────
    virtual bool existsIocDataIndex() = 0;
    virtual std::unordered_map<std::string, std::string> getIocTypeHashes() = 0;
    virtual std::size_t streamIocsByType(std::string_view iocType,
                                         std::size_t batchSize,
                                         const IocRecordCallback& onIoc) = 0;

    // ── Remote configuration ──────────────────────────────
    virtual json::Json getEngineRemoteConfig() = 0;

    // ── Queue introspection ───────────────────────────────
    virtual uint64_t getQueueSize() = 0;
};
```

### `PolicyResources`

```cpp
struct PolicyResources
{
    std::vector<json::Json> kvdbs {};       // List of KVDB definitions
    std::vector<json::Json> decoders {};    // List of decoder definitions
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
    WIndexerConnector(const Config&, const LogFunctionType& logFunction, std::size_t maxHitsPerRequest);
    WIndexerConnector(std::string_view jsonOssecConfig, std::size_t maxHitsPerRequest);

    void shutdown();          // Destructive: resets the async connector under exclusive lock
    void requestShutdown();   // Non-destructive: sets abort flag for in-flight pagination loops
    // ... all IWIndexerConnector overrides ...

private:
    std::unique_ptr<IndexerConnectorAsync> m_indexerConnectorAsync;
    std::shared_mutex m_mutex;
    std::size_t m_maxHitsPerRequest;
    std::atomic<bool> m_shutdownRequested {false}; // Checked between pagination batches

    std::size_t queryByBatches(std::string_view indexName,
                               std::string_view query,
                               std::size_t batchSize,
                               const std::function<void(const json::Json&)>& onDocument,
                               const std::optional<std::string_view>& sourceFilter = std::nullopt);
    bool existsIndex(std::string_view indexName);
};
```

### Anonymous-Namespace Helpers

| Helper | Purpose |
|---|---|
| `fromIndexName(indexName)` | Maps an index name suffix to `IndexResourceType` enum (`KVDB`, `DECODER`, `INTEGRATION_DECODER`, `POLICY`) |
| `getQueryFilter(space)` | Builds a `bool/filter/term` query filtering by `space.name` |
| `getSortCriteria()` | Returns `[{"_shard_doc": "asc"}, {"_id": "asc"}]` for deterministic pagination |
| `getSearchAfter(hits)` | Extracts the `sort` array from the last hit for cursor-based pagination |
| `getTotalHits(hits)` | Extracts total hit count from the response, handling both object and numeric formats |
| `extractDocumentFromHit(hit)` | Extracts `_source.document` field as `json::Json` |
| `parseIocHashesDocument(doc)` | Parses the `__ioc_type_hashes__` manifest into a `map<type, sha256>` |
| `buildIocSourceFilter()` | Builds a JSON source filter with the 12 IOC field projections |

### Key Flows

#### `index(index, data)`

Acquires shared lock, delegates to `IndexerConnectorAsync::indexDataStream()`. Exceptions are caught and logged as warnings — indexing failures do not propagate to callers.

#### `getPolicy(space, consumerIdToValidate?)`

1. **When `consumerIdToValidate` is provided** (typically `STANDARD_RULESET_CONSUMER_ID`):
   - Opens a **multi-index PIT** including all 4 policy aliases AND `.wazuh-cti-consumers`.
   - Validates consumer is `idle` within the PIT snapshot.
   - Returns `std::nullopt` if consumer not idle (cmsync skips sync cycle).
2. **Otherwise** (no consumer validation):
   - Opens a PIT across all 4 policy aliases only.
3. Paginates through results using `search_after` cursors.
4. Classifies each hit by index name suffix into `IndexResourceType`.
5. Accumulates resources into `PolicyResources` vectors (with pre-reserved capacity).
6. Enriches the policy with `origin_space` field.
7. PIT is automatically cleaned up via RAII guard.

#### `getPolicyHashAndEnabled(space, consumerIdToValidate?)`

**When `consumerIdToValidate` is provided** (typically `STANDARD_RULESET_CONSUMER_ID`):
- Creates a multi-index PIT including both `wazuh-threatintel-policies` AND `.wazuh-cti-consumers`.
- Validates consumer is `idle` within the PIT snapshot.
- Queries policy within the same PIT to guarantee consistency.
- Returns `std::nullopt` if consumer not idle.

**Otherwise** (no consumer validation):
- Performs a direct search without PIT.

Returns the hash and `enabled && hasIntegrations`.

#### `streamIocsByType(iocType, batchSize, onIoc, consumerIdToValidate?)`

Uses `queryByBatches()` with a `term` query on `document.type`, projecting only the 12 IOC source fields. For each hit, extracts `document.name` as key and the serialised `document` as value, invoking the callback.

**With consumer validation**:
- If `consumerIdToValidate` is provided (typically `IOC_ENRICHMENT_CONSUMER_ID`), validates the consumer is idle before streaming.
- Returns `std::nullopt` if the consumer is not idle (allowing `iocsync` to skip the sync cycle).
- Returns `std::nullopt` if consumer validation fails with an exception.

**Without consumer validation**:
- Streams IOCs normally without any consumer checks.

#### `getIocTypeHashes(consumerIdToValidate?)`

**When `consumerIdToValidate` is provided** (typically `IOC_ENRICHMENT_CONSUMER_ID`):
- Creates a multi-index PIT including both `wazuh-threatintel-enrichments` AND `.wazuh-cti-consumers`.
- Validates consumer is `idle` within the PIT snapshot.
- Queries IOC hashes within the same PIT to guarantee consistency.
- Returns `std::nullopt` if consumer not idle (iocsync skips sync cycle).

**Otherwise** (no consumer validation):
- Queries directly without PIT.

Parses the `__ioc_type_hashes__` manifest into a `map<type, sha256>`.

#### `getEngineRemoteConfig()`

Searches `.wazuh-settings` for a single document, extracts `_source.engine`, validates it is an object, and returns it as `json::Json`.

## CMake Targets

| Target | Type | Alias | Links |
|---|---|---|---|
| `wIndexerConnector_iwIndexerConnector` | INTERFACE | `wIndexerConnector::iwIndexerConnector` | `base` |
| `wIndexerConnector_wIndexerConnector` | STATIC | `wIndexerConnector::wIndexerConnector` | `base`, `wIndexerConnector::iwIndexerConnector` (public); `indexer_connector` (private) |
| `wIndexerConnector_mocks` | INTERFACE | `wIndexerConnector::mocks` | `GTest::gmock`, `wIndexerConnector::iwIndexerConnector` |
| `wIndexerConnector_utest` | Executable | — | `GTest::gtest_main`, `GTest::gmock`, `wIndexerConnector::wIndexerConnector` |

## Testing

- **Unit tests** (`test/src/unit/wic_test.cpp`) — cover `Config::toJson()` serialisation, constructor validation (empty/invalid JSON, zero `maxHitsPerRequest`), `index()` graceful handling, `shutdown()` lifecycle, `requestShutdown()` semantics (non-destructive, idempotent, composable with `shutdown()`), and concurrent access (multi-threaded indexing and concurrent indexing + shutdown).
- **Mock** (`test/mocks/wiconnector/mockswindexerconnector.hpp`) — `MockWIndexerConnector` in `wiconnector::mocks` implements all `IWIndexerConnector` methods with GMock macros for use by downstream consumers.

## Consumers

| Module | Dependency | Role |
|---|---|---|
| `builder` | `wIndexerConnector::iwIndexerConnector` | Uses the connector to push indexed events via the `indexerOutput` stage builder |
| `cmsync` | `wIndexerConnector::iwIndexerConnector` | Fetches policy resources and hashes from the indexer for content synchronization |
| `iocsync` | `wIndexerConnector::iwIndexerConnector` | Reads IOC type hashes and streams IOC records for local KVDB synchronization |
| `rawevtindexer` | `wIndexerConnector::iwIndexerConnector` | Indexes raw events into the wazuh-indexer |
| `confremote` | `wIndexerConnector::iwIndexerConnector` | Retrieves remote engine configuration from `.wazuh-settings` |
| `main.cpp` | `wIndexerConnector::wIndexerConnector` | Creates the `WIndexerConnector` instance with configuration and injects it into consuming modules |

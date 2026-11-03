# wiconnector

## Overview

The **wiconnector** module is the Engine's **writer** to the wazuh-indexer (OpenSearch), plus the one
read the remote configuration needs. It exposes:

- **Indexing events** — pushing processed / raw-event JSON documents into data-stream indices.
- **Remote engine configuration** — pulling runtime engine settings from `.wazuh-settings`.
- **Queue introspection** — reporting the pending-queue size in bytes and the dropped-event count (exported by `main.cpp` as indexer metrics).

It wraps an asynchronous `IndexerConnectorAsync` (from the shared `indexer_connector` library in
`src/shared_modules/indexer_connector/`; operator page [indexer_connector](../../../../docs/ref/modules/indexer_connector/README.md))
behind the internal `IIndexerConnectorAsync` interface (`IndexerConnectorAsyncAdapter`, so tests can
inject a mock), and guards every operation with a `std::shared_mutex`. Content downloads (rulesets, IOCs) do not go
through it: they are the content manager's, reached through [`cmcontent`](../cmcontent/README.md)
over the same underlying connector.

## Architecture

```
 ┌──────────┐ ┌──────────────┐ ┌──────────┐
 │ builder  │ │rawevtindexer │ │confremote│
 └────┬─────┘ └──────┬───────┘ └────┬─────┘
      └──────────────┼──────────────┘
                     │  IWIndexerConnector
                     ▼
          ┌─────────────────────┐
          │  WIndexerConnector  │
          │  • shared_mutex     │
          └─────────┬───────────┘
                    │  IndexerConnectorAsync (shared with the content topics)
                    ▼
          ┌──────────────────────┐
          │  indexer_connector   │──► wazuh-indexer
          └──────────────────────┘
```

## Key Concepts

### Thread Safety

Every public method acquires either a **shared lock** (indexing, queries) or an **exclusive lock**
(`shutdown`). After `shutdown()` resets the internal `IndexerConnectorAsync`, later calls degrade
gracefully: `index()` returns silently, the queue counters return 0, and `getEngineRemoteConfig()`
throws `std::runtime_error`. `main.cpp` registers `shutdown()` in the exit handler.

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

An alternative constructor accepts a raw JSON OSSEC configuration string directly. `main.cpp`
builds the `IndexerConnectorAsync` once, with `makeIndexerConnectorAsync` (the same parsing that
constructor uses), and hands it both to this module (the constructor taking a
`shared_ptr<IndexerConnectorAsync>`) and, through `content_manager::makeContentIndexer`, to the
content topics of `cmsync` and `iocsync`: one connection, one health monitor, one place to configure
the indexer.

`main.cpp` builds the connector the same way in both modes: it takes the base JSON above and folds in eight more settings
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
│   └── iwindexerconnector.hpp        # IWIndexerConnector
├── include/wiconnector/
│   ├── windexerconnector.hpp         # WIndexerConnector + Config + makeIndexerConnectorAsync
│   └── iindexerConnectorAsync.hpp    # IIndexerConnectorAsync seam over the shared library
├── src/
│   ├── windexerconnector.cpp
│   └── indexerConnectorAsyncAdapter.hpp # Adapter: IIndexerConnectorAsync → IndexerConnectorAsync
└── test/
    ├── mocks/wiconnector/
    │   ├── mockswindexerconnector.hpp     # MockWIndexerConnector
    │   └── mockIndexerConnectorAsync.hpp  # MockIndexerConnectorAsync (the internal async seam)
    └── src/unit/
        └── wic_test.cpp
```

## Public Interface

```cpp
namespace wiconnector
{
class IWIndexerConnector
{
public:
    virtual ~IWIndexerConnector() = default;
    virtual void index(std::string_view index, std::string_view data) = 0;
    virtual json::Json getEngineRemoteConfig() = 0;
    virtual uint64_t getQueueSize() = 0;     // bytes pending
    virtual uint64_t getDroppedEvents() = 0;
};

class WIndexerConnector : public IWIndexerConnector
{
public:
    WIndexerConnector(const Config&, const LogFunctionType& logFunction);
    explicit WIndexerConnector(std::string_view jsonOssecConfig);
    explicit WIndexerConnector(std::shared_ptr<IndexerConnectorAsync> connector);
    explicit WIndexerConnector(std::unique_ptr<IIndexerConnectorAsync> async); // tests
    void shutdown(); // resets the async connector under the exclusive lock
};
}
```

## Key Flows

- **`index(index, data)`** — shared lock, `IndexerConnectorAsync::indexDataStream()`. Exceptions are
  caught and logged as warnings; indexing failures do not propagate.
- **`getEngineRemoteConfig()`** — searches `.wazuh-settings` (`match_all`, `size=1`, source `engine`
  only); exactly one document must exist (zero or several → `IndexerConnectorException`). Extracts
  `_source.engine`, checks it is an object and returns it (for example `{ "index_raw_events": false }`,
  consumed by `confremote`).

## CMake Targets

| Target | Type | Alias | Links |
|---|---|---|---|
| `wIndexerConnector_iwIndexerConnector` | INTERFACE | `wIndexerConnector::iwIndexerConnector` | `base` |
| `wIndexerConnector_wIndexerConnector` | STATIC | `wIndexerConnector::wIndexerConnector` | `base`, `wIndexerConnector::iwIndexerConnector`, `indexer_connector` (all public) |
| `wIndexerConnector_mocks` | INTERFACE | `wIndexerConnector::mocks` | `GTest::gmock`, `wIndexerConnector::iwIndexerConnector` (test builds only) |
| `wIndexerConnector_utest` | Executable | — | `GTest::gtest_main`, `GTest::gmock`, `wIndexerConnector::wIndexerConnector`, `wIndexerConnector::mocks`; discovered tests hold the `rocks_db_lock` resource lock (test builds only) |

## Testing

- **Unit tests** (`test/src/unit/wic_test.cpp`) — `Config::toJson()`, constructor validation,
  `index()` error handling, `shutdown()`, concurrent indexing (with and without a concurrent
  shutdown), the queue counters, and `getEngineRemoteConfig()` against a mocked
  `IIndexerConnectorAsync`.
- **Mocks** — `MockWIndexerConnector` (`test/mocks/wiconnector/mockswindexerconnector.hpp`, namespace
  `wiconnector::mocks`) for downstream consumers; `MockIndexerConnectorAsync`
  (`mockIndexerConnectorAsync.hpp`) mocks the internal async seam.

## Consumers

| Module | Dependency | Role |
|---|---|---|
| `builder` | `wIndexerConnector::iwIndexerConnector` | Pushes indexed events via the `indexerOutput` stage |
| `rawevtindexer` | `wIndexerConnector::iwIndexerConnector` | Indexes raw events |
| `confremote` | `wIndexerConnector::iwIndexerConnector` | Reads the remote engine configuration |
| `main.cpp` | `wIndexerConnector::wIndexerConnector` | Builds the connector (only when event processing is enabled), injects it, exports `getQueueSize()`/`getDroppedEvents()` as metrics, and registers `shutdown()` on exit |

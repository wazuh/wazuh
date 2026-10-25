# wiconnector

## Overview

The **wiconnector** module is the Engine's **writer** to the wazuh-indexer (OpenSearch), plus the one
read the remote configuration needs, and (since E10a) the owner of the Engine's `indexer_client` runtime. It exposes:

- **Indexing events** — pushing processed / raw-event JSON documents into data-stream indices.
- **Remote engine configuration** — pulling runtime engine settings from `.wazuh-settings`.
- **Queue introspection** — reporting the pending-queue size in bytes and the dropped-event count (exported by `main.cpp` as indexer metrics).

**Two connections until E10b.** The writes (`index()`) still go through an asynchronous `IndexerConnectorAsync`
(from the shared `indexer_connector` library, the v1). The reads go through the Engine's `indexer_client`
`Client` `analysisd` (the v2): the remote configuration read here and the content downloads of
[`cmcontent`](../cmcontent/README.md), which the content manager makes through that same Client. Each indexer outage
therefore logs one line per connection. Every operation is guarded with a `std::shared_mutex`.

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
                    │  writes: IndexerConnectorAsync (v1)      reads: indexer_client Client `analysisd` (v2)
                    ▼
          ┌──────────────────────┐        ┌──────────────────────┐
          │  indexer_connector   │──►  wazuh-indexer  ◄──│    indexer_client    │
          └──────────────────────┘        └──────────────────────┘
```

The Client is created by `EngineIndexerRuntime`, shared with the content topics and handed to
`WIndexerConnector` for the remote configuration read.

## Key Concepts

### Thread Safety

Every public method acquires either a **shared lock** (indexing, queries) or an **exclusive lock**
(`shutdown`). After `shutdown()` resets the internal `IndexerConnectorAsync` and releases the read Client, later calls degrade
gracefully: `index()` returns silently, the queue counters return 0, and `getEngineRemoteConfig()`
throws `std::runtime_error`. `shutdown()` takes the exclusive lock **after** the Client's `requestClose()`, so a remote
configuration search in flight returns `ClientClosed` instead of holding the lock. `main.cpp` registers `shutdown()` in the exit handler.

### Runtime and two-phase stop (`EngineIndexerRuntime`)

`EngineIndexerRuntime` (`engineIndexerRuntime.hpp`) owns the process's `indexer_client` runtime and the one Client
(`analysisd`, no buckets). `start(process, source)` validates the configuration, starts the runtime and creates the
Client; every call must come from the thread that started it (the runtime's owner: the Engine's main thread). The
stop is in two phases that `main.cpp` places around the scheduler's stop:

1. `beginStop()`, before the scheduler stops: fixes the shutdown deadline (now + 3 s, `STOP_BUDGET`) and closes the
   Client's admission (`requestClose()`), so a read in flight returns `ClientClosed`. `WIndexerConnector::shutdown()` follows.
2. `finishStop()`, after the scheduler has stopped: `awaitClosed` without a drain, releases the Client and joins the runtime.

Queued work is **discarded**, not drained, as the v1 does (I186); the whole stop fits in 3 s. `finishStop()` without a
previous `beginStop()` runs both phases; each phase runs once.

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

Credentials are not part of `Config`: the connector reads them from the keystore (`indexer` / `username`, `password`).
The Client's credentials come from the same keystore column through `keystoreCredentials()` (an injectable `CredentialsProvider`;
the engine does not link `keystore`, it calls the `Keystore::get` that `libindexer_connector.so` exports), and the runtime's local copy of the password is erased after `start` (the keystore keeps its own).

#### `EngineConfigSource` (the Client's configuration)

`EngineConfigSource` implements `indexer_client::IConfigSource` for the Engine. Keys are the full names under
`analysisd.indexer_client_` (the Engine's prefix, in standalone too). Each key resolves from the environment variable
`WAZUH_<key without "analysisd.", upper case>` (the convention of `conf`), then, in manager mode only, from the internal
options file; otherwise it is unset and the library default applies. Standalone never reads the file. `keysWithPrefix` also
enumerates the environment, so an unknown `WAZUH_INDEXER_CLIENT_*` variable is rejected like an unknown file key. The `<indexer>`
section is the manager's (`hosts`, `ssl`); standalone builds it from `analysisd.indexer_hosts|ssl_*` through the environment only.

Two v1 keys feed their v2 equivalent when that one is not set (I192): `analysisd.indexer_request_timeout` (s) →
`indexer_client_request_timeout_ms` and `analysisd.indexer_monitoring_interval` (s) → `indexer_client_probe_interval_ms`.
"Set" means an environment variable or a file entry, never a `conf` default. Both set and different in ms is reported by
`problem()` on the v2 key (the start fails); a v1 value of `0` leaves the v2 key unset and is reported once by `warnings()`
(logged as WARN). The operator-facing list is in [Indexer client](../../../../docs/ref/modules/engine/README.md#indexer-client).

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
│   ├── engineConfigSource.hpp        # EngineConfigSource, keystoreCredentials
│   └── engineIndexerRuntime.hpp      # EngineIndexerRuntime (start, beginStop, finishStop)
├── src/
│   ├── windexerconnector.cpp
│   ├── engineConfigSource.cpp
│   └── engineIndexerRuntime.cpp
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
    // E10a: writes through the v1 connector, reads through the Engine's Client
    WIndexerConnector(std::shared_ptr<IndexerConnectorAsync> connector,
                      std::shared_ptr<indexer_client::IClient> reader,
                      std::chrono::milliseconds requestTimeout);   // + a test variant taking a unique_ptr<IIndexerConnectorAsync>
    void shutdown(); // resets the async connector under the exclusive lock
};
}
```

## Key Flows

- **`index(index, data)`** — shared lock, `IndexerConnectorAsync::indexDataStream()`. Exceptions are
  caught and logged as warnings; indexing failures do not propagate.
- **`getEngineRemoteConfig()`** — searches `.wazuh-settings` for exactly one document through the Client's `IQuery::search`
  (same body as the v1, unwrapping the v2 `hits`), extracts `_source.engine`, checks it is an object and returns it. One
  attempt (`maxAttempts = 1`: the retry is the caller's), a page deadline of the runtime's `request_timeout_ms` and a call
  deadline a margin above it. Once every node has been probed and none is usable it fails at once (I190, I190b); before
  the first probe round it waits as I158b says. A null `query()` is `ClientClosed`, which throws like every other failure (it is
  never read as "no config"); 0 or more than one hit, or no `_source.engine`, throw as in the v1.

## CMake Targets

| Target | Type | Alias | Links |
|---|---|---|---|
| `wIndexerConnector_iwIndexerConnector` | INTERFACE | `wIndexerConnector::iwIndexerConnector` | `base` |
| `wIndexerConnector_wIndexerConnector` | STATIC | `wIndexerConnector::wIndexerConnector` | `base`, `wIndexerConnector::iwIndexerConnector`, `indexer_client` (public); `indexer_connector` (public); only the include directory of `keystore` |
| `wIndexerConnector_mocks` | INTERFACE | `wIndexerConnector::mocks` | `GTest::gmock`, `wIndexerConnector::iwIndexerConnector` |
| `wIndexerConnector_utest` | Executable | — | `GTest::gtest_main`, `GTest::gmock`, `wIndexerConnector::wIndexerConnector` |

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
| `main.cpp` | `wIndexerConnector::wIndexerConnector` | Starts `EngineIndexerRuntime` (when event processing is enabled), builds the connector and injects it, registers the two stop phases |

# wiconnector

## Overview

The **wiconnector** module provides the **Wazuh Indexer Connector** — a thread-safe client that the engine uses to communicate with the wazuh-indexer (OpenSearch). It exposes a unified interface for:

- **Indexing events** — pushing alert / raw-event JSON documents into data-stream indices.
- **Existence and readiness checks** — whether a policy exists for a space, whether the IoC index exists, and whether a CTI consumer is ready for synchronization.
- **Remote engine configuration** — pulling runtime engine settings from `.wazuh-settings`.
- **Queue introspection** — reporting the current size and dropped-event count of the pending-event queue.

Internally the module wraps an asynchronous `IndexerConnectorAsync` instance (from the shared `indexer_connector` library) and protects every operation with a `std::shared_mutex` for concurrent access.

### What this module no longer does

Content **downloading** used to live here: PIT pagination, `search_after` cursors, per-space and
per-type hash retrieval, in-PIT consumer validation, and a batched query loop — roughly 700 lines.
All of it duplicated, with different consistency guarantees, what the Vulnerability Detection module
had solved separately in `shared_modules/content_manager`. That library is now generic and serves
all three consumers, so `cmsync` and `iocsync` no longer ask this connector for content at all: they
drive a `ContentRegister` per space / per type (see [`cmcontent`](../cmcontent/README.md)).

What is left here is what is genuinely this module's own: writing events to the indexer, and the
cheap read-only probes that let a caller decide whether starting a sync cycle is worth it.

## Architecture

```
 ┌──────────┐ ┌─────────┐ ┌──────────┐ ┌──────────────┐ ┌──────────┐
 │ builder  │ │ cmsync  │ │ iocsync  │ │rawevtindexer │ │confremote│
 └────┬─────┘ └────┬────┘ └────┬─────┘ └──────┬───────┘ └────┬─────┘
      │            │           │               │              │
      │            │ (pre-flight probes only)  │              │
      └────────────┴─────┬─────┴───────────────┴──────────────┘
                         │  IWIndexerConnector
                         ▼
              ┌─────────────────────┐
              │  WIndexerConnector  │
              │                     │
              │  • shared_mutex     │
              │  • index()          │
              │  • existence probes │
              └─────────┬───────────┘
                        │  IndexerConnectorAsync
                        ▼
              ┌──────────────────────┐
              │  indexer_connector   │
              │  (OpenSearch client) │
              └──────────┬───────────┘
                         ▼
              ┌─────────────────────┐
              │   wazuh-indexer     │
              │   (OpenSearch)      │
              └─────────────────────┘

 Content download takes a different path:

 ┌─────────┐ ┌──────────┐        ┌───────────┐        ┌──────────────────┐
 │ cmsync  │ │ iocsync  │───────►│ cmcontent │───────►│ content_manager  │
 └─────────┘ └──────────┘  sinks └───────────┘ topics │  (shared .so)    │
                                                      └──────────────────┘
```

## Key Concepts

### Pre-flight readiness, not consistency

`isConsumerReadyForSync()` is a **cheap, non-PIT** check that a CTI consumer is worth querying. It
verifies two things:

1. `status == "ready"` — the indexer is not actively rewriting the data.
2. `local_offset != 0` — the consumer has received at least one CTI update, so the hash and data
   documents actually exist.

It is explicitly **not** the consistency guarantee. A check made outside a snapshot can go stale
between the check and the read, so the content manager re-validates the same consumer document from
*inside* the PIT it is about to read content from. This module keeps the cheap layer because one
query here short-circuits every registration at once, and because `local_offset` is not covered by
the in-snapshot check.

### Well-Known Consumer IDs

| Constant | Value | Used By | Purpose |
|---|---|---|---|
| `STANDARD_RULESET_CONSUMER_ID` | `"cti:catalog:consumer:ruleset"` | cmsync | Pre-flight check before a ruleset sync cycle |
| `IOC_ENRICHMENT_CONSUMER_ID` | `"cti:catalog:consumer:iocs"` | iocsync | Pre-flight check before an IoC sync cycle |

### Thread Safety

Every public method acquires either a **shared lock** (read operations, indexing) or an **exclusive lock** (`shutdown`). After `shutdown()` resets the internal `IndexerConnectorAsync`, subsequent calls degrade gracefully — `index()` silently returns, while query methods throw `std::runtime_error`.

### Graceful Shutdown

`WIndexerConnector` supports a two-phase shutdown for responsive process termination:

1. **`requestShutdown()`** — sets an `std::atomic<bool> m_shutdownRequested` flag (non-destructive, idempotent), observed by any in-flight query.
2. **`shutdown()`** — also sets the flag (defense in depth), then acquires the exclusive lock and destroys the underlying `IndexerConnectorAsync`.

In `main.cpp`, the exit handler registers both: `requestShutdown()` executes first (LIFO) so in-flight operations release their shared locks quickly, then `shutdown()` acquires the exclusive lock without blocking.

Note that the long-running operation this used to protect — paginating a whole policy or IoC type —
no longer happens here. Its equivalent now lives in the content manager, which is interrupted by
`ContentRegister::requestStop()`; `CMSync`/`IocSync` call it from their own `requestShutdown()`.

### Well-Known Indices

| Constant | Index Name | Purpose |
|---|---|---|
| `POLICY_INDEX` | `wazuh-threatintel-policies` | Policy existence checks |
| `IOC_INDEX` | `wazuh-threatintel-enrichments` | IoC index existence check |
| `REMOTE_CONF_INDEX` | `.wazuh-settings` | Remote engine runtime configuration |
| `CTI_CONSUMERS_INDEX` | `.wazuh-cti-consumers` | Consumer readiness documents |

The full list of indices a ruleset or IoC download reads from is now configuration owned by
[`cmcontent`](../cmcontent/README.md), not constants here.

### Configuration

The `Config` struct encapsulates connection parameters:

```cpp
struct Config
{
    std::vector<std::string> hosts;   // e.g. ["https://localhost:9200"]
    std::string username;             // OpenSearch username
    std::string password;             // OpenSearch password
    size_t maxQueueBytes {0};         // 0 = unlimited (bytes)
    size_t maxRetryDelaySeconds {15}; // Retry backoff ceiling

    struct {
        std::vector<std::string> cacert; // CA bundle paths
        std::string cert;                // Client certificate
        std::string key;                 // Client private key
    } ssl;

    std::string toJson() const;      // Serialises to JSON for IndexerConnectorAsync
};
```

An alternative constructor accepts a raw JSON OSSEC configuration string directly. `main.cpp` uses
that one, and hands the **same** JSON to the content registrations, so there is no second place to
configure the indexer.

## Directory Structure

```
wiconnector/
├── CMakeLists.txt
├── README.md
├── interface/wiconnector/
│   └── iwindexerconnector.hpp        # IWIndexerConnector pure-virtual interface
├── include/wiconnector/
│   └── windexerconnector.hpp         # WIndexerConnector concrete implementation + Config
├── src/
│   └── windexerconnector.cpp         # Full implementation (~430 lines)
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
    virtual ~IWIndexerConnector() = default;

    // ── Indexing ───────────────────────────────────────────
    virtual void index(std::string_view index, std::string_view data) = 0;

    // ── Existence / readiness probes ──────────────────────
    virtual bool existsPolicy(std::string_view space) = 0;
    virtual bool existsIocDataIndex() = 0;
    virtual bool isConsumerReadyForSync(std::string_view consumerId) = 0;

    // ── Remote configuration ──────────────────────────────
    virtual json::Json getEngineRemoteConfig() = 0;

    // ── Queue introspection ───────────────────────────────
    virtual uint64_t getQueueSize() = 0;
    virtual uint64_t getDroppedEvents() = 0;
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
    WIndexerConnector(std::unique_ptr<IIndexerConnectorAsync> async, std::size_t maxHitsPerRequest); // test-only

    void shutdown();          // Destructive: resets the async connector under exclusive lock
    void requestShutdown();   // Non-destructive: sets the abort flag
    // ... all IWIndexerConnector overrides ...

private:
    std::unique_ptr<IIndexerConnectorAsync> m_indexerConnectorAsync;
    std::shared_mutex m_mutex;
    std::size_t m_maxHitsPerRequest;
    std::atomic<bool> m_shutdownRequested {false};

    bool existsIndex(std::string_view indexName);
};
```

### Anonymous-Namespace Helpers

| Helper | Purpose |
|---|---|
| `getQueryFilter(space)` | Builds a `bool/filter/term` query filtering by `space.name` |
| `getTotalHits(hits)` | Extracts total hit count from the response, handling both object and numeric formats |

### Key Flows

#### `index(index, data)`

Acquires shared lock, delegates to `IndexerConnectorAsync::indexDataStream()`. Exceptions are caught and logged as warnings — indexing failures do not propagate to callers.

#### `existsPolicy(space)`

Searches `wazuh-threatintel-policies` with `size=1` filtered by `space.name`, projecting only
`space.name`. Returns whether any hit came back. Used by `cmsync` to skip a space that has nothing
published for it yet.

#### `existsIocDataIndex()`

Attempts a `size=0` `match_all` against `wazuh-threatintel-enrichments`; a thrown
`IndexerConnectorException` means the index is absent.

#### `isConsumerReadyForSync(consumerId)`

Searches `.wazuh-cti-consumers` for the consumer document and returns true only when
`status == "ready"` **and** `local_offset != 0`. Every error path returns `false` — the safe
default is to skip the sync, not to attempt one against an indexer that cannot answer.

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

- **Unit tests** (`test/src/unit/wic_test.cpp`) — cover `Config::toJson()` serialisation, constructor validation (empty/invalid JSON, zero `maxHitsPerRequest`), `index()` graceful handling, `shutdown()` lifecycle, `requestShutdown()` semantics (non-destructive, idempotent, composable with `shutdown()`), concurrent access (multi-threaded indexing and concurrent indexing + shutdown), and the existence / readiness / remote-config query paths against a mocked `IIndexerConnectorAsync`.
- **Mock** (`test/mocks/wiconnector/mockswindexerconnector.hpp`) — `MockWIndexerConnector` in `wiconnector::mocks` implements all `IWIndexerConnector` methods with GMock macros for use by downstream consumers.

## Consumers

| Module | Dependency | Role |
|---|---|---|
| `builder` | `wIndexerConnector::iwIndexerConnector` | Uses the connector to push indexed events via the `indexerOutput` stage builder |
| `cmsync` | `wIndexerConnector::iwIndexerConnector` | Pre-flight checks (`existsPolicy`, `isConsumerReadyForSync`) before a ruleset sync cycle |
| `iocsync` | `wIndexerConnector::iwIndexerConnector` | Pre-flight checks (`existsIocDataIndex`, `isConsumerReadyForSync`) before an IoC sync cycle |
| `rawevtindexer` | `wIndexerConnector::iwIndexerConnector` | Indexes raw events into the wazuh-indexer |
| `confremote` | `wIndexerConnector::iwIndexerConnector` | Retrieves remote engine configuration from `.wazuh-settings` |
| `main.cpp` | `wIndexerConnector::wIndexerConnector` | Creates the `WIndexerConnector` instance with configuration and injects it into consuming modules |

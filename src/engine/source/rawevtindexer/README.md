# Raw Event Indexer Module

## Overview

The **rawevtindexer** module provides a thin, thread-safe abstraction for indexing raw (unprocessed) security events into the Wazuh Indexer before they pass through the engine's policy pipelines. This gives operators access to the original event data for forensic analysis and debugging, independent of the processed output.

The module is designed as a simple on/off gate around an `IWIndexerConnector`, with atomic enable/disable toggling and runtime hot-reload support for remote configuration changes.

## Architecture

```
                          ┌────────────────────────┐
                          │    IRawEventIndexer     │  ← Public interface
                          │  index() / enable()    │
                          │  disable() / isEnabled()│
                          │  hotReloadConf()        │
                          └────────────┬───────────┘
                                       │
                          ┌────────────▼───────────┐
                          │   RawEventIndexer       │  ← Implementation
                          │  atomic<bool> m_enabled │
                          │  weak_ptr<connector>    │
                          │  m_indexName             │
                          └────────────┬───────────┘
                                       │ delegates to
                          ┌────────────▼───────────┐
                          │  IWIndexerConnector     │  ← External dependency
                          │  index(indexName, data) │
                          └────────────────────────┘
```

## Key Concepts

| Concept | Description |
|---|---|
| **Raw Event** | The original event data (JSON string) as received by the engine, before any policy processing. Indexed with a `/@timestamp` and `/event/original` field. |
| **Enable Gate** | An `atomic<bool>` flag that controls whether `index()` calls are forwarded to the connector. Starts disabled. |
| **Weak Connector** | The indexer holds a `weak_ptr` to the `IWIndexerConnector`. If the connector is destroyed, indexing silently becomes a no-op. |
| **Hot Reload** | The `hotReloadConf()` method allows remote configuration to toggle indexing on/off at runtime, accepting a JSON boolean value. |
| **Default Index** | Raw events are written to the `wazuh-events-raw-v5` index by default, configurable at construction time. |

## Directory Structure

```
rawevtindexer/
├── CMakeLists.txt
├── README.md
├── interface/rawevtindexer/
│   └── iraweventindexer.hpp        # IRawEventIndexer abstract interface
├── include/rawevtindexer/
│   └── raweventindexer.hpp         # RawEventIndexer implementation header
├── src/
│   └── raweventindexer.cpp         # Implementation
└── test/
    ├── mocks/rawevtindexer/
    │   └── mockraweventindexer.hpp  # GMock mock
    └── src/
        ├── unit/
        │   └── raweventindexer_test.cpp
        └── component/
            └── raweventindexer_test.cpp
```

## Public Interface

### `IRawEventIndexer` ([iraweventindexer.hpp](interface/rawevtindexer/iraweventindexer.hpp))

| Method | Description |
|---|---|
| `index(const std::string&)` | Index raw event data (string) if enabled; errors are silently logged |
| `index(const char*)` | Index raw event data (C-string); null/empty are skipped |
| `index(std::string_view)` | Index raw event data (zero-copy view); empty is skipped |
| `enable()` | Enable the indexer |
| `disable()` | Disable the indexer |
| `isEnabled()` | Check current state |
| `hotReloadConf(json::Json)` | Apply a remote config boolean to enable/disable; throws `std::invalid_argument` on non-boolean |

### `RawEventIndexer` ([raweventindexer.hpp](include/rawevtindexer/raweventindexer.hpp))

```cpp
explicit RawEventIndexer(
    std::weak_ptr<wiconnector::IWIndexerConnector> connector,
    std::string_view indexName = DEFAULT_INDEX_NAME  // "wazuh-events-raw-v5"
);
```

- **Thread-safe**: The `m_enabled` flag uses `std::atomic<bool>` with acquire/release ordering.
- **Fault-tolerant**: Connector exceptions are caught and logged as warnings; connector expiry is handled gracefully.
- **Always starts disabled**: Must be explicitly enabled after construction.

## Implementation Details

### Index Flow

Each `index()` overload follows the same pattern:

1. **Guard empty input** — `const char*` and `string_view` overloads return early on null/empty data.
2. **Check enabled** — `m_enabled.load(memory_order_acquire)`. If disabled, return immediately.
3. **Lock connector** — `m_connector.lock()`. If the connector has been destroyed, return silently.
4. **Delegate** — Call `connector->index(m_indexName, data)` inside a try/catch. Failures are logged at WARNING level but never propagated.

### Hot Reload

`hotReloadConf()` validates that the incoming `json::Json` is a boolean. If `true`, calls `enable()`; if `false`, calls `disable()`. Non-boolean values cause a `std::invalid_argument` exception with a descriptive message.

### Caller Context

The `RouterWorker` (in the `router` module) calls `index()` on every event it dequeues from the production queue, *before* parsing and routing the event. The raw indexing payload is built by combining the original event JSON with `/@timestamp` and `/event/original` fields.

## CMake Targets

| Target | Type | Description |
|---|---|---|
| `rawevtindexer::irawindexer` | INTERFACE | Public interface (`IRawEventIndexer`) |
| `rawevtindexer::rawevtindexer` | STATIC | Implementation (`RawEventIndexer`) |
| `rawevtindexer::mocks` | INTERFACE | GMock mock for testing (test builds only) |
| `rawevtindexer_utest` | Executable | Unit tests |
| `rawevtindexer_ctest` | Executable | Component/integration tests |

**Key dependencies**: `base`, `wIndexerConnector::iwIndexerConnector`

## Testing

### Unit Tests

- Constructor throws on expired connector
- Always starts disabled
- Enable/disable toggles state
- Each `index()` overload calls connector when enabled
- No-op when disabled
- Early return on null/empty input
- Connector exceptions are swallowed
- Graceful behavior when connector expires after construction
- `hotReloadConf` accepts booleans, rejects non-booleans

### Component Tests

- End-to-end workflow: disabled → ignored, enabled → indexed, disabled → ignored
- Connector failures are handled and subsequent events continue indexing
- Concurrent indexing from multiple threads (8 threads × 50 events)
- No-throw when connector expires at runtime

## Consumers

| Consumer | Usage |
|---|---|
| **`router`** | `RouterWorker` calls `index()` during production event drain; `Orchestrator` receives the indexer via `Options` |
| **`api/rawevtindexer`** | REST API handlers to query/toggle indexer state |
| **`api/event`** | Event ingestion API passes the indexer reference |
| **`confremote`** | Remote configuration synchronization — calls `hotReloadConf()` to toggle indexing |
| **`main.cpp`** | Engine entry point — creates `RawEventIndexer`, registers hot-reload callback, passes to Orchestrator and API |

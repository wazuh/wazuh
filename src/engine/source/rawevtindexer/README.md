# Raw Event Indexer Module

## Overview

The **rawevtindexer** module provides a thin, thread-safe abstraction for indexing raw (unprocessed) security events into the Wazuh Indexer before they pass through the engine's policy pipelines. This gives operators access to the original event data for forensic analysis and debugging, independent of the processed output.

The module is designed as a simple on/off gate around an `IWIndexerConnector`, with atomic enable/disable toggling and runtime hot-reload support for remote configuration changes (the `index_raw_events` setting read by `confremote`).

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
| **Raw Event** | The original event data as received by the engine, before any policy processing. The caller (`RouterWorker`) builds the document from the event header plus `/@timestamp`, `/event/original` and `/wazuh/event/id`. |
| **Enable Gate** | An `atomic<bool>` flag that controls whether `index()` calls are forwarded to the connector. Starts disabled. |
| **Weak Connector** | The indexer holds a `weak_ptr` to the `IWIndexerConnector`. The constructor throws `std::runtime_error` if it is already expired; if it expires later, indexing silently becomes a no-op. |
| **Hot Reload** | The `hotReloadConf()` method allows remote configuration to toggle indexing on/off at runtime, accepting a JSON boolean value. |
| **Default Index** | Raw events are written to the `wazuh-events-raw-v5` index (`DEFAULT_INDEX_NAME`), which is what `main.cpp` passes; the constructor accepts another name. |

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
| `index(const std::string&)` | Index raw event data (string) if enabled |
| `index(const char*)` | Index raw event data (C-string); null/empty are skipped |
| `index(std::string_view)` | Index raw event data (zero-copy view); empty is skipped |
| `enable()` | Enable the indexer |
| `disable()` | Disable the indexer |
| `isEnabled()` | Check current state |
| `hotReloadConf(const json::Json&)` | Apply a remote config boolean to enable/disable; throws `std::invalid_argument` on non-boolean |

### `RawEventIndexer` ([raweventindexer.hpp](include/rawevtindexer/raweventindexer.hpp))

```cpp
explicit RawEventIndexer(
    std::weak_ptr<wiconnector::IWIndexerConnector> connector,
    std::string_view indexName = DEFAULT_INDEX_NAME  // "wazuh-events-raw-v5"
);
```

- **Thread-safe**: The `m_enabled` flag uses `std::atomic<bool>` with acquire/release ordering.
- **Connector expiry tolerated**: an expired connector after construction makes `index()` a no-op. Connector exceptions are **not** caught here (see [Index Flow](#index-flow)).
- **Always starts disabled**: Must be explicitly enabled after construction.

## Implementation Details

### Index Flow

Each `index()` overload follows the same pattern:

1. **Guard empty input** — `const char*` and `string_view` overloads return early on null/empty data.
2. **Check enabled** — `m_enabled.load(memory_order_acquire)`. If disabled, return immediately.
3. **Lock connector** — `m_connector.lock()`. If the connector has been destroyed, return silently.
4. **Delegate** — Call `connector->index(m_indexName, data)`. There is no try/catch: an exception from the connector propagates to the caller. In the router worker it is caught by the per-event handler, which logs `Failed processing queued event in router worker: …` and skips routing that event.

### Hot Reload

`hotReloadConf()` validates that the incoming `json::Json` is a boolean. If `true`, calls `enable()`; if `false`, calls `disable()`. Non-boolean values throw `std::invalid_argument` (`Expected boolean for 'index_raw_events', got: …`).

`main.cpp` registers it as the `confremote` trigger for `index_raw_events` (default `false`) and applies the initial value at startup. The indexer exists only when event processing is enabled (`analysisd.server_enable_event_processing`, default `true`).

### Caller Context

The `RouterWorker` (in the `router` module) calls `index()` on every event it dequeues from the production queue while `isEnabled()` is true, *before* parsing and routing the event. The payload is the event header JSON with `/@timestamp`, `/event/original` (the raw event text) and `/wazuh/event/id` set; the same timestamp and id are then stamped on the routed event.

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
- Graceful behavior when connector expires after construction
- `hotReloadConf` accepts booleans, rejects non-booleans

### Component Tests

- End-to-end workflow: disabled → ignored, enabled → indexed, disabled → ignored
- Concurrent indexing from multiple threads (8 threads × 50 events)
- No-throw when connector expires at runtime

## Consumers

| Consumer | Usage |
|---|---|
| **`router`** | `RouterWorker` calls `index()` during production event drain; `Orchestrator` receives the indexer via `Options` |
| **`api/rawevtindexer`** | `POST /_internal/raweventindexer/status` handler, reports the enabled state (read-only; registered only when the indexer exists) |
| **`confremote`** | Remote configuration synchronization — invokes the `index_raw_events` trigger that `main.cpp` binds to `hotReloadConf()` |
| **`main.cpp`** | Engine entry point — creates `RawEventIndexer`, registers hot-reload callback, passes to Orchestrator and API |

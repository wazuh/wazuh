# Dumper Module

## Overview

The **dumper** module provides an activatable event-dumping mechanism for the Wazuh engine. When active, it writes the raw body of every batch received on `POST /events/enriched` (`engine-ingest-http.sock`) to rotating files via the `streamlog` subsystem. When inactive, all `dump()` calls are silently discarded (no-op). The module can be toggled at runtime through API endpoints on `engine-api-http.sock`, enabling on-demand event capture for debugging and diagnostics without restarting the engine.

The dumper and its consumer exist only when event processing is enabled
(`analysisd.server_enable_event_processing`, default `true`; `main.cpp`). The API routes are registered
unconditionally; with processing disabled they answer an internal error (`Error: Handler is not initialized`,
`api/adapter/include/api/adapter/adapter.hpp`).

## Architecture

```
                  Incoming events (NDJSON batches)
                          │
              ┌───────────▼───────────────────────────────┐
              │      api/event – pushEvent handler         │
              │                                            │
              │   dumpRef->dump(batchToDump)               │
              └───────────┬───────────────────────────────┘
                          │
              ┌───────────▼───────────────────────────────┐
              │           IDumper                          │
              │   dump(string | char* | string_view)       │
              │   activate() / deactivate() / isActive()   │
              └───────────┬───────────────────────────────┘
                          │
              ┌───────────▼───────────────────────────────┐
              │            Dumper                           │
              │                                            │
              │   m_logWriter ──► streamlog::WriterEvent    │
              │      (null when inactive)                   │
              │                                            │
              │   active:   (*m_logWriter)(data)            │
              │   inactive: return (no-op)                  │
              └───────────┬───────────────────────────────┘
                          │
              ┌───────────▼───────────────────────────────┐
              │     streamlog::ILogManager                  │
              │   ensureAndGetWriter("event-dumps", cfg)    │
              │                                            │
              │   → rotating log files on disk              │
              │     (async, buffered, compressible)         │
              └────────────────────────────────────────────┘

              ┌────────────────────────────────────────────┐
              │   API Endpoints (api/dumper)                │
              │                                            │
              │   POST /_internal/event-dumper/activate     │
              │   POST /_internal/event-dumper/deactivate   │
              │   POST /_internal/event-dumper/status       │
              └────────────────────────────────────────────┘
```

## Key Concepts

### Interface (`IDumper`)

Defined in `interface/dumper/idumper.hpp`. All methods are virtual:

| Method | Description |
|--------|-------------|
| `dump(const std::string&)` | Write data to the log channel (no-op if inactive); an empty string is still written |
| `dump(const char*)` | Write data from C-string; returns early on `nullptr` or empty string |
| `dump(std::string_view)` | Write data from zero-copy view; returns early on empty view |
| `activate()` | Enable the dumper (creates the streamlog writer); throws `std::runtime_error` if the log manager is gone or the channel cannot be created |
| `deactivate()` | Disable the dumper (releases the writer) |
| `isActive()` | Returns `true` if the dumper currently holds an active writer |

No `dump()` overload reports an error: if the dumper is inactive the call is ignored, and the writer's `false`
(queue full or channel closed) is discarded, so that data is silently lost.

### Active/Inactive State

The dumper's state is determined by whether `m_logWriter` is non-null:

- **Active**: `m_logWriter` points to a `streamlog::WriterEvent` bound to the `"event-dumps"` channel. Data passed to `dump()` is forwarded to `(*m_logWriter)(data)`, which asynchronously writes to rotating log files.
- **Inactive**: `m_logWriter` is null. All `dump()` calls check for null and return immediately.

State transitions:

| Operation | From → To | Effect |
|-----------|-----------|--------|
| `activate()` | inactive → active | Calls `ILogManager::ensureAndGetWriter()` to obtain a writer. No-op if already active |
| `deactivate()` | active → inactive | Resets `m_logWriter` to null. No-op if already inactive |

The constructor's `isActive` argument (default `false`) starts the dumper active; the constructor throws
`std::runtime_error("Logger for dumper is not available")` when the log manager has already expired. The channel
configuration is applied only when the channel is first created; a later `activate()` reuses the existing channel.

### Streamlog Channel

The dumper writes to a channel named `"event-dumps"` with extension `"log"` (constants `CHANNEL_NAME` and `CHANNEL_EXTENSION`). Streamlog places a channel in `<basePath>/<channel>/`, so with the defaults the files are
`/var/wazuh-manager/logs/event-dumps/<YYYY>/<MMM>/wazuh-event-dumps-<DD>.log`, with a hard link
`/var/wazuh-manager/logs/event-dumps/event-dumps.log` to the current file (`streamlog/src/logger.cpp`,
`streamlog/src/channel.cpp`). The channel is configured via `streamlog::RotationConfig`:

| Field | Type | Description |
|-------|------|-------------|
| `basePath` | `std::filesystem::path` | Base directory for log files |
| `pattern` | `std::string` | File naming pattern (supports `${YYYY}`, `${YY}`, `${MM}`, `${MMM}`, `${DD}`, `${HH}`, `${name}`, and `${counter}` when `maxSize > 0`; the extension is appended) |
| `maxSize` | `size_t` | Max size per file before rotation (`0` = unlimited) |
| `bufferSize` | `size_t` | Queue capacity, in events |
| `shouldCompress` | `bool` | Whether to compress rotated files |
| `compressionLevel` | `size_t` | Compression level (if enabled) |
| `maxFiles` | `size_t` | Max number of rotated files to keep |
| `maxAccumulatedSize` | `size_t` | Max total size across all rotated files |

## Dependencies

| Dependency | CMake Target | Role |
|------------|-------------|------|
| `base` | `base` | Error handling, JSON |
| `streamlog` | `streamlogger::istreamlogger` | `ILogManager` and `WriterEvent` for file-based async logging |

## Configuration

`main.cpp` fills the `RotationConfig` and the initial state from these `conf::key` constants
(`conf/include/conf/keys.hpp`). Their `analysisd.*` names, environment variables and defaults are documented for
operators in [Stream log](../../../../docs/ref/modules/engine/configuration.md#stream-log) and
[Event dumper](../../../../docs/ref/modules/engine/configuration.md#event-dumper):

| `conf::key` constant | Feeds |
|-----------|-------------|
| `STREAMLOG_BASE_PATH` | `basePath` (shared with the events stream) |
| `STREAMLOG_DUMPER_PATTERN` | `pattern` |
| `STREAMLOG_DUMPER_MAX_SIZE` | `maxSize` |
| `STREAMLOG_DUMPER_BUFFER_SIZE` | `bufferSize` |
| `STREAMLOG_SHOULD_COMPRESS` | `shouldCompress` (shared) |
| `STREAMLOG_COMPRESSION_LEVEL` | `compressionLevel` (shared) |
| `STREAMLOG_MAX_FILES` | `maxFiles` (shared) |
| `STREAMLOG_MAX_ACCUMULATED_SIZE` | `maxAccumulatedSize` (shared) |
| `DUMPER_ENABLED` (`analysisd.dumper_enabled`, default `false`) | Initial active state |

## Integration in `main.cpp`

```cpp
// 1. Build rotation config from conf keys
const auto dumperConfig = streamlog::RotationConfig {
    .basePath = confManager.get<std::string>(conf::key::STREAMLOG_BASE_PATH),
    .pattern  = confManager.get<std::string>(conf::key::STREAMLOG_DUMPER_PATTERN),
    // ... remaining RotationConfig fields ...
};

// 2. Construct dumper with streamlog manager, config, and initial enabled state
dumper = std::make_shared<dumper::Dumper>(
    streamLogger, dumperConfig, confManager.get<bool>(conf::key::DUMPER_ENABLED));

// 3. Register exit handler to deactivate on shutdown
exitHandler.add([dumper]() { dumper->deactivate(); });

// 4. Register the runtime-control routes on the API server, and pass the dumper to pushEvent
api::dumper::handlers::registerHandlers(dumper, apiServer);
engineRemoteServer->addRoute(httpsrv::Method::POST, "/events/enriched",
                             api::event::handlers::pushEvent(orchestrator, dumper, agentMetadataCache));
```

### Consumer: Event Ingestion (`api/event`)

The `pushEvent` HTTP handler (`api/event/src/handlers.cpp`) holds a `weak_ptr<IDumper>` and dumps each request body, minus one trailing newline, before parsing it:

```cpp
if (auto dumpRef = weakDump.lock(); dumpRef)
{
    std::string_view batchToDump = req.body;
    if (!batchToDump.empty() && batchToDump.back() == '\n')
        batchToDump.remove_suffix(1);
    dumpRef->dump(batchToDump);
}
```

### Consumer: Runtime Control (`api/dumper`)

Three HTTP endpoints (`api/dumper/include/api/dumper/handlers.hpp`) allow runtime toggling; their request and
response bodies are in the engine's
[private API reference](../../../../docs/ref/modules/engine/private-api-reference.md):

| Endpoint | Method | Action |
|----------|--------|--------|
| `/_internal/event-dumper/activate` | POST | `dumper->activate()` |
| `/_internal/event-dumper/deactivate` | POST | `dumper->deactivate()` |
| `/_internal/event-dumper/status` | POST | `dumper->isActive()`, returned as `active` |

Runtime toggling is not persisted: the next start uses `analysisd.dumper_enabled` again.

## Thread Safety

- `m_loggerMutex` (`std::shared_mutex`) protects all access to `m_logWriter`:
  - `dump()` acquires a **shared lock** — multiple threads can dump concurrently.
  - `activate()`, `deactivate()`, and the destructor acquire a **unique lock**.
  - `isActive()` acquires a **shared lock**.
- `m_logger` is held as `std::weak_ptr` to avoid preventing destruction of the log manager.

## File Structure

```
dumper/
├── CMakeLists.txt                              # Build: iface (INTERFACE), dumper (STATIC), mocks, utest
├── interface/dumper/
│   └── idumper.hpp                             # IDumper interface (dump, activate, deactivate, isActive)
├── include/dumper/
│   └── dumper.hpp                              # Dumper class declaration + inline activate/deactivate/isActive
├── src/
│   └── dumper.cpp                              # dump() overloads implementation
├── test/
│   ├── mocks/dumper/
│   │   └── mockDumper.hpp                      # GMock mock for IDumper (used by other modules' tests)
│   └── src/unit/
│       └── dumper_test.cpp                     # Unit tests with mocked streamlog
```

## Testing

### Unit Tests (`dumper_utest`)

Test the dumper with mocked `ILogManager` and `WriterEvent`:

| Test | Verifies |
|------|----------|
| `ConstructorWithInvalidLogger` | Null logger throws `std::runtime_error` |
| `ConstructorInactive` | Default state is inactive |
| `ConstructorActive` | Active construction creates writer |
| `IsActiveWhenInactive` / `IsActiveWhenActive` | `isActive()` reflects the writer |
| `Activate` | Transition from inactive to active |
| `ActivateWhenAlreadyActive` | No duplicate writer creation |
| `ActivateWithInvalidLogger` | Expired logger throws on activate |
| `Deactivate` | Transition from active to inactive |
| `DeactivateWhenAlreadyInactive` | No-op on double deactivate |
| `DumpStringWhenActive` | Data forwarded to writer |
| `DumpStringWhenInactive` | Data silently discarded |
| `DumpCStringWhenActive` | C-string forwarded to writer |
| `DumpCStringWhenInactive` | C-string silently discarded |
| `DumpNullCString` | `nullptr` returns early without writing |
| `DumpEmptyCString` | Empty string returns early without writing |
| `DumpWriterReturnsFalse` | No throw when the writer returns `false` |
| `ThreadSafety` | Concurrent `isActive()` calls are safe |
| `DestructorCleansUp` | Destructor releases writer cleanly |

The `std::string_view` overload, the one `pushEvent` uses, has no dedicated test.

Build tests with `ENGINE_TEST=y`:

```bash
make -C src -j TARGET=manager ENGINE_TEST=y
```

Run:

```bash
src/build/engine/source/dumper/dumper_utest
```

## Mock

A GMock mock is provided at `test/mocks/dumper/mockDumper.hpp` (`dumper::mocks::MockDumper`) for use by other modules that depend on `IDumper`. CMake target: `dumper::mocks`.

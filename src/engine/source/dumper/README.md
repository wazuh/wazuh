# Dumper Module

## Overview

The **dumper** module provides an activatable event-dumping mechanism for the Wazuh engine. When active, it writes incoming event data to rotating log files via the `streamlog` subsystem. When inactive, all `dump()` calls are silently discarded (no-op). The module can be toggled at runtime through API endpoints, enabling on-demand event capture for debugging and diagnostics without restarting the engine.

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
| `dump(const std::string&)` | Write data to the log channel (no-op if inactive) |
| `dump(const char*)` | Write data from C-string; returns early on `nullptr` or empty string |
| `dump(std::string_view)` | Write data from zero-copy view; returns early on empty view |
| `activate()` | Enable the dumper (creates the streamlog writer) |
| `deactivate()` | Disable the dumper (releases the writer) |
| `isActive()` | Returns `true` if the dumper currently holds an active writer |

All `dump()` overloads are **non-throwing**: if the dumper is inactive, calls are silently ignored.

### Active/Inactive State

The dumper's state is determined by whether `m_logWriter` is non-null:

- **Active**: `m_logWriter` points to a `streamlog::WriterEvent` bound to the `"event-dumps"` channel. Data passed to `dump()` is forwarded to `(*m_logWriter)(data)`, which asynchronously writes to rotating log files.
- **Inactive**: `m_logWriter` is null. All `dump()` calls check for null and return immediately.

State transitions:

| Operation | From → To | Effect |
|-----------|-----------|--------|
| `activate()` | inactive → active | Calls `ILogManager::ensureAndGetWriter()` to obtain a writer. No-op if already active |
| `deactivate()` | active → inactive | Resets `m_logWriter` to null. No-op if already inactive |

### Streamlog Channel

The dumper writes to a channel named `"event-dumps"` with extension `"log"` (constants `CHANNEL_NAME` and `CHANNEL_EXTENSION`). The channel is configured via `streamlog::RotationConfig`:

| Field | Type | Description |
|-------|------|-------------|
| `basePath` | `std::string` | Base directory for log files |
| `pattern` | `std::string` | File naming pattern (supports `${YYYY}`, `${MMM}`, `${DD}`, `${name}`) |
| `maxSize` | `size_t` | Max size per file before rotation (`0` = unlimited) |
| `bufferSize` | `size_t` | In-memory write buffer size |
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

The dumper configuration is sourced from `conf` keys (passed via `RotationConfig` at construction):

| Key prefix | Description |
|-----------|-------------|
| `STREAMLOG_BASE_PATH` | Base directory for dump log files |
| `STREAMLOG_DUMPER_PATTERN` | File naming pattern for the dumper channel |
| `STREAMLOG_DUMPER_MAX_SIZE` | Max file size before rotation |
| `STREAMLOG_DUMPER_BUFFER_SIZE` | Write buffer size |
| `STREAMLOG_SHOULD_COMPRESS` | Enable compression of rotated files |
| `STREAMLOG_COMPRESSION_LEVEL` | Compression level |
| `STREAMLOG_MAX_FILES` | Max rotated file count |
| `STREAMLOG_MAX_ACCUMULATED_SIZE` | Max total rotated file size |
| `DUMPER_ENABLED` | Initial active state (`true`/`false`) |

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
```

### Consumer: Event Ingestion (`api/event`)

The `pushEvent` HTTP handler receives a `weak_ptr<IDumper>` and dumps each incoming NDJSON batch before parsing:

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

Three HTTP endpoints allow runtime toggling:

| Endpoint | Method | Action |
|----------|--------|--------|
| `/_internal/event-dumper/activate` | POST | `dumper->activate()` |
| `/_internal/event-dumper/deactivate` | POST | `dumper->deactivate()` |
| `/_internal/event-dumper/status` | POST | `dumper->isActive()` |

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
| `Activate` | Transition from inactive to active |
| `ActivateWhenAlreadyActive` | No duplicate writer creation |
| `ActivateWithInvalidLogger` | Expired logger throws on activate |
| `Deactivate` | Transition from active to inactive |
| `DeactivateWhenAlreadyInactive` | No-op on double deactivate |
| `DumpStringWhenActive` | Data forwarded to writer |
| `DumpStringWhenInactive` | Data silently discarded |
| `DumpCStringWhenActive` | C-string forwarded to writer |
| `DumpNullCString` | `nullptr` returns early without writing |
| `DumpEmptyCString` | Empty string returns early without writing |
| `DumpWriterReturnsFalse` | No throw even if writer fails |
| `ThreadSafety` | Concurrent `isActive()` calls are safe |
| `DestructorCleansUp` | Destructor releases writer cleanly |

Build tests with `ENGINE_TEST=y`:

```bash
make --directory=$WAZUH_REPO/src -j TARGET=manager ENGINE_TEST=y DEBUG=yes
```

Run:

```bash
$ENGINE_BUILD/source/dumper/dumper_utest
```

## Mock

A GMock mock is provided at `test/mocks/dumper/mockDumper.hpp` (`dumper::mocks::MockDumper`) for use by other modules that depend on `IDumper`. CMake target: `dumper::mocks`.

# Streamlog Module — Developer Guide

> **Module path:** `src/engine/source/streamlog`
> **Namespace:** `streamlog`
> **Library alias (CMake):** `streamlogger::streamlogger` (implementation), `streamlogger::istreamlogger` (interface-only)

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Directory Layout](#directory-layout)
4. [Key Classes & Relationships](#key-classes--relationships)
5. [Data Flow & Threading Model](#data-flow--threading-model)
6. [Rotation Mechanics](#rotation-mechanics)
7. [Compression](#compression)
8. [Crash-Recovery (Store Persistence)](#crash-recovery-store-persistence)
9. [Configuration Reference](#configuration-reference)
10. [Pattern Placeholders](#pattern-placeholders)
11. [Usage Examples](#usage-examples)
12. [Error Handling Strategy](#error-handling-strategy)
13. [Build & Test](#build--test)
14. [Design Decisions & Rationale](#design-decisions--rationale)
15. [Dependency Graph](#dependency-graph)
16. [FAQ & Gotchas](#faq--gotchas)

---

## Overview

The **streamlog** module provides high-performance, named, rotating log channels with fully asynchronous writes. It is the engine's primary mechanism for writing structured logs (NDJSON) to disk — used for alerts, archives, and any other line-oriented log stream.

### Key capabilities

| Feature | Details |
|---------|---------|
| **Named Channels** | Each channel is identified by a unique name and has its own rotation policy. |
| **Asynchronous I/O** | A dedicated worker thread per channel drains a lock-free queue and writes to disk. |
| **Dual Rotation** | Size-based (counter suffix) and time-based (date placeholders in file name). |
| **Hard-Link "Latest"** | `<basePath>/<name>.<ext>` always points to the active file — external tools tail this stable path. |
| **Gzip Compression** | Rotated files are compressed asynchronously via the `scheduler::IScheduler`. |
| **Crash Recovery** | The current file path is persisted to the `store::IStore`; on restart, pending compressions are resumed. |
| **Zero-Copy Enqueue** | Writers `std::move` messages into the queue — no copies on the hot path. |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           Application Threads                          │
│                                                                        │
│   auto w = logManager->getWriter("alerts");                            │
│   (*w)( R"({"ts":"...","msg":"hello"})" );   // enqueue (move)        │
│                                                                        │
└──────────────────────────┬──────────────────────────────────────────────┘
                           │  shared_ptr<WriterEvent>
                           ▼
┌──────────────────────────────────────────────────────────────────────────┐
│  ChannelWriter  (implements WriterEvent)                                │
│  ┌──────────────────────┐                                              │
│  │ m_queue  (shared_ptr)├──────┐                                       │
│  │ m_channelState       │      │                                       │
│  │ m_channelHandler (wp)│      │  lock-free push                       │
│  └──────────────────────┘      │                                       │
└────────────────────────────────┼────────────────────────────────────────┘
                                 ▼
┌──────────────────────────────────────────────────────────────────────────┐
│  FastQueueType  (fastqueue::StdQueue<std::string>)                     │
│  ┌────────────────────────────────────────────────────────────────┐     │
│  │  [msg1] [msg2] [msg3] ... [msgN]                              │     │
│  └───────────────────────────────────┬────────────────────────────┘     │
└──────────────────────────────────────┼──────────────────────────────────┘
                                       │  waitPop (1 s timeout)
                                       ▼
┌──────────────────────────────────────────────────────────────────────────┐
│  ChannelHandler  (worker thread)                                       │
│                                                                        │
│   loop:                                                                │
│     1. waitPop(message, 1000ms)                                        │
│     2. needsRotation(message.size())  →  Size | Time | No             │
│     3. if rotation → rotateFile() → schedule compression               │
│     4. writeMessage(message)  →  outputFile << msg << '\n'; flush()   │
│                                                                        │
│  State:                                                                │
│   • outputFile  (std::ofstream, append mode)                           │
│   • currentFile, latestLink  (filesystem paths)                        │
│   • currentSize, counter, lastRotation                                 │
│   • channelState  (atomic: Running | StopRequested | ErrorClosed)      │
└──────────────────────────────────────────────────────────────────────────┘
                                       │
                                       ▼  (on rotation, if shouldCompress)
┌──────────────────────────────────────────────────────────────────────────┐
│  scheduler::IScheduler  →  compressLogFile()  (gzip + remove original) │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## Directory Layout

```
streamlog/
├── CMakeLists.txt                        # Build definition
├── README.md                             # ← This file
│
├── interface/streamlog/
│   └── ilogger.hpp                       # Public interface: WriterEvent, ILogManager
│
├── include/streamlog/
│   └── logger.hpp                        # Public header: RotationConfig, LogManager
│
├── src/
│   ├── channel.hpp                       # Internal: ChannelWriter, ChannelHandler, ChannelState
│   ├── channel.cpp                       # Internal: all I/O, rotation, compression logic
│   └── logger.cpp                        # LogManager implementation (delegates to ChannelHandler)
│
└── test/
    ├── mocks/streamlog/
    │   └── mockStreamlog.hpp             # GMock: MockILogManager, MockWriterEvent
    └── src/
        ├── unit/
        │   ├── channel_test.cpp          # Unit tests for ChannelHandler (~2 000 lines)
        │   └── logger_test.cpp           # Unit tests for LogManager    (~586 lines)
        └── component/
            └── logger_test.cpp           # Component / integration test placeholder
```

### Header dependency rules

| Header | Audience | Depends on |
|--------|----------|------------|
| `interface/streamlog/ilogger.hpp` | **Any consumer** (read-only) | `<string>`, `<memory>` |
| `include/streamlog/logger.hpp` | **Owner / configurator** | `ilogger.hpp`, `store::IStore`, `scheduler::IScheduler` |
| `src/channel.hpp` | **Library-internal only** | `logger.hpp`, `base/logging`, `fastqueue`, `store`, `scheduler` |

---

## Key Classes & Relationships

### Class Diagram (simplified)

```
  ┌──────────────────┐          ┌────────────────────────┐
  │   «interface»     │          │      RotationConfig     │
  │   ILogManager     │          │ ─────────────────────── │
  │ ─────────────────│          │  basePath               │
  │ +getWriter(name) │          │  pattern                │
  └────────┬─────────┘          │  maxSize                │
           │ implements          │  bufferSize             │
           ▼                     │  shouldCompress         │
  ┌──────────────────┐          │  compressionLevel       │
  │    LogManager     │          └────────────────────────┘
  │ ─────────────────│                     │ used by
  │  m_channels       │─── owns N ──►┌─────┴──────────────┐
  │  m_channelsMutex  │              │   ChannelHandler    │
  │  m_scheduler (wp) │              │ ──────────────────  │
  │  m_store          │              │  m_config (const)   │
  │ ─────────────────│              │  m_channelName      │
  │ +registerLog()   │              │  m_stateData        │
  │ +updateConfig()  │              │  m_activeWriters    │
  │ +destroyChannel()│              │  m_store            │
  │ +getWriter()     │              │  m_scheduler (wp)   │
  │ +hasChannel()    │              │ ──────────────────  │
  │ +getConfig()     │              │ +create() [factory] │
  │ +cleanup()       │              │ +createWriter()     │
  └──────────────────┘              │ -workerThreadFunc() │
                                    │ -needsRotation()    │
  ┌──────────────────┐              │ -rotateFile()       │
  │  «interface»      │              │ -writeMessage()     │
  │  WriterEvent      │              │ -compressLogFile()  │
  │ ─────────────────│              └──────┬──────────────┘
  │ +operator()(msg) │                     │ creates
  └────────┬─────────┘                     ▼
           │ implements          ┌────────────────────────┐
           ▼                     │    ChannelWriter        │
  ┌──────────────────┐          │ ──────────────────────  │
  │  ChannelWriter    │◄─────── │  m_queue (shared_ptr)   │
  │  (see left)       │          │  m_channelState (sp)    │
  └──────────────────┘          │  m_channelHandler (wp)  │
                                 └────────────────────────┘
```

### Class Summary

| Class | Visibility | Responsibility |
|-------|-----------|----------------|
| `WriterEvent` | **Public interface** | Abstract write handle. `operator()(string&&) → bool`. |
| `ILogManager` | **Public interface** | Abstract channel registry. `getWriter(name)`. |
| `RotationConfig` | **Public** | POD-like struct describing a channel's rotation/compression policy. |
| `LogManager` | **Public** | Concrete registry. Owns `ChannelHandler` instances. Thread-safe via `shared_mutex`. |
| `ChannelHandler` | **Internal** | Per-channel engine: worker thread, file I/O, rotation, compression scheduling. Created via `create()` factory. |
| `ChannelWriter` | **Internal** | Concrete `WriterEvent`. Pushes into the queue. Non-copyable. Destructor calls `onWriterDestroyed()`. |
| `ChannelState` | **Internal** | Enum: `Running`, `StopRequested`, `ErrorClosed`. |

---

## Data Flow & Threading Model

### Threads involved

| Thread | Role |
|--------|------|
| **Caller threads** (N) | Call `(*writer)(msg)` — only a `queue.push()` on the hot path. |
| **Worker thread** (1 per channel) | `workerThreadFunc()` — pops, checks rotation, writes, flushes. |
| **Scheduler thread** (shared) | Runs `compressLogFile()` tasks asynchronously. |

### Hot-path cost breakdown

1. `writer->operator()(move(msg))` — atomic load of `ChannelState` + `queue.push()`.
2. Worker: `queue.waitPop()` → `needsRotation()` (size comparison + optional hour check) → `ofstream << msg << '\n'` → `flush()`.

### Writer lifecycle and worker thread

```
createWriter()          → if first writer: startWorkerThread()
                          ++m_activeWriters.count
                          return shared_ptr<ChannelWriter>

~ChannelWriter()        → handler->onWriterDestroyed()
                          --m_activeWriters.count
                          if count == 0: stopWorkerThread()  (join)
```

This "lazy start / eager stop" model ensures no background threads exist when a channel has no consumers.

---

## Rotation Mechanics

### Size-Based Rotation

Triggered when `currentSize + messageSize >= maxSize`.

1. Increment `counter`.
2. Generate new path from pattern (e.g. `alerts-3.log`).
3. Create directories if needed.
4. Close current file, open new file (`updateOutputFileAndLink()`).
5. Update hard-link to point to the new file.
6. Schedule compression of the previous file.

### Time-Based Rotation

Triggered when the **hour boundary** changes and the resolved pattern produces a **different path**.

1. Reset `counter` to 0.
2. Generate new path from pattern (e.g. `2025/Jul/alerts-15.json` → `2025/Jul/alerts-16.json`).
3. Same steps 3–6 as size-based rotation.

### Rotation check frequency

`needsRotation()` is called **once per message** (inside the single worker thread), so there is zero contention. The hour comparison uses `duration_cast<hours>` for a fast integer comparison.

---

## Compression

When `shouldCompress` is `true` and the `scheduler` weak pointer is valid:

1. After `rotateFile()`, a one-shot task is scheduled:
   ```cpp
   scheduler::TaskConfig {
       .interval = 0,           // one-time
       .CPUPriority = 0,
       .timeout = 0,
       .taskFunction = [path, level]() { compressLogFile(path, level); }
   };
   ```
2. `compressLogFile()` calls `Utils::ZlibHelper::gzipCompress()` and removes the original.
3. If the scheduler is unavailable (expired `weak_ptr`), a warning is logged and the file is left uncompressed.

---

## Crash-Recovery (Store Persistence)

On each rotation (when compression is enabled), the current file path is saved to the `store::IStore` under:

```
streamlog/<channelName>/0  →  { "/last_current": "/path/to/current/file.json" }
```

On channel construction:

1. Read the previous path from the store.
2. If it differs from the newly computed current path **and** the file exists on disk → schedule compression.
3. Save the new current path.
4. If compression is disabled, clear the persisted path.

This ensures that a rotated file that was not yet compressed before a crash will still be compressed after restart.

---

## Configuration Reference

### `RotationConfig` Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `basePath` | `std::filesystem::path` | *(required)* | Absolute, existing, writable directory. |
| `pattern` | `std::string` | *(required)* | File name pattern with placeholders. May contain subdirectories. |
| `maxSize` | `size_t` | `0` | Max file size in bytes before size rotation. `0` = disabled. Clamped to ≥ 1 MiB. |
| `bufferSize` | `size_t` | `1 << 20` | Queue capacity (events). `0` is promoted to default. |
| `shouldCompress` | `bool` | `true` | Gzip rotated files. |
| `compressionLevel` | `size_t` | `5` | 1 (fastest) – 9 (best). Only used when `shouldCompress`. |

### Validation Rules (applied in `validateAndNormalizeConfig`)

- `basePath` must be absolute, exist, and be writable (verified by test-writing a file and directory).
- `pattern` must not be empty, exceed 255 chars, or contain `../`.
- If `maxSize > 0` and no `${counter}` in pattern → counter is auto-inserted before the last `.`.
- At least one time placeholder is required when `maxSize == 0`.
- `bufferSize == 0` → promoted to `1 << 20`.
- `maxSize` in `(0, 1 MiB)` → clamped to `1 MiB`.
- `compressionLevel` must be in `[1, 9]` when `shouldCompress`.

### Channel Name Rules

- 1–255 characters.
- Only `[a-zA-Z0-9_-]` (alphanumeric, underscores, dashes).

---

## Pattern Placeholders

| Placeholder | Expansion | Example |
|-------------|-----------|---------|
| `${YYYY}` | 4-digit year | `2025` |
| `${YY}` | 2-digit year | `25` |
| `${MMM}` | 3-letter month | `Jul` |
| `${MM}` | 2-digit month | `07` |
| `${DD}` | 2-digit day | `01` |
| `${HH}` | 2-digit hour (24h) | `14` |
| `${name}` | Channel name | `alerts` |
| `${counter}` | Rotation counter | `3` |

**Example:** pattern `${YYYY}/${MMM}/wazuh-${name}-${DD}.json` for channel `alerts` on July 1, 2025 → `2025/Jul/wazuh-alerts-01.json`.

---

## Usage Examples

### Minimal: Register a channel and write

```cpp
#include <streamlog/logger.hpp>

// Create the LogManager (needs a store; scheduler is optional)
auto store = /* obtain store::IStore */ ;
auto scheduler = /* obtain scheduler::IScheduler */ ;
streamlog::LogManager logManager(store, scheduler);

// Register a channel
streamlog::RotationConfig cfg {
    "/var/wazuh-manager/logs/alerts",
    "wazuh-${name}-${YYYY}-${MM}-${DD}.json",
    10 * 1024 * 1024,   // 10 MiB max size
    1 << 20,            // buffer
    true,               // compress
    5                   // compression level
};
logManager.registerLog("alerts", cfg, "json");

// Obtain a writer (starts the worker thread)
auto writer = logManager.getWriter("alerts");

// Write from any thread
(*writer)(R"({"timestamp":"2025-07-01T12:00:00Z","level":"warning","msg":"disk 90%"})");

// Writer is reference-counted; when destroyed, worker thread may stop
writer.reset();
```

### Consumer-only (interface dependency)

```cpp
#include <streamlog/ilogger.hpp>

void processEvent(streamlog::ILogManager& logManager) {
    auto writer = logManager.getWriter("alerts");
    (*writer)(buildJsonString());
}
```

### Isolated base path (one subdirectory per channel)

```cpp
streamlog::RotationConfig cfg { /* ... */ };
streamlog::LogManager::isolatedBasePath("alerts", cfg);
// cfg.basePath is now "<original>/alerts/"
logManager.registerLog("alerts", cfg, "json");
```

### Update config at runtime

```cpp
// Only allowed when no writers are active
auto newCfg = logManager.getConfig("alerts");
newCfg.maxSize = 20 * 1024 * 1024;
logManager.updateConfig("alerts", newCfg, "json");
```

---

## Error Handling Strategy

| Scenario | Behaviour |
|----------|-----------|
| File cannot be opened | `ChannelState → ErrorClosed`; all subsequent writes return `false`. |
| Hard-link creation fails | File is closed; `runtime_error` thrown (during init) or channel closed (during rotation). |
| Queue full | `writer->operator()` returns `false`; message is dropped. |
| Store read / write failure | Warning logged; operation continues normally. |
| Scheduler unavailable | Warning logged; rotated file left uncompressed. |
| Directory creation fails during rotation | Warning logged; channel may enter `ErrorClosed`. |

**Philosophy:** Never crash the process. Log an emergency message and gracefully degrade.

---

## Build & Test

### CMake Targets

| Target | Type | Description |
|--------|------|-------------|
| `streamlogger::istreamlogger` | `INTERFACE` | Headers only (`ilogger.hpp`). |
| `streamlogger::streamlogger` | `STATIC` | Full implementation library. |
| `streamlogger::mocks` | `INTERFACE` | GMock mocks for testing consumers. |
| `streamlogger_utest` | `EXECUTABLE` | Unit tests (GTest). |
| `streamlogger_ctest` | `EXECUTABLE` | Component tests (GTest). |
| `streamlogger_benchmark` | `EXECUTABLE` | Performance benchmarks (Google Benchmark). |

### Running tests

```bash
# From the engine build directory
cmake --build . --target streamlogger_utest
ctest -R streamlogger_utest --output-on-failure

# Unit tests directly
./streamlogger_utest --gtest_filter='ChannelHandlerTest.*'
./streamlogger_utest --gtest_filter='LogManagerTest.*'
```

### Test overview

| Suite | File | ~Tests | Coverage |
|-------|------|--------|----------|
| `ChannelHandlerTest` | `unit/channel_test.cpp` | 40+ | Validation, writing, rotation (size & time), compression, concurrency, store persistence, error paths. |
| `LogManagerTest` | `unit/logger_test.cpp` | 20+ | Registration, update, destroy, writer lifecycle, concurrency, edge cases. |
| Component | `component/logger_test.cpp` | 1 (placeholder) | End-to-end (skipped). |

---

## Design Decisions & Rationale

### Why one thread per channel?

Serialising all I/O for a channel in a single thread **eliminates file-locking** and guarantees message ordering. The lock-free queue pushes the contention to a highly optimised atomic operation.

### Why `shared_ptr` + `weak_ptr` for writers?

- `ChannelWriter` must not prevent `ChannelHandler` destruction → `weak_ptr`.
- `ChannelHandler` must survive as long as **any** writer exists during normal operation → `shared_ptr` ownership in `LogManager::m_channels`.
- The active-writer counter (protected by mutex) decouples thread lifecycle from pointer lifetime.

### Why a factory (`create()`) instead of a public constructor?

`ChannelHandler` uses `enable_shared_from_this`, which requires the object to already be owned by a `shared_ptr` when `shared_from_this()` is called (in `createWriter()`). A private constructor + static factory enforces this.

### Why hard-links instead of symlinks?

Hard-links allow external tools (e.g. Filebeat) to continue reading the file even after the link is replaced. A symlink would require following the link each time, and some tools handle symlink changes poorly.

### Why flush after every message?

Durability: in case of a crash, the maximum data loss is one message. This is acceptable for structured security logs where completeness matters more than throughput. For higher throughput, the buffer queue absorbs write bursts.

---

## Dependency Graph

```
streamlogger::streamlogger
  ├── PUBLIC  base                     (logging, Name, json::Json, process utils)
  ├── PUBLIC  fastqueue::fastqueue     (StdQueue — lock-free queue)
  ├── PUBLIC  scheduler::ischeduler    (IScheduler for compression tasks)
  ├── PUBLIC  streamlogger::istreamlogger (WriterEvent, ILogManager)
  ├── PUBLIC  store::istore            (IStore for crash-recovery persistence)
  └── PRIVATE urlrequest               (transitive, via base)
```

---

## FAQ & Gotchas

**Q: Can I use `WriterEvent` from multiple threads simultaneously?**
A: Yes. The `operator()` only performs an atomic load + a queue push. Both are thread-safe.

**Q: What happens if the queue is full?**
A: `operator()` returns `false` and the message is dropped. Monitor the return value in latency-sensitive code.

**Q: Can I update a channel's config while writers are active?**
A: No. `updateConfig()` throws if `getActiveWritersCount() > 0`. Destroy all writers first.

**Q: Why does `maxSize < 1 MiB` get clamped?**
A: Extremely small files cause excessive rotation and disk I/O. The 1 MiB floor is a safety net.

**Q: How is `localtime` thread-safety handled?**
A: `replacePlaceholders()` is only called from the single worker thread per channel, so the non-reentrant `std::localtime` is safe. Do **not** call it from multiple threads.

**Q: The store errors don't stop the channel — is that intentional?**
A: Yes. Store persistence is best-effort. The worst consequence is that a file might not be compressed after a crash, but no data is lost.

**Q: Why are `ChannelWriter` copy and move disabled?**
A: To maintain an exact 1:1 mapping between writer objects and the reference count. Copies would skew the count.

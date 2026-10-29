# Streamlog Module — Developer Guide

> **Module path:** `src/engine/source/streamlog`
> **Namespace:** `streamlog`
> **Library alias (CMake):** `streamlogger::streamlogger` (implementation), `streamlogger::istreamlogger` (interface-only), `streamlogger::mocks` (test builds)

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Directory Layout](#directory-layout)
4. [Key Classes & Relationships](#key-classes--relationships)
5. [Data Flow & Threading Model](#data-flow--threading-model)
6. [Rotation Mechanics](#rotation-mechanics)
7. [Compression](#compression)
8. [Retention Policies](#retention-policies)
9. [Crash-Recovery (Store Persistence)](#crash-recovery-store-persistence)
10. [Configuration Reference](#configuration-reference)
11. [Pattern Placeholders](#pattern-placeholders)
12. [Usage Examples](#usage-examples)
13. [Error Handling Strategy](#error-handling-strategy)
14. [Build & Test](#build--test)
15. [Design Decisions & Rationale](#design-decisions--rationale)
16. [Dependency Graph](#dependency-graph)
17. [FAQ & Gotchas](#faq--gotchas)

---

## Overview

The **streamlog** module provides high-performance, named, rotating log channels with fully asynchronous writes. It is the engine's mechanism for writing line-oriented output (NDJSON) to disk. Its two consumers in the engine are the builder's `file` output stage (channel `<originSpace>-<file value>`, extension `json`) and the event dumper (channel `event-dumps`, extension `log`); `main.cpp` creates one `LogManager` (with the store and the scheduler) only when event processing is enabled.

With the defaults (`analysisd.streamlog_base_path` = `<home>/logs/`, pattern `${YYYY}/${MMM}/wazuh-${name}-${DD}`, see `conf.cpp`), a channel writes `/var/wazuh-manager/logs/<channel>/<YYYY>/<MMM>/wazuh-<channel>-<DD>.<ext>`, with the hard link `/var/wazuh-manager/logs/<channel>/<channel>.<ext>` on the active file. The operator-facing settings are documented in the engine [configuration reference](../../../../docs/ref/modules/engine/configuration.md#stream-log).

### Key capabilities

| Feature | Details |
|---------|---------|
| **Named Channels** | Each channel is identified by a unique name and has its own rotation policy. |
| **Asynchronous I/O** | A dedicated worker thread per channel drains a bounded queue (`fastqueue::StdQueue`, mutex-based) and writes to disk. |
| **Dual Rotation** | Size-based (counter suffix) and time-based (date placeholders in file name). |
| **Hard-Link "Latest"** | `<basePath>/<name>.<ext>` always points to the active file — external tools tail this stable path. |
| **Gzip Compression** | Rotated files are compressed asynchronously via the `scheduler::IScheduler`. |
| **Retention Policies** | Configurable limits on rotated file count (`maxFiles`) and total rotated size (`maxAccumulatedSize`). Oldest files are deleted first. |
| **Crash Recovery** | The current file path and counter are persisted to the `store::IStore`; on restart, the file is resumed or a pending compression is scheduled. |
| **Zero-Copy Enqueue** | Writers `std::move` messages into the queue — no copies on the hot path. |
| **Lazy channels** | `ensureAndGetWriter()` creates a channel on first use under `<basePath>/<name>/` (it calls `isolatedBasePath()` itself); for an existing channel the `cfg` argument is ignored. |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           Application Threads                          │
│                                                                        │
│   auto w = logManager->ensureAndGetWriter("example-channel", cfg, "json"); │
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
│  │ m_channelHandler (wp)│      │  push (bounded, mutex-based)          │
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
│     3. if rotation → rotateFile() → schedule compression + retention   │
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
│                         →  deleteOldFilesStatic()  (retention cleanup)  │
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
│   └── ilogger.hpp                       # Public interface: RotationConfig, WriterEvent, ILogManager
│
├── include/streamlog/
│   └── logger.hpp                        # Public header: LogManager
│
├── src/
│   ├── channel.hpp                       # Internal: ChannelWriter, ChannelHandler, ChannelState
│   ├── channel.cpp                       # Internal: all I/O, rotation, compression logic
│   └── logger.cpp                        # LogManager implementation (delegates to ChannelHandler)
│
├── benchmark/
│   ├── src/async_vs_sync_bench.cpp       # Google Benchmark: async channel vs synchronous writes
│   └── analyze_results.py                # Helper to analyse benchmark output
│
└── test/
    ├── mocks/streamlog/
    │   └── mockStreamlog.hpp             # GMock: MockILogManager, MockWriterEvent
    └── src/
        ├── unit/
        │   ├── channel_test.cpp          # ChannelHandlerTest
        │   └── logger_test.cpp           # LogManagerTest
        └── component/
            ├── channel_test.cpp          # ChannelHandlerComponentTest (real filesystem)
            └── logger_test.cpp           # LogManagerComponentTest (real filesystem)
```

### Header dependency rules

| Header | Audience | Depends on |
|--------|----------|------------|
| `interface/streamlog/ilogger.hpp` | **Any consumer**: `RotationConfig`, `WriterEvent`, `ILogManager` | `<filesystem>`, `<memory>`, `<string>`, `<string_view>` |
| `include/streamlog/logger.hpp` | **Owner / configurator**: `LogManager` | `ilogger.hpp`, `store::IStore`, `scheduler::IScheduler` |
| `src/channel.hpp` | **Library-internal only** | `logger.hpp`, `base/logging`, `fastqueue`, `store`, `scheduler` |

---

## Key Classes & Relationships

### Class Diagram (simplified)

```
«interface» ILogManager                     RotationConfig (ilogger.hpp)
  +ensureAndGetWriter(name, cfg, ext)         basePath, pattern, maxSize, bufferSize,
        ▲ implements                          shouldCompress, compressionLevel,
        │                                     maxFiles, maxAccumulatedSize
LogManager                                            │ copied into
  m_channels : map<name, shared_ptr<ChannelHandler>> ─┼──► ChannelHandler (src/channel.hpp)
  m_channelsMutex (shared_mutex)                      │      m_config (const), m_channelName
  m_scheduler (weak_ptr), m_store                     │      m_stateData, m_activeWriters
  m_compressionShouldRun                              │      m_store, m_scheduler (weak_ptr)
  +hasChannel() +getActiveWritersCount()              │      m_inFlightFiles, m_retentionMutex
  +destroyChannel() +requestShutdown()                │      +create() [factory]  +createWriter()
  +isolatedBasePath() [static]                        │      -workerThreadFunc() -needsRotation()
                                                      │      -rotateFile() -writeMessage()
«interface» WriterEvent                               │      -compressLogFile() -deleteOldFiles()
  +operator()(std::string&&) → bool                   │              │ createWriter()
        ▲ implements                                  │              ▼
        └──────────────────────────────────────── ChannelWriter (src/channel.hpp)
                                                    m_queue (shared_ptr), m_channelState (shared_ptr)
                                                    m_channelHandler (weak_ptr)
```

### Class Summary

| Class | Visibility | Responsibility |
|-------|-----------|----------------|
| `WriterEvent` | **Public interface** | Abstract write handle. `operator()(string&&) → bool`. |
| `ILogManager` | **Public interface** | Abstract channel registry. `ensureAndGetWriter(name, cfg, ext)`. |
| `RotationConfig` | **Public interface** | Aggregate describing a channel's rotation/compression policy. |
| `LogManager` | **Public** | Concrete registry. Owns `ChannelHandler` instances. Thread-safe via `shared_mutex`. Also `hasChannel()`, `getActiveWritersCount()`, `destroyChannel()` (throws if the channel is missing or has writers), `isolatedBasePath()`, `requestShutdown()` (cancels in-flight compressions and drops every channel). |
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
| **Scheduler worker** (shared) | Runs `compressLogFile()` tasks, then retention cleanup, asynchronously. |

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
                          if count == 0: stopWorkerThread()  (join, then discard queued messages)
```

This "lazy start / eager stop" model ensures no background threads exist when a channel has no consumers. Messages still queued when the last writer goes away are discarded (`Discarded N pending messages for channel: …` warning). `createWriter()` throws if the channel is `ErrorClosed`.

---

## Rotation Mechanics

### Size-Based Rotation

Triggered when `currentSize + messageSize >= maxSize`.

1. Increment `counter`.
2. Generate new path from pattern (e.g. `2026/Mar/wazuh-example-channel-26-3.json` with the default pattern, to which `-${counter}` is appended).
3. Create the parent directories if they changed and do not exist.
4. Close current file, open new file (`updateOutputFileAndLink()`).
5. Update hard-link to point to the new file.
6. Persist the rotation state to the store.
7. Schedule compression of the previous file (if `shouldCompress`); otherwise run retention cleanup here.

If the new path equals the current one, nothing rotates; if opening the new file or the link fails, the previous state is restored and the channel becomes `ErrorClosed`.

### Time-Based Rotation

Triggered when the **hour boundary** changes and the resolved pattern produces a **different path**.

1. Reset `counter` to 0.
2. Generate new path from pattern (e.g. `2026/Mar/wazuh-example-channel-26.json` → `2026/Mar/wazuh-example-channel-27.json`).
3. Same steps 3–7 as size-based rotation.

### Rotation check frequency

`needsRotation()` is called **once per message** (inside the single worker thread), so there is zero contention. The hour comparison uses `duration_cast<hours>` for a fast integer comparison; only when the hour changed is the pattern re-resolved and compared with the current path. Rotation is therefore evaluated only when a message arrives: an idle channel keeps its file until the next write.

---

## Compression

When `shouldCompress` is `true` and the `scheduler` weak pointer is valid:

1. After `rotateFile()`, a one-shot task is scheduled:
   ```cpp
   scheduler::TaskConfig {
       .interval = 0,           // one-time
       .runImmediately = false,
       .CPUPriority = 0,
       .taskFunction = [filePath, /* level, retention settings, registries, shouldRun */]()
       { compressLogFile(filePath, compressionLevel, shouldRun); /* + steps 3-4 */ }
   };
   ```
   The task is named `CompressLog-<channel>-<file name>`, and both the source and the `.gz` path are registered as in-flight first.
2. `compressLogFile()` calls `Utils::ZlibHelper::gzipCompress()` and removes the original. `LogManager::requestShutdown()` clears the shared `shouldRun` flag, which aborts compressions still running.
3. In-flight paths (source and `.gz`) are unregistered so future retention runs can consider them.
4. If retention is configured (`maxFiles > 0` or `maxAccumulatedSize > 0`), `deleteOldFilesStatic()` runs **after** compression. In the happy path this means cleanup sees files in their final compressed size.
5. If the scheduler is unavailable (expired `weak_ptr`), a warning is logged and the file is left uncompressed.

> **Compression failure:** Steps 3-4 execute unconditionally. If `gzipCompress()` throws, the original file remains on disk and a partial `.gz` artefact may also be present. Retention cleanup proceeds in best-effort mode against whatever state is on disk — it may observe uncompressed sizes for that file, but the system self-heals on the next successful rotation cycle.

---

## Retention Policies

Retention limits how many files accumulate in the channel directory (`basePath`). Two independent policies can be combined:

| Policy | Field | Default | Behaviour |
|--------|-------|---------|-----------|
| **File count** | `maxFiles` | `90` | Keep at most N files in the channel directory. The active file is always excluded from the count. |
| **Accumulated size** | `maxAccumulatedSize` | `20 GiB` | Delete oldest non-active files until their combined on-disk size fits within the limit. The active file is excluded from this accounting. |

Both policies are applied **in sequence** (accumulated-size first, then file-count), so they act as an AND — both constraints are satisfied simultaneously.

### Cleanup algorithm (`deleteOldFiles` / `deleteOldFilesStatic`)

1. Scan `basePath` **recursively** for all regular files.
2. Exclude the current active file (identified by the inode of the `latestLink` hard link) and any file registered as in-flight (being compressed).
3. Sort by `mtime` ascending (oldest first).
4. **Strategy 1 — size:** delete oldest non-active files until their combined size ≤ `maxAccumulatedSize`.
5. **Strategy 2 — count:** delete oldest remaining non-active files until count ≤ `maxFiles`.
6. **Empty directory pruning:** after any files are deleted, scan `basePath` recursively for empty subdirectories, sorted deepest-first, and remove each one. This keeps the directory tree clean when retention removes all files from a date-based subdirectory (e.g. `2026/Jan/`).

> **Active file is never a deletion candidate.** The file currently being written is excluded from both policies. If it has grown beyond `maxAccumulatedSize` on its own, it will not be deleted — it becomes subject to retention only after the next rotation closes it.

> **Pattern-agnostic:** The scan uses `mtime` ordering, not filename parsing. This means retention works correctly even if the `pattern` was changed after files were already rotated under a previous naming scheme.

### When does cleanup run?

| Compression | Cleanup trigger |
|-------------|----------------|
| **Disabled** | Immediately inside `rotateFile()`, after the new file is opened. |
| **Enabled** | After each compression task completes (in the scheduler thread), via the captured `deleteOldFilesStatic()` call in the compression task callback. |

Deferring cleanup to post-compression avoids a race where the still-uncompressed (larger) rotated file would cause over-aggressive size-based deletion. If compression fails, retention still runs in best-effort mode against the actual on-disk state (see [Compression](#compression)).

### Configuration

Set via `wazuh-manager-internal-options.conf` or environment variables:

| Key | Env var | Default |
|-----|---------|---------|
| `analysisd.streamlog_max_files` | `WAZUH_STREAMLOG_MAX_FILES` | `90` |
| `analysisd.streamlog_max_accumulated_size` | `WAZUH_STREAMLOG_MAX_ACCUMULATED_SIZE` | `21474836480` (20 GiB) |

Set either to `0` to disable that specific policy.

---

## Crash-Recovery (Store Persistence)

When a channel is created and after every successful rotation (whether or not compression is enabled), the current file path and counter are saved to the `store::IStore` under:

```
streamlog/<channelName>/0  →  { "last_current": "/path/to/current/file.json", "last_counter": 28 }
```

### Startup sequence (`maxSize > 0`)

1. Read `last_current` and `last_counter` from the store.
2. If both are present: reconstruct the candidate path using the stored counter via `replacePlaceholders(now)`.
   - If the reconstructed path equals `last_current` **and** the file exists on disk → **resume writing** to that file (fast path, no disk scan).
   - Otherwise (time period changed, file deleted by retention, etc.) → fall through to step 3.
3. If no stored state or resume not possible: start at `counter = 0` and advance it past any existing files (from a prior run in the same time window, including their `.gz` when compression is on) by iterating `exists()` until a free slot is found.
4. Save both `last_current` and `last_counter` to the store.

`last_counter` is stored alongside `last_current` to make resume a single-shot O(1) path lookup. Without it, resume would require either parsing the counter from the filename (fragile and pattern-dependent) or scanning from 0 (O(N) `stat` calls).

### Compression catch-up on restart

If compression is enabled and `last_current` refers to a file that differs from the newly computed current path and still exists on disk, a compression task is scheduled for it — ensuring that a file rotated before a crash is still compressed after restart.

With compression disabled the stored state is kept and updated like any other (`clearCurrentRotationStateFromStore()` exists but nothing calls it).

---

## Configuration Reference

### `RotationConfig` Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `basePath` | `std::filesystem::path` | *(required)* | Absolute, existing, writable directory. |
| `pattern` | `std::string` | *(required)* | File name pattern with placeholders. May contain subdirectories. |
| `maxSize` | `size_t` | *(no initializer; `0` when omitted in aggregate init)* | Max file size in bytes before size rotation. `0` = disabled. Clamped to ≥ 1 MiB. |
| `bufferSize` | `size_t` | `1 << 20` | Queue capacity (number of messages, not bytes). `0` is promoted to default. |
| `shouldCompress` | `bool` | `true` | Gzip files on rotation. |
| `compressionLevel` | `size_t` | `5` | 1 (fastest) – 9 (best). Only used when `shouldCompress`. |
| `maxFiles` | `size_t` | `90` | Max files to keep in the channel directory. `0` = unlimited. Active file excluded. |
| `maxAccumulatedSize` | `size_t` | `20 GiB` | Max combined on-disk bytes of non-active files in the channel directory. `0` = unlimited. Active file excluded from accounting. Oldest deleted first. |

### Validation Rules (applied in `validateAndNormalizeConfig`)

- `basePath` must be absolute, exist, and be writable (verified by test-writing a file and directory).
- `pattern` must not be empty, exceed 255 chars, or contain `../`.
- If `maxSize > 0` and no `${counter}` in pattern → `-${counter}` is appended to the pattern as a suffix.
- At least one time placeholder (`${YYYY}`, `${YY}`, `${MM}`, `${DD}`, `${HH}`; `${MMM}` does not count) is required when `maxSize == 0`.
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
| `${name}` | Channel name | `example-channel` |
| `${counter}` | Rotation counter (replaced only when `maxSize > 0`) | `3` |

Dates use local time (`std::localtime`).

**Example:** the default pattern `${YYYY}/${MMM}/wazuh-${name}-${DD}` with `ext = "json"` for channel `example-channel` on March 26, 2026 → `2026/Mar/wazuh-example-channel-26.json`. The file extension is **not** part of the pattern — it is appended automatically from the `ext` parameter passed to `ensureAndGetWriter()` (and on to `ChannelHandler::create()`).

### Example Filesystem Layout

With `basePath = "/var/wazuh-manager/logs"`, `name = "example-channel"`, `ext = "json"` and `pattern = "${YYYY}/${MMM}/wazuh-${name}-${DD}"` (the isolated `<basePath>/<name>/` directory is added by `ensureAndGetWriter()`), the resulting layout is:

```text
/var/wazuh-manager/logs/example-channel/
├── example-channel.json
└── 2026/
  └── Mar/
    └── wazuh-example-channel-26.json
```

The `example-channel.json` hard link and all rotated files share the same extension (`ext`); it is never encoded in the pattern itself.

---

## Usage Examples

### Minimal: Register a channel and write

```cpp
#include <streamlog/logger.hpp>

// Create the LogManager (needs a store; scheduler is optional)
auto store = /* obtain store::IStore */ ;
auto scheduler = /* obtain scheduler::IScheduler */ ;
streamlog::LogManager logManager(store, scheduler);

// Channel configuration (basePath is the parent directory; the channel gets <basePath>/<name>/)
streamlog::RotationConfig cfg {
    .basePath = "/var/wazuh-manager/logs",
    .pattern = "${YYYY}/${MMM}/wazuh-${name}-${DD}", // extension ("json") is passed separately
    .maxSize = 10 * 1024 * 1024,                     // 10 MiB max size
    .bufferSize = 1 << 20,                           // queue capacity (messages)
    .shouldCompress = true,
    .compressionLevel = 5,
    .maxFiles = 30,                                  // keep at most 30 files in the channel directory
    .maxAccumulatedSize = 20ULL * 1024 * 1024 * 1024 // max 20 GiB accumulated size in the channel directory
};

// Obtain a writer (creates the channel on first use and starts the worker thread)
auto writer = logManager.ensureAndGetWriter("example-channel", cfg, "json");

// Write from any thread
(*writer)(R"({"timestamp":"2025-07-01T12:00:00Z","level":"warning","msg":"disk 90%"})");

// Writer is reference-counted; when destroyed, worker thread may stop
writer.reset();
```

### Consumer-only (interface dependency)

```cpp
#include <streamlog/ilogger.hpp>

void processEvent(streamlog::ILogManager& logManager) {
    streamlog::RotationConfig cfg {
        .basePath = "/var/wazuh-manager/logs",
        .pattern = "${YYYY}/${MMM}/wazuh-${name}-${DD}", // time rotation only (maxSize = 0)
        .maxSize = 0,
        .maxFiles = 30,
        .maxAccumulatedSize = 2ULL * 1024 * 1024 * 1024};
    auto writer = logManager.ensureAndGetWriter("example-channel", cfg, "json");
    (*writer)(buildJsonString());
}
```

### Isolated base path (one subdirectory per channel)

`ensureAndGetWriter()` applies `LogManager::isolatedBasePath()` to its copy of `cfg` before creating a channel, so callers pass the parent directory. Calling it yourself first would nest the channel twice (`<base>/<name>/<name>/`). The static helper validates the name and the config, creates `<basePath>/<name>/` and rewrites `cfg.basePath`:

```cpp
streamlog::RotationConfig cfg { /* ... */ };
streamlog::LogManager::isolatedBasePath("example-channel", cfg);
// cfg.basePath is now "<original>/example-channel"
```

---

## Error Handling Strategy

| Scenario | Behaviour |
|----------|-----------|
| File cannot be opened | At creation: `std::runtime_error` (`Failed to initialize channel …`). On rotation: `ChannelState → ErrorClosed`; all subsequent writes return `false`. |
| Write to the file fails | `ChannelState → ErrorClosed`. |
| Hard-link creation fails | File is closed; `runtime_error` thrown (during init) or channel closed (during rotation). |
| Queue full | `writer->operator()` returns `false`; message is dropped. |
| Store read / write failure | Warning logged; operation continues normally. |
| Scheduler unavailable | Warning logged; rotated file left uncompressed. |
| Compression fails (`gzipCompress` throws) | Warning logged; original file left on disk, partial `.gz` may remain. In-flight entries are unregistered and retention cleanup runs in best-effort mode on whatever state is on disk. |
| `scheduleTask()` throws | Warning logged; in-flight entries are unregistered immediately so retention is not permanently blocked. File is left uncompressed. |
| Retention cleanup fails to delete a file | File remains on disk and stays in the accounting (not marked as freed). |
| Empty subdirectory removal fails | Directory remains on disk; a debug message is logged. Non-fatal. |
| Directory creation fails during rotation | Warning logged; channel may enter `ErrorClosed`. |

**Philosophy:** Never crash the process from the worker or scheduler threads: log an error or warning and degrade gracefully. Configuration and channel-name errors are thrown to the caller of `ensureAndGetWriter()`.

---

## Build & Test

### CMake Targets

| Target | Type | Description |
|--------|------|-------------|
| `streamlogger::istreamlogger` | `INTERFACE` | Headers only (`ilogger.hpp`). |
| `streamlogger::streamlogger` | `STATIC` | Full implementation library. |
| `streamlogger::mocks` | `INTERFACE` | GMock mocks for testing consumers (`ENGINE_BUILD_TEST`). |
| `streamlogger_utest` | `EXECUTABLE` | Unit tests (GTest, `ENGINE_BUILD_TEST`). |
| `streamlogger_ctest` | `EXECUTABLE` | Component tests (GTest, `ENGINE_BUILD_TEST`). |
| `streamlogger_benchmark` | `EXECUTABLE` | Performance benchmarks (Google Benchmark, `ENGINE_BUILD_BENCHMARK`). |

### Running tests

Both test executables are registered with `gtest_discover_tests`, so `ctest` sees the GTest names (`ChannelHandlerTest.*`, `LogManagerTest.*`, `ChannelHandlerComponentTest.*`, `LogManagerComponentTest.*`), not the executable names; filter with `ctest -R '^ChannelHandlerTest\.'` or run the binary with `--gtest_filter`. Lane reproduction is in the `wazuh-testing` skill.

### Test overview

| Suite | File | ~Tests | Coverage |
|-------|------|--------|----------|
| `ChannelHandlerTest` | `unit/channel_test.cpp` | 35 | Validation, writing, rotation (size & time), compression, store persistence, error paths. |
| `LogManagerTest` | `unit/logger_test.cpp` | 17 | Channel creation, destroy, writer lifecycle, edge cases. |
| `ChannelHandlerComponentTest` | `component/channel_test.cpp` | 76 | Real-filesystem rotation, compression, retention, crash recovery, concurrency. |
| `LogManagerComponentTest` | `component/logger_test.cpp` | 22 | Real-filesystem channel management and concurrent writers. |

---

## Design Decisions & Rationale

### Why one thread per channel?

Serialising all I/O for a channel in a single thread **eliminates file-locking** and guarantees message ordering. The queue (`fastqueue::StdQueue`) keeps the producers' cost to a push.

### Why `shared_ptr` + `weak_ptr` for writers?

- `ChannelWriter` must not prevent `ChannelHandler` destruction → `weak_ptr`.
- `ChannelHandler` is owned by `LogManager::m_channels`; `destroyChannel()` refuses to drop a channel with active writers, while `requestShutdown()` drops all of them (a writer outliving it holds only a `weak_ptr`).
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
  ├── PUBLIC  fastqueue::fastqueue     (StdQueue)
  ├── PUBLIC  scheduler::ischeduler    (IScheduler for compression tasks)
  ├── PUBLIC  streamlogger::istreamlogger (RotationConfig, WriterEvent, ILogManager)
  ├── PUBLIC  store::istore            (IStore for crash-recovery persistence)
  ├── PUBLIC  ZLIB::ZLIB
  └── PUBLIC  Minizip::Minizip

streamlogger::istreamlogger  →  base, scheduler::ischeduler, store::istore
```

---

## FAQ & Gotchas

**Q: Can I use `WriterEvent` from multiple threads simultaneously?**
A: Yes. The `operator()` only performs an atomic load + a queue push. Both are thread-safe.

**Q: What happens if the queue is full?**
A: `operator()` returns `false` and the message is dropped. Monitor the return value in latency-sensitive code.

**Q: Why does `maxSize < 1 MiB` get clamped?**
A: Extremely small files cause excessive rotation and disk I/O. The 1 MiB floor is a safety net.

**Q: How is `localtime` thread-safety handled?**
A: `replacePlaceholders()` is only called from the single worker thread per channel, so the non-reentrant `std::localtime` is safe. Do **not** call it from multiple threads.

**Q: The store errors don't stop the channel — is that intentional?**
A: Yes. Store persistence is best-effort. The worst consequence is that a file might not be compressed after a crash, but no data is lost.

**Q: Why are `ChannelWriter` copy and move disabled?**
A: To maintain an exact 1:1 mapping between writer objects and the reference count. Copies would skew the count.

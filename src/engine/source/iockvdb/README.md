# IOC KVDB — Indicator of Compromise Key-Value Database

## Overview

`iockvdb` is a RocksDB-backed key-value database manager designed for high-throughput, real-time Indicator of Compromise (IOC) lookups. It provides **lock-free reads** via an RCU-like publish/subscribe pattern and supports **atomic hot-swap** of entire database instances, allowing readers to transparently switch to updated data without interruption.

The module is purpose-built for the IOC enrichment pipeline: each IOC type (connection, URL, hash, etc.) maps to a dedicated database, and runtime synchronization replaces databases atomically via `hotSwap()`.

## Architecture

```
                    ┌───────────────────────────────────────────┐
                    │              KVDBManager                  │
                    │  ┌─────────────────────────────────────┐  │
                    │  │  Registry  (shared_mutex)           │  │
                    │  │  map<name, shared_ptr<DbHandle>>    │  │
                    │  └──────────┬──────────────────────────┘  │
                    │             │                              │
                    │    ┌────────┼─────────┐                   │
                    │    ▼        ▼         ▼                   │
                    │ DbHandle  DbHandle  DbHandle              │
                    │ (atomic)  (atomic)  (atomic)              │
                    │    │        │         │                   │
                    │    ▼        ▼         ▼                   │
                    │ DbInstance DbInstance DbInstance           │
                    │ (RocksDB)  (RocksDB)  (RocksDB)          │
                    │                                           │
                    │  ┌─────────────────────────────────────┐  │
                    │  │  Retired Queue (mutex)              │  │
                    │  │  deque<RetiredInstance>              │  │
                    │  │  → old instances pending cleanup    │  │
                    │  └─────────────────────────────────────┘  │
                    └───────────────────────────────────────────┘

    Reader threads ─────► DbHandle::load() ───► atomic shared_ptr ───► DbInstance::get()
                          (lock-free)              (acquire)             (RocksDB read)

    Hot-swap ────► structuralMutex lock ──► DbHandle::exchange() ──► old → retired queue
                                              (atomic swap)
```

### Concurrency Model

| Operation | Lock Acquired | Contention |
|-----------|---------------|------------|
| `KVDBManager::get()` / `multiGet()` | Registry shared_lock (handle lookup only), then atomic load | Readers-only |
| `DbHandle::get()` / `multiGet()` (`IReadOnlyKVDBHandler`) | None (atomic load) | Lock-free |
| `exists()` | Registry shared_lock | Readers-only |
| `add()` | Registry shared_lock check, unique_lock insert, then structural mutex | Serialized per-DB |
| `put()` | Registry shared_lock + structural mutex | Serialized per-DB |
| `hotSwap()` | Registry shared_lock + both structural mutexes; unique_lock to drop the source | Serialized per-DB pair |
| `remove()` | Registry unique_lock + structural mutex | Serialized per-DB |

## Key Concepts

### RCU-Like Hot Swap

The core design enables zero-downtime database replacement:

1. A new `DbInstance` is built and populated (e.g., from downloaded IOC data)
2. `DbHandle::exchange()` atomically publishes the new instance
3. Readers holding the old `shared_ptr<DbInstance>` continue reading safely
4. The old instance is enqueued in the **retired queue**
5. Opportunistic cleanup (at the end of `add()`, `hotSwap()` and `remove()`) destroys retired instances whose `use_count == 1`

### IOC Type Routing

The `helpers.hpp` header provides a single source of truth mapping IOC types to database names:

| IOC Type | Database Name |
|----------|---------------|
| `connection` | `ioc_connections` |
| `url_full` | `ioc_urls_full` |
| `url_domain` | `ioc_urls_domain` |
| `hash_md5` | `ioc_hashes_md5` |
| `hash_sha1` | `ioc_hashes_sha1` |
| `hash_sha256` | `ioc_hashes_sha256` |

Helper functions extract `/name` (used as the KVDB key) and `/type` (used for routing) from IOC JSON documents.

### Persistence

`KVDBManager` persists its state (database names, instance paths relative to the root directory, and a `created` timestamp that every save refreshes) to the engine's internal `store::IStore` under the document `kvdb-ioc/status/0`. On construction, if that document exists, it reopens every RocksDB instance still on disk; an instance that fails to open is logged as a warning and its database is registered without an instance.

The root directory is the `analysisd.kvdb_ioc_path` setting (default `/var/wazuh-manager/data/kvdb-ioc`, `WAZUH_KVDB_IOC_PATH`), passed by `main.cpp`; see the engine [configuration](../../../../docs/ref/modules/engine/configuration.md) page.

### Retired Instance Queue

When a `hotSwap()` or `remove()` replaces an active instance, the old one is:

1. Marked for deletion (`markForDeletion()`)
2. Enqueued in the retired queue
3. Cleaned up opportunistically at the end of `add()`, `hotSwap()` and `remove()`, once no reader holds it
4. On destroy: flushes the memtable, cancels background work, flushes again, closes, deletes the instance directory, and removes the parent directory if it is now empty

## Directory Structure

```
iockvdb/
├── CMakeLists.txt
├── interface/iockvdb/               # Public interfaces (consumed by dependents)
│   ├── iManager.hpp                 # IKVDBManager — full manager interface
│   ├── iReadOnlyHandler.hpp         # IReadOnlyKVDBHandler — read-only handle
│   ├── types.hpp                    # DbState, ErrorCode enums
│   └── helpers.hpp                  # IOC type routing, DB/key extraction, updateValueInDB
├── include/iockvdb/                 # Implementation headers
│   ├── manager.hpp                  # KVDBManager — concrete manager
│   ├── dbHandle.hpp                 # DbHandle — RCU-like stable indirection point
│   └── dbInstance.hpp               # DbInstance — RocksDB wrapper with lifecycle
├── src/
│   ├── manager.cpp                  # Manager lifecycle, persistence, retired queue
│   ├── dbHandle.cpp                 # Lock-free get/multiGet/put delegation
│   └── dbInstance.cpp               # RocksDB get/multiGet/put, JSON parsing
└── test/
    ├── mocks/iockvdb/
    │   ├── mockManager.hpp          # GMock of IKVDBManager
    │   └── mockReadOnlyHandler.hpp  # GMock of IReadOnlyKVDBHandler
    └── src/
        ├── unit/
        │   ├── kvdb_handler_test.cpp
        │   └── kvdb_manager_test.cpp
        └── component/
            └── kvdb_test.cpp
```

## Public Interface

### `IKVDBManager` (iManager.hpp)

Full lifecycle manager for IOC databases.

```cpp
namespace ioc::kvdb {
class IKVDBManager {
    virtual void add(std::string_view dbName) = 0;
    virtual bool exists(std::string_view dbName) const noexcept = 0;
    virtual void put(std::string_view dbName, std::string_view key, std::string_view value) = 0;
    virtual void hotSwap(std::string_view sourceDb, std::string_view targetDb) = 0;
    virtual std::optional<json::Json> get(std::string_view dbName, std::string_view key) const = 0;
    virtual std::vector<std::optional<json::Json>> multiGet(
        std::string_view dbName, const std::vector<std::string_view>& keys) const = 0;
    virtual void remove(std::string_view dbName) = 0;
};
}
```

### `IReadOnlyKVDBHandler` (iReadOnlyHandler.hpp)

A handle bound to a specific database that transparently follows hot-swap updates.

```cpp
namespace ioc::kvdb {
class IReadOnlyKVDBHandler {
    virtual const std::string& name() const noexcept = 0;
    virtual std::optional<json::Json> get(std::string_view key) const = 0;
    virtual std::vector<std::optional<json::Json>> multiGet(
        const std::vector<std::string_view>& keys) const = 0;
    virtual bool hasInstance() const noexcept = 0;
};
}
```

### Helper Functions (helpers.hpp)

Namespace `ioc::kvdb::details`:

| Function | Description |
|----------|-------------|
| `getKeyFromIOC(json)` | Extracts `/name` field as KVDB key (throws if missing or empty) |
| `getTypeFromIOC(json)` | Extracts `/type` field for routing (throws if missing or empty) |
| `getDbAndKeyFromIOC(json)` | Returns `(dbName, key)` pair from an IOC document (throws on an unknown type) |
| `getDbNameFromType(typeStr)` | Maps a type string to its database name (throws on an unknown type) |
| `initializeDBs(manager, suffix = "")` | Creates all 6 IOC databases (name + `suffix`) if they don't exist |
| `updateValueInDB(manager, db, key, value)` | Upserts a value, appending to arrays if key exists |
| `getSupportedIocTypes()` | Returns all supported IOC type strings |
| `findIOCTypeInfo(key)` | Looks up `IOCTypeInfo` for a type string |
| `parseIOCType(key)` | Maps a type string to `IOCType` (`UNKNOWN` if unsupported) |

### Types (types.hpp)

- **`DbState`**: `READY`, `DELETING`
- **`ErrorCode`**: `OK`, `DB_NOT_FOUND`, `NO_INSTANCE`, `ALREADY_EXISTS`, `BUILD_IN_PROGRESS`, `NO_BUILD`, `STATE_BUSY`, `IN_USE`, `ROCKSDB_ERROR`, `JSON_PARSE_ERROR`, `FILESYSTEM_ERROR`

## Implementation Details

### `KVDBManager` (manager.hpp / manager.cpp)

- **Constructor**: Takes `filesystem::path rootDir` + `shared_ptr<store::IStore>`. Creates root directory, loads persisted state from store if available.
- **Registry**: `unordered_map<string, shared_ptr<DbHandle>>` protected by `shared_mutex`. Read operations use shared locks; structural operations use unique locks.
- **`add()`**: Creates a new `DbHandle` and `DbInstance` with a fresh RocksDB at a timestamped path. RAII rollback guard removes the handle if creation fails.
- **`hotSwap(source, target)`**: Rejects a swap onto itself or from a source without an instance. Locks both structural mutexes atomically (deadlock-free via `std::lock`). Transfers the instance pointer from source to target (zero-copy: the target now serves from the source's directory), enqueues the old target instance for retirement, removes source from registry.
- **Path generation**: `makeNextInstancePath()` creates `rootDir/dbName/<8 random hex chars>` (`base::utils::generators::randomHexString(8)`; a timestamp-derived suffix collided under rapid `add()`/`hotSwap()` cycles).
- **RocksDB tuning**: `applyIocStoreTuning()` sets `write_buffer_size` to 8 MiB and `manifest_preallocation_size` to 64 KiB for every instance, so each store does not preallocate a ~70 MB WAL and a 4 MiB manifest.
- **Persistence**: `saveStateToStore()` / `loadStateFromStore()` serialize the registry to a JSON array in the store.

### `DbHandle` (dbHandle.hpp / dbHandle.cpp)

- Implements `IReadOnlyKVDBHandler` for transparent read access.
- **Atomic instance pointer**: `shared_ptr<DbInstance> m_current` accessed via `atomic_load_explicit` / `atomic_exchange_explicit` with acquire/release semantics.
- **State machine**: Atomic `DbState` with `tryEnterDeleting()` using `compare_exchange_strong`.
- **Structural mutex**: Per-handle `std::mutex` serializes `add`/`swap`/`delete` without blocking readers.

### `DbInstance` (dbInstance.hpp / dbInstance.cpp)

- Wraps a raw `rocksdb::DB*` pointer with a custom deleter (`DbDeleter`).
- **`get(key)`**: Reads from RocksDB, parses result as JSON. Returns `std::nullopt` if not found.
- **`multiGet(keys)`**: Batch-reads via `rocksdb::DB::MultiGet()`, returns vector of optional JSON values.
- **`put(key, value)`**: Writes directly to RocksDB.
- **Destruction**: `~DbInstance` flushes the memtable; the custom `DbDeleter` then cancels background work, flushes again and closes. If `markForDeletion()` was called, the directory (and its parent, if empty) is removed from disk.

## CMake Targets

| Target | Type | Alias | Description |
|--------|------|-------|-------------|
| `iockvdb_ikvdb` | INTERFACE | `iockvdb::ikvdb` | Public interfaces + helpers |
| `iockvdb_kvdb` | STATIC | `iockvdb::kvdb` | Implementation (links RocksDB, store::istore) |
| `iockvdb_mocks` | INTERFACE | `iockvdb::mocks` | GMock mocks for testing |
| `iockvdb_utest` | Executable | — | Unit tests |
| `iockvdb_ctest` | Executable | — | Component tests |

## Testing

- **Unit tests** (`kvdb_handler_test.cpp`, `kvdb_manager_test.cpp`): Test `DbHandle` and `KVDBManager` logic with mocks.
- **Component tests** (`kvdb_test.cpp`): Integration tests with real RocksDB instances and mocked store.

## Consumers

| Consumer | Dependency | Usage |
|----------|------------|-------|
| **builder** | `iockvdb::ikvdb` | IOC enrichment builders use `IKVDBManager` + helpers to look up IOCs during event processing |
| **iocsync** | `iockvdb::ikvdb` | Synchronization module that downloads IOCs from the indexer, populates temp DBs, and hot-swaps into live databases |
| **api/ioccrud** | `iockvdb::ikvdb` | API handlers for IOC CRUD operations via `IKVDBManager` |
| **main.cpp** | `iockvdb::kvdb` | Instantiates `KVDBManager`, calls `initializeDBs()`, passes manager to dependents |

# KVDB Store Module

## Overview

The **kvdbstore** module provides an in-memory, read-only key-value database (KVDB) layer for the Wazuh Engine. It materializes KVDB resources from the Content Manager store (`cmstore`) into immutable `KVMapStore` instances (an `unordered_map<string, json::Json>` plus the compacted source document that owns its string data) and exposes them through lightweight handlers, enabling fast O(1) key lookups during event processing.

The module implements a **weak-pointer cache** strategy: once a KVDB is loaded, all handlers share the same underlying map. When all handlers are released, the cache entry expires automatically, and the next request will rebuild the map from fresh data. This provides both efficient memory reuse and automatic data refresh without explicit invalidation.

## Architecture

```
                    ┌───────────────────────────────┐
                    │        IKVDBManager            │  Public interface
                    │  getKVDBHandler(nsReader, db)  │
                    └──────────────┬────────────────┘
                                   │
                    ┌──────────────▼────────────────┐
                    │         KVDBManager            │  Implementation
                    │  Registry: ns → db → weak_ptr  │
                    │   <const KVMapStore>           │
                    │  shared_mutex for thread safety │
                    └──────────────┬────────────────┘
                                   │
                         ┌─────────▼─────────┐
                    hit? │  Cache lookup      │
                         │  (shared lock)     │
                         └─────┬───────┬─────┘
                          hit  │       │ miss
                    ┌──────────▼┐  ┌───▼───────────────────────────┐
                    │  Return   │  │ nsReader.getResourceByName    │  Fetch from
                    │  handler  │  │   <KVDB>(db).getData()        │  Content Manager
                    └───────────┘  │ → require JSON object         │
                                   │ → compact + extract members   │
                                   │ → cache weak_ptr (unique lock)│
                                   └───────┬───────────────────────┘
                                           │
                    ┌──────────────────────▼────────────────┐
                    │            KVDBHandler                 │
                    │  shared_ptr<const KVMapStore> m_store  │
                    │  get(key) → const json::Json&          │
                    │  contains(key) → bool                  │
                    └───────────────────────────────────────┘
```

## Key Concepts

| Concept | Description |
|---|---|
| **KVDB** | A key-value database stored as a JSON object in the Content Manager. Keys are string field names; values are arbitrary JSON. |
| **KVMap** | `unordered_map<string, json::Json>` — the in-memory representation of a KVDB's entries. |
| **KVMapStore** | `{ json::Json sourceDoc; KVMap entries; }` — the compacted source document keeps the string pool alive for the entries swapped out of it; shared immutably across all handlers. |
| **KVDBHandler** | A read-only view over a single `KVMapStore`. Returns direct references to stored JSON values (zero-copy). |
| **KVDBManager** | Manages a two-level cache (namespace → dbName → `weak_ptr<const KVMapStore>`). Builds maps on demand from the Content Manager store. |
| **Weak Cache** | The registry holds `weak_ptr<const KVMapStore>`. While any handler is alive, the map stays cached. When all handlers expire, the next request rebuilds from fresh data. |
| **Namespace Isolation** | KVDBs are scoped to Content Manager namespaces. The same dbName in different namespaces produces independent maps. |

## Directory Structure

```
kvdbstore/
├── CMakeLists.txt
├── README.md
├── interface/kvdbstore/
│   ├── ikvdbhandler.hpp       # IKVDBHandler — read-only key-value interface
│   └── ikvdbmanager.hpp       # IKVDBManager — handler factory interface
├── include/kvdbstore/
│   ├── kvdbHandler.hpp        # KVDBHandler implementation header
│   └── kvdbManager.hpp        # KVDBManager implementation header
├── src/
│   ├── kvdbHandler.cpp        # KVDBHandler — get(), contains()
│   └── kvdbManager.cpp        # KVDBManager — cache + build logic
└── test/
    ├── mocks/kvdbstore/
    │   ├── mockKvdbHandler.hpp  # GMock mock for IKVDBHandler
    │   └── mockKvdbManager.hpp  # GMock mock for IKVDBManager
    └── src/
        ├── unit/
        │   ├── kvdb_handler_test.cpp   # Handler unit tests
        │   └── kvdb_manager_test.cpp   # Manager unit tests
        └── component/
            └── kvdb_test.cpp           # Integration tests
```

## Public Interface

### `IKVDBHandler` ([ikvdbhandler.hpp](interface/kvdbstore/ikvdbhandler.hpp))

Read-only access to a single KVDB:

| Method | Description |
|---|---|
| `get(const std::string& key) → const json::Json&` | Returns a direct reference to the stored value. Throws `std::out_of_range` if key is not found or the store is null. |
| `contains(const std::string& key) → bool` (`noexcept`) | Checks if a key exists. Returns `false` if the backing store is null. |

### `IKVDBManager` ([ikvdbmanager.hpp](interface/kvdbstore/ikvdbmanager.hpp))

Handler factory:

| Method | Description |
|---|---|
| `getKVDBHandler(const cm::store::ICMStoreNSReader& nsReader, const std::string& dbName) → shared_ptr<IKVDBHandler>` | Returns a handler bound to the specified namespace and database. Fetches from the Content Manager on cache miss. Never returns `nullptr`: throws `std::runtime_error` if the KVDB does not exist or cannot be read (from `getResourceByName`) or if its payload is not a JSON object. |

## Implementation Details

### KVDBHandler

The handler holds a `shared_ptr<const KVMapStore>` and provides zero-copy access:
- `get()` returns a `const json::Json&` aliasing the stored value directly — no copies.
- `contains()` is `noexcept` and handles a null backing store gracefully.
- Multiple handlers over the same map all return references to the same underlying data.
- Thread-safe for concurrent reads (the map is immutable after construction).

### KVDBManager — Cache Strategy

`getKVDBHandler()` uses a double-checked locking pattern:

1. **Fast path (shared lock)**: Check registry for `(namespaceId, dbName)`. If a live `weak_ptr` is found, lock it and return a new handler wrapping the existing map.

2. **Cold path (no lock)**: Fetch the KVDB JSON from the Content Manager via `nsReader.getResourceByName<cm::store::dataType::KVDB>(dbName).getData()`, reject a non-object payload, compact it (`json::Json::compact()`) and move its members out with `extractObjectMembers()` into a `KVMapStore` (no deep copy).

3. **Publish (unique lock)**: Insert the new store as a `weak_ptr` into the registry. If another thread won the race and its store is still alive, reuse it instead; an expired entry is overwritten.

The `Registry` type is `unordered_map<cm::store::NamespaceId, DBMap>` with `DBMap = unordered_map<string, weak_ptr<const KVMapStore>>`, providing O(1) lookup by namespace and database name.

### Automatic Cache Expiry

Since the registry stores `weak_ptr`, the cached map is automatically freed when all handlers are destroyed. The next `getKVDBHandler()` call detects the expired pointer and rebuilds from the Content Manager, picking up any updated content.

## CMake Targets

| Target | Type | Description |
|---|---|---|
| `kvdbstore::ikvdb` (`kvdbstore_ikvdb`) | INTERFACE | Public interfaces (`IKVDBHandler`, `IKVDBManager`) |
| `kvdbstore::kvdb` (`kvdbstore_kvdb`) | STATIC | Implementation (`KVDBHandler`, `KVDBManager`) |
| `kvdbstore::mocks` (`kvdbstore_mocks`) | INTERFACE | GMock mocks for testing (`ENGINE_BUILD_TEST` only) |
| `kvdbstore_utest` | Executable | Unit tests (handler, manager; `ENGINE_BUILD_TEST` only) |
| `kvdbstore_ctest` | Executable | Component tests with mocked `cmstore` (`ENGINE_BUILD_TEST` only) |

**Key dependencies**: `base`, `cmstore::icmstore`

## Testing

### Unit Tests

**Handler** (`kvdb_handler_test`):
- Basic get/contains for string, number, and object values
- Direct reference verification (no copies — pointer equality)
- Multiple handlers over the same map share references
- Null map safety
- Empty key and empty value handling
- Concurrent readers safety (8 threads × 2000 iterations)
- Large value verbatim return (20KB string)

**Manager** (`kvdb_manager_test`):
- Cache hit does not re-fetch from Content Manager
- Cache hit reuses the exact same underlying map
- Cache expiry after all handlers are released triggers rebuild with new content
- Different dbNames within the same namespace use separate maps
- Parallel warm reads return the same pointer (no re-fetch)
- Parallel cold race converges on one cached map
- Parallel requests for the same namespace/db share the cached map; different namespaces or dbNames stay isolated

### Component Tests

- Build-once-then-cache workflow with pointer stability verification
- Expire-all-handlers-then-rebuild with updated content
- Cross-namespace and cross-dbName isolation (distinct caches)
- Concurrent cold race convergence (parallel first-time requests)
- A non-object payload throws
- Nested values are accessible and compare equal to the source

## Consumers

| Consumer | Usage |
|---|---|
| **`builder`** | The `Builder` holds an `IKVDBManager` reference. KVDB operation map builders (`opmap/kvdb`) use handlers to resolve key lookups during event processing. |
| **`main.cpp`** | Engine entry point — creates `KVDBManager` and passes it to the builder configuration. |

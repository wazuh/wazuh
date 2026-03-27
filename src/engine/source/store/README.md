# Store Module

## Overview

The **store** module provides a document-oriented key-value storage abstraction for the Wazuh engine. It manages JSON documents organized hierarchically by name (using `base::Name` as a multi-part key) and supports full CRUD operations plus collection listing.

The module follows a **driver-based architecture**: a thin `Store` facade implements the `IStore` interface and delegates all persistence operations to a pluggable `IDriver` backend. The only shipped driver is `FileDriver`, which maps document names to filesystem paths.

## Architecture

```
┌───────────────────────────────────────────────┐
│                  Consumers                     │
│  (router, builder, geo, iockvdb, iocsync, …)  │
│                                                │
│          std::shared_ptr<IStore>                │
└──────────────────┬────────────────────────────┘
                   │
          ┌────────▼────────┐
          │     IStore       │  (interface)
          │  createDoc()     │
          │  readDoc()       │
          │  updateDoc()     │
          │  upsertDoc()     │
          │  deleteDoc()     │
          │  readCol()       │
          │  existsDoc()     │
          └────────┬─────────┘
                   │
          ┌────────▼────────┐
          │      Store       │  (facade)
          │                  │
          │  delegates to    │
          │  IDriver         │
          └────────┬─────────┘
                   │
          ┌────────▼────────┐
          │     IDriver      │  (interface)
          │  same CRUD ops   │
          └────────┬─────────┘
                   │
          ┌────────▼────────┐
          │   FileDriver     │  (concrete)
          │                  │
          │  filesystem I/O  │
          └──────────────────┘
```

## Key Concepts

### Document Naming (`base::Name`)

Documents are identified by a hierarchical `base::Name`, e.g. `"router/router/0"`. Each part of the name maps to a segment in the underlying storage path. This naming convention naturally defines **collections**: the name `"router/router"` is the parent collection of `"router/router/0"`.

### Type Aliases

Defined in `idriver.hpp`:

| Alias | Type | Description |
|-------|------|-------------|
| `Doc` | `json::Json` | A single JSON document |
| `Col` | `std::vector<base::Name>` | A list of document names forming a collection |

### Upsert Semantics

`Store::upsertDoc` checks document existence first and routes to `createDoc` or `updateDoc` accordingly. This logic lives in the `Store` layer, not in the driver (the `FileDriver` has its own `upsertDoc` that does the same, but `Store` uses the existence check + create/update path).

### Utility: `jsonGenerator`

The `store::utils::jsonGenerator` function wraps a JSON document with metadata:

```json
{
  "json": { /* original parsed content */ },
  "original": "raw string content",
  "format": "json" | "yml"
}
```

This is used by consumers that need to store both parsed JSON and the original source format.

## Directory Structure

```
store/
├── CMakeLists.txt
├── interface/store/
│   ├── istore.hpp         # IStore – public document store interface
│   ├── idriver.hpp         # IDriver – low-level storage backend interface
│   └── utils.hpp           # jsonGenerator utility
├── include/store/
│   └── store.hpp           # Store – concrete IStore implementation
├── src/
│   └── store.cpp           # Store implementation
├── drivers/
│   └── fileDriver/
│       ├── include/store/drivers/
│       │   └── fileDriver.hpp   # FileDriver header
│       └── src/
│           └── fileDriver.cpp   # FileDriver implementation
└── test/
    ├── mocks/store/
    │   ├── mockDriver.hpp   # GMock for IDriver
    │   └── mockStore.hpp    # GMock for IStore
    └── src/unit/
        ├── fileDriver_test.cpp  # FileDriver unit tests
        └── store_test.cpp       # Store unit tests (with mocked driver)
```

## Public Interface

### `IStore` (interface/store/istore.hpp)

The primary interface consumed by the rest of the engine:

| Method | Signature | Description |
|--------|-----------|-------------|
| `createDoc` | `(const base::Name&, const Doc&) → base::OptError` | Create a new document; fails if it already exists |
| `readDoc` | `(const base::Name&) → base::RespOrError<Doc>` | Read a document by name |
| `updateDoc` | `(const base::Name&, const Doc&) → base::OptError` | Update an existing document; fails if not found |
| `upsertDoc` | `(const base::Name&, const Doc&) → base::OptError` | Create or update a document |
| `deleteDoc` | `(const base::Name&) → base::OptError` | Delete a document |
| `readCol` | `(const base::Name&) → base::RespOrError<Col>` | List all entries in a collection (directory) |
| `existsDoc` | `(const base::Name&) → bool` | Check if a document exists |

### `IDriver` (interface/store/idriver.hpp)

Mirror of `IStore` — defines the same CRUD contract for backend implementations. The separation allows the `Store` layer to add cross-cutting logic (e.g. the upsert check) without touching driver internals.

## Implementation Details

### Store (src/store.cpp)

A thin facade that holds a `std::shared_ptr<IDriver>` and forwards every operation to it. The only added logic is in `upsertDoc`, which calls `existsDoc` → `createDoc` or `updateDoc` on the driver level.

Constructor throws `std::runtime_error` if the driver pointer is null.

### FileDriver (drivers/fileDriver/)

Maps `base::Name` to filesystem paths rooted at a configurable base directory.

| Behavior | Detail |
|----------|--------|
| **Name → Path** | Each `base::Name` part becomes a path segment: `"type/name/version"` → `<base>/type/name/version` |
| **createDoc** | Validates for duplicate JSON keys, checks the file doesn't exist, creates parent directories, writes `prettyStr()` |
| **readDoc** | Reads the file, parses it as JSON; fails if the path is a directory |
| **updateDoc** | Validates for duplicate keys, checks the file exists and is not a directory, overwrites |
| **deleteDoc** | Removes the file and then cleans up empty parent directories up to the base path |
| **readCol** | Lists entries in a directory and constructs `base::Name` objects from each entry |
| **existsDoc** | Returns `true` only if the path exists and is a regular file |
| **Construction** | Optionally creates the base directory (`create = true`); validates it is a directory |

### Error Handling

All mutating operations return `base::OptError` (an `std::optional<base::Error>`):
- Empty optional → success
- Populated optional → error with descriptive message

Read operations return `base::RespOrError<T>` (an `std::variant<T, base::Error>`), allowing callers to use `base::isError()` and `std::get<>` to handle results.

## CMake Targets

| Target | Alias | Type | Description |
|--------|-------|------|-------------|
| `store_istore` | `store::istore` | INTERFACE | Public interfaces (`IStore`, `IDriver`, utils) |
| `store_fileDriver` | `store::fileDriver` | STATIC | FileDriver implementation |
| `store` | — | STATIC | Store facade |
| `store_mocks` | `store::mocks` | INTERFACE | GMock classes for IStore and IDriver |
| `store_fileDriver_unit_test` | — | EXECUTABLE | FileDriver tests |
| `store_utest` | — | EXECUTABLE | Store unit tests |

**Dependency graph:**

```
store::istore  ←── base
     ↑
     ├──── store::fileDriver
     ├──── store  (facade)
     └──── store::mocks  ←── GTest::gmock
```

## Testing

### Store Tests (store_test.cpp)

Use `MockDriver` to verify that `Store` correctly delegates to the driver. Covers:

- Null driver rejection (throws `std::runtime_error`)
- All CRUD operations: `createDoc`, `readDoc`, `updateDoc`, `deleteDoc`, `readCol`, `existsDoc`
- Upsert logic: verifies the `existsDoc` → `createDoc`/`updateDoc` routing

### FileDriver Tests (fileDriver_test.cpp)

Use a real temporary directory (`/tmp/fileDriver_test/<pid>_<tid>`). Covers:

- Construction: valid paths, non-existing paths with/without `create` flag, file-as-path rejection
- CRUD operations on the real filesystem
- Multiple document versions under the same collection
- Duplicate document creation failure
- Collection listing
- Non-existing document/collection reads

Both test suites clean up their temporary directories in `TearDown`.

## Consumers

The store is instantiated once in `main.cpp` using `FileDriver` pointed at the configured storage path, then injected as `std::shared_ptr<IStore>` into:

| Consumer Module | Usage |
|-----------------|-------|
| **router** (Orchestrator) | Persists and restores router/tester configuration snapshots |
| **builder** | Reads engine schema, allowed fields, and log parser overrides |
| **geo** | Stores MMDB database hashes for GeoIP update detection |
| **iockvdb** | Persists IOC KVDB state |
| **iocsync** | Stores IOC synchronization state |
| **confremote** | Stores remote runtime configuration |
| **streamlog** | Logger configuration persistence |
| **api/ioccrud** | Updates IOC sync status documents |

### Known Document Paths

| Path | Owner | Description |
|------|-------|-------------|
| `schema/engine-schema/0` | builder | Engine schema definition |
| `schema/allowed-fields/0` | builder | Allowed fields restrictions |
| `schema/wazuh-logpar-overrides/0` | builder | Log parser overrides |
| `router/router/0` | router | Router configuration snapshot |
| `router/tester/0` | router | Tester configuration snapshot |
| `geo/mmdb-hash/internal` | geo | GeoIP database hashes |
| `kvdb/ioc/state/0` | iockvdb | IOC KVDB state |
| `ioc/sync-state/0` | iocsync | IOC synchronization state |
| `ioc/remote-status/0` | api/ioccrud | IOC sync status |
| `confremote/*` | confremote | Remote configuration settings |

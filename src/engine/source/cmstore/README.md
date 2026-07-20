# CMStore — Content Manager Store

## Overview

`cmstore` is the **primary content repository** for the Wazuh Engine. It manages all the resources that define the event processing pipeline: **decoders**, **filters**, **outputs**, **integrations**, **KVDBs**, and **policies**. These resources are organized into **namespaces**, each backed by a filesystem directory with a bidirectional UUID↔name cache for O(1) lookups.

CMStore is the single source of truth that the **builder** reads to compile the processing pipeline and that the **backend** ultimately executes. It also provides the CRUD layer used by the management API (`cmcrud`), the test API (`api/tester`), and the KVDB store (`kvdbstore`).

## Architecture

```
                    ┌─────────────────────────────────────────────┐
                    │                 ICMStore                    │
                    │         (namespace management)              │
                    │  createNamespace / deleteNamespace / getNS  │
                    └────────────────┬────────────────────────────┘
                                     │
              ┌──────────────────────┼──────────────────────┐
              ▼                      ▼                      ▼
     ┌────────────────┐    ┌────────────────┐    ┌────────────────┐
     │  CMStoreNS     │    │  CMStoreNS     │    │  CMStoreNS     │
     │  ns: "wazuh"   │    │  ns: "custom"  │    │  ns: "..."     │
     │                │    │                │    │                │
     │  ┌──────────┐  │    │  ┌──────────┐  │    │                │
     │  │ CacheNS  │  │    │  │ CacheNS  │  │    │                │
     │  │ UUID↔Name│  │    │  │ UUID↔Name│  │    │                │
     │  └──────────┘  │    │  └──────────┘  │    │                │
     │                │    │                │    │                │
     │  Filesystem:   │    │  Filesystem:   │    │                │
     │  decoders/     │    │  decoders/     │    │                │
     │  filters/      │    │  filters/      │    │                │
     │  outputs/      │    │  outputs/      │    │                │
     │  integrations/ │    │  integrations/ │    │                │
     │  kvdbs/        │    │  kvdbs/        │    │                │
     │  policy.json   │    │  policy.json   │    │                │
     │  cache_ns.json │    │  cache_ns.json │    │                │
     └────────────────┘    └────────────────┘    └────────────────┘

                         Consumers:
         ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐
         │ builder  │  │ router   │  │ kvdbstore│  │  cmcrud  │
         └──────────┘  └──────────┘  └──────────┘  └──────────┘
```

### Concurrency Model

| Scope | Lock | Granularity |
|-------|------|-------------|
| Namespace map (`CMStore`) | `shared_mutex` | Read: shared / Write: unique |
| Per-namespace files + cache (`CMStoreNS`) | `shared_mutex` | Read: shared / Write: unique |

Read operations (get asset, resolve UUID) acquire a shared lock. Write operations (create, update, delete resource) acquire an exclusive lock per namespace.

## Key Concepts

### Namespaces

A namespace is an isolated content partition on disk. Each namespace has its own directory containing subdirectories for each resource type plus a policy file and a UUID cache. Forbidden namespace names: `output`, `system`, `default`.

### Resource Types

```cpp
enum class ResourceType : uint8_t {
    DECODER, OUTPUT, FILTER, INTEGRATION, KVDB
};
```

- **Decoders** — Parse raw log events, organized in parent-child hierarchies
- **Filters** — Pre/post-processing filters applied to events
- **Outputs** — Define where processed events are sent (indexer, alerts, etc.)
- **Integrations** — Group decoders and KVDBs under a category with a UUID manifest
- **KVDBs** — Key-value lookup tables for enrichment (stored as JSON content)

### UUID System

Every resource has a UUIDv4 identifier. When a resource is created via YAML/JSON, CMStore either extracts the existing `/id` field or generates a new UUID and injects it. The UUID is the canonical identifier used across the policy, integrations, and all cross-references.

### Bidirectional Cache (`CacheNS`)

Each namespace maintains an in-memory bidirectional cache:
- `UUID → (Name, ResourceType)` for UUID-based lookups
- `(Name, ResourceType) → UUID` for name-based lookups

The cache is serialized to `cache_ns.json` on every mutation. On startup, the cache is loaded from disk; if corrupt, it is rebuilt by scanning the filesystem.

### Policy

A `Policy` defines the complete event processing pipeline within a namespace:

- **root_decoder** — UUID of the entry-point decoder
- **integrations** — Ordered list of integration UUIDs
- **filters** — Pre/post-filter chain
- **enrichments** — Enrichment plugins (file, ip, domain-name, url, geo)
- **outputs** — Output UUIDs
- **origin_space** — Space key for output resolution
- **Flags**: `index_unclassified_events`, `index_discarded_events`, `cleanup_decoder_variables`

### Categories

Integrations are assigned to one of 8 predefined categories:

`access-management`, `applications`, `cloud-services`, `network-activity`, `other`, `security`, `system-activity`, `unclassified`

### Asset Adaptation

The `detail.hpp` header provides `adaptDecoder()` and `adaptFilter()` functions that normalize YAML/JSON documents into a canonical key ordering before consumption by the builder. For decoders: `name → parents → definitions → check → parse|* → normalize → enabled → id`.

## Directory Structure

```
cmstore/
├── CMakeLists.txt
├── interface/cmstore/                    # Public interfaces
│   ├── icmstore.hpp                      # ICMStore, ICMstoreNS, ICMStoreNSReader
│   ├── types.hpp                         # ResourceType enum, NamespaceId, data type imports
│   ├── categories.hpp                    # AVAILABLE_CATEGORIES, exists()
│   ├── detail.hpp                        # adaptDecoder(), adaptFilter(), UUID validation
│   ├── datapolicy.hpp                    # dataType::Policy — pipeline definition
│   ├── dataintegration.hpp               # dataType::Integration — integration manifest
│   └── datakvdb.hpp                      # dataType::KVDB — key-value database definition
├── include/cmstore/
│   └── cmstore.hpp                       # CMStore — concrete top-level implementation
├── src/
│   ├── cmstore.cpp                       # CMStore: namespace lifecycle, disk loading
│   ├── storens.hpp                       # CMStoreNS — per-namespace implementation
│   ├── storens.cpp                       # CRUD operations, policy, integration, KVDB, assets
│   ├── cachens.hpp                       # CacheNS — bidirectional UUID↔Name cache
│   ├── cachens.cpp                       # Cache serialization, add/remove/lookup
│   └── fileutils.hpp                     # File I/O helpers (upsert, read, delete, permissions)
├── test/
│   ├── mocks/cmstore/
│   │   └── mockcmstore.hpp               # GMock: MockICMStoreNSReader, MockICMstoreNS, MockICMstore
│   └── src/
│       ├── unit/
│       │   ├── cachens_test.cpp          # CacheNS unit tests
│       │   └── cmstore_test.cpp          # CMStore/CMStoreNS unit tests
│       └── component/
│           └── cmstore_test.cpp          # Full component tests with filesystem
└── benchmark/src/
    └── cmsync_bench.cpp                  # Sync benchmark
```

## Public Interface

### `ICMStore` (icmstore.hpp)

Top-level store managing namespaces.

```cpp
namespace cm::store {
class ICMStore {
    virtual std::shared_ptr<ICMStoreNSReader> getNSReader(const NamespaceId& nsId) const = 0;
    virtual std::shared_ptr<ICMstoreNS> getNS(const NamespaceId& nsId) = 0;
    virtual std::shared_ptr<ICMstoreNS> createNamespace(const NamespaceId& nsId) = 0;
    virtual void deleteNamespace(const NamespaceId& nsId) = 0;
    virtual void renameNamespace(const NamespaceId& from, const NamespaceId& to) = 0;
    virtual bool existsNamespace(const NamespaceId& nsId) const = 0;
    virtual std::vector<NamespaceId> getNamespaces() const = 0;
};
}
```

### `ICMStoreNSReader` (icmstore.hpp)

Read-only access to namespace content — used by the builder and router to read the pipeline definition.

```cpp
class ICMStoreNSReader {
    // General
    virtual const NamespaceId& getNamespaceId() const = 0;
    virtual std::vector<std::tuple<std::string, std::string>> getCollection(ResourceType type) const = 0;
    virtual std::tuple<std::string, ResourceType> resolveNameFromUUID(const std::string& uuid) const = 0;
    virtual std::string resolveUUIDFromName(const std::string& name, ResourceType type) const = 0;
    virtual bool assetExistsByName(const base::Name& name) const = 0;
    virtual bool assetExistsByUUID(const std::string& uuid) const = 0;

    // Policy
    virtual dataType::Policy getPolicy() const = 0;

    // Integrations
    virtual dataType::Integration getIntegrationByName(const std::string& name) const = 0;
    virtual dataType::Integration getIntegrationByUUID(const std::string& uuid) const = 0;

    // KVDBs
    virtual dataType::KVDB getKVDBByName(const std::string& name) const = 0;
    virtual dataType::KVDB getKVDBByUUID(const std::string& uuid) const = 0;

    // Assets (decoders, filters, outputs)
    virtual json::Json getAssetByName(const base::Name& name) const = 0;
    virtual json::Json getAssetByUUID(const std::string& uuid) const = 0;
    virtual const std::vector<json::Json> getOutputsForSpace(std::string_view spaceKey) const = 0;

    // Template helpers
    template<typename T> auto getResourceByName(const std::string& name) const;
    template<typename T> auto getResourceByUUID(const std::string& uuid) const;
};
```

### `ICMstoreNS` (icmstore.hpp)

Read-write interface extending `ICMStoreNSReader`:

```cpp
class ICMstoreNS : public ICMStoreNSReader {
    virtual std::string createResource(const std::string& name, ResourceType type, const std::string& ymlContent) = 0;
    virtual void updateResourceByName(const std::string& name, ResourceType type, const std::string& ymlContent) = 0;
    virtual void updateResourceByUUID(const std::string& uuid, const std::string& ymlContent) = 0;
    virtual void deleteResourceByName(const std::string& name, ResourceType type) = 0;
    virtual void deleteResourceByUUID(const std::string& uuid) = 0;
    virtual void upsertPolicy(const dataType::Policy& policy) = 0;
    virtual void deletePolicy() = 0;
};
```

### Data Types

| Type | Namespace | Key Fields |
|------|-----------|------------|
| `Policy` | `cm::store::dataType` | title, enabled, root_decoder, integrations[], filters[], enrichments[], outputs[], origin_space, hash, index_unclassified_events, index_discarded_events, cleanup_decoder_variables |
| `Integration` | `cm::store::dataType` | uuid, name, enabled, category, default_parent?, decoders[], kvdbs[] |
| `KVDB` | `cm::store::dataType` | uuid, name, content (JSON object), enabled |

## Implementation Details

### `CMStore` (cmstore.hpp / cmstore.cpp)

- **Constructor**: Takes absolute `basePath` and `outputsPath`. Validates both paths exist and are writable (writes test files). Loads all existing namespaces from disk.
- **Namespace map**: `unordered_map<NamespaceId, shared_ptr<ICMstoreNS>>` protected by `shared_mutex`.
- **`createNamespace()`**: Creates directory with 0750 permissions, initializes empty `cache_ns.json`, constructs `CMStoreNS`.
- **`deleteNamespace()`**: Checks `use_count > 1` to abort if active references exist. Removes directory recursively.
- **Forbidden namespaces**: `output`, `system`, `default` are rejected on create/delete.

### `CMStoreNS` (storens.hpp / storens.cpp)

- **Constructor**: Takes `NamespaceId`, storage path, and outputs path. Loads or rebuilds the UUID cache on startup.
- **Resource CRUD**: All operations follow: validate → acquire lock → update cache → write file → flush cache.
- **UUID handling**: `upsertUUID()` parses content as JSON/YAML, extracts or generates UUID, re-injects it into content.
- **Path mapping**: Resource names have `/` replaced with `_` for safe filenames. The type determines the subdirectory (`decoders/`, `filters/`, etc.).
- **Assets are stored as `.json`**; policies as `policy.json`.
- **File permissions**: Files get 0640, directories get 0750.
- **Output resolution**: `getOutputsForSpace()` checks for a space-specific directory under the outputs path; falls back to `default/`.

### `CacheNS` (cachens.hpp / cachens.cpp)

- Two `unordered_map`s: `UUID → EntryData(name, type)` and `(Name, Type) → UUID`.
- Not thread-safe — synchronized externally by `CMStoreNS`'s `shared_mutex`.
- Serialized as JSON array, flushed on every write operation.
- `rebuildCacheFromStorage()` scans all resource directories, re-extracting UUIDs and names from files.

## CMake Targets

| Target | Type | Alias | Description |
|--------|------|-------|-------------|
| `cmstore_icmstore` | INTERFACE | `cmstore::icmstore` | Public interfaces + data types |
| `cmstore_cmstore` | STATIC | `cmstore::cmstore` | Concrete implementation (links yml, base) |
| `cmstore_mocks` | INTERFACE | `cmstore::mocks` | GMock mocks for all interfaces |
| `cmstore_utest` | Executable | — | Unit tests (cache, store) |
| `cmstore_ctest` | Executable | — | Component tests (filesystem) |

## Testing

- **Unit tests** (`cachens_test.cpp`, `cmstore_test.cpp`): Test CacheNS bidirectional lookups, serialization, CMStore namespace operations.
- **Component tests** (`cmstore_test.cpp`): Full integration tests with real filesystem operations, resource CRUD cycles.

## Consumers

| Consumer | Dependency | Usage |
|----------|------------|-------|
| **builder** | `cmstore::icmstore` | Reads policy, integrations, decoders, KVDBs, and outputs to compile the processing pipeline |
| **router** | `cmstore::icmstore` | Uses `ICMStoreNSReader` and types for environment building and routing configuration |
| **kvdbstore** | `cmstore::icmstore` | Reads KVDB definitions from CMStore to populate the in-memory read-only KVDB layer |
| **cmcrud** | `cmstore::icmstore` | CRUD service layer that exposes CMStore operations through the management API |
| **api/tester** | `cmstore::icmstore` | Test API uses CMStore reader to validate and test pipeline configurations |

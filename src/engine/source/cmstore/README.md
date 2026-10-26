# CMStore — Content Manager Store

## Overview

`cmstore` is the **primary content repository** for the Wazuh Engine. It manages all the resources that define the event processing pipeline: **decoders**, **filters**, **outputs**, **integrations**, **KVDBs**, and **policies**. These resources are organized into **namespaces**, each backed by a filesystem directory with a bidirectional UUID↔name cache for O(1) lookups.

CMStore is the engine's local copy of the content: the **builder** reads it to compile the processing pipeline that the **backend** executes. The source of truth is `wazuh-indexer`, whose spaces `cmsync` imports into namespaces through `cmcrud`. CMStore is also read and written by the CRUD service (`cmcrud`), the test API (`api/tester`) and the KVDB manager (`kvdbstore`).

`main.cpp` constructs one `CMStore` from two settings (operator reference: the engine's [internal options, Paths](../../../../docs/ref/modules/engine/configuration.md#paths)):

| Constructor argument | Setting | Env var | Default on a manager |
|---|---|---|---|
| `path` (namespaces) | `analysisd.cm_ruleset_path` | `WAZUH_CM_RULESET_PATH` | `/var/wazuh-manager/data/ruleset` |
| `outputsPath` (default outputs) | `analysisd.output_path` | `WAZUH_OUTPUTS_PATH` | `/etc/wazuh-manager/outputs/` |

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
     │  ns: "<ns1>"   │    │  ns: "<ns2>"   │    │  ns: "..."     │
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
   ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌────────────┐
   │ builder  │  │ router   │  │ kvdbstore│  │  cmcrud  │  │ api/tester │
   └──────────┘  └──────────┘  └──────────┘  └──────────┘  └────────────┘
```

Namespaces created by `cmsync` are named `cmsync_<space>_<hex4>` (one per synchronized space); others come from the `/_internal/content/namespace/*` routes and the temporary namespace of `POST /content/validate/policy` (`api/cmcrud`).

### Concurrency Model

| Scope | Lock | Granularity |
|-------|------|-------------|
| Namespace map (`CMStore`) | `shared_mutex` | Read: shared / Write: unique |
| Per-namespace files + cache (`CMStoreNS`) | `shared_mutex` | Read: shared / Write: unique |

Read operations (get asset, resolve UUID) acquire a shared lock. Write operations (create, update, delete resource) acquire an exclusive lock per namespace.

## Key Concepts

### Namespaces

A namespace is an isolated content partition on disk. Each namespace has its own directory containing subdirectories for each resource type plus a policy file and a UUID cache. A `NamespaceId` must be non-empty and contain only alphanumerics and `_` (`types.hpp`). Forbidden namespace names: `output`, `system`, `default` — rejected by create, delete and rename, and skipped when loading from disk. A directory under the store path whose name is not a valid `NamespaceId` is skipped at load with a warning (`Ignoring directory '<path>': not a valid namespace name`) and left on disk.

### Resource Types

```cpp
enum class ResourceType : uint8_t {
    UNDEFINED = 0, DECODER = 1, OUTPUT = 2, FILTER = 3, INTEGRATION = 4, KVDB = 5
};
```

- **Decoders** — Parse raw log events, organized in parent-child hierarchies
- **Filters** — Pre/post-processing filters applied to events
- **Outputs** — Define where processed events are sent (indexer, alerts, etc.)
- **Integrations** — Group decoders and KVDBs under a category with a UUID manifest
- **KVDBs** — Key-value lookup tables for enrichment (stored as JSON content)

### UUID System

Every resource has a UUID identifier. When a resource is created (`createResource()`, JSON content), CMStore either extracts the existing `/id` field or generates a new UUIDv4 and injects it. Identifiers coming from the content are opaque: any UUID version (v4, v5, ...) or any other string is accepted and never interpreted. The UUID is the canonical identifier used across the policy, integrations, and all cross-references.

The validity rule is `base::utils::generators::isValidResourceId()` (`base/utils/generator.hpp`), applied at every entry point (data types, `CMStoreNS::upsertUUID()`, the CRUD service and the `/_internal/content/get|delete` handlers):

- non-empty (an empty `/id` means "no identifier" and triggers generation where allowed);
- at most `MAX_RESOURCE_ID_LENGTH` (256) bytes;
- no control characters (`0x00`-`0x1F`, `0x7F`).

Identifiers are **never normalized**: no case folding, no trimming. They are stored, looked up and compared byte by byte, both in the cache and when `findDuplicateOrInvalidUUID()` rejects duplicates inside a reference list, so `ABC` and `abc` are two different identifiers.

### Bidirectional Cache (`CacheNS`)

Each namespace maintains an in-memory bidirectional cache:
- `UUID → (Name, ResourceType)` for UUID-based lookups
- `(Name, ResourceType) → UUID` for name-based lookups

The cache is serialized to `cache_ns.json` after every resource create, update or delete (policy writes do not touch it). When a namespace is loaded, the cache is read from disk; if that fails (missing or corrupt file), it is rebuilt by scanning the resource directories and flushed back.

### Policy

A `Policy` defines the complete event processing pipeline within a namespace:

- **title** — read from `/metadata/title`
- **enabled** — required boolean
- **root_decoder** — UUID of the entry-point decoder
- **integrations** — Ordered list of integration UUIDs
- **filters** — Pre/post-filter chain
- **enrichments** — Enrichment plugins (file, ip, domain-name, url, geo)
- **outputs** — Output UUIDs
- **origin_space** — Space key for output resolution
- **Flags**: `index_unclassified_events`, `index_discarded_events`, `cleanup_decoder_variables`

### Categories

Integrations are assigned to one of 8 predefined categories (`categories.hpp`; `Integration` rejects any other):

`access-management`, `applications`, `cloud-services`, `network-activity`, `other`, `security`, `system-activity`, `unclassified`

### Asset Adaptation

The `detail.hpp` header provides `adaptDecoder()`, `adaptFilter()` and `adaptOutput()`, which rebuild a JSON asset document with its known keys in a canonical order (unknown keys are dropped), check that `name` is `<type>/<name>/<version>`, and require a boolean `enabled`. `cmcrud` applies them before storing an asset. For decoders: `name → parents → definitions → check → parse|* (at most one) → normalize → enabled → id`; for filters: `name → parents → definitions → type → check → enabled → id`; for outputs: `name → parents → definitions → outputs → enabled → id`. It also provides `findDuplicateOrInvalidUUID()` for reference lists.

## Directory Structure

```
cmstore/
├── CMakeLists.txt
├── interface/cmstore/                    # Public interfaces
│   ├── icmstore.hpp                      # ICMStore, ICMstoreNS, ICMStoreNSReader
│   ├── types.hpp                         # ResourceType enum, NamespaceId, data type imports
│   ├── categories.hpp                    # AVAILABLE_CATEGORIES, exists()
│   ├── detail.hpp                        # adaptDecoder/Filter/Output(), findDuplicateOrInvalidUUID()
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
│       │   ├── cmstore_test.cpp          # CMStore/CMStoreNS unit tests
│       │   └── detail_test.cpp           # detail.hpp adapters and UUID checks
│       └── component/
│           └── cmstore_test.cpp          # Full component tests with filesystem
└── benchmark/src/
    └── cmsync_bench.cpp                  # Placeholder (BM_Dummy only); no CMake target builds it
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
    virtual std::string createResource(const std::string& name, ResourceType type, const json::Json& content) = 0;
    virtual void updateResourceByName(const std::string& name, ResourceType type, const json::Json& content) = 0;
    virtual void updateResourceByUUID(const std::string& uuid, const json::Json& content) = 0;
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
| `Integration` | `cm::store::dataType` | id, name (`/metadata/title`), enabled, category, default_parent?, decoders[], kvdbs[] |
| `KVDB` | `cm::store::dataType` | id, name (`/metadata/title`), content (JSON object), enabled |

## Implementation Details

### `CMStore` (cmstore.hpp / cmstore.cpp)

- **Constructor**: Takes absolute `path` and `outputsPath`. Both must exist and be directories; `path` must be writable (it creates and removes a test file and a test directory). Loads all existing namespaces from disk.
- **Namespace map**: `unordered_map<NamespaceId, shared_ptr<ICMstoreNS>>` protected by `shared_mutex`.
- **`createNamespace()`**: Creates directory with 0750 permissions, initializes empty `cache_ns.json`, constructs `CMStoreNS`.
- **`deleteNamespace()`** / **`renameNamespace()`**: abort when `use_count > 1` (a reader or writer still holds the namespace). Delete removes the directory recursively; rename moves it and reloads the namespace under the new id.
- **Lookups**: `getNS()` / `getNSReader()` throw `Namespace does not exist: <ns>` for an unknown id.
- **Forbidden namespaces**: `output`, `system`, `default` are rejected on create, delete and rename.

### `CMStoreNS` (storens.hpp / storens.cpp)

- **Constructor**: Takes `NamespaceId`, storage path, and outputs path. Loads or rebuilds the UUID cache on startup.
- **Resource writes**: resolve the file path (validates the name) → take the exclusive lock → check the cache (name, UUID) → write the file → update the cache → flush `cache_ns.json`. `createResource()` refuses a name whose file already exists, because `/`→`_` folding can map two names to one file.
- **Updates**: `updateResourceByName()` and `updateResourceByUUID()` require the content's `/id` to match the stored UUID.
- **UUID handling**: `upsertUUID()` takes the JSON object, validates an existing `/id` or generates a UUIDv4 and writes it into the content.
- **Path mapping**: Resource names of every type have `/` replaced with `_` for the file name, which must pass `fileutils::isValidFileName()` (no traversal, no control characters, at most 255 bytes). The type determines the subdirectory (`decoders/`, `filters/`, `outputs/`, `integrations/`, `kvdbs/`).
- **Every resource is stored as `<name>.json`**; the policy as `policy.json`. When rebuilding the cache, asset file names get their first and last `_` turned back into `/`.
- **File permissions**: Files get 0640, directories get 0750.
- **Output resolution**: `getOutputsForSpace(spaceKey)` reads every `.yml`/`.yaml` file of `<outputsPath>/<spaceKey>/` if that directory exists, else of `<outputsPath>/default/`. These YAML outputs are separate from the namespace's own `outputs/` resources.

### `CacheNS` (cachens.hpp / cachens.cpp)

- Two `unordered_map`s: `UUID → EntryData(name, type)` and `(Name, Type) → UUID`.
- Not thread-safe — synchronized externally by `CMStoreNS`'s `shared_mutex`.
- Serialized as JSON array, flushed on every write operation.
- `rebuildCacheFromStorage()` scans all resource directories, re-extracting UUIDs and names from files.

## CMake Targets

| Target | Type | Alias | Description |
|--------|------|-------|-------------|
| `cmstore_icmstore` | INTERFACE | `cmstore::icmstore` | Public interfaces + data types |
| `cmstore_cmstore` | STATIC | `cmstore::cmstore` | Concrete implementation (public `base`, `cmstore::icmstore`; private `yml`) |
| `cmstore_mocks` | INTERFACE | `cmstore::mocks` | GMock mocks for all interfaces |
| `cmstore_utest` | Executable | — | Unit tests (cache, store, detail) |
| `cmstore_ctest` | Executable | — | Component tests (filesystem) |

The mocks and test executables exist only when `ENGINE_BUILD_TEST` is on.

## Testing

- **Unit tests** (`test/src/unit/`: `cachens_test.cpp`, `cmstore_test.cpp`, `detail_test.cpp`): CacheNS bidirectional lookups and serialization, CMStore namespace operations, the `detail.hpp` adapters.
- **Component tests** (`test/src/component/cmstore_test.cpp`): Full integration tests with real filesystem operations, resource CRUD cycles.

## Consumers

| Consumer | Dependency | Usage |
|----------|------------|-------|
| **builder** | `cmstore::icmstore` | Reads policy, integrations, decoders, KVDBs, and outputs to compile the processing pipeline |
| **router** | `cmstore::icmstore` | Uses only `NamespaceId` (`cmstore/types.hpp`) to identify the namespace of each route and test session |
| **kvdbstore** | `cmstore::icmstore` | `IKVDBManager::getKVDBHandler()` reads KVDB definitions through an `ICMStoreNSReader` |
| **cmcrud** | `cmstore::icmstore` (via `cmcrud::icmcrud`) | CRUD service used by the API handlers and `cmsync` |
| **api/tester** | `cmstore::icmstore` | Tester handlers read namespaces through `ICMStore` |
| **main.cpp** | `cmstore::cmstore` | Constructs the single `CMStore` and injects it into the builder, `CrudService` and the router and tester API handlers |

# Geo Module

## Overview

The **geo** module provides GeoIP enrichment capabilities for the Wazuh engine using MaxMind MMDB databases. It manages the lifecycle of GeoLite2 databases (City and ASN), including automatic downloading from a remote manifest, hash-based update detection, hot-reloading without restart, and persistent state tracking via the internal store. At query time, it provides `ILocator` instances for resolving IP addresses to geographic and network information.

## Architecture

```
              ┌──────────────────────────────────────────────────────────┐
              │       Remote Manifest (analysisd.geo_manifest_url)        │
              │  { "generated_at": ...,                                   │
              │    "city": { "url": "...gz", "md5": "..." },             │
              │    "asn":  { "url": "...gz", "md5": "..." } }            │
              └──────────────────┬────────────────────────────────────────┘
                                 │  downloadManifest()
                                 │  downloadHTTPS() + extractMmdbFromGz()
              ┌──────────────────▼────────────────────────────────────────┐
              │              Manager (IManager)                           │
              │                                                           │
              │  remoteUpsert(manifestUrl, cityPath, asnPath)             │
              │       ◄── scheduler "geo-sync-task" (default 360 s)       │
              │                                                           │
              │  ┌─────────────────────────────────────────────────┐      │
              │  │  m_dbs: map<name, shared_ptr<DbHandle>>        │      │
              │  │  m_dbTypes: map<Type, name>                    │      │
              │  │                                                 │      │
              │  │  DbHandle ──► atomic<shared_ptr<DbInstance>>    │      │
              │  │                    │                             │      │
              │  │              DbInstance (immutable)              │      │
              │  │                MMDB_s (mmap'd .mmdb file)       │      │
              │  │                path, hash, createdAt, type      │      │
              │  └─────────────────────────────────────────────────┘      │
              │                                                           │
              │  getLocator(Type) → Result<shared_ptr<ILocator>>          │
              │  listDbs() / getGeoStatus()                               │
              │                                                           │
              │  ┌────────────────┐     ┌────────────────────────┐       │
              │  │   IStore       │     │   IDownloader          │       │
              │  │ "geo/mmdb/0"   │     │   HTTPS + gz extract   │       │
              │  └────────────────┘     └────────────────────────┘       │
              └──────────────────────────────────────────────────────────┘
                         │
                getLocator(CITY/ASN)
                         │
              ┌──────────▼───────────────────────────────────────────────┐
              │              Locator (ILocator)                           │
              │                                                           │
              │   getString(ip, path)   → Result<string>                  │
              │   getUint32(ip, path)   → Result<uint32_t>                │
              │   getDouble(ip, path)   → Result<double>                  │
              │   getAsJson(ip, path)   → Result<json::Json>              │
              │   getAll(ip)            → Result<json::Json>              │
              │                                                           │
              │   Caches: last IP lookup result + DB instance ref          │
              └──────────────────────────────────────────────────────────┘
                         │
                    Consumers
                         │
              ┌──────────▼──────────────────────┐
              │  builder/enrichment/geo.cpp       │  GeoIP enrichment expressions
              │  builder/opmap/mmdb.cpp           │  MMDB helper map operations
              │  api/geo (HTTP endpoints)         │  On-demand IP lookup API
              │  api/status                       │  getGeoStatus() for engine status
              └──────────────────────────────────┘
```

## Key Concepts

### Database Types

| Type | Enum | Database File | Data |
|------|------|---------------|------|
| City | `geo::Type::CITY` | `GeoLite2-City.mmdb` | Country, city, continent, location (lat/lon), postal code, timezone |
| ASN | `geo::Type::ASN` | `GeoLite2-ASN.mmdb` | Autonomous System Number, organization name |

Only one database per type is allowed at any time. The file names are fixed by `main.cpp`, which joins
them to `analysisd.geo_db_path`; the manager map (`m_dbs`) is keyed by the file name.

### Internal Classes (private to `src/`)

| Class | File | Purpose |
|-------|------|---------|
| `DbInstance` | `dbInstance.hpp` | Immutable RAII wrapper around `MMDB_s`. Opens the `.mmdb` file via `MMDB_open` (memory-mapped) on construction, calls `MMDB_close` on destruction. Holds path, hash, createdAt, type. |
| `DbHandle` | `dbHandle.hpp` | Atomic pointer holder (`std::atomic_load`/`std::atomic_store` on `shared_ptr<const DbInstance>`). Enables lock-free hot-reload: new `DbInstance` is swapped in atomically while existing `Locator` instances continue using the old one. |
| `Locator` | `locator.hpp` | Implements `ILocator`. Holds a `weak_ptr<DbHandle>` and caches the last IP lookup result (`MMDB_lookup_result_s`). Automatically invalidates cache when the underlying `DbInstance` changes (hot-reload). `getLocator()` returns a new `Locator` on every call. |

### Hot-Reload Mechanism

Database updates are applied without restarting the engine:

1. New `.mmdb` is extracted to `<path>.tmp`, then renamed to the final path.
2. A new `DbInstance` is created (opens the renamed file via mmap).
3. `DbHandle::store()` atomically swaps the `shared_ptr`, publishing the new instance.
4. Existing `Locator` instances detect the change on next query (their cached `DbInstance` pointer differs from `DbHandle::load()`), invalidate their IP cache, and switch to the new instance.
5. The old `DbInstance` is destroyed when all references are released.

### Remote Update Flow (`remoteUpsert`)

1. Download and parse the manifest JSON (`generated_at`, `city.url`, `city.md5`, `asn.url`, `asn.md5`).
   On failure both types are marked `FAILED` in the status snapshot and the run ends (a WARNING is logged).
2. For each database type (City, then ASN):
   - Skip with a WARNING if the manifest has no `url`/`md5` for the type.
   - Skip if the stored hash equals the manifest MD5 **and** the stored file still exists (`needsUpdate()`).
   - Mark the type `UPDATING`, download the `.gz` and compare its MD5 with the manifest; a download error
     or a mismatch is retried, for **at most `MAX_RETRIES` = 3 attempts** in total.
   - Extract `.mmdb` from the gz (`Downloader` writes `tmp_download.mmdb.gz` next to the target and
     decompresses it with `Utils::ZlibHelper::gzipDecompress`).
   - Rename `<path>.tmp` → `<path>` and set its permissions to 0640.
   - Hot-load a new `DbInstance` into the type's `DbHandle`.
   - Persist `path`, `hash`, `generated_at` and `last_successful_update` to the internal store.
   - Mark the type `READY` (or `FAILED` on any error, keeping the previously loaded version available).
3. The shutdown flag (`m_shouldRun`) is checked before the run, before each download attempt and
   between the two types; `Downloader` also passes it to the HTTP client to cancel an in-flight transfer.

### Sync Status (`getGeoStatus`)

`getGeoStatus()` returns one `GeoDbStatus` per type (`city`, `asn`): `available`, `status`
(`base::SyncStatus`: `READY`, `UPDATING`, `FAILED`), `hash` and `lastSuccessfulUpdate`. The per-type state
is mutated only by the sync thread and published as a lock-free `base::StatusSnapshot`; on construction it
is restored from the store (`available`, `hash`, `last_successful_update`). `api/status` reports it.

### Error Handling (`Result<T>` and `ErrorCode`)

The module uses a custom `Result<T>` type (similar to `std::expected`) with typed `ErrorCode` enum instead of string errors. Error categories:

| Category | Codes |
|----------|-------|
| Success | `SUCCESS` (the `Result<void>` success value) |
| Database | `DB_NOT_AVAILABLE`, `DB_HANDLE_EXPIRED`, `DB_TYPE_NOT_AVAILABLE` |
| IP/Network | `IP_TRANSLATION`, `IP_NOT_FOUND` |
| Data access | `DATA_TYPE_MISMATCH`, `DATA_TYPE_MISMATCH_SIMPLE`, `DATA_TYPE_MISMATCH_STRING`, `DATA_TYPE_MISMATCH_UINT32`, `DATA_TYPE_MISMATCH_DOUBLE`, `DATA_ENTRY_EMPTY` |
| MMDB library | `MMDB_VALUE_ERROR`, `MMDB_LIBMMDB_ERROR`, `MMDB_RETRIEVAL_ENTRY_LIST`, `MMDB_DUMP_ENTRY` |
| General | `UNKNOWN_ERROR` (also the value of a default-constructed `Result<T>`) |

`getErrorDescription()` maps each code to a fixed message (`interface/geo/errorCodes.hpp`).

### ILocator Query Interface

| Method | Return | Description |
|--------|--------|-------------|
| `getString(ip, path)` | `Result<string>` | Get string value at dot-path (e.g., `"country.names.en"`) |
| `getUint32(ip, path)` | `Result<uint32_t>` | Get uint32 value (e.g., ASN number) |
| `getDouble(ip, path)` | `Result<double>` | Get double value (e.g., latitude/longitude) |
| `getAsJson(ip, path)` | `Result<json::Json>` | Get a scalar value as JSON at a path; a map or array is `DATA_TYPE_MISMATCH_SIMPLE` |
| `getAll(ip)` | `Result<json::Json>` | Get complete record for IP as JSON |

The `path` parameter is a `DotPath` matching the MMDB internal structure (e.g., `"city.names.en"`, `"location.latitude"`).

## Dependencies

| Dependency | CMake Target | Role |
|------------|-------------|------|
| `base` | `base` (via `geo::igeo`) | Logging, JSON, error handling, hash utilities, `StatusSnapshot` |
| `store` | `store::istore` (public) | Persisting database metadata (`geo/mmdb/0`) |
| `maxminddb` | `maxminddb::maxminddb` (private) | libmaxminddb C library for MMDB file reading |
| `urlrequest` | `urlrequest` (private) | `HTTPRequest` client for the manifest and databases; also provides `zlibHelper.hpp` for gz decompression |

## Configuration

The module reads no setting itself; `main.cpp` passes them in. The four `analysisd.geo_*` keys
(registered in `conf/src/conf.cpp`, constants in `conf/include/conf/keys.hpp`) — `geo_sync_interval`
(seconds, `0` disables the sync task), `geo_db_path`, `geo_manifest_url` and `geo_download_timeout`
(milliseconds, passed to `Downloader`) — with their environment overrides and defaults are documented for
operators in the engine configuration reference: [Geo](../../../../docs/ref/modules/engine/configuration.md#geo).

## Integration in `main.cpp`

```cpp
// 1. Create downloader with timeout and manager with store
auto geoDownloader = std::make_shared<geo::Downloader>(geoDownloadTimeout);
geoManager = std::make_shared<geo::Manager>(store, geoDownloader);
geoDownloader->setShouldRun(geoManager->shouldRunFlag());

// 2. Shutdown hook
exitHandler.add([geoManager]() { geoManager->requestShutdown(); });

// 3. Register API endpoints
api::geo::handlers::registerHandlers(geoManager, apiServer);

// 4. Inject into builder for enrichment
builderDeps.geoManager = geoManager;

// 5. Schedule periodic sync (only when analysisd.geo_sync_interval > 0)
auto cityPath = (std::filesystem::path(geoDbPath) / "GeoLite2-City.mmdb").string();
auto asnPath = (std::filesystem::path(geoDbPath) / "GeoLite2-ASN.mmdb").string();
scheduler->scheduleTask(
    "geo-sync-task",
    scheduler::TaskConfig {.interval = geoSyncInterval,
                           .runImmediately = true,
                           .CPUPriority = 0,
                           .taskFunction = [geoManager, manifestUrl, cityPath, asnPath]()
                           { geoManager->remoteUpsert(manifestUrl, cityPath, asnPath); }});
```

With the sync disabled, the manager still serves whatever databases the store points to.

## Consumers

| Module | Usage |
|--------|-------|
| **builder/enrichment** | `getLocator(CITY)` + `getLocator(ASN)` to build GeoIP enrichment expressions in decoder/rule pipelines |
| **builder/opmap** | `getLocator()` in MMDB map operations for event field enrichment |
| **api/geo** | `POST /_internal/geo/db/get` (IP lookup) and `POST /_internal/geo/db/list` (list loaded DBs) |
| **api/status** | `getGeoStatus()` for the engine status report |
| **main.cpp** | Periodic `remoteUpsert` via scheduler; `requestShutdown()` on exit |

## Thread Safety

- **Registry maps** (`m_dbs`, `m_dbTypes`): Protected by `std::shared_mutex` — shared lock for `getLocator()` / `listDbs()`, unique lock in `processDbEntry()` only while validating and obtaining the type's handle (released before the download).
- **Status**: `m_typeState` is touched only by the sync thread; readers get the published `StatusSnapshot` copy.
- **DbHandle**: Lock-free atomic swap of `shared_ptr<const DbInstance>` via `std::atomic_load`/`std::atomic_store`.
- **Locator**: Not thread-safe per-instance (each consumer should hold its own `Locator`). IP lookup result is cached per-locator.
- **Shutdown**: `std::shared_ptr<std::atomic<bool>>` flag shared between Manager and Downloader (`shouldRunFlag()` / `setShouldRun()`) for mid-transfer cancellation.

## Persistence

Database metadata is stored in a single document at `geo/mmdb/0` in the internal store:

```json
{
  "city": {
    "path": "/var/wazuh-manager/data/mmdb/GeoLite2-City.mmdb",
    "hash": "<manifest md5 of the .gz>",
    "generated_at": 1715270400,
    "last_successful_update": 1715271000
  },
  "asn": {
    "path": "/var/wazuh-manager/data/mmdb/GeoLite2-ASN.mmdb",
    "hash": "<manifest md5 of the .gz>",
    "generated_at": 1715270400,
    "last_successful_update": 1715271000
  }
}
```

`hash` is the manifest MD5 of the downloaded `.gz`, not of the `.mmdb`. `generated_at` comes from the
manifest; `last_successful_update` is the local time of the successful swap. On construction, the
manager loads this document and opens each type whose `path`, `hash` and `generated_at` are present
(otherwise a WARNING, and the type stays unloaded). On update, only the changed type's fields are
written.

## File Structure

```
geo/
├── CMakeLists.txt                                  # Build: igeo (INTERFACE), geo (STATIC), mocks, tests, benchmark
├── interface/geo/
│   ├── imanager.hpp                                # IManager interface (listDbs, remoteUpsert, getLocator, requestShutdown, getGeoStatus), Type, DbInfo, GeoDbStatus
│   ├── ilocator.hpp                                # ILocator interface (getString, getUint32, getDouble, getAsJson, getAll)
│   ├── idownloader.hpp                             # IDownloader interface (downloadHTTPS, downloadManifest, extractMmdbFromGz)
│   └── errorCodes.hpp                              # ErrorCode enum + Result<T> type
├── include/geo/
│   ├── manager.hpp                                 # Manager class declaration
│   └── downloader.hpp                              # Downloader class declaration
├── src/
│   ├── manager.cpp                                 # Manager implementation (remoteUpsert, processDbEntry, store persistence)
│   ├── downloader.cpp                              # HTTP download + gz extraction
│   ├── locator.cpp                                 # Locator implementation (MMDB lookups)
│   ├── locator.hpp                                 # Locator class declaration (private)
│   ├── dbHandle.hpp                                # Atomic shared_ptr holder for hot-reload (private)
│   └── dbInstance.hpp                              # Immutable MMDB_s RAII wrapper (private)
├── test/
│   ├── mocks/geo/
│   │   ├── mockManager.hpp                         # GMock mock for IManager
│   │   └── mockLocator.hpp                         # GMock mock for ILocator
│   └── src/
│       ├── testdb.mmdb                             # Test MMDB database file
│       ├── generateTestDB.pl                       # Script to regenerate test database
│       ├── mockDownloader.hpp                      # Mock for IDownloader (used in tests)
│       ├── unit/
│       │   ├── manager_test.cpp                    # Manager unit tests (mocked store + downloader)
│       │   └── locator_test.cpp                    # Locator unit tests (with test MMDB)
│       └── component/
│           └── manager_test.cpp                    # Component tests (concurrent lookups on the test MMDB)
└── benchmark/src/
    └── geo_bench.cpp                               # MMDB lookup benchmarks
```

## Testing

### Unit Tests (`geo_utest`)

| File | Covers |
|------|--------|
| `manager_test.cpp` | Construction from the store (including store errors and incomplete documents), getLocator, remoteUpsert with the mocked downloader (up to date, manifest error, download failure, MD5 mismatch, extraction failure, missing url/md5, shutdown before and between types), `getGeoStatus()`, `ErrorCode` descriptions and `Result<T>` |
| `locator_test.cpp` | IP lookup (getString, getUint32, getDouble, getAsJson, getAll), cache invalidation, error codes for invalid IPs/paths |

### Component Tests (`geo_ctest`)

| File | Covers |
|------|--------|
| `manager_test.cpp` | Concurrent lookups, `listDbs()` and `getLocator()` from many threads, and a combined use case, against `testdb.mmdb` |

### Benchmarks (`geo_benchmark`)

| File | Covers |
|------|--------|
| `geo_bench.cpp` | `Locator` getters on cache hit / miss / not found, the enrichment-style geo and AS field patterns, and `Manager::getLocator()`, against `testdb.mmdb` |

Build and run:

```bash
# ENGINE_TEST=y turns on both ENGINE_BUILD_TEST and ENGINE_BUILD_BENCHMARK (and sticks in the cache)
make -C src -j TARGET=manager ENGINE_TEST=y
src/build/engine/source/geo/geo_utest
src/build/engine/source/geo/geo_ctest
src/build/engine/source/geo/geo_benchmark
```

## Mocks

Available at `test/mocks/geo/` (CMake target: `geo::mocks`):

| Mock | Class |
|------|-------|
| `mockManager.hpp` | `geo::mocks::MockManager` — mocks `IManager` |
| `mockLocator.hpp` | `geo::mocks::MockLocator` — mocks `ILocator` |

`MockDownloader` (`test/src/mockDownloader.hpp`) is private to this module's tests. `geo::mocks` is used
by the `builder`, `api/geo` and `api/status` test targets.

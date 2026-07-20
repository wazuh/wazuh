# Geo Module

## Overview

The **geo** module provides GeoIP enrichment capabilities for the Wazuh engine using MaxMind MMDB databases. It manages the lifecycle of GeoLite2 databases (City and ASN), including automatic downloading from a remote manifest, hash-based update detection, hot-reloading without restart, and persistent state tracking via the internal store. At query time, it provides `ILocator` instances for resolving IP addresses to geographic and network information.

## Architecture

```
              ┌──────────────────────────────────────────────────────────┐
              │                Remote Manifest (S3)                       │
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
              │       ◄── scheduler (periodic, default 6 min)             │
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
              │  getLocator(Type) → shared_ptr<ILocator>                  │
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
              └──────────────────────────────────┘
```

## Key Concepts

### Database Types

| Type | Enum | Database File | Data |
|------|------|---------------|------|
| City | `geo::Type::CITY` | `GeoLite2-City.mmdb` | Country, city, continent, location (lat/lon), postal code, timezone |
| ASN | `geo::Type::ASN` | `GeoLite2-ASN.mmdb` | Autonomous System Number, organization name |

Only one database per type is allowed at any time.

### Internal Classes (private to `src/`)

| Class | File | Purpose |
|-------|------|---------|
| `DbInstance` | `dbInstance.hpp` | Immutable RAII wrapper around `MMDB_s`. Opens the `.mmdb` file via `MMDB_open` (memory-mapped) on construction, calls `MMDB_close` on destruction. Holds path, hash, createdAt, type. |
| `DbHandle` | `dbHandle.hpp` | Atomic pointer holder (`std::atomic_load`/`std::atomic_store` on `shared_ptr<const DbInstance>`). Enables lock-free hot-reload: new `DbInstance` is swapped in atomically while existing `Locator` instances continue using the old one. |
| `Locator` | `locator.hpp` | Implements `ILocator`. Holds a `weak_ptr<DbHandle>` and caches the last IP lookup result (`MMDB_lookup_result_s`). Automatically invalidates cache when the underlying `DbInstance` changes (hot-reload). |

### Hot-Reload Mechanism

Database updates are applied without restarting the engine:

1. New `.mmdb` is written to a temp file, then atomically renamed to the final path.
2. A new `DbInstance` is created (opens the renamed file via mmap).
3. `DbHandle::store()` atomically swaps the `shared_ptr`, publishing the new instance.
4. Existing `Locator` instances detect the change on next query (their cached `DbInstance` pointer differs from `DbHandle::load()`), invalidate their IP cache, and switch to the new instance.
5. The old `DbInstance` is destroyed when all references are released.

### Remote Update Flow (`remoteUpsert`)

1. Download and parse manifest JSON from URL.
2. For each database type (City, ASN):
   - Compare manifest MD5 hash with stored hash → skip if unchanged.
   - Download `.gz` file from manifest URL.
   - Validate MD5 of downloaded content (retry up to 3 times on mismatch).
   - Extract `.mmdb` from gz via `zlibHelper`.
   - Atomic rename temp file → final path (permissions set to 640).
   - Hot-load new `DbInstance` into `DbHandle`.
   - Persist metadata (path, hash, generated_at) to internal store.
3. Shutdown flag (`m_shouldRun`) is checked between operations for graceful cancellation.

### Error Handling (`Result<T>` and `ErrorCode`)

The module uses a custom `Result<T>` type (similar to `std::expected`) with typed `ErrorCode` enum instead of string errors. Error categories:

| Category | Codes |
|----------|-------|
| Database | `DB_NOT_AVAILABLE`, `DB_HANDLE_EXPIRED`, `DB_TYPE_NOT_AVAILABLE` |
| IP/Network | `IP_TRANSLATION`, `IP_NOT_FOUND` |
| Data access | `DATA_TYPE_MISMATCH`, `DATA_TYPE_MISMATCH_STRING`, `DATA_TYPE_MISMATCH_UINT32`, `DATA_TYPE_MISMATCH_DOUBLE`, `DATA_ENTRY_EMPTY` |
| MMDB library | `MMDB_VALUE_ERROR`, `MMDB_LIBMMDB_ERROR`, `MMDB_RETRIEVAL_ENTRY_LIST`, `MMDB_DUMP_ENTRY` |

### ILocator Query Interface

| Method | Return | Description |
|--------|--------|-------------|
| `getString(ip, path)` | `Result<string>` | Get string value at dot-path (e.g., `"country.names.en"`) |
| `getUint32(ip, path)` | `Result<uint32_t>` | Get uint32 value (e.g., ASN number) |
| `getDouble(ip, path)` | `Result<double>` | Get double value (e.g., latitude/longitude) |
| `getAsJson(ip, path)` | `Result<json::Json>` | Get value as JSON at specific path |
| `getAll(ip)` | `Result<json::Json>` | Get complete record for IP as JSON |

The `path` parameter uses dot notation matching the MMDB internal structure (e.g., `"city.names.en"`, `"location.latitude"`).

## Dependencies

| Dependency | CMake Target | Role |
|------------|-------------|------|
| `base` | `base` | Logging, JSON, error handling, hash utilities |
| `store` | `store::istore` | Persisting database metadata (hash, path, generated_at) |
| `maxminddb` | `maxminddb::maxminddb` | libmaxminddb C library for MMDB file reading |
| `urlrequest` | `urlrequest` | HTTP client for downloading manifests and databases |
| `zlibHelper` | (via urlrequest) | Gz decompression for downloaded database archives |

## Configuration

| Key | Env Override | Default | Description |
|-----|-------------|---------|-------------|
| `analysisd.geo_sync_interval` | `WAZUH_GEO_SYNC_INTERVAL` | `360` | Seconds between sync checks (`0` = disabled) |
| `analysisd.geo_db_path` | `WAZUH_GEO_DB_PATH` | `{wazuhRoot}/data/mmdb` | Directory for `.mmdb` files |
| `analysisd.geo_manifest_url` | `WAZUH_GEO_MANIFEST_URL` | S3 URL | Manifest JSON URL |
| `analysisd.geo_download_timeout` | `WAZUH_GEO_DOWNLOAD_TIMEOUT` | `60000` | HTTP download timeout (ms) |

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

// 5. Schedule periodic sync
scheduler->scheduleTask("geo-sync-task", {
    .interval = geoSyncInterval,
    .runImmediately = true,
    .taskFunction = [geoManager, manifestUrl, cityPath, asnPath]() {
        geoManager->remoteUpsert(manifestUrl, cityPath, asnPath);
    }
});
```

## Consumers

| Module | Usage |
|--------|-------|
| **builder/enrichment** | `getLocator(CITY)` + `getLocator(ASN)` to build GeoIP enrichment expressions in decoder/rule pipelines |
| **builder/opmap** | `getLocator()` in MMDB map operations for event field enrichment |
| **api/geo** | `POST /_internal/geo/db/get` (IP lookup) and `POST /_internal/geo/db/list` (list loaded DBs) |
| **main.cpp** | Periodic `remoteUpsert` via scheduler |

## Thread Safety

- **Registry maps** (`m_dbs`, `m_dbTypes`): Protected by `std::shared_mutex` — shared lock for `getLocator()` / `listDbs()`, unique lock for `processDbEntry()`.
- **DbHandle**: Lock-free atomic swap of `shared_ptr<const DbInstance>` via `std::atomic_load`/`std::atomic_store`.
- **Locator**: Not thread-safe per-instance (each consumer should hold its own `Locator`). IP lookup result is cached per-locator.
- **Shutdown**: `std::atomic<bool>` flag shared between Manager and Downloader for mid-transfer cancellation.

## Persistence

Database metadata is stored in a single document at `geo/mmdb/0` in the internal store:

```json
{
  "city": {
    "path": "/var/wazuh-manager/data/mmdb/GeoLite2-City.mmdb",
    "hash": "abc123...",
    "generated_at": 1715270400
  },
  "asn": {
    "path": "/var/wazuh-manager/data/mmdb/GeoLite2-ASN.mmdb",
    "hash": "def456...",
    "generated_at": 1715270400
  }
}
```

On construction, the manager loads this document and opens any `.mmdb` files found. On update, only the changed type's fields are updated.

## File Structure

```
geo/
├── CMakeLists.txt                                  # Build: igeo (INTERFACE), geo (STATIC), mocks, tests, benchmark
├── interface/geo/
│   ├── imanager.hpp                                # IManager interface (listDbs, remoteUpsert, getLocator, requestShutdown)
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
│           └── manager_test.cpp                    # Component tests (end-to-end update flow)
└── benchmark/src/
    └── geo_bench.cpp                               # MMDB lookup benchmarks
```

## Testing

### Unit Tests (`geo_utest`)

| File | Covers |
|------|--------|
| `manager_test.cpp` | Construction from store, addDb, remoteUpsert with mocked downloader, hash comparison, error handling |
| `locator_test.cpp` | IP lookup (getString, getUint32, getDouble, getAsJson, getAll), cache invalidation, error codes for invalid IPs/paths |

### Component Tests (`geo_ctest`)

| File | Covers |
|------|--------|
| `manager_test.cpp` | End-to-end update flow with real MMDB file operations |

### Benchmarks (`geo_benchmark`)

| File | Covers |
|------|--------|
| `geo_bench.cpp` | MMDB lookup performance (latency per query) |

Build and run:

```bash
# Tests
make --directory=$WAZUH_REPO/src -j TARGET=manager ENGINE_TEST=y DEBUG=yes
$ENGINE_BUILD/source/geo/geo_utest
$ENGINE_BUILD/source/geo/geo_ctest

# Benchmarks (requires ENGINE_BUILD_BENCHMARK=ON)
$ENGINE_BUILD/source/geo/geo_benchmark
```

## Mocks

Available at `test/mocks/geo/` (CMake target: `geo::mocks`):

| Mock | Class |
|------|-------|
| `mockManager.hpp` | `geo::mocks::MockManager` — mocks `IManager` |
| `mockLocator.hpp` | `geo::mocks::MockLocator` — mocks `ILocator` |

Used by `builder` and `api/geo` test targets.

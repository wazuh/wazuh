# IOC Sync — Indicator of Compromise Synchronization

## Overview

`iocsync` is the synchronization module that keeps local IOC databases up to date with the remote Wazuh Indexer. It implements a **hash-based change detection** strategy: for each IOC type, it compares a local hash against the remote hash and, when a change is detected, downloads the full dataset into a temporary database and performs an **atomic hot-swap** via `iockvdb`.

The module runs as a periodic task and is designed so that readers of the IOC databases experience zero downtime during updates.

## Architecture

```
                ┌──────────────┐
                │   Scheduler  │  (periodic trigger)
                └──────┬───────┘
                       │ synchronize()
                       ▼
              ┌────────────────┐
              │    IocSync     │
              │                │
              │  For each IOC  │
              │  type:         │
              │  ┌───────────┐ │    ┌───────────────────────┐
              │  │ Compare   │─┼───►│  Wazuh Indexer         │
              │  │ hashes    │ │    │  (IWIndexerConnector)  │
              │  └─────┬─────┘ │    └───────────────────────┘
              │        │       │
              │   changed?     │
              │     no │ yes   │
              │     ▼  │       │
              │   skip ▼       │
              │  ┌───────────┐ │
              │  │ Download  │ │    streamIocsByType()
              │  │ IOCs into │ │    → temp DB
              │  │ temp DB   │ │
              │  └─────┬─────┘ │
              │        │       │
              │        ▼       │
              │  ┌───────────┐ │    ┌──────────────────┐
              │  │ Hot-swap  │─┼───►│  IKVDBManager    │
              │  │ temp→live │ │    │  (iockvdb)       │
              │  └─────┬─────┘ │    └──────────────────┘
              │        │       │
              │        ▼       │
              │  Update hash   │
              │  in state      │
              └────────────────┘
                       │
                       ▼
              ┌────────────────┐
              │  store::IStore │  (persist sync state)
              └────────────────┘
```

### Synchronization Flow

1. **Lock resources**: Acquire `IKVDBManager` and `IWIndexerConnector` from weak pointers
2. **Check remote index**: Verify the IOC data index exists in the Wazuh Indexer
3. **Fetch remote hashes**: Get per-type hash map from the indexer
4. **For each IOC type**:
   - Compare remote hash against locally stored hash
   - If identical and DB exists → skip
   - If different or DB missing → download and replace:
     1. Create a temporary database with a random name
     2. Stream IOCs via `streamIocsByType()` in batches of 1000
     3. Store each IOC key-value pair (keys normalized to lowercase)
     4. Ensure the target database exists
     5. `hotSwap(tempDB, targetDB)` — atomic, zero-downtime
     6. Update local hash
5. **Persist state** if any type was updated

## Key Concepts

### Hash-Based Change Detection

Each IOC type has a remote hash maintained by the Wazuh Indexer. `IocSync` stores the last known hash per type in `SyncedIOCDatabase::m_lastDataHash`. A sync cycle only downloads data when the hashes differ, minimizing unnecessary network and disk I/O.

### Weak Pointer Resource Model

All external dependencies (`IWIndexerConnector`, `IKVDBManager`, `store::IStore`) are held as `weak_ptr`. This allows the sync module to be safely outlived by the resources it depends on and provides clear error messages if a resource has been destroyed.

### Retry Logic

Remote operations (`existIocDataInRemote`, `getRemoteHashesFromRemote`) use `base::utils::executeWithRetry` with configurable `m_attempts` (default: 3) and `m_waitSeconds` (default: 5) for resilience against transient network issues. The shutdown flag `m_shutdownRequested` is passed to `executeWithRetry`, which checks it before each attempt and during inter-retry sleep (split into 1-second chunks).

### Graceful Shutdown

`IocSync` supports responsive shutdown via `requestShutdown()`:

- Sets `m_shutdownRequested` (`std::atomic<bool>`) to `true`.
- `synchronize()` checks the flag at multiple points: before starting, before each IOC type iteration, and in the outer `catch` block.
- `executeWithRetry` aborts early when the flag is set.
- If the underlying indexer throws `IndexerConnectorException` during `streamIocsByType()` (due to `WIndexerConnector::requestShutdown()`), the exception propagates through `downloadAndPopulateDB()` which triggers a rollback of the temporary database — **preventing promotion of a partially-downloaded dataset via hot-swap**.
- The module is registered in the exit handler in `main.cpp`; on SIGINT/SIGTERM, `requestShutdown()` is called and the sync cycle aborts within one batch round-trip.

### Rollback on Failure

If the download-and-populate step fails, the temporary database is removed. If the hot-swap itself fails, the temporary database is also cleaned up. The target database remains untouched.

### Persistence

Sync state is stored in the engine's internal store under `iocsync/status/0` as a JSON array of `SyncedIOCDatabase` entries. Each entry tracks the IOC type and its last known data hash.

## Directory Structure

```
iocsync/
├── CMakeLists.txt
├── interface/iocsync/
│   └── iiocsync.hpp              # IIocSync — abstract synchronization interface
├── include/iocsync/
│   └── iocsync.hpp               # IocSync — concrete implementation
└── src/
    └── iocsync.cpp               # Full implementation + SyncedIOCDatabase class
```

## Public Interface

### `IIocSync` (iiocsync.hpp)

```cpp
namespace ioc::sync {
class IIocSync {
    virtual void synchronize() = 0;
    virtual void requestShutdown() = 0;
};
}
```

- `synchronize()` performs a full sync cycle for all configured IOC types.
- `requestShutdown()` signals the module to abort as soon as possible (idempotent, thread-safe).

## Implementation Details

### `IocSync` (iocsync.hpp / iocsync.cpp)

**Constructor**: Takes `shared_ptr<IWIndexerConnector>`, `shared_ptr<IKVDBManager>`, and `shared_ptr<store::IStore>` (stored as weak pointers). On first run (no persisted state), initializes the sync list with all IOC types from `ioc::kvdb::details::getSupportedIocTypes()`.

**Key Members**:

| Member | Type | Purpose |
|--------|------|---------|
| `m_indexerPtr` | `weak_ptr<IWIndexerConnector>` | Remote IOC data source |
| `m_kvdbiocManagerPtr` | `weak_ptr<IKVDBManager>` | Local IOC database manager |
| `m_store` | `weak_ptr<store::IStore>` | Persistence for sync state |
| `m_databasesState` | `vector<SyncedIOCDatabase>` | Per-type sync state (type + last hash) |
| `m_mutex` | `shared_mutex` | Protects `m_databasesState` and sync operations |
| `m_attempts` | `size_t` | Retry count for remote operations (default: 3) |
| `m_waitSeconds` | `size_t` | Wait between retries (default: 5) |
| `m_shutdownRequested` | `std::atomic<bool>` | Abort flag checked at multiple points during sync |

**`synchronize()`**: Acquires the KVDB manager, checks remote availability, fetches hashes, iterates all configured IOC types calling `syncIOCType()` for each, and persists state if anything changed.

**`syncIOCType()`**: Per-type logic — compares hashes, downloads to temp DB via `downloadAndPopulateDB()`, ensures target exists, performs `hotSwap()`, updates local hash. Returns `true` if the database was updated.

**`downloadAndPopulateDB()`**: Streams IOC documents from the indexer in batches of 1000. Each document's key is normalized to lowercase. Values are stored via `ioc::kvdb::details::updateValueInDB()` which appends to arrays if the key already exists.

### `SyncedIOCDatabase` (internal class in iocsync.cpp)

Tracks per-type sync state with JSON serialization:

```json
{ "ioc_type": "connection", "last_data_hash": "abc123..." }
```

## CMake Targets

| Target | Type | Alias | Description |
|--------|------|-------|-------------|
| `iocsync_iiocsync` | INTERFACE | `iocsync::iiocsync` | Public interface (`IIocSync`) |
| `iocsync_iocsync` | STATIC | `iocsync::iocsync` | Implementation (links `iockvdb::ikvdb`, `wIndexerConnector::iwIndexerConnector`, `store::istore`) |

Tests are not yet enabled (commented out in `CMakeLists.txt`).

## Testing

No tests are currently enabled for this module. The test section in `CMakeLists.txt` is commented out.

## Consumers

| Consumer | Dependency | Usage |
|----------|------------|-------|
| **main.cpp** | `iocsync::iocsync` | Creates `IocSync` instance and triggers periodic synchronization |

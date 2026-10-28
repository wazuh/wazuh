# IOC Sync — Indicator of Compromise Synchronization

## Overview

`iocsync` is the synchronization module that keeps local IOC databases up to date with the remote Wazuh Indexer. It implements a **hash-based change detection** strategy: for each IOC type, it compares a local hash against the remote hash and, when a change is detected, downloads the full dataset into a temporary database and performs an **atomic hot-swap** via `iockvdb`.

The module runs as the `ioc-sync-task` scheduler task (created in `main.cpp` only when `analysisd.server_enable_event_processing` is true; scheduled every `analysisd.ioc_sync_interval` seconds, default 360, run immediately on start, disabled with `0`) and is designed so that readers of the IOC databases experience zero downtime during updates. It also publishes a per-type status snapshot read by the engine API's `GET /status`. The operator-facing settings are on the engine [configuration](../../../../docs/ref/modules/engine/configuration.md) page.

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

1. **Lock resources**: Acquire `IKVDBManager` from its weak pointer and take `m_mutex` exclusively
2. **Pre-flight consumer check**: `isConsumerReadyForSync(IOC_ENRICHMENT_CONSUMER_ID)` (with retry) — the `cti:catalog:consumer:iocs` document in `.wazuh-cti-consumers` must have `status` `"ready"` and a non-zero `local_offset`; otherwise the cycle is skipped
3. **Check remote index**: Verify the IOC data index (`wazuh-threatintel-enrichments`) exists in the Wazuh Indexer. A missing index (404) returns `false` and skips the cycle without retrying; any other error is retried and then fails the cycle
4. **Fetch remote hashes**: Get the per-type hash map (`__ioc_type_hashes__`) from the indexer; `std::nullopt` (consumer not ready) skips the cycle
5. **For each IOC type** (marked `UPDATING` in the status snapshot while it runs; afterwards `READY` when it was updated or already current, `FAILED` when its sync errored — even if the previous version stays available — and, when it was skipped, `FAILED` only if it holds no version yet):
   - Compare remote hash against locally stored hash
   - No remote hash for the type → skip with a warning
   - If identical and DB exists → skip
   - If different or DB missing → download and replace:
     1. Create a temporary database named `iocsync_<type>_<4 random hex chars>`
     2. Stream IOCs via `streamIocsByType()` in batches of `analysisd.ioc_indexer_connector_sync_batch_size` documents (default 1000)
     3. Store each IOC key-value pair (keys normalized to lowercase)
     4. Ensure the target database exists
     5. `hotSwap(tempDB, targetDB)` — atomic, zero-downtime
     6. Update local hash and the type's last-successful-update timestamp
6. **Persist state** if any type was updated

Every skipped or failed cycle (except one aborted by a shutdown) calls `reportSyncFailure()`: types with no usable version yet (empty hash) or interrupted mid-sync are marked `FAILED`; types that already hold data keep their status.

## Key Concepts

### Consumer Validation for Consistency

To prevent data inconsistency when the wazuh-indexer is mid-update, `iocsync` implements **consumer validation via Point-In-Time (PIT)**:

0. **Pre-flight**: `synchronize()` first calls `isConsumerReadyForSync()` (see step 2 of the flow above).

1. **Hash check phase**: `getRemoteHashesFromRemote()` passes `IOC_ENRICHMENT_CONSUMER_ID` to the indexer connector.
   - The connector creates a multi-index PIT (`wazuh-threatintel-enrichments` + `.wazuh-cti-consumers`).
   - It validates the consumer is in the `ready` status within that PIT snapshot.
   - If ready: returns the hashes (and the check is consistent).
   - If not ready: returns `std::nullopt` → sync cycle is skipped.

2. **Download phase**: `downloadAndPopulateDB()` passes the same consumer ID to `streamIocsByType()`.
   - The connector again validates the consumer is ready within a NEW PIT snapshot.
   - If ready: streams IOCs within that PIT snapshot.
   - If not ready: returns `std::nullopt` → download is skipped, temp DB is rolled back.

This two-phase validation ensures the indexer is NOT actively updating the IOCs before or during the download.

### Hash-Based Change Detection

Each IOC type has a remote hash maintained by the Wazuh Indexer. `IocSync` stores the last known hash per type in `SyncedIOCDatabase::m_lastDataHash`. A target database that no longer exists forces a full resync even when the hashes match. A sync cycle only downloads data when the hashes differ, minimizing unnecessary network and disk I/O.

### Weak Pointer Resource Model

All external dependencies (`IWIndexerConnector`, `IKVDBManager`, `store::IStore`) are held as `weak_ptr`. The sync module does not extend the lifetime of the resources it depends on; `base::utils::lockWeakPtr()` throws a clear error if one has already been destroyed.

### Retry Logic

Remote checks (`isConsumerReadyForSync`, `existIocDataInRemote`, `getRemoteHashesFromRemote`) use `base::utils::executeWithRetry` with `m_attempts` (`analysisd.ioc_indexer_connector_max_retries`, default 3) and `m_waitSeconds` (`analysisd.ioc_indexer_connector_retry_interval`, default 5) for resilience against transient network issues; a zero is raised to 1. The download stream itself is not retried. The shutdown flag `m_shutdownRequested` is passed to `executeWithRetry`, which checks it before each attempt and during inter-retry sleep (split into 1-second chunks).

### Graceful Shutdown

`IocSync` supports responsive shutdown via `requestShutdown()`:

- Sets `m_shutdownRequested` (`std::atomic<bool>`) to `true`.
- `synchronize()` checks the flag at multiple points: before starting, before each IOC type iteration, and in the outer `catch` block (where types left `UPDATING` are reset to `READY`).
- `executeWithRetry` aborts early when the flag is set.
- If the underlying indexer throws `IndexerConnectorException` during `streamIocsByType()` (due to `WIndexerConnector::requestShutdown()`), the exception propagates through `downloadAndPopulateDB()` which triggers a rollback of the temporary database — **preventing promotion of a partially-downloaded dataset via hot-swap**.
- The module is registered in the exit handler in `main.cpp`; on SIGINT/SIGTERM, `requestShutdown()` is called and the sync cycle aborts within one batch round-trip.

### Rollback on Failure

If the download-and-populate step fails or the consumer turns out not ready, the temporary database is removed. If ensuring the target database or the hot-swap itself fails, the temporary database is also cleaned up. The target database remains untouched, and the local hash is not updated, so the next cycle retries.

### Error Text in Log Lines

An indexer connector error ends with the whole response body; a circuit-breaker `429` is more than a kilobyte,
its root cause repeated. Every `WARNING` that carries a caught error passes it through `summarizeError()`
(`src/errorSummary.hpp`): the text before the body (which holds the HTTP status), then the body's `error.type`
and `error.reason` (the reason cut to 160 characters), the whole line's error part bounded to 400 characters.

### Persistence

Sync state is stored in the engine's internal store under `iocsync/status/0` as a JSON array of `SyncedIOCDatabase` entries (an object with a `/databases` array is also accepted on load). Each entry tracks the IOC type, its last known data hash and the Unix time of its last successful update. On first setup (no document), every type from `getSupportedIocTypes()` is added and the document is written.

## Directory Structure

```
iocsync/
├── CMakeLists.txt
├── interface/iocsync/
│   └── iiocsync.hpp              # IIocSync — abstract synchronization interface
├── include/iocsync/
│   └── iocsync.hpp               # IocSync — concrete implementation
├── src/
│   ├── iocsync.cpp               # Full implementation + SyncedIOCDatabase class
│   └── errorSummary.hpp          # summarizeError(): bounded indexer error text for log lines
└── test/
    ├── mocks/iocsync/
    │   └── mockIocSync.hpp       # GMock of IIocSync
    └── src/unit/
        ├── iocsync_status_test.cpp
        └── errorSummary_test.cpp
```

## Public Interface

### `IIocSync` (iiocsync.hpp)

```cpp
namespace ioc::sync {
struct IocTypeStatus {
    std::string type;
    bool available {false};
    base::SyncStatus status {base::SyncStatus::READY};
    std::string hash;
    uint32_t lastSuccessfulUpdate {0};
};

class IIocSync {
    virtual void synchronize() = 0;
    virtual void requestShutdown() = 0;
    virtual std::vector<IocTypeStatus> getIocStatus() const = 0;
};
}
```

- `synchronize()` performs a full sync cycle for all configured IOC types.
- `requestShutdown()` signals the module to abort as soon as possible (idempotent, thread-safe).
- `getIocStatus()` returns the last published per-type snapshot (wait-free read of a `base::StatusSnapshot`); `available` is true when the type has a hash and its database exists, `status` is `base::SyncStatus` (`READY`, `UPDATING`, `FAILED`, rendered `ready`/`updating`/`failed` by `GET /status`).

## Implementation Details

### `IocSync` (iocsync.hpp / iocsync.cpp)

**Constructor**: `IocSync(indexerPtr, kvdbiocManagerPtr, storePtr, maxRetries, retryIntervalSeconds, iocSyncBatchSize)` — the three resources are `shared_ptr<IWIndexerConnector>`, `shared_ptr<IKVDBManager>` and `shared_ptr<store::IStore>` (stored as weak pointers); `main.cpp` passes the three `analysisd.ioc_indexer_connector_*` settings. On first run (no persisted state), initializes the sync list with all IOC types from `ioc::kvdb::details::getSupportedIocTypes()`.

**Key Members**:

| Member | Type | Purpose |
|--------|------|---------|
| `m_indexerPtr` | `weak_ptr<IWIndexerConnector>` | Remote IOC data source |
| `m_kvdbiocManagerPtr` | `weak_ptr<IKVDBManager>` | Local IOC database manager |
| `m_store` | `weak_ptr<store::IStore>` | Persistence for sync state |
| `m_databasesState` | `vector<SyncedIOCDatabase>` | Per-type sync state (type + last hash) |
| `m_mutex` | `shared_mutex` | Protects `m_databasesState` and sync operations |
| `m_attempts` | `size_t` | Retry count for remote operations (`maxRetries`) |
| `m_waitSeconds` | `size_t` | Wait between retries (`retryIntervalSeconds`) |
| `m_iocSyncBatchSize` | `size_t` | Documents per indexer batch during download |
| `m_shutdownRequested` | `std::atomic<bool>` | Abort flag checked at multiple points during sync |
| `m_iocStatus` | `base::StatusSnapshot<IocTypeStatus>` | Lock-free status snapshot served by `getIocStatus()` |

**`synchronize()`**: Acquires the KVDB manager, checks consumer readiness and remote availability, fetches hashes, iterates all configured IOC types calling `syncIOCType()` for each, and persists state if anything changed.

**`syncIOCType()`**: Per-type logic — compares hashes, downloads to temp DB via `downloadAndPopulateDB()`, ensures target exists, performs `hotSwap()`, updates local hash. Returns a `TypeSyncResult`: `UPDATED` (database replaced), `UNCHANGED` (hash matches), `SKIPPED` (no remote hash for the type, or the consumer turned not ready) or `FAILED` (download, target creation or hot-swap error). `synchronize()` maps it to the type's `status`, so an error is never reported as `ready`.

**`downloadAndPopulateDB()`**: Streams IOC documents from the indexer in batches of `m_iocSyncBatchSize` via `streamIocsByType()`, passing `IOC_ENRICHMENT_CONSUMER_ID` for consumer validation. Returns `bool` (false if consumer not ready). Each document's key is normalized to lowercase. Values are stored via `ioc::kvdb::details::updateValueInDB()` which appends to arrays if the key already exists. On consumer-not-ready or download failure, rolls back the temp database.

### `SyncedIOCDatabase` (internal class in iocsync.cpp)

Tracks per-type sync state with JSON serialization:

```json
{ "ioc_type": "connection", "last_data_hash": "abc123...", "last_successful_update": 1735689600 }
```

## CMake Targets

| Target | Type | Alias | Description |
|--------|------|-------|-------------|
| `iocsync_iiocsync` | INTERFACE | `iocsync::iiocsync` | Public interface (`IIocSync`) |
| `iocsync_iocsync` | STATIC | `iocsync::iocsync` | Implementation (links `iockvdb::ikvdb`, `wIndexerConnector::iwIndexerConnector`, `store::istore`) |
| `iocsync_mocks` | INTERFACE | `iocsync::mocks` | GMock mock of `IIocSync` (`ENGINE_BUILD_TEST`) |
| `iocsync_utest` | Executable | — | Unit tests (`ENGINE_BUILD_TEST`) |

## Testing

`iocsync_status_test.cpp` (`iocsync_utest`) covers the status snapshot and failure reporting with mocked store, indexer connector and KVDB manager: initial status, failed cycles marking unsynced types `FAILED`, a failed per-type download reported `FAILED` while the old version stays available, a successful per-type sync reported `READY`, a type with no remote hash and no version reported `FAILED`, an index-check error retried then failing the cycle, a missing IOC index not retried, and restoring `last_successful_update` from the store. `errorSummary_test.cpp` (same executable) covers `summarizeError()`: a 429 circuit-breaker body reduced to status, type and a short reason; a message without a body unchanged; an unparseable body dropped; a plain-string `error` kept; a long message bounded.

## Consumers

| Consumer | Dependency | Usage |
|----------|------------|-------|
| **main.cpp** | `iocsync::iocsync` | Creates `IocSync`, registers `requestShutdown()` in the exit handler and schedules `ioc-sync-task` |
| **api/status** | `IIocSync` | `GET /status` reports `getIocStatus()` per IOC type |

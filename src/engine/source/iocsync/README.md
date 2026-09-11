# IOC Sync — Indicator of Compromise Synchronization

## Overview

`iocsync` keeps local IOC databases up to date with the remote Wazuh Indexer. It implements a **hash-based change detection** strategy: for each IOC type, a remote hash is compared against the locally stored one and, when it has moved, the full dataset is downloaded into a staging database and promoted with an **atomic hot-swap** via `iockvdb`.

The module runs as a periodic task and is designed so that readers of the IOC databases experience zero downtime during updates.

### What moved out

The download itself — the PIT, `search_after` pagination, consumer validation, the per-type hash
manifest read — used to live in `wiconnector` and be driven from here. It is now one
`ContentRegister` per IOC type over `shared_modules/content_manager`, the same library the
Vulnerability Detection module uses. The engine-specific half (topic configuration and the sink)
lives in [`cmcontent`](../cmcontent/README.md).

What stayed here is what is genuinely IOC-specific: which types are tracked, what their persisted
state looks like, and how a cycle's outcome becomes `IocTypeStatus`.

## Architecture

```
                ┌──────────────┐
                │   Scheduler  │  (periodic trigger)
                └──────┬───────┘
                       │ synchronize()
                       ▼
              ┌────────────────────┐
              │      IocSync       │
              │                    │
              │  pre-flight  ──────┼──► wiconnector ──► wazuh-indexer
              │  (ready? index?)   │
              │                    │
              │  for each type:    │
              │   runOnce() ───────┼──► ContentRegister ──► wazuh-indexer
              │                    │     (content_manager)
              │                    │            │ IContentSink
              │                    │            ▼
              │                    │     ┌──────────────┐
              │                    │     │ IocTypeSink  │
              │                    │     │ (cmcontent)  │
              │                    │     └──────┬───────┘
              │                    │            │ add / put / hotSwap
              │                    │            ▼
              │                    │     ┌──────────────┐
              │                    │     │ IKVDBManager │
              │  fold outcome into │     │  (iockvdb)   │
              │  state + status    │     └──────────────┘
              └─────────┬──────────┘
                        ▼
               ┌────────────────┐
               │  store::IStore │  (persist sync state)
               └────────────────┘
```

### Synchronization Flow

1. **Pre-flight**: verify the IOC consumer is ready and has data (`local_offset != 0`), and that the IOC data index exists. Either failing short-circuits the whole cycle.
2. **For each IOC type**:
   - If the target database is **physically missing**, ask for a forced full reload — a matching hash says the *content* has not moved, not that the database still exists.
   - Run one content cycle, wrapped in `executeWithRetry`.
   - The cycle compares the remote hash against the stored one and, if it moved, pages documents into `IocTypeSink`, which stages them in a temporary database and hot-swaps it into place.
   - Fold the outcome into the type's state and status.
3. **Persist state** once, if any type was updated.

## Key Concepts

### Consistency: validated inside the snapshot

Data inconsistency while the wazuh-indexer is mid-update is prevented by validating the CTI consumer
**inside the same Point-In-Time the content is read from**. That check lives in the content manager,
not here: checking before opening the snapshot leaves a window in which the indexer starts rewriting
between the check and the read.

`iocsync` keeps a cheap **pre-flight** check (`isConsumerReadyForSync`) before entering the loop. It
is not the guarantee — it is an optimisation that short-circuits all six registrations at once and
additionally covers `local_offset != 0`, which the in-snapshot check does not.

### Hash-Based Change Detection

Each IOC type has a remote hash published in the `__ioc_type_hashes__` manifest. `IocSync` stores the
last known hash per type in `SyncedIOCDatabase::m_lastDataHash`, and the content cycle only downloads
when the two differ — minimising network and disk I/O.

Two manifest shapes are accepted: the current one nesting every type under `type_hashes`, and an
older flat one. The first pointer that resolves wins, so both keep working without a migration.

### Staging and Hot-Swap

`IocTypeSink` stages into a database named `iocsync_<type>_staging`, writes every document into it
with a lower-cased key, and only then hot-swaps it onto the live database. Readers never observe a
half-written database, because the database they read is only ever swapped whole. Every failure
path — a page that cannot be decoded, a failed swap, an aborted cycle, or a later session finding
an abandoned staging database — removes it.

The name is fixed per type rather than randomised. Two cycles for one type can never run at once
(the content manager refuses the second), so a random suffix bought nothing — and it cost the only
thing that matters after a crash: a name that existed solely in the memory of the process that
created it can never be found again, so every interrupted sync leaked a database permanently. A
fixed name is recoverable, and `beginSession` reclaims a leftover before creating its own.

### Weak Pointer Resource Model

All external dependencies (`IWIndexerConnector`, `IKVDBManager`, `store::IStore`) are held as `weak_ptr`. This allows the sync module to be safely outlived by the resources it depends on and provides clear error messages if a resource has been destroyed.

### Retry Logic

The pre-flight probes and each `runOnce()` are wrapped in `base::utils::executeWithRetry` with
configurable `m_attempts` (default: 3) and `m_waitSeconds` (default: 5). `runOnce()` is `noexcept`
and reports by status rather than throwing, so the wrapper's lambda rethrows on a retryable outcome
to drive it. The existing `analysisd.ioc_indexer_connector_{max_retries,retry_interval}` settings keep
their meaning and now guard the whole cycle instead of a single query. The shutdown flag is passed to
`executeWithRetry`, which checks it before each attempt and during inter-retry sleep.

### Graceful Shutdown

`IocSync` supports responsive shutdown via `requestShutdown()`:

- Sets `m_shutdownRequested` (`std::atomic<bool>`) to `true`.
- `synchronize()` checks the flag before starting, before each IOC type iteration, and in the outer `catch` block.
- `executeWithRetry` aborts early when the flag is set.
- It also calls `ContentRegister::requestStop()` on every registration, so an in-flight page loop winds down at its next checkpoint. That iteration takes only `m_registrationsMutex`, never `m_mutex` — the cycle being interrupted is holding `m_mutex`.
- An interrupted cycle never promotes: the staging database is discarded rather than hot-swapped, so a partially-downloaded dataset cannot go live.
- The module is registered in the exit handler in `main.cpp`; on SIGINT/SIGTERM the cycle aborts within one page round-trip.

### Registration Lifetime

Registrations are derived state over `m_databasesState`, held in a map guarded by the same `m_mutex`.
`~ContentRegister` blocks until any in-flight cycle for that topic has drained, and that cycle reaches
back into this object through the token store — so `removeIOCTypeFromSync()` moves the registration
out of the map under the lock and lets it destruct **after** the lock is released.

### Persistence

Sync state is stored in the engine's internal store under `iocsync/status/0` as a JSON array of
`SyncedIOCDatabase` entries. **The document shape and field names are unchanged**, so an upgrade
needs no migration and a downgrade reads it back.

The content manager's token store for this module is an adapter over that in-memory state rather
than a second writer into `store::IStore`: `synchronize()` dumps the whole document once per cycle,
and a second writer would race it over an array it does not own.

## Directory Structure

```
iocsync/
├── CMakeLists.txt
├── README.md
├── interface/iocsync/
│   └── iiocsync.hpp              # IIocSync interface + IocTypeStatus
├── include/iocsync/
│   └── iocsync.hpp               # IocSync — concrete implementation
├── src/
│   └── iocsync.cpp               # Full implementation + SyncedIOCDatabase class
└── test/
    ├── mocks/iocsync/
    │   └── mockIocSync.hpp       # GMock mock (MockIocSync)
    └── src/unit/
        └── iocsync_status_test.cpp
```

## Public Interface

### `IIocSync` (iiocsync.hpp)

```cpp
namespace ioc::sync {
class IIocSync {
    virtual void synchronize() = 0;
    virtual void requestShutdown() = 0;
    virtual std::vector<IocTypeStatus> getIocStatus() const = 0;
    virtual void requestOnDemandUpdate(std::string_view iocType = {}) = 0;
};
}
```

- `synchronize()` performs a full sync cycle for all configured IOC types.
- `requestShutdown()` signals the module to abort as soon as possible (idempotent, thread-safe).
- `getIocStatus()` returns a wait-free snapshot, served by `GET /status`.
- `requestOnDemandUpdate()` queues a cycle off the scheduler and returns immediately; it backs
  `POST /content/ioc/sync`.

## Implementation Details

### `IocSync` (iocsync.hpp / iocsync.cpp)

**Constructor**: takes `shared_ptr<IWIndexerConnector>`, `shared_ptr<IKVDBManager>`,
`shared_ptr<store::IStore>` (stored as weak pointers), the indexer connection settings, retry
tunables and `cmcontent::Options`. On first run (no persisted state) it initializes the sync list
with every type from `ioc::kvdb::details::getSupportedIocTypes()`. In both cases it builds one
content registration per tracked type.

`indexerConnection` is the **same** JSON `main.cpp` builds the indexer connector from, so there is no
second place to configure the indexer.

**Key Members**:

| Member | Type | Purpose |
|--------|------|---------|
| `m_indexerPtr` | `weak_ptr<IWIndexerConnector>` | Pre-flight probes |
| `m_kvdbiocManagerPtr` | `weak_ptr<IKVDBManager>` | Local IOC database manager |
| `m_store` | `weak_ptr<store::IStore>` | Persistence for sync state |
| `m_databasesState` | `vector<SyncedIOCDatabase>` | Per-type sync state (type, hash, timestamp, status) |
| `m_registrations` | `unordered_map<string, Registration>` | One sink + `ContentRegister` per type |
| `m_mutex` | `shared_mutex` | Protects `m_databasesState` and sync operations |
| `m_registrationsMutex` | `mutex` | Guards only the registration container's iteration |
| `m_attempts` / `m_waitSeconds` | `size_t` | Retry budget for remote operations |
| `m_shutdownRequested` | `atomic<bool>` | Abort flag checked at multiple points |

**`syncIOCType()`**: per-type logic — forces a full reload when the target database is physically
missing, runs one cycle with retry, and reports whether the persisted state changed.

**`loadToken()` / `storeToken()`**: read and write a type's hash in the in-memory state. `storeToken`
deliberately does not touch the store; `synchronize()` performs the single write per cycle.

### `SyncedIOCDatabase` (internal class in iocsync.cpp)

Tracks per-type sync state with JSON serialization:

```json
{ "ioc_type": "connection", "last_data_hash": "abc123...", "last_successful_update": 1700000000 }
```

## CMake Targets

| Target | Type | Alias | Description |
|--------|------|-------|-------------|
| `iocsync_iiocsync` | INTERFACE | `iocsync::iiocsync` | Public interface (`IIocSync`) |
| `iocsync_iocsync` | STATIC | `iocsync::iocsync` | Implementation (links `iockvdb::ikvdb`, `wIndexerConnector::iwIndexerConnector`, `store::istore`, `cmcontent::cmcontent`) |
| `iocsync_mocks` | INTERFACE | `iocsync::mocks` | `MockIocSync` for downstream consumers |
| `iocsync_utest` | Executable | — | Unit tests |

## Testing

- **Unit tests** (`test/src/unit/iocsync_status_test.cpp`) — first-setup initialisation, state restore
  from the store including `last_successful_update`, availability derived from the KVDB, and the
  status transitions the API reports.
- The download and promotion behaviour is covered where it now lives: `cmcontent_utest`
  (`IocTypeSink`: staging, lower-cased keys, malformed documents skipped, hot-swap, every rollback
  path) and `content_manager_utest` / `content_manager_ctest` (the cycle, consumer readiness, token
  rules).
- **Mock** (`test/mocks/iocsync/mockIocSync.hpp`) — `MockIocSync` for downstream consumers of `IIocSync`.

## Consumers

| Consumer | Dependency | Usage |
|----------|------------|-------|
| **main.cpp** | `iocsync::iocsync` | Creates `IocSync` and triggers periodic synchronization |
| **api::status** | `iocsync::iiocsync` | Reports per-type sync status through `GET /status` |
| **api::contentsync** | `iocsync::iiocsync` | Backs `POST /content/ioc/sync` |

# cmsync

## Overview

The **cmsync** module is the **Content Manager Synchronization Service**. It keeps the engine's local content (namespaces, policies, decoders, integrations, KVDBs) in sync with the wazuh-indexer. On each synchronization cycle it:

1. Checks whether each configured remote *space* has changed (the indexer's `space.hash.sha256` against the hash of the space's current route).
2. Downloads updated content from the wazuh-indexer via `wiconnector`.
3. Imports it into a new local namespace via `cmcrud`.
4. Hot-swaps the router route to point at the fresh namespace.
5. Cleans up the old namespace.

The module persists its own state (which spaces are tracked and their current namespace IDs) in the internal `store`, so it survives engine restarts. By default it tracks the `standard` and `custom` spaces. It also publishes a per-space status snapshot (`getSpacesStatus()`) that the engine's `GET /status` handler (`api/status`) reports.

Operator view (spaces, the synchronization process, the `analysisd.cm_sync_*` and `analysisd.cmsync_indexer_connector_*` settings): the engine's [Synchronization process](../../../../docs/ref/modules/engine/README.md#synchronization-process) and [Synchronization settings](../../../../docs/ref/modules/engine/configuration.md#synchronization).

## Architecture

```
                    ┌─────────────────────────┐
                    │        main.cpp          │
                    │ (scheduler: cm-sync-task)│
                    └────────────┬─────────────┘
                                 │  synchronize()
                                 ▼
                    ┌─────────────────────────┐
                    │         CMSync           │
                    │                          │
                    │  • SyncedNamespace state │
                    │  • Hash-based diffing    │
                    │  • Download & enrich     │
                    │  • Route hot-swap        │
                    │  • Rollback on failure   │
                    └──┬────┬────┬────┬────────┘
                       │    │    │    │
          ┌────────────┘    │    │    └──────────────┐
          ▼                 ▼    ▼                   ▼
  ┌──────────────┐  ┌──────────┐ ┌──────────┐ ┌──────────┐
  │ wiconnector  │  │  cmcrud  │ │  router  │ │  store   │
  │ (indexer     │  │ (CRUD    │ │ (Orches- │ │ (persist │
  │  queries)    │  │  service)│ │  trator) │ │  state)  │
  └──────────────┘  └──────────┘ └──────────┘ └──────────┘
         │
         ▼
  ┌──────────────┐
  │wazuh-indexer │
  └──────────────┘
```

## Key Concepts

### Consumer Validation for Consistency

To prevent partial policy downloads when the wazuh-indexer is mid-update, `CMSync` implements **consumer validation via Point-In-Time (PIT)**. The `ready`/`running`/`failed` status is the one the Content Manager plugin of the wazuh-indexer writes in `.wazuh-cti-consumers`.

0. **Pre-flight check** (spaces with a consumer id — only `standard`, `cti:catalog:consumer:ruleset`, by default): `isConsumerReadyForSync()` reads the consumer document directly and requires `status == "ready"` and `local_offset != 0` (at least one CTI update loaded). Otherwise the space is skipped with `Synchronization skipped for space '…' because wazuh-indexer consumer '…' is not ready for sync`.
   - A missing consumer document, or a missing `.wazuh-cti-consumers` index (404 `index_not_found_exception`, a fresh indexer), also counts as "not ready", without retries.
   - Any other error (transport, 429, 5xx, 401/403) is raised, so `executeWithRetry()` retries it and the real cause is logged.

1. **Hash check phase**: `getPolicyHashAndEnabledFromRemote()` passes the space's consumer id (`STANDARD_RULESET_CONSUMER_ID` for `standard`; none for `custom`, which skips the PIT validation) to the indexer connector.
   - The connector creates a multi-index PIT (policy indices + `.wazuh-cti-consumers`).
   - It validates the consumer is in the `ready` status within that PIT snapshot.
   - If ready: returns the hash and enabled status (and the check is consistent).
   - If not ready: returns `std::nullopt` → sync cycle is skipped.

2. **Download phase**: `downloadAndEnrichNamespace()` → `downloadNamespace()` calls `getPolicy()` with the same consumer ID.
   - The connector again validates the consumer is ready within a NEW PIT snapshot.
   - If ready: retrieves full policy resources within that PIT.
   - If not ready: returns `std::nullopt` → nothing is imported and the space keeps its current route this cycle.

This two-phase validation ensures the indexer is NOT actively updating policy/decoder/KVDB assets before or during the download.

### Synchronization Lifecycle

The `synchronize()` method iterates through all tracked spaces and handles four cases:

| Case | Remote State | Local Route | Action |
|---|---|---|---|
| **1** | Policy **disabled**, or with no integrations or no root decoder | Route exists | Delete route and namespace, set dummy ID (no route: nothing to do) |
| **2** | Policy enabled, hash **unchanged** | Route enabled | Skip (no-op) |
| **3** | Policy enabled | No route exists | Download → enrich → create route |
| **4** | Policy enabled, hash **changed** (or route not enabled) | Route exists | Download → enrich → hot-swap → delete old NS |

Before these cases, a space that does not exist in the indexer is skipped with a warning. Failures at any step are caught per space (status `FAILED`, warning logged) so that one space's error does not block synchronization of the others.

### SyncedNamespace

An internal class (defined in `cmsync.cpp`) that tracks the state of a single synchronized space:

| Field | Persisted as | Description |
|---|---|---|
| `m_originSpace` | `origin_space` | Remote space name in the wazuh-indexer (e.g. `"standard"`, `"custom"`) |
| `m_routeName` | — | Derived router route name (`"cmsync_<space>"`) |
| `m_nsId` | `namespace_id` | Local `NamespaceId` in `cmstore` (`dummy_ns_id`, `DUMMY_NAMESPACE_ID`, before the first sync or after a disable) |
| `m_consumerId` | `consumer_id` | Optional CTI consumer document id validated during sync |
| `m_lastSuccessfulUpdate` | `last_successful_update` | Unix time of the last successful sync |
| `m_enabled` | `enabled` | Remote policy enabled flag, as last read |
| `m_disabledByPolicy` | `disabled_by_policy` | Last successful policy read was disabled (no route by decision) |
| `m_syncStatus`, `m_available`, `m_hash` | — | Live state, not persisted: the sync status (`READY`/`UPDATING`/`FAILED`, set by `synchronize()`), and the route's presence and hash (re-derived from the router at construction and on each sync) |

`SyncedNamespace` serializes to/from JSON for persistence in the internal store under the key `cmsync/status/0`.

### Download and Enrich

`downloadAndEnrichNamespace()` performs a two-phase operation with consumer validation:

1. **Download** — fetches KVDBs, decoders, integrations, and the policy from the wazuh-indexer via `wiconnector::getPolicy(consumerIdToValidate=STANDARD_RULESET_CONSUMER_ID)`, then imports them into a new namespace via `cmcrud::importNamespace()` with `softValidation = true`.
   - If the consumer is not ready (returns `std::nullopt`), download is skipped and `std::nullopt` is returned (sync cycle aborts gracefully).
2. **Enrich** — placeholder for adding local-only assets (outputs, default filters) that don't come from the indexer.

The target namespace gets a unique random ID (`cmsync_<space>_<hex4>`, regenerated while it already exists). If the import throws, `downloadNamespace()` deletes the namespace; if the route update then fails, `synchronize()` deletes it.

### Route Management

`syncNamespaceInRoute()` ensures the router has an up-to-date entry:

- If the route **already exists** → `hotSwapNamespace()` atomically replaces the backing namespace.
- If the route **does not exist** → takes the lowest priority from 1 to `EntryPost::maxPriority()` that no route uses and creates a new `EntryPost`.

### Retry With Back-off

Remote operations (`existsPolicy`, `isConsumerReadyForSync`, `getPolicyHashAndEnabled`, `getPolicy`) are wrapped in `base::utils::executeWithRetry()`, which retries up to `m_attempts` times with `m_waitSeconds` between each attempt (`analysisd.cmsync_indexer_connector_max_retries`, default 3, and `analysisd.cmsync_indexer_connector_retry_interval`, default 5, read in `main.cpp`). The shutdown flag `m_shutdownRequested` is passed to `executeWithRetry`, which checks it before each attempt and splits inter-retry sleep into 1-second chunks for responsive cancellation.

### Early Retry While a Space Has No Route

When a space ends a cycle without a route and its policy is not disabled (the indexer failed, or the content is not published or the CTI consumer not ready yet), `synchronize()` returns `true`. The `cm-sync-task` in `main.cpp` then runs the next cycle after `analysisd.cm_sync_retry_interval` seconds (default 30) instead of `analysisd.cm_sync_interval` (default 120), until every space has a route or a disabled policy. The retry interval is capped at `analysisd.cm_sync_interval`. "Disabled policy" is the last successful policy read (`disabled_by_policy` in the state document), so a cycle that fails before reading the policy does not change it. A space that keeps its previous route after a failed cycle does not trigger it: the old route keeps processing events.

### Logging of a Missing Space

A space the indexer has no policy for is logged once per absence, at the level its effect deserves: `WARNING` when the engine still serves a route for it (the deployed content is kept and nothing can refresh it until the space is published again), `INFO` when the space was never deployed (first start before the indexer loads its content). The following cycles log it at `DEBUG` until the space appears, which is logged at `INFO`. The absence flag lives in memory only; a restart logs the first miss again.

A cycle that fails on the indexer (for example the 3 attempts of the space check after a boot, before the indexer is up) leaves the space `FAILED` in the status snapshot and keeps the deployed route. The next cycle that reaches the indexer clears it: `INFO` "back in sync ... the deployed content is current" when the hash is unchanged, or the usual "Changes detected ... Successfully synchronized" lines when it is not.

### Graceful Shutdown

`CMSync` supports responsive shutdown via `requestShutdown()`:

- Sets `m_shutdownRequested` (`std::atomic<bool>`) to `true`.
- `synchronize()` checks the flag at the start of each space iteration, before reading the policy hash, and before the download, and returns `false` when it is set.
- `executeWithRetry` throws (`… aborted before attempt N`) when the flag is set.
- An exception during `getPolicy()` (for example after `WIndexerConnector::requestShutdown()`) is raised before anything is imported; the per-space handler marks the space `FAILED` and the next iteration's flag check ends the loop.
- The module is registered in the exit handler in `main.cpp`; on SIGINT/SIGTERM, `requestShutdown()` is called and the sync cycle aborts within one batch round-trip.

### Weak-Pointer Resource Model

All four dependencies (`IWIndexerConnector`, `ICrudService`, `IStore`, `IRouterAPI` — the `router::Orchestrator` in `main.cpp`) are stored as `std::weak_ptr` and locked on entry via `base::utils::lockWeakPtr()`, throwing if the underlying object has been destroyed.

### State Persistence

The sync state (array of `SyncedNamespace` objects) is persisted in the internal `store` at key `cmsync/status/0`. On construction, `CMSync` either loads existing state or initializes with the default spaces (`"standard"` with its consumer id, `"custom"`) and writes the initial state.

## Directory Structure

```
cmsync/
├── CMakeLists.txt
├── README.md
├── interface/cmsync/
│   └── icmsync.hpp                  # ICMSync base interface
├── include/cmsync/
│   └── cmsync.hpp                   # CMSync concrete implementation header
├── src/
│   └── cmsync.cpp                   # Implementation + SyncedNamespace class
└── test/
    ├── mocks/cmsync/
    │   └── mockCMSync.hpp           # GMock mock (MockCMSync)
    ├── src/unit/
    │   └── cmsync_test.cpp          # Unit tests
    └── src/component/
        └── cmsync_test.cpp          # Component tests (currently disabled)
```

## Public Interface

### `ICMSync` (namespace `cm::sync`)

```cpp
struct SpaceStatus
{
    std::string name;                 // "standard", "custom"
    bool available {false};           // a route exists for the space
    bool enabled {false};             // remote policy enabled flag
    base::SyncStatus status {base::SyncStatus::READY};
    std::string hash;                 // hash of the deployed route
    uint32_t lastSuccessfulUpdate {0};
};

class ICMSync
{
public:
    virtual ~ICMSync() = default;
    virtual void requestShutdown() = 0;
    virtual std::vector<SpaceStatus> getSpacesStatus() const = 0;
};
```

`getSpacesStatus()` reads a lock-free snapshot (`base::StatusSnapshot`) rebuilt by `synchronize()` from the cached per-space state; it never queries the router.

### `CMSync`

```cpp
class CMSync : public ICMSync
{
public:
    CMSync(const std::shared_ptr<wiconnector::IWIndexerConnector>& indexerPtr,
           const std::shared_ptr<cm::crud::ICrudService>& cmcrudPtr,
           const std::shared_ptr<store::IStore>& storePtr,
           const std::shared_ptr<router::IRouterAPI>& routerPtr,
           size_t attempts,
           size_t waitSeconds);
    ~CMSync() override;

    /**
     * @brief Perform synchronization of all configured namespaces.
     *
     * Iterates each tracked space, checks for remote changes, downloads
     * updated content, enriches it, and updates the router routes.
     *
     * @return true if a space is left without a route although its policy is not disabled.
     */
    bool synchronize();

    /**
     * @brief Signal the module to abort as soon as possible.
     *
     * Idempotent, thread-safe. Sets an internal flag checked at multiple
     * checkpoints within synchronize().
     */
    void requestShutdown() override;
    std::vector<SpaceStatus> getSpacesStatus() const override;
};

// Next-cycle delay while a space has no route: min(retry, sync); main.cpp treats 0 as "no early retry".
constexpr std::size_t earlyRetryInterval(std::size_t retryInterval, std::size_t syncInterval);
```

## Implementation Details

### Constructor

1. Checks if the store document `cmsync/status/0` exists.
2. **If yes** → calls `loadStateFromStore()` to restore `m_namespacesState`, then reconciles each space's live route state (present, hash) with the router.
3. **If no** (first setup) → adds `"standard"` and `"custom"` spaces and dumps state to store.

### `synchronize()` — Main Loop

```
for each SyncedNamespace in m_namespacesState:
  0. existsEntry(route)                  → refresh availability (router is local)
  1. existSpaceInRemote(space)           → skip if not found
  2. isConsumerReadyForSync(consumer)    → skip if not ready (spaces with a consumer id)
  3. getPolicyHashAndEnabledFromRemote() → get (hash, enabled), or skip on nullopt
  4. Check current route config          → get (enabled, nsId, routeHash) or nullopt
  5. Evaluate case (1-4) based on remote/local state
  6. If sync needed:
     a. downloadAndEnrichNamespace()     → new NamespaceId (nullopt: skip)
     b. syncNamespaceInRoute()           → hot-swap or create route
     c. Update nsState, dump to store
     d. Delete old namespace
return true if any space has no route and is not disabled by policy
```

### Private Methods

| Method | Purpose |
|---|---|
| `existSpaceInRemote(space)` | Checks policy existence in indexer with retry |
| `downloadNamespace(origin, dst, consumerId)` | Downloads policy resources via `getPolicy(consumerIdToValidate)` and imports into namespace. Returns `bool` (false if consumer not ready). |
| `getPolicyHashAndEnabledFromRemote(space, consumerId)` | Gets SHA-256 hash and enabled flag with retry, passing consumer validation. Returns `std::optional` (nullopt if consumer not ready). |
| `downloadAndEnrichNamespace(origin, consumerId)` | Generates unique NS ID, downloads, enriches (placeholder), returns NS ID or `std::nullopt` |
| `syncNamespaceInRoute(nsState, newNsId)` | Hot-swaps or creates router route |
| `addSpaceToSync(space)` | Adds a space to the tracked list (currently not called) |
| `removeSpaceFromSync(space)` | Removes a space from the tracked list (currently not called) |
| `updateSpacesStatusSnapshot()` | Rebuilds and publishes the `SpaceStatus` snapshot |
| `loadStateFromStore()` | Deserializes `SyncedNamespace` array from store |
| `dumpStateToStore()` | Serializes `SyncedNamespace` array to store |

### Anonymous-Namespace Helpers

| Helper | Purpose |
|---|---|
| `generateNamespaceId(space)` | Returns `"cmsync_<space>_<random_hex4>"` |

## CMake Targets

| Target | Type | Alias | Links |
|---|---|---|---|
| `cmsync_icmsync` | INTERFACE | `cmsync::icmsync` | `base` |
| `cmsync_cmsync` | STATIC | `cmsync::cmsync` | `base`, `cmsync::icmsync`, `cmcrud::icmcrud`, `store::istore`, `router::irouter`, `wIndexerConnector::iwIndexerConnector` |
| `cmsync_mocks` | INTERFACE | `cmsync::mocks` | `GTest::gmock`, `cmsync::icmsync` |
| `cmsync_utest` | Executable | — | `GTest::gtest_main`, `GTest::gmock`, `cmsync::cmsync`, `router::mocks`, `store::mocks`, `wIndexerConnector::mocks`, `cmcrud::mocks` |

Component tests (`cmsync_ctest`) are defined but currently commented out in the CMakeLists.

## Testing

- **Unit tests** (`test/src/unit/cmsync_test.cpp`) — test the full lifecycle with all four dependencies mocked (strict mocks): constructor initialisation (first-setup vs. restore), state serialisation to/from store, the `synchronize()` flow for each of the four cases, `requestShutdown()` abort behaviour (before loop, mid-loop, before download, hot-swap failure rollback), the early-retry return value and `earlyRetryInterval()`, and the status snapshot.
- **Component tests** (`test/src/component/cmsync_test.cpp`) — exist in the tree but are currently disabled in the build.
- **Mock** (`test/mocks/cmsync/mockCMSync.hpp`) — provides `MockCMSync` for downstream consumers that mock the `ICMSync` interface (`api/status` tests).

## Consumers

| Module | Dependency | Role |
|---|---|---|
| `main.cpp` | `cmsync::cmsync` | Creates the `CMSync` instance (only when event processing is enabled) and runs `synchronize()` in the `cm-sync-task` scheduler task (`analysisd.cm_sync_interval`, early retry `analysisd.cm_sync_retry_interval`) |
| `api/status` | `cmsync::icmsync` | Reports `getSpacesStatus()` in `GET /status` |

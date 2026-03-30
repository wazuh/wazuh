# cmsync

## Overview

The **cmsync** module is the **Content Manager Synchronization Service**. It keeps the engine's local content (namespaces, policies, decoders, integrations, KVDBs) in sync with the wazuh-indexer. On each synchronization cycle it:

1. Checks whether each configured remote *space* has changed (comparing SHA-256 hashes).
2. Downloads updated content from the wazuh-indexer via `wiconnector`.
3. Imports it into a new local namespace via `cmcrud`.
4. Hot-swaps the router route to point at the fresh namespace.
5. Cleans up the old namespace.

The module persists its own state (which spaces are tracked and their current namespace IDs) in the internal `store`, so it survives engine restarts. By default it tracks the `standard` and `custom` spaces.

## Architecture

```
                    ┌─────────────────────────┐
                    │        main.cpp          │
                    │   (periodic scheduler)   │
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
  │ (indexer     │  │ (CRUD    │ │ (route   │ │ (persist │
  │  queries)    │  │  service)│ │  mgmt)   │ │  state)  │
  └──────────────┘  └──────────┘ └──────────┘ └──────────┘
         │
         ▼
  ┌──────────────┐
  │wazuh-indexer │
  └──────────────┘
```

## Key Concepts

### Synchronization Lifecycle

The `synchronize()` method iterates through all tracked spaces and handles four cases:

| Case | Remote State | Local Route | Action |
|---|---|---|---|
| **1** | Policy **disabled** | Route exists | Delete route and namespace, set dummy ID |
| **2** | Policy enabled, hash **unchanged** | Route enabled | Skip (no-op) |
| **3** | Policy enabled | No route exists | Download → enrich → create route |
| **4** | Policy enabled, hash **changed** | Route exists | Download → enrich → hot-swap → delete old NS |

Failures at any step are caught per-namespace so that one space's error does not block synchronization of the others.

### SyncedNamespace

An internal class (defined in `cmsync.cpp`) that tracks the state of a single synchronized space:

| Field | Description |
|---|---|
| `m_originSpace` | Remote space name in the wazuh-indexer (e.g. `"standard"`, `"custom"`) |
| `m_routeName` | Derived router route name (`"cmsync_<space>"`) |
| `m_nsId` | Local `NamespaceId` in `cmstore` (or `DUMMY_NAMESPACE_ID` before first sync) |

`SyncedNamespace` serializes to/from JSON for persistence in the internal store under the key `cmsync/status/0`.

### Download and Enrich

`downloadAndEnrichNamespace()` performs a two-phase operation:

1. **Download** — fetches KVDBs, decoders, integrations, and the policy from the wazuh-indexer via `wiconnector::getPolicy()`, then imports them into a new namespace via `cmcrud::importNamespace()` with `softValidation = true`.
2. **Enrich** — placeholder for adding local-only assets (outputs, default filters) that don't come from the indexer.

The target namespace gets a unique random ID (`cmsync_<space>_<hex4>`) to avoid collisions. On failure the namespace is rolled back.

### Route Management

`syncNamespaceInRoute()` ensures the router has an up-to-date entry:

- If the route **already exists** → `hotSwapNamespace()` atomically replaces the backing namespace.
- If the route **does not exist** → finds the first available priority and creates a new `EntryPost`.

### Retry With Back-off

Remote operations (`existsPolicy`, `getPolicy`, `getPolicyHashAndEnabled`) are wrapped in `base::utils::executeWithRetry()`, which retries up to `m_attemps` times with `m_waitSeconds` between each attempt.

### Weak-Pointer Resource Model

All four dependencies (`IWIndexerConnector`, `ICrudService`, `IStore`, `IRouterAPI`) are stored as `std::weak_ptr` and locked on entry via `base::utils::lockWeakPtr()`, throwing if the underlying object has been destroyed.

### State Persistence

The sync state (array of `SyncedNamespace` objects) is persisted in the internal `store` at key `cmsync/status/0`. On construction, `CMSync` either loads existing state or initializes with the default spaces (`"standard"`, `"custom"`) and writes the initial state.

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
│   └── cmsync.cpp                   # Full implementation (~560 lines) + SyncedNamespace class
└── test/
    ├── mocks/cmsync/
    │   └── mockcmsync.hpp           # GMock mocks
    ├── src/unit/
    │   └── cmsync_test.cpp          # Unit tests
    └── src/component/
        └── cmsync_test.cpp          # Component tests (currently disabled)
```

## Public Interface

### `ICMSync` (namespace `cm::sync`)

```cpp
class ICMSync
{
public:
    virtual ~ICMSync() = default;
};
```

A minimal base interface. The concrete `CMSync` class exposes the full API.

### `CMSync`

```cpp
class CMSync : public ICMSync
{
public:
    CMSync(const std::shared_ptr<wiconnector::IWIndexerConnector>& indexerPtr,
           const std::shared_ptr<cm::crud::ICrudService>& cmcrudPtr,
           const std::shared_ptr<store::IStore>& storePtr,
           const std::shared_ptr<router::IRouterAPI>& routerPtr,
           size_t attemps,
           size_t waitSeconds);
    ~CMSync() override;

    /**
     * @brief Perform synchronization of all configured namespaces.
     *
     * Iterates each tracked space, checks for remote changes, downloads
     * updated content, enriches it, and updates the router routes.
     */
    void synchronize();
};
```

## Implementation Details

### Constructor

1. Checks if the store document `cmsync/status/0` exists.
2. **If yes** → calls `loadStateFromStore()` to restore `m_namespacesState`.
3. **If no** (first setup) → adds `"standard"` and `"custom"` spaces and dumps state to store.

### `synchronize()` — Main Loop

```
for each SyncedNamespace in m_namespacesState:
  1. existSpaceInRemote(space)           → skip if not found
  2. getPolicyHashAndEnabledFromRemote() → get (hash, enabled)
  3. Check current route config          → get (enabled, nsId, routeHash) or nullopt
  4. Evaluate case (1-4) based on remote/local state
  5. If sync needed:
     a. downloadAndEnrichNamespace()     → new NamespaceId
     b. syncNamespaceInRoute()           → hot-swap or create route
     c. Update nsState, dump to store
     d. Delete old namespace
```

### Private Methods

| Method | Purpose |
|---|---|
| `existSpaceInRemote(space)` | Checks policy existence in indexer with retry |
| `downloadNamespace(origin, dst)` | Downloads policy resources and imports into namespace via `cmcrud::importNamespace()` |
| `getPolicyHashAndEnabledFromRemote(space)` | Gets SHA-256 hash and enabled flag with retry |
| `downloadAndEnrichNamespace(origin)` | Generates unique NS ID, downloads, enriches (placeholder), returns NS ID |
| `syncNamespaceInRoute(nsState, newNsId)` | Hot-swaps or creates router route |
| `addSpaceToSync(space)` | Adds a space to the tracked list |
| `removeSpaceFromSync(space)` | Removes a space from the tracked list |
| `loadStateFromStore()` | Deserializes `SyncedNamespace` array from store |
| `dumpStateToStore()` | Serializes `SyncedNamespace` array to store |

### Anonymous-Namespace Helpers

| Helper | Purpose |
|---|---|
| `generateRouteName(space)` | Returns `"cmsync_<space>"` |
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

- **Unit tests** (`test/src/unit/cmsync_test.cpp`) — test the full lifecycle with all four dependencies mocked (strict mocks): constructor initialisation (first-setup vs. restore), state serialisation to/from store, and the `synchronize()` flow for each of the four cases.
- **Component tests** (`test/src/component/cmsync_test.cpp`) — exist in the tree but are currently disabled in the build.
- **Mock** (`test/mocks/cmsync/mockcmsync.hpp`) — provides `MockICmsync`, `MockICmsyncNSReader`, `MockICmsyncNS` for downstream consumers (the mock covers a broader store-oriented interface used in legacy code paths).

## Consumers

| Module | Dependency | Role |
|---|---|---|
| `main.cpp` | `cmsync::cmsync` | Creates the `CMSync` instance and invokes `synchronize()` on a periodic schedule |

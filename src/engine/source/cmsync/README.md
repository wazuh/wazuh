# cmsync

## Overview

The **cmsync** module is the **Content Manager Synchronization Service**. It keeps the engine's local content (namespaces, policies, decoders, filters, integrations, KVDBs) in sync with the wazuh-indexer. On each synchronization cycle it:

1. Asks the shared content manager to run one cycle per tracked remote *space*.
2. That cycle compares the remote SHA-256 hash against what is deployed and, if it moved, pages the content into `RulesetSpaceSink`.
3. The sink imports it into a new local namespace via `cmcrud`, hot-swaps the router route onto it, and deletes the old namespace.
4. `cmsync` folds the outcome into its persisted state and into the status the API reports.

The module persists its own state (which spaces are tracked and their current namespace IDs) in the internal `store`, so it survives engine restarts. By default it tracks the `standard` and `custom` spaces.

### What moved out

The download itself — the PIT, `search_after` pagination, consumer validation, per-space hash
retrieval — used to live in `wiconnector` and be driven from here. It is now one `ContentRegister`
per space over `shared_modules/content_manager`, the same library the Vulnerability Detection module
uses. The engine-specific half (topic configuration and the sink) lives in
[`cmcontent`](../cmcontent/README.md).

What stayed here is what is genuinely ruleset-specific: which spaces are tracked, how their state
document is written and read back, and how a cycle's outcome becomes `SpaceStatus`.

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
                    │  • one registration per  │
                    │    tracked space         │
                    │  • status snapshot       │
                    └──┬──────────┬────────────┘
                       │          │
         pre-flight ┌──┘          └──┐ runOnce()
                    ▼                ▼
          ┌──────────────┐   ┌────────────────────┐
          │ wiconnector  │   │  ContentRegister   │
          │ existsPolicy │   │ (content_manager)  │
          │ isConsumer…  │   └─────────┬──────────┘
          └──────┬───────┘             │ IContentSink
                 │                     ▼
                 │           ┌────────────────────┐
                 │           │ RulesetSpaceSink   │
                 │           │   (cmcontent)      │
                 │           └────┬──────────┬────┘
                 │                ▼          ▼
                 │         ┌──────────┐ ┌──────────┐
                 │         │  cmcrud  │ │  router  │
                 │         └──────────┘ └──────────┘
                 ▼
          ┌──────────────┐              ┌──────────┐
          │wazuh-indexer │              │  store   │
          └──────────────┘              └──────────┘
```

## Key Concepts

### Consistency: validated inside the snapshot

Partial ruleset downloads while the wazuh-indexer is mid-update are prevented by validating the CTI
consumer **inside the same Point-In-Time the content is read from**. That check lives in the content
manager, not here: checking before opening the snapshot leaves a window in which the indexer starts
rewriting between the check and the read.

`cmsync` keeps a cheap **pre-flight** check (`isConsumerReadyForSync`) before entering a cycle. It is
not the guarantee — it is an optimisation that short-circuits every space at once and additionally
covers `local_offset != 0`, which the in-snapshot check does not.

### Synchronization Lifecycle

Per space, per cycle:

| Case | Remote State | Local Route | Action |
|---|---|---|---|
| **1** | Policy **disabled**, or has no integrations | Route exists | Sink tears down: delete route and namespace, state set to dummy ID |
| **2** | Policy enabled, hash **unchanged** | Route enabled at that hash | Skip (no-op) |
| **3** | Policy enabled | No route exists | Full download → import → create route |
| **4** | Policy enabled, hash **changed** | Route exists | Full download → import → hot-swap → delete old NS |

Case 2 is decided by the content cycle, which compares the remote hash against the token. For this
module the token is **the hash the router reports for the deployed route** — the router knows what is
actually serving traffic, so a route deleted out of band reads back as "no token" and the next cycle
rebuilds it. No extra field was added to the state document for it.

Failures at any step are caught per-namespace so that one space's error does not block
synchronization of the others.

### SyncedNamespace

An internal class (defined in `cmsync.cpp`) that tracks the state of a single synchronized space:

| Field | Description |
|---|---|
| `m_originSpace` | Remote space name in the wazuh-indexer (e.g. `"standard"`, `"custom"`) |
| `m_routeName` | Derived router route name (`"cmsync_<space>"`) |
| `m_nsId` | Local `NamespaceId` in `cmstore` (or `DUMMY_NAMESPACE_ID` before first sync) |
| `m_consumerId` | Optional CTI consumer document to pre-flight |
| `m_lastSuccessfulUpdate` | Unix timestamp of the last successful sync |
| `m_enabled` | Last known remote-policy enabled flag (persisted) |
| `m_available`, `m_hash` | Live router-derived state, re-derived on each sync (not persisted) |

`SyncedNamespace` serializes to/from JSON for persistence in the internal store under the key
`cmsync/status/0`. **The document shape and field names are unchanged**, so an upgrade needs no
migration and a downgrade reads it back.

### Retry With Back-off

`existsPolicy`, `isConsumerReadyForSync` and each `runOnce()` are wrapped in
`base::utils::executeWithRetry()`, which retries up to `m_attempts` times with `m_waitSeconds`
between attempts. `runOnce()` is `noexcept` and reports by status rather than throwing, so the
wrapper's lambda rethrows on a retryable outcome to drive it. The existing
`analysisd.cmsync_indexer_connector_{max_retries,retry_interval}` settings keep their meaning and now
guard the whole cycle instead of a single query.

### Graceful Shutdown

`CMSync` supports responsive shutdown via `requestShutdown()`:

- Sets `m_shutdownRequested` (`std::atomic<bool>`) to `true`.
- `synchronize()` checks the flag before each namespace iteration.
- `executeWithRetry` aborts early when the flag is set.
- It also calls `ContentRegister::requestStop()` on every registration, so an in-flight page loop
  winds down at its next checkpoint instead of running to completion. That iteration takes only
  `m_registrationsMutex`, never `m_mutex` — the cycle being interrupted is holding `m_mutex`.
- The module is registered in the exit handler in `main.cpp`; on SIGINT/SIGTERM, `requestShutdown()`
  is called and the sync cycle aborts within one page round-trip.

### Registration Lifetime

Registrations are derived state over `m_namespacesState`, held in a map guarded by the same
`m_mutex`. `~ContentRegister` blocks until any in-flight cycle for that topic has drained, and that
cycle's sink calls back into the router and the namespace store — so `removeSpaceFromSync()` moves
the registration out of the map under the lock and lets it destruct **after** the lock is released.

### Weak-Pointer Resource Model

All four dependencies (`IWIndexerConnector`, `ICrudService`, `IStore`, `IRouterAPI`) are stored as `std::weak_ptr` and locked on entry via `base::utils::lockWeakPtr()`, throwing if the underlying object has been destroyed.

## Directory Structure

```
cmsync/
├── CMakeLists.txt
├── README.md
├── interface/cmsync/
│   └── icmsync.hpp                  # ICMSync interface + SpaceStatus
├── include/cmsync/
│   └── cmsync.hpp                   # CMSync concrete implementation header
├── src/
│   └── cmsync.cpp                   # Full implementation + SyncedNamespace class
└── test/
    ├── mocks/cmsync/
    │   └── mockCMSync.hpp           # GMock mock (MockCMSync)
    ├── src/unit/
    │   └── cmsync_test.cpp          # Unit tests
    └── src/component/
        └── cmsync_test.cpp          # Component tests
```

## Public Interface

### `ICMSync` (namespace `cm::sync`)

```cpp
class ICMSync
{
public:
    virtual ~ICMSync() = default;

    virtual void requestShutdown() = 0;
    virtual std::vector<SpaceStatus> getSpacesStatus() const = 0;
    virtual void requestOnDemandUpdate(std::string_view space = {}) = 0;
};
```

`requestOnDemandUpdate()` queues a cycle off the scheduler and returns immediately; it backs
`POST /content/ruleset/update`.

### `CMSync`

```cpp
class CMSync : public ICMSync
{
public:
    CMSync(const std::shared_ptr<wiconnector::IWIndexerConnector>& indexerPtr,
           const std::shared_ptr<cm::crud::ICrudService>& cmcrudPtr,
           const std::shared_ptr<store::IStore>& storePtr,
           const std::shared_ptr<router::IRouterAPI>& routerPtr,
           nlohmann::json indexerConnection,
           size_t attempts,
           size_t waitSeconds,
           cmcontent::Options contentOptions);
    ~CMSync() override;

    void synchronize();
    void requestShutdown() override;
    std::vector<SpaceStatus> getSpacesStatus() const override;
    void requestOnDemandUpdate(std::string_view space = {}) override;
};
```

`indexerConnection` is the **same** JSON `main.cpp` builds the indexer connector from, so there is no
second place to configure the indexer.

## Implementation Details

### Constructor

1. Checks if the store document `cmsync/status/0` exists.
2. **If yes** → `loadStateFromStore()`, builds one registration per restored space, and reconciles
   each space's route state from the router so a restart does not report the ruleset as missing.
3. **If no** (first setup) → adds `"standard"` and `"custom"`, builds their registrations, and dumps
   state once.

### `synchronize()` — Main Loop

```
for each SyncedNamespace in m_namespacesState:
  1. existSpaceInRemote(space)          → skip if nothing published for it
  2. isConsumerReadyForSync(consumerId) → skip if the consumer is busy or has no data
  3. syncSpace(nsState):
     a. sink->prepare(currentNamespaceId)
     b. registration->runOnce()  (wrapped in executeWithRetry)
     c. fold sink->takeOutcome() into nsState: namespace id, hash, availability, timestamp
        (taken, not borrowed: an on-demand cycle must not leave its result to be read as ours)
  4. dumpStateToStore() once, if anything changed
```

### Private Methods

| Method | Purpose |
|---|---|
| `existSpaceInRemote(space)` | Checks policy existence in the indexer, with retry |
| `syncSpace(nsState)` | Runs one content cycle for a space and folds its outcome into the state |
| `registerTopic(nsState)` | Builds the sink, the token store and the `ContentRegister` for a space |
| `loadToken(topic)` | Reads the deployed hash from the router (the authoritative "what is live") |
| `addSpaceToSync(space)` / `removeSpaceFromSync(space)` | Manage the tracked list and its registrations |
| `loadStateFromStore()` / `dumpStateToStore()` | (De)serialize the `SyncedNamespace` array |
| `updateSpacesStatusSnapshot()` | Rebuild and publish the lock-free status snapshot |

## CMake Targets

| Target | Type | Alias | Links |
|---|---|---|---|
| `cmsync_icmsync` | INTERFACE | `cmsync::icmsync` | `base` |
| `cmsync_cmsync` | STATIC | `cmsync::cmsync` | `base`, `cmsync::icmsync`, `cmcrud::icmcrud`, `store::istore`, `router::irouter`, `wIndexerConnector::iwIndexerConnector`, `cmcontent::cmcontent` |
| `cmsync_mocks` | INTERFACE | `cmsync::mocks` | `GTest::gmock`, `cmsync::icmsync` |
| `cmsync_utest` | Executable | — | `GTest::gtest_main`, `GTest::gmock`, `cmsync::cmsync`, `router::mocks`, `store::mocks`, `wIndexerConnector::mocks`, `cmcrud::mocks` |
| `cmsync_ctest` | Executable | — | same set; component-level wiring tests |

## Testing

- **Unit tests** (`test/src/unit/cmsync_test.cpp`) — which spaces are tracked, first-setup vs. restore, state-document round-trip, router reconciliation on startup, malformed-state rejection, and the skip paths (`existsPolicy == false`, consumer not ready).
- **Component tests** (`test/src/component/cmsync_test.cpp`) — `CMSync` wired to **real** content registrations with only the far ends faked: one registration per tracked space, a cycle against an unreachable indexer failing without throwing, and shutdown interrupting the iteration.
- The download behaviour itself is covered where it now lives: `cmcontent_utest` (`RulesetSpaceSink`:
  disabled-policy teardown, resource bucketing, route swap, every rollback path) and
  `content_manager_utest` / `content_manager_ctest` (the cycle, consumer readiness, token rules).
- **Mock** (`test/mocks/cmsync/mockCMSync.hpp`) — `MockCMSync` for downstream consumers of `ICMSync`.

## Consumers

| Module | Dependency | Role |
|---|---|---|
| `main.cpp` | `cmsync::cmsync` | Creates the `CMSync` instance and invokes `synchronize()` on a periodic schedule |
| `api::status` | `cmsync::icmsync` | Reports per-space sync status through `GET /status` |
| `api::contentsync` | `cmsync::icmsync` | Backs `POST /content/ruleset/update` |

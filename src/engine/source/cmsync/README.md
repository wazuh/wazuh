# cmsync

## Overview

`cmsync` keeps the Engine's ruleset in step with the wazuh-indexer. It tracks two spaces, `standard`
and `custom`, each as one content topic whose sink ([`cmcontent::RulesetSpaceSink`](../cmcontent/README.md))
deploys the space: imports a namespace, points the space's route at it, retires the old one.

This module decides **when** the topics run and **what their outcome means**: it runs each space
once per `synchronize()`, turns the outcome into the per-space status `GET /status` reports, and
persists what the router does not record — when each space last updated and whether its remote
policy is enabled.

Operator view (spaces, the synchronization process, the `analysisd.cm_sync_*` and `analysisd.cmsync_indexer_connector_*` settings): the engine's [Synchronization process](../../../../docs/ref/modules/engine/README.md#synchronization-process) and [Synchronization settings](../../../../docs/ref/modules/engine/configuration.md#synchronization).

## Architecture

```
   main.cpp: TriggerableTask "cm-sync-task"  ◄── POST /content/ruleset/update (trigger)
                     │ synchronize()
                     ▼
            ┌──────────────────┐
            │      CMSync      │── status snapshot ──► GET /status
            │  one Space per   │── record ───────────► store  cmsync/status/0
            │  tracked space   │
            └────────┬─────────┘
                     │ runWithRetries(topic)
                     ▼
            ContentRegister (content_manager) ──► wazuh-indexer
                     │ IContentSink / IContentTokenStore
                     ▼
            RulesetSpaceSink (cmcontent) ──► cmcrud, router
```

## Behaviour

### One runner

`synchronize()` is the only thing that runs the topics, one call at a time (`m_syncMutex`). It
runs from the scheduler task `cm-sync-task` (a `scheduler::TriggerableTask`): on
`analysisd.cm_sync_interval`, at startup before any other task, and whenever
`POST /content/ruleset/update` triggers it. A request that arrives during a run makes the task run
once more right after, so every request is served by a run that started after it.

### Per space, per run

The cycle compares the remote policy hash with the hash of the deployed route (the sink is the
topic's token store) and, when it moved, downloads and deploys the space. The outcome becomes the
space's status:

| Cycle status | Space status | Record |
|---|---|---|
| `Updated` | READY | `last_successful_update` = now |
| `Unchanged` | READY | — |
| `SkippedConsumerNotReady`, `SkippedPreconditionUnmet` | READY (the deployed ruleset is still in force) | — |
| `FailedTransport`, `FailedSink` (after the retries), `FailedConfig` | FAILED | — |
| `SkippedStopRequested`, `SkippedAlreadyRunning` | unchanged (nothing ran) | — |

After each cycle the space's `available` and `hash` are read back from the sink's deployment, and
`enabled` from the policy's metadata when the cycle probed it. A change to `enabled` is persisted.
`enabled` is the sink's verdict, not the raw flag: a policy that is disabled, has no integrations or
has no root decoder (`root_decoder` missing, `null`, `""` or not a string) counts as disabled, and the
sink removes the space's route and namespace.

`FailedTransport` and `FailedSink` are retried within the run by `cmcontent::runWithRetries`, up to
`analysisd.cmsync_indexer_connector_max_retries` attempts,
`analysisd.cmsync_indexer_connector_retry_interval` seconds apart.

### Early retry while a space has no route

`synchronize()` returns `true` when a run ends with a space that has no route and whose policy is
not known to be disabled (the indexer was unreachable, or the content is not published or the CTI
consumer not ready yet). The `cm-sync-task` then runs the next cycle after
`analysisd.cm_sync_retry_interval` seconds (default 30, `0` disables it, capped at
`analysisd.cm_sync_interval`) instead of `analysisd.cm_sync_interval`, until every space has a route
or a disabled policy. The task passes that choice to the scheduler through
`TriggerableTask`'s `nextInterval`.

"Disabled" comes only from a policy read, now or persisted in the record, so a cycle that fails
before reading the policy does not change it, and an unread policy is never persisted as disabled.
A space that keeps an older route after a failed cycle does not ask for the retry: that route keeps
processing events. A run ended by `requestShutdown()` returns `false`.

### Logging of a missing space

A space the indexer has no policy for is logged once per absence, at the level its effect deserves:
`WARNING` when the engine still serves a route for it (the deployed content is kept and nothing can
refresh it until the space is published again), `INFO` when the space was never deployed (a fresh
install whose indexer is still loading its content). Later cycles log the absence at `DEBUG` only
(the sink's `has no policy in the indexer`), and the space appearing again at `INFO` (`is published
in wazuh-indexer, resuming synchronization`). The sink reports the absence through
`RulesetDeployment::policyMissing`, as of its last probe; `CMSync` keeps the per-space flag, which is
not persisted.

A cycle that fails on the indexer leaves the space `FAILED` and keeps the deployed route. When the
next cycle finds the deployed content current, the recovery is logged at `INFO` (`Space '<name>' is
back in sync with wazuh-indexer`); a cycle that finds new content logs the usual deployment lines.

### Startup

The constructor builds one sink and one topic per tracked space, deletes the space's namespaces no
route serves (`collectOrphanNamespaces`), reads the deployment from the router and the record from
the store, and publishes the status — so a restart reports the deployed ruleset before the first
run.

### The record

`cmsync/status/0` is an array with one entry per space:

```json
{ "origin_space": "standard", "last_successful_update": 1700000000, "enabled": true }
```

Everything else about a space — the namespace in force, its hash, whether a route serves it — is
read from the router, which is the record of what is deployed.

### Shutdown

`requestShutdown()` sets the shutdown flag, which ends the run before the next space and the retry
waits, and stops every topic, so an in-flight download winds down at its next page. Each `Space`
declares its topic after its sink, so destroying the service waits for an in-flight cycle before the
sink it is using goes away.

The engine stops `CMSync` before the router and the indexer connector, so a cycle still running can
fail against them (`Orchestrator has been shutdown`, an aborted indexer query). Once the flag is set,
such a failure is logged at `INFO` as `Synchronization aborted for space '<space>' by the shutdown:
<error>` instead of the `WARNING` `Failed to synchronize space …`, and the space is still `FAILED`.
`requestShutdown()` also tells each space's sink (`RulesetSpaceSink::requestShutdown()`), whose failed
route swap is then logged the same way instead of the `ERROR` `Failed to sync the namespace in route
for space …`. Any failure after the request is reported as an abort, including a genuine one that
coincides with the stop: the engine is stopping and the space is `FAILED` either way.

The `RouteStatusReporter` of the `cm-sync-task` is stopped before `CMSync` (and so before the
orchestrator, whose `getEntries()` returns no routes once shut down): from the return of its
`requestShutdown()` on, the task logs neither `No active routes available` nor `Event processing is
now active`, also for a report already querying the router.

## Directory Structure

```
cmsync/
├── CMakeLists.txt
├── README.md
├── interface/cmsync/icmsync.hpp     # ICMSync + SpaceStatus
├── include/cmsync/
│   ├── cmsync.hpp                   # CMSync
│   └── routeStatusReporter.hpp      # RouteStatusReporter (route status logging of the cm-sync-task)
├── src/
│   ├── cmsync.cpp
│   └── routeStatusReporter.cpp
└── test/
    ├── mocks/cmsync/mockCMSync.hpp  # MockCMSync
    └── src/
        ├── unit/captureLogs.hpp                # Captures the engine log lines of a call, with their level
        ├── unit/cmsync_test.cpp                # Orchestration, through a scripted topic
        ├── unit/routeStatusReporter_test.cpp   # RouteStatusReporter
        └── component/cmsync_test.cpp           # Real registrations, far ends faked
```

## Public Interface

```cpp
namespace cm::sync
{
struct SpaceStatus
{
    std::string name;                 // "standard", "custom"
    bool available {false};           // a route serves the space
    bool enabled {false};             // remote policy enabled (see "Per space, per run")
    base::SyncStatus status {base::SyncStatus::READY};
    std::string hash;                 // hash of the deployed ruleset
    uint32_t lastSuccessfulUpdate {0};
};

class ICMSync
{
public:
    virtual bool synchronize() = 0;                              // one cycle per tracked space; true = early retry
    virtual void requestShutdown() = 0;                          // idempotent, thread-safe
    virtual std::vector<SpaceStatus> getSpacesStatus() const = 0; // wait-free snapshot
};

class CMSync final : public ICMSync
{
public:
    CMSync(const std::shared_ptr<cm::crud::ICrudService>& cmcrudPtr,
           const std::shared_ptr<store::IStore>& storePtr,
           const std::shared_ptr<router::IRouterAPI>& routerPtr,
           const cmcontent::TopicFactory& topicFactory,
           const cmcontent::Options& contentOptions,
           cmcontent::RetryPolicy retry);
};

// Next-cycle delay while a space has no route: min(retry, sync); main.cpp treats 0 as "no early retry".
constexpr std::size_t earlyRetryInterval(std::size_t retryInterval, std::size_t syncInterval);
}
```

### `RouteStatusReporter`

Logs whether incoming events have an enabled route. `main.cpp` builds it with a callback over the orchestrator's `getEntries()` and calls `report()` before and after each `synchronize()` of the `cm-sync-task`.

```cpp
class RouteStatusReporter
{
public:
    RouteStatusReporter(std::function<bool()> hasEnabledRoutes, bool firstStart);
    void report();          // logs only on a transition; the first report always logs
    void requestShutdown(); // idempotent, thread-safe; afterwards report() logs nothing
};
```

- Transition to "no enabled route": `WARNING [CMSync] No active routes available. Incoming events will be discarded until content synchronization completes`, or `INFO` on the first start of the engine (no content synchronized yet).
- Transition to "at least one enabled route": `INFO [CMSync] Event processing is now active`.
- `report()` queries the callback without a lock, then checks the shutdown, updates the last reported state and logs under one mutex, which `requestShutdown()` also takes. Once `requestShutdown()` has returned nothing is logged, including by a `report()` that was already querying the router, and `requestShutdown()` never waits for the router. A callback exception propagates and leaves the reported state unchanged.

## CMake Targets

| Target | Type | Alias | Links |
|---|---|---|---|
| `cmsync_icmsync` | INTERFACE | `cmsync::icmsync` | `base` |
| `cmsync_cmsync` | STATIC | `cmsync::cmsync` | `base`, `cmsync::icmsync`, `cmcrud::icmcrud`, `store::istore`, `router::irouter`, `cmcontent::cmcontent` |
| `cmsync_mocks` | INTERFACE | `cmsync::mocks` | `GTest::gmock`, `cmsync::icmsync` |
| `cmsync_utest` | Executable | — | `cmsync::cmsync`, `router::mocks`, `store::mocks`, `cmcrud::mocks`, `cmcontent::mocks`, GTest |
| `cmsync_ctest` | Executable | — | `cmsync::cmsync`, `router::mocks`, `store::mocks`, `cmcrud::mocks`, GTest |

## Testing

- **Unit** — one topic per tracked space whose sink is also its token store, orphan collection at
  startup, the record and the deployment read back, a malformed record rejected, the status table
  above, retries, shutdown (a failure after the request logged as an abort at `INFO`, the same failure
  without it at `WARNING`), the early-retry return value and `earlyRetryInterval()`, and the logging
  of a missing space and of a recovery.
- **Unit** (`routeStatusReporter_test.cpp`) — `RouteStatusReporter` against the real log lines and
  their level (`captureLogs()` and `countAtLevel()` of `captureLogs.hpp`, shared with
  `cmsync_test.cpp`): the first-start INFO vs restart WARNING, transitions only, silence after
  `requestShutdown()`, a report parked in the router query while `requestShutdown()` returns, and
  callback exceptions.
- **Component** — `CMSync` over real registrations with the router and stores faked: a cycle
  against an empty indexer defers or finds nothing without failing, and shutdown stops the run.
- The download and deployment are covered by `cmcontent_utest` and `content_manager_utest`.

## Consumers

| Module | Dependency | Role |
|---|---|---|
| `main.cpp` | `cmsync::cmsync` | Builds `CMSync` (only when event processing is enabled) and the `cm-sync-task` that runs it; builds the `RouteStatusReporter` that task calls around each `synchronize()`, and stops it before `CMSync` and the orchestrator |
| `api::status` | `cmsync::icmsync` | Reports per-space status through `GET /status` |

# cmsync

## Overview

`cmsync` keeps the Engine's ruleset in step with the wazuh-indexer. It tracks two spaces, `standard`
and `custom`, each as one content topic whose sink ([`cmcontent::RulesetSpaceSink`](../cmcontent/README.md))
deploys the space: imports a namespace, points the space's route at it, retires the old one.

This module decides **when** the topics run and **what their outcome means**: it runs each space
once per `synchronize()`, turns the outcome into the per-space status `GET /status` reports, and
persists what the router does not record — when each space last updated and whether its remote
policy is enabled.

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

## Directory Structure

```
cmsync/
├── CMakeLists.txt
├── README.md
├── interface/cmsync/icmsync.hpp     # ICMSync + SpaceStatus
├── include/cmsync/cmsync.hpp        # CMSync
├── src/cmsync.cpp
└── test/
    ├── mocks/cmsync/mockCMSync.hpp  # MockCMSync
    └── src/
        ├── unit/cmsync_test.cpp       # Orchestration, through a scripted topic
        └── component/cmsync_test.cpp  # Real registrations, far ends faked
```

## Public Interface

```cpp
namespace cm::sync
{
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
}
```

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
  above, retries, shutdown.
- **Component** — `CMSync` over real registrations with the router and stores faked: a cycle
  against an empty indexer defers or finds nothing without failing, and shutdown stops the run.
- The download and deployment are covered by `cmcontent_utest` and `content_manager_utest`.

## Consumers

| Module | Dependency | Role |
|---|---|---|
| `main.cpp` | `cmsync::cmsync` | Builds `CMSync` and the `cm-sync-task` that runs it |
| `api::status` | `cmsync::icmsync` | Reports per-space status through `GET /status` |

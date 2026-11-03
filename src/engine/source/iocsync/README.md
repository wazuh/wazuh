# IOC Sync

## Overview

`iocsync` keeps the Engine's IOC enrichment databases in step with the wazuh-indexer. Each supported
IOC type is one content topic whose sink ([`cmcontent::IocTypeSink`](../cmcontent/README.md)) loads it
into a staging KVDB and hot-swaps it onto the live one, so readers never see a half-written
database.

This module decides **when** the topics run and **what their outcome means**: it runs every type
once per `synchronize()`, forces a full reload of a database that has gone missing, turns each
outcome into the per-type status `GET /status` reports, and persists each type's hash — which is also
the topic's change-detection token.

`main.cpp` builds it only when `analysisd.server_enable_event_processing` is true. The
operator-facing settings are on the engine [configuration](../../../../docs/ref/modules/engine/configuration.md) page.

## Architecture

```
   main.cpp: TriggerableTask "ioc-sync-task"  ◄── POST /content/ioc/sync (trigger)
                     │ synchronize()
                     ▼
            ┌──────────────────┐
            │     IocSync      │── status snapshot ──► GET /status
            │  one IocType per │── hashes ───────────► store  iocsync/status/0
            │  supported type  │
            └────────┬─────────┘
                     │ runWithRetries(topic)
                     ▼
            ContentRegister (content_manager) ──► wazuh-indexer
                     │ IContentSink
                     ▼
            IocTypeSink (cmcontent) ──► iockvdb (staging + hot-swap)
```

## Behaviour

### One runner

`synchronize()` is the only thing that runs the topics, one call at a time (`m_syncMutex`). It
runs from the scheduler task `ioc-sync-task` (a `scheduler::TriggerableTask`): at startup, then every
`analysisd.ioc_sync_interval` seconds (default 360; `0` = only on request, no startup run either), and
whenever `POST /content/ioc/sync` triggers it. A request that arrives during a run makes the task run once more right after.

### Per type, per run

1. If the type's database is missing, the cycle is a forced full reload: a matching hash says the
   content has not moved, not that its database still exists.
2. The cycle compares the type's hash in the manifest with the stored one and, when it moved,
   downloads and swaps the database. The token store (`cmcontent::EngineTokenStore`) reads and
   writes the hash in this module's state; it is only touched from inside `synchronize()`.
3. The type is reported `UPDATING` while its cycle runs; the outcome becomes the type's status:

| Cycle status | Type status | Persisted |
|---|---|---|
| `Updated` | READY | new hash, `last_successful_update` = now |
| `Unchanged` | READY | — |
| `SkippedConsumerNotReady`, `SkippedPreconditionUnmet` | READY (the database in force is still usable) | — |
| `FailedTransport`, `FailedSink` (after the retries), `FailedConfig` | FAILED | — |
| `SkippedStopRequested`, `SkippedAlreadyRunning` | unchanged (nothing ran) | — |

`available` is true when the type has a hash and its database exists. The state document is written
once at the end of a run, only when something changed. `FailedTransport` and `FailedSink` are retried
within the run, up to `analysisd.ioc_indexer_connector_max_retries` attempts,
`analysisd.ioc_indexer_connector_retry_interval` seconds apart.

### The record

`iocsync/status/0` is an array with one entry per type (an object holding the array under
`databases` is also read):

```json
{ "ioc_type": "url_domain", "last_data_hash": "abc123...", "last_successful_update": 1700000000 }
```

The tracked types are always `ioc::kvdb::details::getSupportedIocTypes()`; entries for other types
are ignored.

### Shutdown

`requestShutdown()` sets the shutdown flag, which ends the run before the next type and the retry
waits, and stops every topic. An interrupted cycle never promotes: its staging database is dropped.
Each `IocType` declares its topic after its sink, so destroying the service waits for an in-flight
cycle before the sink goes away.

## Directory Structure

```
iocsync/
├── CMakeLists.txt
├── README.md
├── interface/iocsync/iiocsync.hpp    # IIocSync + IocTypeStatus
├── include/iocsync/iocsync.hpp       # IocSync
├── src/iocsync.cpp
└── test/
    ├── mocks/iocsync/mockIocSync.hpp # MockIocSync
    └── src/unit/iocsync_test.cpp     # Orchestration, through a scripted topic
```

## Public Interface

```cpp
namespace ioc::sync
{
struct IocTypeStatus
{
    std::string type;
    bool available {false};           // the type has a hash and its database exists
    base::SyncStatus status {base::SyncStatus::READY}; // READY, UPDATING, FAILED
    std::string hash;
    uint32_t lastSuccessfulUpdate {0};
};

class IIocSync
{
public:
    virtual void synchronize() = 0;                               // one cycle per IOC type
    virtual void requestShutdown() = 0;                           // idempotent, thread-safe
    virtual std::vector<IocTypeStatus> getIocStatus() const = 0;  // wait-free snapshot
};

class IocSync final : public IIocSync
{
public:
    IocSync(const std::shared_ptr<ioc::kvdb::IKVDBManager>& kvdbiocManagerPtr,
            const std::shared_ptr<store::IStore>& storePtr,
            const cmcontent::TopicFactory& topicFactory,
            const cmcontent::Options& contentOptions,
            cmcontent::RetryPolicy retry);
};
}
```

## CMake Targets

| Target | Type | Alias | Links |
|---|---|---|---|
| `iocsync_iiocsync` | INTERFACE | `iocsync::iiocsync` | `base` |
| `iocsync_iocsync` | STATIC | `iocsync::iocsync` | `iocsync::iiocsync`, `cmcontent::cmcontent`, `store::istore`, `iockvdb::ikvdb` |
| `iocsync_mocks` | INTERFACE | `iocsync::mocks` | `GTest::gmock`, `iocsync::iiocsync` |
| `iocsync_utest` | Executable | — | `iocsync::iocsync`, `store::mocks`, `iockvdb::mocks`, `cmcontent::mocks`, GTest |

## Testing

`iocsync_utest`: one topic per supported type, each starting from its persisted hash, both state
document shapes, an unreadable state rejected, the forced reload of a missing database, a committed
hash reported and persisted, nothing written when nothing changed, the status table above, retries,
and shutdown. The download and the swap are covered by `cmcontent_utest` and `content_manager_utest`.

## Consumers

| Consumer | Dependency | Usage |
|---|---|---|
| `main.cpp` | `iocsync::iocsync` | Builds `IocSync` (only when event processing is enabled), registers `requestShutdown()` in the exit handler, and the `ioc-sync-task` that runs it |
| `api::status` | `iocsync::iiocsync` | Reports per-type status through `GET /status` |

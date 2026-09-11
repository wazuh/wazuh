# cmcontent

## Overview

`cmcontent` is the engine's half of the shared **content manager**. The library in
`src/shared_modules/content_manager` owns everything generic about pulling content out of the
wazuh-indexer — the Point-in-Time, the pagination, consumer readiness, change detection, the token
rules. This module supplies the three things that are specific to the engine:

1. **Topic configuration** — what each ruleset space and each IOC type looks like as a content topic.
2. **Sinks** — where the downloaded documents go and who decides they are safe to keep.
3. **A token store adapter** — how a topic's change-detection token maps onto state `cmsync` and
   `iocsync` already persist.

It exists so that `cmsync` and `iocsync` share one download implementation with the Vulnerability
Detection module instead of carrying a second one. Before this, the engine had its own PIT handling,
its own `search_after` loop and its own consumer validation in `wiconnector`; every fix had to be
made twice, and usually was not.

## Architecture

```
  ┌─────────┐                 ┌──────────┐
  │ cmsync  │                 │ iocsync  │
  └────┬────┘                 └────┬─────┘
       │ one ContentRegister per   │ one ContentRegister per
       │ tracked space             │ tracked IOC type
       ▼                           ▼
  ┌──────────────────────────────────────────┐
  │              cmcontent                    │
  │                                           │
  │  registration.hpp   topic names + config  │
  │  rulesetSink.hpp    namespace + route     │
  │  iocTypeSink.hpp    staging KVDB + swap   │
  │  engineTokenStore   hash <-> service state│
  └──────────────────┬───────────────────────┘
                     │ IContentSink / IContentTokenStore
                     ▼
  ┌──────────────────────────────────────────┐
  │   content_manager (shared .so)            │
  │   PIT · pagination · consumer gate ·      │
  │   change detection · token durability     │
  └──────────────────┬───────────────────────┘
                     ▼
              wazuh-indexer
```

## Components

### `registration.hpp` — what a topic is

`rulesetParameters()` and `iocParameters()` build the JSON a `ContentRegister` is constructed from.
Both produce `changeDetection: "hash"` topics with no `interval` (the engine drives each cycle from
its own scheduler, which has CPU priorities and a startup ordering the library cannot reproduce) and
no `databasePath` (engine state lives in `store::IStore`, and the token travels with it).

Topic names are `content.ruleset.<space>` and `content.ioc.<type>` — **one topic per space and per
type**, because the hash, the promotion and the status are all already per-space and per-type. A
single multi-stream topic would have to invent a sub-stream concept inside the generic contract for
the benefit of exactly one consumer.

Two details worth knowing:

- **The ruleset hash probe cannot filter on `_index`.** Its PIT spans the policy aliases with
  wildcard expansion, so the `_index` metafield reports the concrete backing index, not the alias.
  The probe therefore discriminates on `document.enabled`, a policy-only field — and reads it back as
  metadata in the same query.
- **The IOC hash probe accepts two manifest shapes**, the current nested `type_hashes` one and an
  older flat one. First pointer that resolves wins, so both work without a migration.

Sorting is on `_shard_doc` and `_id` only. `_shard_doc` is synthesised by the PIT itself, so it is
mapped in every index the PIT spans — including the consumer status index — which is why the engine
needs no `unmapped_type` injection.

### `rulesetSink.hpp` — assemble in memory, swap the route

One sink per space. It buckets each hit by the index it came from, stashes the space hash onto the
policy document at `/hash`, and on commit calls `importNamespace(softValidation=true)` followed by a
router hot-swap, then deletes the namespace the route used to serve.

Staging is in memory rather than on disk: a ruleset is small and the promotion is a single import
plus a route swap, so there is nothing to gain from writing it out first. That is also why every page
is only `Accepted` — until `commit` runs, none of it exists anywhere a reader could see.

Failure modes are distinguished on purpose:

| Situation | Result | Why |
|---|---|---|
| Remote policy disabled, or has no integrations | teardown + `Skip` | Deploying it would route nothing |
| Unrecognised `_index`, or a policy with no hash | `Reject` | Silently dropping it would deploy a namespace quietly missing resources |
| No policy document delivered | `RejectedRetryFull` | Nothing to route: a content problem, so re-fetch from scratch |
| Import or route swap failed | `RejectedRetrySame` + rollback | A promotion problem, not a content one; the imported namespace is garbage and is removed |

### `iocTypeSink.hpp` — stage on disk, swap the database

One sink per IOC type. It stages into a KVDB named `iocsync_<type>_staging` — fixed per type, so a
database left behind by a crash is still addressable and is reclaimed by the next session — writes
each document
under a lower-cased `document.name` (indicators arrive with whatever casing the feed used; lookups
have their own), and on commit hot-swaps it onto the live database, creating that database first if
it does not exist.

A staging database has no meaningful intermediate durability — nothing reads it until the swap, and a
partial one is thrown away rather than resumed — so every page is `Accepted` and never `Durable`.
Malformed documents are skipped rather than rejected: one bad indicator must not discard a whole
feed.

A `NoChange` session is **skipped**, not proceeded with. Rebuilding a physically deleted database is
the caller's job: `iocsync` notices before the cycle starts and asks for a forced full reload
instead, because a `NoChange` session carries no documents to swap in.

### `engineTokenStore.hpp` — a view, not a second writer

The token each topic needs is exactly the hash the engine already persists: a space's
`space.hash.sha256` and an IOC type's `last_data_hash`. The store is therefore an adapter over two
callbacks supplied by the owning service, not a second writer into `store::IStore` — `CMSync` and
`IocSync` each hold their state in memory, mutate it under their own mutex and dump the whole
document in one write, and a second writer would race that over an array it does not own.

For `cmsync` the loader goes further and reads the hash **from the router**: the router knows what is
actually deployed, so a route deleted out of band reads back as "no token" and the next cycle
rebuilds it. Storing is then a no-op — the hot-swap already did it.

The existing `cmsync/status/0` and `iocsync/status/0` documents keep their shape and field names, so
there is no state migration and a downgrade reads them back.

## Directory Structure

```
cmcontent/
├── CMakeLists.txt
├── README.md
├── include/cmcontent/
│   ├── registration.hpp        # Topic names and per-topic configuration
│   ├── rulesetSink.hpp         # IContentSink for one ruleset space
│   ├── iocTypeSink.hpp         # IContentSink for one IOC type
│   └── engineTokenStore.hpp    # IContentTokenStore over the services' own state
├── src/
│   ├── registration.cpp
│   ├── rulesetSink.cpp
│   ├── iocTypeSink.cpp
│   └── engineTokenStore.cpp
└── test/src/unit/
    ├── registration_test.cpp
    ├── rulesetSink_test.cpp
    ├── iocTypeSink_test.cpp
    └── engineTokenStore_test.cpp
```

## The DSO boundary

`content_manager` is a **shared** library built outside the engine tree, and `wazuh-engine` links
libstdc++ statically while `content_manager.so` links it dynamically. Two copies of libstdc++ in one
process make throwing across the boundary undefined, so the contract is designed around it:

- the whole `IContentSink` / `IContentTokenStore` surface and `ContentRegister::runOnce` are
  `noexcept`, and report failure by value;
- everything this module's sinks do is wrapped so nothing escapes — including the token-store
  callbacks, which reach back into engine code;
- only layout-stable types cross, pinned by `static_assert`s and a `CONTRACT_ABI_VERSION` checked at
  registration.

`content_manager` is a `PUBLIC` dependency of this target because this module's own public headers
name its types.

## `contentTopic.hpp` — the seam, and where the token lives

Two small pieces that exist because of *how* the sync services are driven, not what they download.

**`IContentTopic` + `TopicFactory`.** `ContentRegister` is concrete: constructing one registers with
a process-wide facade and opens real connections to the indexer. A sync service holding one
therefore could not be unit-tested at all, which is why the orchestration in `CMSync` and `IocSync`
— which outcome makes a space FAILED, when a missing database forces a full reload, what an
already-running cycle does to the persisted state — had no coverage. The factory defaults to the
real thing and is substituted in tests.

**`TokenCell`.** A cycle's token is read and written on whichever thread drove the cycle: the sync
service's scheduler task for a scheduled run, a content-manager lane worker for one triggered
through the on-demand API. Those are different threads, and nothing the sync service holds
serialises the second against the first. Routing the token through a cell keeps the service's own
state vector single-threaded — it is reconciled from the cells at cycle boundaries, where the owning
thread already holds its mutex. `cellTokenStore` wraps one for `iocsync`; `derivedTokenStore` covers
`cmsync`, whose token is not stored but *derived* from the hash the router is actually serving, so
there is nothing separate to keep in step.

## CMake Targets

| Target | Type | Alias | Links |
|---|---|---|---|
| `cmcontent_cmcontent` | STATIC | `cmcontent::cmcontent` | `base`, `store::istore`, `cmcrud::icmcrud`, `router::irouter`, `iockvdb::ikvdb`, `content_manager` |
| `cmcontent_mocks` | INTERFACE | `cmcontent::mocks` | `GTest::gmock`, `cmcontent::cmcontent` |
| `cmcontent_utest` | Executable | — | `cmcontent::cmcontent`, `iockvdb::mocks`, `cmcrud::mocks`, `router::mocks`, GTest |

`cmcontent::mocks` carries `FakeTopicRegistry`, the scripted `IContentTopic` that `cmsync_utest` and
`iocsync_utest` drive their orchestration through.

## Testing

`cmcontent_utest` covers the parts that used to be untestable without a live cluster:

- **registration** — no `interval`, no `databasePath`, connection settings forwarded verbatim, the
  ruleset probe's discriminator, both IOC manifest shapes, the 12-field IOC projection, page-size
  clamping, and metafield-only sorting.
- **rulesetSink** — disabled-policy teardown, integration-less policy treated as disabled, `NoChange`
  skip, resource bucketing across all five index kinds, route creation vs. hot-swap, old-namespace
  deletion, and every reject/rollback path.
- **iocTypeSink** — staging database naming, lower-cased keys, malformed documents skipped, target
  creation on first sync, hot-swap, rollback on failed swap, abort, and abandoned-staging cleanup.
- **engineTokenStore** — delegation, clear-as-empty-hash, failed writes reported by value, and
  callback exceptions swallowed rather than crossing the DSO boundary.

## Consumers

| Module | Role |
|---|---|
| `cmsync` | One registration per tracked ruleset space |
| `iocsync` | One registration per tracked IOC type |

# cmcontent

## Overview

`cmcontent` is what is Engine-specific about downloading content from the wazuh-indexer through the
shared content manager (`src/shared_modules/content_manager`). The library owns how content is read —
the Point-in-Time, pagination, consumer readiness, change detection, the token rules. This module
owns:

1. **Topic specs** — what each ruleset space and each IOC type looks like as a content topic.
2. **Sinks** — how the downloaded documents become Engine state, and when they are safe to keep.
3. **The topic seam** — the interface the sync services drive a topic through, and the retry policy
   they share.

When topics run and what their outcome means for the reported status belongs to the sync services,
[`cmsync`](../cmsync/README.md) and [`iocsync`](../iocsync/README.md).

## Architecture

```
  ┌─────────┐                 ┌──────────┐
  │ cmsync  │                 │ iocsync  │
  └────┬────┘                 └────┬─────┘
       │ one topic per space       │ one topic per IOC type
       ▼                           ▼
  ┌──────────────────────────────────────────┐
  │              cmcontent                    │
  │  registration     topic names + specs     │
  │  contentTopic     IContentTopic, retries  │
  │  rulesetSink      namespace + route       │
  │  iocTypeSink      staging KVDB + swap     │
  │  engineTokenStore token over owner state  │
  └──────────────────┬───────────────────────┘
                     │ IContentSink / IContentTokenStore
                     ▼
  ┌──────────────────────────────────────────┐
  │   content_manager (shared .so)            │
  └──────────────────┬───────────────────────┘
                     ▼
              wazuh-indexer
```

## Components

### `registration.hpp` — what a topic is

`rulesetSpec()` and `iocSpec()` build the `content_manager::TopicSpec` of a topic. Both use hash
change detection, no interval (the Engine's scheduler runs each topic) and no `databasePath` (the
token lives in Engine state, see below).

Topic names are `content.ruleset.<space>` and `content.ioc.<type>` — one topic per space and per
type, because the hash, the promotion and the status are all per space and per type.

- **The ruleset hash probe selects the policies index with a wildcard on `_index`.** Its PIT spans
  every resource alias with wildcard expansion, so `_index` reports the concrete, suffixed backing
  index and an exact match would miss it. No document field can stand in for it: `enabled` is
  required on decoders and filters as well as on the policy. The wildcard (`*policies*`) is the
  rule the sink classifies hits by, so the two agree on which document is the policy.
- **The `custom` space has no consumer gate.** No CTI consumer writes it, so a CTI re-index of the
  standard content says nothing about whether its documents are complete.
- **The IOC hash probe accepts two manifest shapes**, the nested `type_hashes` one and a flat one.
  The first pointer that resolves wins.
- The page size is capped at `MAX_PAGE_SIZE` (1000) whatever the configuration asks for.

### `contentTopic.hpp` — the seam

**`IContentTopic` + `TopicFactory`.** `ContentRegister` is concrete and talks to an indexer; the
sync services hold an `IContentTopic` instead, built by a `TopicFactory`, so their orchestration —
which outcome makes a space FAILED, when a missing database forces a full reload — is unit-tested
against a scripted topic (`cmcontent::mocks::FakeTopicRegistry`). `defaultTopicFactory(indexer)`
builds real registrations over the Engine's one indexer connector.

**`runWithRetries`.** Runs a topic and retries `FailedTransport` and `FailedSink` up to
`RetryPolicy::maxAttempts`, `waitSeconds` apart, stopping early on shutdown. A deferral, a
configuration failure or a stop returns at once: retrying cannot change it within one run.

### `releasableIndexer.hpp` — the topics' share of the connector

The content topics and the event writer (`wiconnector`) share one `IndexerConnectorAsync`, and a
topic holds its indexer for its whole life. `ReleasableIndexer` is the indexer the topics get:
`main.cpp` releases it in the same exit handler that shuts the writer down, so the connector's queue
and threads stop there rather than when `main` returns. `release()` waits for the requests in flight;
after it every call fails as an unreachable indexer would.

### `rulesetSink.hpp` — assemble in memory, swap the route

One `RulesetSpaceSink` per space. It owns the space's deployment — the route `cmsync_<space>` and
the namespaces `cmsync_<space>_<suffix>` it creates and retires — and the router is the record of
it: the namespace the route serves is the one in force, and its hash is the topic's token. The sink
is therefore also the topic's `IContentTokenStore`: `load` reads the served hash, `store` and `clear`
write nothing (the commit's route swap already recorded it). A route deleted out of band reads back
as "no token", and the next cycle rebuilds it.

The sink buckets each hit by the index it came from, stashes the space hash onto the policy
document, and on commit imports the namespace, points the route at it (creating the route when
missing) and deletes the namespace the route used to serve. Staging is in memory: a ruleset is
small and nothing exists anywhere a reader could see until `commit`, so every page is `Accepted`.

`collectOrphanNamespaces()` deletes the space's namespaces that no route serves — what a process
killed between import and route swap leaves behind. Without a readable router it deletes nothing.

| Situation | Result | Why |
|---|---|---|
| No policy document in the indexer | `Skip` | Nothing to deploy, nothing to tear down |
| Policy without a boolean `enabled` or an `integrations` array | `Abort` | A malformed document must not stop event processing; the deployed ruleset stays |
| Policy disabled, or with no integrations | teardown + `Skip` | Deploying it would route nothing |
| Unrecognised `_index`, or a policy with no hash | page `Reject` | Dropping it would deploy a namespace quietly missing resources |
| No policy document delivered | `RejectedRetryFull` | A content problem: re-fetch from scratch |
| Import or route swap failed | `RejectedRetrySame` + rollback | A promotion problem; the staging namespace is removed |

### `iocTypeSink.hpp` — stage on disk, swap the database

One `IocTypeSink` per IOC type. It stages into a KVDB named `iocsync_<type>_staging`, writes each
document under its lower-cased `document.name`, and on commit hot-swaps it onto the live database,
creating that database first if it does not exist.

The staging name is fixed per type: two cycles of a type never run at once, and a fixed name is one
the next session can still find and remove after a crash. Pages are only `Accepted` — a partial
staging database is thrown away, never resumed. Malformed documents are skipped: one bad indicator
must not discard a whole feed. A `NoChange` session is skipped; rebuilding a database that went
missing is `iocsync`'s to ask for, with a forced full reload.

### `engineTokenStore.hpp` — a token over its owner's state

An `IContentTokenStore` over two callbacks, for a token that lives in state its owner already
persists: `iocsync` keeps each type's hash in `iocsync/status/0` and writes that document once per
run, so it stays the document's only writer. A clear stores "".

## The DSO boundary

`content_manager` is a shared library built outside the Engine tree, and `wazuh-engine` links
libstdc++ statically while the library links it dynamically, so nothing may be thrown across the
boundary: the whole `IContentSink` / `IContentTokenStore` surface and `ContentRegister::runOnce` are
`noexcept` and report failure by value, and every sink and token-store method here catches
everything. `content_manager` is a `PUBLIC` dependency of this target because its public headers
name the library's types.

## Directory Structure

```
cmcontent/
├── CMakeLists.txt
├── README.md
├── include/cmcontent/
│   ├── registration.hpp        # Topic names and specs
│   ├── contentTopic.hpp        # IContentTopic, TopicFactory, runWithRetries
│   ├── releasableIndexer.hpp   # The topics' indexer, released at shutdown
│   ├── rulesetSink.hpp         # Sink and token store for one ruleset space
│   ├── iocTypeSink.hpp         # Sink for one IOC type
│   └── engineTokenStore.hpp    # Token store over the owner's state
├── src/                        # One .cpp per header
└── test/
    ├── mocks/cmcontent/fakeContentTopic.hpp   # FakeTopicRegistry
    └── src/unit/                              # One test per component
```

## CMake Targets

| Target | Type | Alias | Links |
|---|---|---|---|
| `cmcontent_cmcontent` | STATIC | `cmcontent::cmcontent` | `base`, `cmcrud::icmcrud`, `router::irouter`, `iockvdb::ikvdb`, `content_manager` |
| `cmcontent_mocks` | INTERFACE | `cmcontent::mocks` | `GTest::gmock`, `cmcontent::cmcontent` |
| `cmcontent_utest` | Executable | — | `cmcontent::cmcontent`, `iockvdb::mocks`, `cmcrud::mocks`, `router::mocks`, GTest |

## Testing

`cmcontent_utest`:

- **registration** — topic names, no interval and no state path, the ruleset probe, the ungated
  `custom` space, both IOC manifest shapes, the IOC projection, page-size capping.
- **contentTopic** — which statuses are retried, the attempt budget, stopping early.
- **releasableIndexer** — forwarding, dropping its share on release, failing after it, waiting for
  a request in flight.
- **rulesetSink** — the token read from the router, orphan collection, malformed metadata, teardown,
  resource bucketing, route creation and hot-swap, old-namespace deletion, every reject and rollback.
- **iocTypeSink** — staging naming, lower-cased keys, malformed documents skipped, target creation,
  hot-swap, rollback, abort, leftover staging cleanup, an unregistered staging handle.
- **engineTokenStore** — delegation, clear as an empty token, failures reported by value, callback
  exceptions contained.

## Consumers

| Module | Role |
|---|---|
| `cmsync` | One topic per tracked ruleset space |
| `iocsync` | One topic per IOC type |
| `main.cpp` | Builds the `defaultTopicFactory` over a `ReleasableIndexer` of the Engine's connector |

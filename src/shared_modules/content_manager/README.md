# Content Manager

The Content Manager downloads content from the Wazuh Indexer and keeps it up to date. It is a
generic library: the Vulnerability Detection module, the Engine's ruleset sync (`cmsync`) and the
Engine's IOC enrichment sync (`iocsync`) all drive it, each with its own change-detection strategy,
its own destination and its own token storage.

## The cycle

Every consumer runs the same cycle, once per scheduled or on-demand execution:

```
open a PIT over {data indices} ∪ {consumer status index}
  → validate the consumer is "ready" INSIDE the PIT      (consistency)
  → probe the remote change token and compare it locally (change detection)
  → if it moved: paginate the PIT with search_after      (fetch)
  → the sink accepts pages, then promotes atomically     (delivery)
  → persist the new token only after promotion           (durability)
close the PIT
```

Only change detection, delivery and token storage genuinely differ between consumers. Fetching
differs only by *configuration* — indices, query, sort keys, `_source` filter, page size, slice
count.

Validating the consumer from inside the PIT rather than before opening it is what closes the window
in which the indexer starts rewriting content between the check and the snapshot. It has two
consequences the configuration has to respect, both handled by the library:

- sort keys that are not metafields get an `unmapped_type` injected. Not because the consumer status
  index lacks them — OpenSearch only needs a sort field mapped in *one* index of the search — but
  because on a cold start the data index has no documents and therefore no dynamic mapping either,
  leaving the key unmapped everywhere, which does fail the whole search. That is exactly a new
  manager's first feed load;
- consumer documents are excluded from results twice — query-side with a `must_not` on `_index`, and
  hit-side by dropping anything that still arrives from that index.

## Components

| Component | Responsibility |
|---|---|
| `IContentIndexer` | The host's indexer: the four read operations the cycle needs (public, `contentIndexer.hpp`). The library ships adapters over `IndexerConnectorSync` and `IndexerConnectorAsync` (`makeContentIndexer`); tests pass a fake. It never builds a connection of its own (D1). |
| `PitSession` | Opens and closes the PIT; validates consumer readiness inside it; scopes queries to the data indices. |
| `ConsumerGate` | Cheap, bounded, cached pre-flight readiness probe, shared across topics watching the same consumer. |
| `IChangeDetector` | `OffsetCursorDetector` (monotonic integer cursor) and `ContentHashDetector` (content hash, doc- or query-probed). |
| `PitPaginator` | `search_after` pagination, optionally sliced. No domain knowledge. |
| `ContentCycle` | Runs the cycle exactly once and returns a `CycleOutcome`. Never throws, never loops indefinitely. |
| `IContentSink` | Where the content goes, and who decides it is safe to keep. Implemented by the host. |
| `IContentTokenStore` | Where the change-detection token lives. `RocksDbTokenStore` by default; hosts may supply their own. |

Operator-facing behaviour (indices, state on disk, logs, configuration) is documented in the published
reference, [docs/ref/modules/content_manager/README.md](../../../docs/ref/modules/content_manager/README.md).
This README covers the library's interface and internals.

## Usage

```cpp
// The host's own connector — the one it already uses for everything else (D1).
const auto indexer = content_manager::makeContentIndexer(myConnector);
ContentRegister registration {topicName, parameters, std::make_shared<MySink>(), indexer};

// Host-driven (the Engine): call it from your own scheduler.
const auto outcome = registration.runOnce();

// Library-driven (the vulnerability scanner): pass "interval" in the parameters and the library
// spawns a thread that calls runOnce for you.
```

`runOnce` is bounded: every gate is single-pass, and a deferred cycle reports `CycleOutcome::retryAfter`
instead of parking the calling thread. A driver must honour `retryAfter` when it is non-zero —
otherwise a topic whose consumer is briefly busy waits a whole scheduler interval, which for VD's
60-minute default means an hour with no data.

Cycles are mutually exclusive per topic: a scheduled run and an on-demand one cannot overlap. The
loser gets `CycleStatus::SkippedAlreadyRunning`, which is deliberately **not**
`SkippedStopRequested` — a caller folding a cycle's result into its own state has to be able to tell
"nothing ran, so I observed nothing" from "a cycle ran and found nothing to do", and the two lead to
opposite conclusions about whatever it reads next. Registering the topic elsewhere is not blocked
while a cycle runs: the registry lock is held only long enough to find the topic and claim its run
slot, never for the download.

### Configuration

A registration is a `content_manager::TopicSpec` (`include/contentTopicSpec.hpp`), grouped by
concern: `schedule` (interval, on-demand), `source` (indices, query, source filter, paging, slices,
PIT lease), an optional `readiness` gate (the CTI consumer document; absent means never gated),
`detection` (either a cursor or a content hash, each carrying only its own settings), `fullLoad`
(documents a full load requires) and `state` (the built-in token store). Hosts fill the struct and
pass `content_manager::toParameters(spec)` to `ContentRegister`, which parses it strictly: every
unknown key is rejected, naming its block. The full shape, the defaults and what each old key became
are in [D2](#d2-in-detail).

### Example — Vulnerability Detection

```cpp
content_manager::TopicSpec spec;
spec.schedule.intervalSeconds = 3600;
spec.schedule.onDemand = true;
spec.source.indices = {".wazuh-threatintel-vulnerabilities"};
spec.source.slices = 2;
spec.source.sourceFilter = getCve5SourceFilter();
spec.readiness = content_manager::Readiness {".wazuh-cti-consumers", "cti:catalog:consumer:vulnerabilities"};
spec.detection = content_manager::CursorDetection {"offset"};
spec.fullLoad.requiredDocumentIds = {"FEED-GLOBAL", "OSCPE-GLOBAL", "CNA-MAPPING-GLOBAL"};
spec.state.databasePath = "queue/vd/vd_updater/rocksdb";
```

### Example — Engine ruleset sync (one topic per space)

```cpp
content_manager::TopicSpec spec;
spec.schedule.onDemand = true; // no interval: the Engine's scheduler drives runOnce
spec.source.indices = {"wazuh-threatintel-kvdbs", "wazuh-threatintel-decoders", "wazuh-threatintel-filters",
                       "wazuh-threatintel-integrations", "wazuh-threatintel-policies"};
spec.source.expandWildcards = true;
spec.source.query = nlohmann::json {{"bool", {{"filter", {{{"term", {{"space.name", "standard"}}}}}}}}};
spec.readiness = content_manager::Readiness {".wazuh-cti-consumers", "cti:catalog:consumer:ruleset"};

content_manager::HashDetection hash;
hash.probe = content_manager::QueryProbe {/* space.name = standard AND _index wildcard *policies* */};
hash.tokenPointers = {"/space/hash/sha256"};
hash.metadata = {{"enabled", "/document/enabled"}, {"integrations", "/document/integrations"}};
spec.detection = hash;
```

> The Content Manager ships a [test tool](./testtool/main.cpp) that registers one topic against a
> live indexer and prints the delivery contract as it happens.

## Design decisions (D1–D2)

| ID | Decision |
|---|---|
| D1 | **The library never owns an indexer connection; every registration uses the host's.** Before this, each registration built its own `IndexerSession` (keystore read, startup health check, its own health-monitor thread) and its own `IndexerConnectorSync` from connection settings copied into `configData.indexer`. Every host therefore ran two connector stacks against the same cluster — VD its scan pool plus this one, the Engine its async connector plus this one — so an indexer outage was reported twice, by two monitors, and each host paid for a second set of connector objects. The detailed contract follows the table. |
| D2 | **Registrations are described by concern, and each change-detection strategy carries only its own settings.** The parameters were one flat `configData.indexer` object mixing five concerns — what to read, the consumer readiness gate, change detection, full-load preconditions, token state — where half the keys meant something only under one `changeDetection` value, so the validator had to reject combinations ("exactly one of hashDocId/hashIndex", "hashQuery requires hashIndex") instead of the shape ruling them out. Some keys were dead (`consumerName` since D1, `hashIndex` beyond picking the probe shape), the topic name was given twice, a missing gate was expressed by deleting a key, and every host hand-assembled the JSON. The detailed contract follows the table. |

### D1 in detail

**Contract.** A new public header, `include/contentIndexer.hpp`, defines
`content_manager::IContentIndexer` — the four operations a cycle needs, and nothing else:

| Operation | Used for |
|---|---|
| `openPit(indices, keepAlive, expandWildcards)` | The snapshot a cycle reads from |
| `closePit(pit)` | Releasing it; never throws (a leaked PIT expires after `keepAlive`) |
| `search(pit, size, query, sort, searchAfter, source, slice)` | Every probe and every page, sliced or not |
| `searchIndex(index, size, query, source)` | The pre-flight consumer probe, outside any PIT. Returns the **hits object** (`{"total": …, "hits": [...]}`), the shape both connectors already return |

It replaces the private `IIndexerQueryPort`. `clone()` is gone: an implementation **must accept
concurrent calls** — slice workers, several topics, the scheduler and the on-demand lane all use the
one instance at once — and must not hold a lock of its own across a request.

`ContentRegister` takes it as a required argument:
`ContentRegister(topicName, parameters, sink, std::shared_ptr<content_manager::IContentIndexer> indexer, tokenStore = nullptr, contractVersion = …)`.
A null `indexer` throws `std::invalid_argument`, like a null sink. The registration holds the
`shared_ptr` for its whole life, so the connector cannot be destroyed under a running cycle whatever
order the host tears down in.

**Adapters.** The library ships the two hosts need, in `include/contentIndexerAdapters.hpp`:
`content_manager::makeContentIndexer(std::shared_ptr<IndexerConnectorSync>)` and
`content_manager::makeContentIndexer(std::shared_ptr<IndexerConnectorAsync>)`. The header
forward-declares both classes instead of including `indexerConnector.hpp`, so the C++17 public-header
guard (`content_manager_public_abi_c17`) keeps compiling with the include directories it has today. A
future host either uses one of these or implements the interface.

**Why sharing is safe.** Checked in the code, not assumed:

- A search takes no connector lock. `IndexerConnectorSync::search` and `executeSearchQuery` use only
  local state; `m_mutex` is taken by bulk operations and `scopeLock()` alone. A content download on a
  connector therefore never waits for, and never holds up, a bulk write on the same connector.
- HTTP concurrency is per thread, not per connector. Every connector posts through the process-wide
  `HTTPRequest::instance()`, whose curl handles are cached per `std::thread::id`; its mutex covers the
  cache lookup only. A second connector instance adds no parallelism — the old "HTTP state must not
  be shared across threads" reason for `clone()` did not hold.
- Host selection is `RoundRobinSelector` over an atomic index, and the health monitor is shared
  already (one session per host).
- `IndexerConnectorAsync::search` is a direct synchronous request on the calling thread; it does not
  go through the event-indexing queue, so the Engine's event throughput is untouched by downloads.

**What moves, per host.**

- **Vulnerability Scanner.** The feed registration uses `makeContentIndexer(m_scanConnectors.front())`
  — slot 0 of the existing scan pool, which already doubles as `ScanAgentList`'s read-only connector.
  No instance is added. A scan checks a slot out exclusively only to serialise its `scopeLock()`/bulk
  section, which downloads never take, so a long feed download does not delay scans or the inventory
  sync's VD lane. `buildUpdaterConfig` stops copying the `<indexer>` section into
  `configData.indexer`. `TDatabaseFeedManager` takes the `IContentIndexer` as its last constructor
  argument and passes it to the registration.
- **Engine.** `main.cpp` builds the one `IndexerConnectorAsync` as a `shared_ptr` and hands it to
  `WIndexerConnector` (new constructor taking it; the adapter holds a `shared_ptr` instead of a
  `unique_ptr`) and, through `makeContentIndexer`, to `CMSync` and `IocSync`. Their constructors take
  `std::shared_ptr<content_manager::IContentIndexer>` instead of the `indexerConnection` JSON, and
  pass it to `cmcontent::defaultTopicFactory(indexer)`, which captures it — so `TopicFactory`'s
  signature, and every fake factory a test substitutes, is unchanged. `rulesetParameters`/
  `iocParameters` drop their `connection` parameter.
- **Library.** Removed: `ContentModuleFacade::sessionFor`, `fingerprint`, `m_sessions`, the
  `IndexerConnectorQueryPort` class (its body becomes the `IndexerConnectorSync` adapter) and every
  `clone()`. `configData.indexer` keeps the query specification only (indices, consumer, probe,
  paging); connection keys in it are ignored. The library no longer reads the keystore.
- **Test tool.** `testtool/main.cpp` builds its own `IndexerConnectorSync` from its configuration and
  registers through `makeContentIndexer`, exactly as a host does.

**Logging.** A failed request is now logged once, by the host's connector, under the host's tag
(`wazuh-manager-modulesd:vulnerability-scanner(indexer-connector)`, the Engine's own) — no longer a
second time under `content-updater(indexer-connector)` by a second connector. The cycle's own lines
(`Content update for '<topic>' …`) are unchanged.

**Tests.** Every unit test already drives the cycle through a fake port; it now implements
`IContentIndexer` and loses `clone()`. `content_manager_ctest` and every host test pass a fake
explicitly. That removes the last tests that reached the real keystore: `cmsync_ctest`'s credential
seeding and its `rocks_db_lock` go away. New: a slicing test asserting every slice runs on the **same**
instance concurrently, and a registration test asserting a null indexer is rejected. The two adapters
are thin forwarding shims (LCOV-excluded); the VD efficacy suite and the Engine integration suites
exercise them end to end.

### D2 in detail

**Shape.** The parameters a `ContentRegister` receives become, with every key optional unless marked:

```json,fragment
{
  "schedule":  { "intervalSeconds": 3600, "onDemand": true },
  "source":    { "indices": ["…"],                          // required, non-empty
                 "expandWildcards": false, "query": {…}, "sourceFilter": {…},
                 "pageSize": 100, "slices": 1, "pitKeepAlive": "5m" },
  "readiness": { "consumerIndex": "…", "consumerId": "…",   // both required when the block is present
                 "retrySeconds": 60, "cacheSeconds": 5 },
  "detection": { "type": "cursor", "field": "offset", "unmappedType": "long" }
            or { "type": "hash",
                 "probe": { "type": "document", "id": "…" } or { "type": "query", "query": {…} },
                 "tokenPointers": ["/…"],                     // required, non-empty
                 "metadata": { "enabled": "/document/enabled" } },
  "fullLoad":  { "requiredDocumentIds": ["…"] },
  "state":     { "databasePath": "…", "resetOnRegister": false }
}
```

`detection` is required. What the old keys became:

| Old | New |
|---|---|
| `topicName` | removed: the topic is `ContentRegister`'s first argument, which was already required and had to match |
| `interval`, `ondemand` | `schedule.intervalSeconds`, `schedule.onDemand` |
| `configData.consumerName` | removed: dead since D1 (it was the User-Agent of the library's own connector) |
| `configData.changeDetection` | `detection.type` |
| `configData.databasePath`, `resetStateOnRegister` | `state.databasePath`, `state.resetOnRegister` |
| `configData.consumerRetryIntervalSeconds` | `readiness.retrySeconds` |
| `indexer.index` / `indices`, `expandWildcards`, `pageSize`, `numSlices`, `keepAlive`, `sourceFilter` | `source.indices` (always a list), `source.expandWildcards`, `source.pageSize`, `source.slices`, `source.pitKeepAlive`, `source.sourceFilter` |
| `indexer.dataQuery` (hash only) | `source.query`, now for **both** strategies: a full fetch runs it as is, an incremental cursor fetch runs it AND the cursor range. Absent means everything, which is what cursor mode did before |
| `indexer.consumerStatusIndex` / `Id`, `consumerStatusCacheSeconds` | `readiness.consumerIndex` / `consumerId`, `readiness.cacheSeconds`. **No `readiness` block means no gate**, replacing the deleted key `registration.cpp` used for the `custom` space |
| `indexer.cursorField`, `sortUnmappedType` | `detection.field`, `detection.unmappedType` (cursor only) |
| `indexer.hashDocId` / `hashIndex` + `hashQuery` | `detection.probe`: `{"type": "document", "id"}` or `{"type": "query", "query"}`. `hashIndex` is gone; the ambiguity error names the probe query instead |
| `indexer.hashPointers`, `metadataPointers` | `detection.tokenPointers`, `detection.metadata` (hash only) |
| `indexer.sortKeys` | removed: derived from the strategy — cursor sorts on its field (with `unmappedType` when a consumer index joins the PIT) then `_id`, hash on `_shard_doc` then `_id`. The only two hosts used exactly these |
| `indexer.requiredDocumentIds` | `fullLoad.requiredDocumentIds` |
| any connection key | rejected, like every other unknown key |

**Strict.** Every block rejects keys it does not know, naming the key and its block, and a key
belonging to the other strategy is unknown to this one. A stale or mistyped registration therefore
fails at construction with a message an operator can act on, instead of being half-ignored — which
is what happened to connection keys after D1.

**Parsed once.** The library turns the JSON into one typed internal model at registration; validation
and `FactoryContentUpdater` both read that model, so the scattered `value(key, default)` reads, the
separate type checks in `ExecutionContext` and their defaults living in two places all go away.

**Typed builders for hosts.** A header-only public header, `include/contentTopicSpec.hpp`, gives
hosts a C++17 struct with the defaults above — `content_manager::TopicSpec`, with
`std::variant<CursorDetection, HashDetection>`, `std::optional<Readiness>` — and an inline
`toParameters(const TopicSpec&)` that emits the JSON. It runs in the host, so only JSON crosses the
library boundary and no struct layout joins the `CONTRACT_ABI_VERSION` guard; the C++17 public-header
check compiles it. VD's `buildUpdaterConfig` and the Engine's `rulesetParameters`/`iocParameters`
build a `TopicSpec` instead of JSON.

**What else goes.** VD's `configuration["updater"]` override of the whole registration, whose only
user was `testtool/scanner/config.content_generation.json` — itself still in the pre-5.x CTI
snapshot format the library dropped long ago — is removed, and so is that file. The policy-driven
interval change (`changeSchedulerInterval`) is unaffected.

**Tests.** The registrations the suites build move to the new shape (most through `TopicSpec`). New:
`toParameters` → parse round-trips for both strategies; a key from the other strategy, an unknown
key in each block, a `readiness` block missing its id, and an empty `tokenPointers` are each
rejected with the key named; a registration with no `readiness` opens a PIT over the data indices
only; an incremental cursor fetch with a `source.query` runs both clauses.

## Verification

Automated, and run by CI:

| Suite | Covers |
|---|---|
| `content_manager_utest` | Every component through `IContentIndexer`: the full `CycleStatus` matrix, which paths write the token, `retryAfter` per status, slicing, the consumer gate and its cache, the on-demand lane, the token store. |
| `content_manager_ctest` | A whole registration — facade, provider, driver, cycle — against a scripted indexer: the consumer-flip race, forced reloads, on-demand, registry locking under a running cycle. |
| `content_manager_public_abi_c17` | The public headers alone, under C++17, with only the include directories a foreign host gets. Fails on a C++20 construct in a public header, and on a private header leaking into `include/`. |

Two properties are asserted here rather than left to an integration run, because both would otherwise
surface only in production:

- **A deferred cycle comes back on `retryAfter`, not on the scheduler interval.** Driven with the
  vulnerability scanner's real 3600-second interval, holding the consumer busy and asserting the
  cycle completes in seconds. Getting this wrong means a manager that boots during an indexer
  content update has no CVE data for an hour.
- **The registry lock is not held across a download.** One test parks a cycle inside the library and
  registers a second topic while it is parked; another checks that removing a topic still waits for
  its own cycle to drain.

### Against a live cluster

The query contract — the sort surviving the consumer index joining the PIT, and slicing over that
PIT neither losing nor duplicating documents — is automated in
[`testtool/integration`](./testtool/integration/). It needs a cluster but **not** a build: both are
pure query-shape questions issued straight at the REST API.

```bash
cd testtool/integration
docker compose -f docker-compose.yml up -d && ./query_contract_test.py
```

What remains manual is **end-to-end promotion** for each consumer, which needs the built binaries: a
vulnerability feed cold start, a full load with a concurrent consumer update, an Engine ruleset sync
with a mid-download consumer flip, an IOC sync with one type changing, on-demand returning 409 under
a running update, and a graceful shutdown mid-download for each. The table in
[`testtool/integration/README.md`](./testtool/integration/README.md) says what must hold for each.

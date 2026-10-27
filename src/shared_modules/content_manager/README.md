# Content Manager

The Content Manager keeps a host's copy of indexer content in step with the Wazuh Indexer. It is a
generic library: the Vulnerability Detection module (the CVE feed) and the Engine's ruleset and IOC
syncs (`cmcontent`) all use it, each with its own change-detection strategy, its own destination
and its own token storage. A host describes what to read and where it goes; the library owns how it
is read.

## The cycle

Every topic runs the same cycle, once per scheduled or requested execution:

```
pre-flight: is the consumer "ready"? (cheap, cached)        (cost gate)
open a PIT over {data indices} ∪ {consumer status index}
  → validate the consumer is "ready" INSIDE the PIT          (consistency)
  → probe the remote change token and compare it locally     (change detection)
  → if it moved: paginate the PIT with search_after          (fetch)
  → the sink accepts pages, then promotes atomically         (delivery)
  → persist the new token only after promotion               (durability)
close the PIT
tell the sink how the cycle ended                            (cycleFinished)
```

Only change detection, delivery and token storage differ between topics. Fetching differs only by
*configuration* — indices, query, `_source` filter, page size, slice count.

Validating the consumer from inside the PIT rather than before opening it closes the window in
which the indexer starts rewriting content between the check and the snapshot. It has two
consequences the library handles:

- the cursor sort carries an `unmapped_type`. Not because the consumer status index lacks the
  field — OpenSearch only needs a sort field mapped in *one* index of the search — but because on a
  cold start the data index has no documents and therefore no dynamic mapping either, leaving the
  key unmapped everywhere, which fails the whole search. That is exactly a new manager's first feed
  load;
- consumer documents are excluded from results twice — query-side with a `must_not` on `_index`, and
  hit-side by dropping anything that still arrives from that index.

## Components

| Component | Responsibility |
|---|---|
| `ContentRegister` | The public handle of one topic (`contentRegister.hpp`). Owns its `TopicDriver`. |
| `TopicDriver` | One topic: validates the spec, opens the token store, holds the run slot (one cycle at a time), runs the optional driver thread and the pending request, escalates transport backoff, logs each outcome. |
| `ContentCycle` | Runs the cycle exactly once and returns a `CycleOutcome`. Never throws, never waits on a gate. |
| `ConsumerGate` | The consumer document's format (query, `_source` filter, parser) and the cached pre-flight probe, shared across topics watching the same consumer. |
| `PitSession` | Opens and closes the PIT; validates consumer readiness inside it with the gate's parser; scopes queries to the data indices. |
| `IChangeDetector` | `OffsetCursorDetector` (monotonic integer cursor) and `ContentHashDetector` (content hash, document- or query-probed). |
| `PitPaginator` | `search_after` pagination, optionally sliced, with sink calls serialised. No domain knowledge. |
| `FactoryContentUpdater` | Turns a validated `TopicSpec` into a `ContentCycle`. |
| `RocksDbTokenStore` | The built-in token store, one RocksDB per topic under `state.databasePath`. |
| `IContentIndexer` | The host's indexer: the four read operations the cycle needs (`contentIndexer.hpp`), with adapters over both connectors (D1). |
| `IContentSink` | Where the content goes, and who decides it is safe to keep. Implemented by the host. |
| `IContentTokenStore` | Where the change-detection token lives, when the host keeps it. |

Operator-facing behaviour (indices, state on disk, logs, configuration) is documented in the published
reference, [docs/ref/modules/content_manager/README.md](../../../docs/ref/modules/content_manager/README.md).
This README covers the library's interface and internals.

## Usage

```cpp
// Once, before the first registration: the library logs through the host, under the host's tag.
content_manager::setLogFunction(logFunction, "wazuh-manager-modulesd:content-updater");

// The host's own connector — the one it already uses for everything else (D1).
const auto indexer = content_manager::makeContentIndexer(myConnector);
ContentRegister registration {"my.topic", spec, std::make_shared<MySink>(), indexer};

// Host-driven (no schedule.intervalSeconds): run a cycle from your own scheduler.
const auto outcome = registration.runOnce();

// Library-driven (schedule.intervalSeconds set): the driver thread runs a cycle at start and then
// on the interval; a request runs one now and answers when it ends.
registration.requestRun({/*forceFullReload=*/false},
                        [](content_manager::OnDemandResult result) { /* map result.code */ });
```

`runOnce` is bounded: every gate is single-pass, and a deferred cycle reports
`CycleOutcome::retryAfter` instead of parking the calling thread. The driver thread honours
`retryAfter` when it is non-zero — otherwise a topic whose consumer is briefly busy would wait a
whole interval, which for VD's 60-minute default means an hour with no data.

Cycles are mutually exclusive per topic, whoever asks for them. A second one gets
`CycleStatus::SkippedAlreadyRunning` — deliberately **not** `SkippedStopRequested`: a caller folding a
cycle's result into its own state has to tell "nothing ran, so I observed nothing" from "a cycle ran
and found nothing to do". `requestRun` answers `AlreadyRunning` inline in the same situation, or when
a request is already pending.

`IContentSink::cycleFinished(outcome)` is called after every cycle that ran — including one a gate
stopped before `beginSession` — inside the run slot, after the token was written. A sink that
reports status sees every result there, and nothing else can start a cycle of the topic until it
returns.

`requestRun`'s `OnDemandCode` says what a request handler answers:

| Code | Cycle status |
|---|---|
| `Completed` | `Updated`, `Unchanged` |
| `Deferred` | `SkippedConsumerNotReady`, `SkippedPreconditionUnmet` |
| `AlreadyRunning` | a cycle was running or already requested |
| `ShuttingDown` | `SkippedStopRequested`, or the registration is stopping |
| `Failed` | `FailedTransport`, `FailedSink`, `FailedConfig`, or the topic has no interval |

`requestStop()` is permanent: every later cycle returns `SkippedStopRequested`. Hosts that tear down
in two steps (stop everything, then destroy) use it; destroying a registration stops it anyway and
waits for an in-flight cycle.

### Configuration

A registration is a `content_manager::TopicSpec` (`include/contentTopicSpec.hpp`), grouped by
concern: `schedule` (the interval; none = host-driven), `source` (indices, query, source filter,
paging, slices, PIT lease), an optional `readiness` gate (the CTI consumer document; absent means
never gated), `detection` (a cursor or a content hash, each carrying only its own settings),
`fullLoad` (documents a full load requires) and `state` (the built-in token store). Defaults are the
library's; a host sets only what differs. `ContentRegister` validates the values at construction and
names the field at fault (D2).

### Example — Vulnerability Detection

```cpp
content_manager::TopicSpec spec;
spec.schedule.intervalSeconds = 3600;
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
content_manager::TopicSpec spec; // no interval: the Engine's scheduler runs the topic
spec.source.indices = {"wazuh-threatintel-kvdbs", "wazuh-threatintel-decoders", "wazuh-threatintel-filters",
                       "wazuh-threatintel-integrations", "wazuh-threatintel-policies"};
spec.source.expandWildcards = true;
spec.source.query = nlohmann::json {{"bool", {{"filter", {{{"term", {{"space.name", "standard"}}}}}}}}};
spec.readiness = content_manager::Readiness {".wazuh-cti-consumers", "cti:catalog:consumer:ruleset"};

content_manager::HashDetection hash;
hash.probe = content_manager::QueryProbe {/* space.name = standard AND _index wildcard *policies* */};
hash.tokenPointers = {"/space/hash/sha256"};
hash.metadata = {{"enabled", "/document/enabled"},
                 {"integrations", "/document/integrations"},
                 {"root_decoder", "/document/root_decoder"}};
spec.detection = hash;
```

> The Content Manager ships a [test tool](./testtool/main.cpp) that registers one topic against a
> live indexer and prints the delivery contract as it happens.

## Design decisions (D1–D4)

| ID | Decision |
|---|---|
| D1 | **The library never owns an indexer connection; every registration uses the host's.** One connector per process means one health monitor, one keystore read, and an indexer outage reported once. |
| D2 | **Registrations are described by concern, and each change-detection strategy carries only its own settings.** The shape of `TopicSpec` rules out mixed strategies and unknown keys; what is left to validate is values. |
| D3 | **The library is dual-licensed `GPL-2.0-only OR AGPL-3.0-or-later`, and the Engine starts it only when it can use it.** Both modulesd (GPL-2.0) and the Engine (AGPL-3.0) link it. |
| D4 | **One owner per job: the library runs topics; hosts run nothing of their own around it.** Two layers (`ContentRegister` → `TopicDriver` → `ContentCycle`), no process-wide registry, a per-topic request instead of a shared lane, every outcome reaching the sink, and the host's tag on every log line. |

### D1 in detail

**Contract.** `include/contentIndexer.hpp` defines `content_manager::IContentIndexer` — the four
operations a cycle needs:

| Operation | Used for |
|---|---|
| `openPit(indices, keepAlive, expandWildcards)` | The snapshot a cycle reads from |
| `closePit(pit)` | Releasing it; never throws (a leaked PIT expires after `keepAlive`) |
| `search(pit, size, query, sort, searchAfter, source, slice)` | Every probe and every page, sliced or not |
| `searchIndex(index, size, query, source)` | The pre-flight consumer probe, outside any PIT. Returns the **hits object** (`{"total": …, "hits": [...]}`) |

An implementation **must accept concurrent calls** — slice workers and several topics use the one
instance at once — and must not hold a lock of its own across a request. `ContentRegister` takes it
as a required argument and holds the `shared_ptr` for its whole life, so the connector cannot be
destroyed under a running cycle whatever order the host tears down in.

**Adapters.** `include/contentIndexerAdapters.hpp` ships
`content_manager::makeContentIndexer(std::shared_ptr<IndexerConnectorSync>)` and
`makeContentIndexer(std::shared_ptr<IndexerConnectorAsync>)`. The header forward-declares both classes
instead of including `indexerConnector.hpp`, so the C++17 public-header guard compiles with the
include directories a foreign host gets. A future host uses one of these or implements the interface.

**Why sharing is safe.** Checked in the code, not assumed:

- A search takes no connector lock. `IndexerConnectorSync::search` and `executeSearchQuery` use only
  local state; `m_mutex` is taken by bulk operations and `scopeLock()` alone. A content download on a
  connector never waits for, and never holds up, a bulk write on the same connector.
- HTTP concurrency is per thread, not per connector. Every connector posts through the process-wide
  `HTTPRequest::instance()`, whose curl handles are cached per `std::thread::id`.
- Host selection is `RoundRobinSelector` over an atomic index, and the health monitor is shared.
- `IndexerConnectorAsync::search` is a direct synchronous request on the calling thread; it does not
  go through the event-indexing queue, so the Engine's event throughput is untouched by downloads.

**Hosts.** The Vulnerability Scanner hands the feed registration slot 0 of its scan pool, which a
scan checks out exclusively only for its `scopeLock()`/bulk section — a section downloads never take.
The Engine builds one `IndexerConnectorAsync` and shares it between `WIndexerConnector` (event
indexing) and every content topic.

### D2 in detail

**Shape.** Every field is optional unless marked:

| Block | Fields |
|---|---|
| `schedule` | `intervalSeconds` (absent = host-driven) |
| `source` | `indices` (required, non-empty), `expandWildcards`, `query`, `sourceFilter`, `pageSize` (100), `slices` (1), `pitKeepAlive` ("5m") |
| `readiness` | `consumerIndex`, `consumerId` (both required when present), `retrySeconds` (60), `cacheSeconds` (5). Absent = never gated |
| `detection` | `CursorDetection {field = "offset", unmappedType = "long"}` or `HashDetection {probe, tokenPointers, metadata}`, with `probe` a `DocumentProbe {id}` or a `QueryProbe {query}` |
| `fullLoad` | `requiredDocumentIds` |
| `state` | `databasePath` (empty = host-supplied store), `resetOnRegister` |

`source.query` narrows both strategies: a full fetch runs it as is, an incremental cursor fetch runs
it AND the cursor range. The sort is implied by the strategy — cursor sorts on its field (always
with its `unmappedType`, which a cold start needs) then `_id`, hash on `_doc` then `_id` (not
`_shard_doc`, which OpenSearch 2.x rejects).

**Validated once.** `validateTopicSpec` rejects what the shape cannot rule out — empty indices, a zero
page size or slice count, a consumer index that is a pattern, a list or an exclusion (both
consumer-document defences compare against the concrete `_index`), a token pointer that is not a JSON
pointer — and names the field. Every later stage reads the typed spec.

### D3 in detail

**License.** Every file of `src/shared_modules/content_manager/` carries
`GPL-2.0-only OR AGPL-3.0-or-later`, with the notice `indexer_connector` uses, and the directory ships
the same `COPYING`. `content_manager` is in `DUAL_DIRS` in `.github/scripts/spdx_scope.py`. Everything
the library includes or links is compatible with both: `utils` and `indexer_connector` are dual,
nlohmann/json is MIT. `src/shared/include` (GPL-2.0 C headers) is not on its include path.

**Started only when used.** The Engine sets the library's log function only when
`analysisd.server_enable_event_processing` is on — the switch that decides whether CMSync and IocSync
exist. The standalone Engine, which runs with it off, loads `libcontent_manager.so` without using it,
as it does `libindexer_connector.so`.

**Shared, not static.** Linking a static build into the Engine was considered and dropped: it would
need a second build of the same sources with link rules that can drift, put the code twice on disk,
and split `Log::GLOBAL_LOG_FUNCTION`, which the shared library defines — while the Engine already
exchanges `nlohmann::json`, strings and exceptions with `indexer_connector` across the same boundary.

### D4 in detail

**Layers.** `ContentRegister` owns a `TopicDriver`, which owns a `ContentCycle`. There is no
process-wide registry: a registration is reached through its handle, and topic names only label log
lines and sink calls.

**Running a topic.** A topic with `schedule.intervalSeconds` gets a driver thread: a cycle at start,
then one per wake-up — the timer (`retryAfter`, or the interval), or a request. `requestRun` never
blocks; it is answered inline when it cannot be queued (a cycle running or already requested, a
stopping topic, a topic without an interval) and on the driver thread otherwise. A topic without an
interval is the host's to run with `runOnce`, from its own scheduler. Both paths share the one run
slot.

**Forced reloads.** `RunRequest::forceFullReload` plans with an empty token and clears the stored one
only once the sink has accepted the full session. A forced request that a gate stops — consumer busy,
required documents missing, an unreachable indexer — leaves the stored token, and with it the host's
reported offset, unchanged.

**Every outcome reaches the sink.** `cycleFinished` is how a host learns about deferrals and
transport failures that never reached `beginSession`, and it runs inside the run slot, so its state
always belongs to the cycle it follows.

**Logging.** `content_manager::setLogFunction(fn, tag)` installs the host's sink and the tag every
library line carries, so each daemon's content downloads appear under that daemon.

**What a host writes.** A sink, optionally a token store, a `TopicSpec`, a `setLogFunction` call, and
either `runOnce` from its own scheduler or an interval plus `requestRun` for on-demand updates.

## Verification

Automated, and run by CI:

| Suite | Covers |
|---|---|
| `content_manager_utest` | Every component through `IContentIndexer`: the full `CycleStatus` matrix, which paths write the token, `retryAfter` per status, slicing, the consumer gate and its cache, the driver (thread, requests, codes, backoff, run slot), spec validation, the token store. |
| `content_manager_ctest` | Whole registrations through the public API against a scripted indexer: the consumer-flip race, forced reloads, requested runs, destruction waiting for a cycle. |
| `content_manager_public_abi_c17` | The public headers alone, under C++17, with only the include directories a foreign host gets. Fails on a C++20 construct in a public header, and on a private header leaking into `include/`. |

Two properties are asserted here rather than left to an integration run, because both would otherwise
surface only in production:

- **A deferred cycle comes back on `retryAfter`, not on the interval.** Driven with VD's real
  3600-second interval and a busy consumer, the driver retries within seconds.
- **A deferred request is not reported as completed.** A request whose cycle the consumer gate
  stops answers `Deferred`, so a handler cannot answer "ok" for a download that did not happen.

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
with a mid-download consumer flip, an IOC sync with one type changing, on-demand under a running
update, and a graceful shutdown mid-download for each. The table in
[`testtool/integration/README.md`](./testtool/integration/README.md) says what must hold for each.

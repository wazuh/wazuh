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
| `IIndexerQueryPort` | The five indexer operations the cycle needs. One production implementation over `IndexerConnectorSync`; a fake in tests. |
| `PitSession` | Opens and closes the PIT; validates consumer readiness inside it; scopes queries to the data indices. |
| `ConsumerGate` | Cheap, bounded, cached pre-flight readiness probe, shared across topics watching the same consumer. |
| `IChangeDetector` | `OffsetCursorDetector` (monotonic integer cursor) and `ContentHashDetector` (content hash, doc- or query-probed). |
| `PitPaginator` | `search_after` pagination, optionally sliced. No domain knowledge. |
| `ContentCycle` | Runs the cycle exactly once and returns a `CycleOutcome`. Never throws, never loops indefinitely. |
| `IContentSink` | Where the content goes, and who decides it is safe to keep. Implemented by the host. |
| `IContentTokenStore` | Where the change-detection token lives. `RocksDbTokenStore` by default; hosts may supply their own. |

## Usage

```cpp
ContentRegister registration {topicName, parameters, std::make_shared<MySink>()};

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

- `topicName`: topic name; also the on-demand route key.
- `interval`: _(optional)_ seconds between executions. Present ⇒ the library spawns a driver thread.
  Absent ⇒ the host drives `runOnce`.
- `ondemand`: if `true`, the topic is published on the on-demand lane.
- `configData`:
  + `consumerName`: name of the caller (e.g. `Wazuh VulnerabilityDetector`). Becomes the HTTP User-Agent.
  + `changeDetection`: `cursor` or `hash`.
  + `databasePath`: _(optional)_ enables the built-in RocksDB token store.
  + `resetStateOnRegister`: _(optional)_ clear the stored token at registration.
  + `consumerRetryIntervalSeconds`: _(optional, default 60)_ backoff when the consumer is not ready.
  + `indexer`: connection settings (`hosts`, `ssl`, credentials) plus the per-topic query spec:
    - `index` / `indices`: the content indices.
    - `consumerStatusIndex` / `consumerStatusId`: the consumer document to validate. The index must
      be a **concrete** name — an alias or pattern is rejected at registration, because both
      consumer-document defences compare against the `_index` metafield.
    - `pageSize`, `numSlices`, `keepAlive`, `expandWildcards`, `sortKeys`, `sourceFilter`.
    - cursor mode: `cursorField` (default `offset`).
    - hash mode: exactly one of `hashDocId` (doc probe) or `hashIndex` + `hashQuery` (query probe),
      plus `hashPointers`, optional `metadataPointers`, and `dataQuery`.
    - `requiredDocumentIds`: _(optional)_ documents that must exist before a full load is attempted.

### Example — Vulnerability Detection

```json
{
    "topicName": "vulnerability_feed_manager",
    "interval": 3600,
    "ondemand": true,
    "configData": {
        "consumerName": "Wazuh VulnerabilityDetector",
        "changeDetection": "cursor",
        "databasePath": "queue/vd/vd_updater/rocksdb",
        "indexer": {
            "hosts": ["https://localhost:9200"],
            "username": "wazuh-manager",
            "password": "wazuh-manager",
            "ssl": {
                "certificate_authorities": ["/etc/wazuh-indexer/certs/root-ca.pem"],
                "certificate": "",
                "key": ""
            },
            "index": ".wazuh-threatintel-vulnerabilities",
            "consumerStatusIndex": ".wazuh-cti-consumers",
            "consumerStatusId": "cti:catalog:consumer:vulnerabilities",
            "cursorField": "offset",
            "pageSize": 100,
            "numSlices": 2,
            "requiredDocumentIds": ["FEED-GLOBAL", "OSCPE-GLOBAL", "CNA-MAPPING-GLOBAL"]
        }
    }
}
```

### Example — Engine ruleset sync (one topic per space)

```json
{
    "topicName": "content.ruleset.standard",
    "ondemand": true,
    "configData": {
        "consumerName": "Wazuh Engine CM Sync",
        "changeDetection": "hash",
        "indexer": {
            "indices": ["wazuh-threatintel-kvdbs", "wazuh-threatintel-decoders", "wazuh-threatintel-filters",
                        "wazuh-threatintel-integrations", "wazuh-threatintel-policies"],
            "expandWildcards": true,
            "consumerStatusIndex": ".wazuh-cti-consumers",
            "consumerStatusId": "cti:catalog:consumer:ruleset",
            "hashIndex": "wazuh-threatintel-policies",
            "hashQuery": {"bool": {"filter": [{"term": {"space.name": "standard"}},
                                              {"exists": {"field": "document.enabled"}}]}},
            "hashPointers": ["/space/hash/sha256"],
            "metadataPointers": {"enabled": "/document/enabled", "integrations": "/document/integrations"},
            "dataQuery": {"bool": {"filter": [{"term": {"space.name": "standard"}}]}},
            "sortKeys": [{"_shard_doc": "asc"}, {"_id": "asc"}]
        }
    }
}
```

> The Content Manager ships a [test tool](./testtool/main.cpp) that registers one topic against a
> live indexer and prints the delivery contract as it happens.

## Verification

Automated, and run by CI:

| Suite | Covers |
|---|---|
| `content_manager_utest` | Every component through `IIndexerQueryPort`: the full `CycleStatus` matrix, which paths write the token, `retryAfter` per status, slicing, the consumer gate and its cache, the on-demand lane, the token store. |
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

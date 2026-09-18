# Content Manager

The Content Manager is a shared library that downloads content from the Wazuh Indexer and hands it to whoever registered for it. It is used by the Vulnerability Scanner to keep its local CVE database up to date, and by the Engine to keep its ruleset (`cmsync`) and IoC enrichment databases (`iocsync`) in step with the indexer.

Source: `src/shared_modules/content_manager/`

## How it works

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

Only three things genuinely differ between consumers — how change is detected, where the content goes, and where the token is kept. Fetching differs only by *configuration*: indices, query, sort keys, `_source` filter, page size and slice count.

**Change detection** comes in two shapes:

- **cursor** — every document carries a monotonically increasing `offset`, and an update is "everything greater than what I already have". Used by the Vulnerability Scanner, which can therefore fetch incrementally.
- **hash** — the source publishes a content hash, and any change means a full reload. Used by both Engine consumers.

**Consumer validation happens inside the PIT snapshot**, not before it is opened. Checking first and snapshotting afterwards leaves a window in which the indexer starts rewriting content between the two, which is exactly the state the check exists to prevent. A cheap pre-flight probe is still made first — it costs one query and avoids taking a lease over a multi-gigabyte index while the indexer is visibly mid-update — but it is an optimisation, not the guarantee.

A cycle is **bounded**: it never waits in a loop for the consumer to become ready. When it cannot proceed it returns immediately and tells its driver how soon to come back (60 s for a busy consumer, escalating 30 s–5 min for a transport failure), which is what makes it safe to run on a shared scheduler worker pool.

## State storage

| Path | Contents |
|------|----------|
| `queue/vd/vd_updater/rocksdb` | Vulnerability Scanner: RocksDB database storing the current fetch cursor (`current_offset`) |
| `cmsync/status/0`, `iocsync/status/0` | Engine: the per-space and per-type hashes live in the sync services' own state documents |

## Indexer indices

| Index | Role |
|-------|------|
| `.wazuh-threatintel-vulnerabilities` | CVE documents (Vulnerability Scanner) |
| `wazuh-threatintel-{kvdbs,decoders,filters,integrations,policies}` | Ruleset resources (Engine `cmsync`) |
| `wazuh-threatintel-enrichments` | IoC documents and the per-type hash manifest (Engine `iocsync`) |
| `.wazuh-cti-consumers` | Consumer status documents, validated inside every PIT |

## Configuration

The module is configured programmatically by its caller, not via `wazuh-manager.conf` directly. Relevant parameters:

| Parameter | Description |
|-----------|-------------|
| `topicName` | Topic name; also the on-demand route key |
| `interval` | Seconds between scheduled executions. **Optional**: when absent, the host drives each cycle from its own scheduler and the library spawns no thread |
| `ondemand` | If `true`, the topic can also be triggered explicitly |
| `configData.consumerName` | Caller name; becomes the HTTP User-Agent |
| `configData.changeDetection` | `cursor` or `hash` |
| `configData.databasePath` | Path to the RocksDB token database. Omitted by hosts that keep the token in their own state |
| `configData.consumerRetryIntervalSeconds` | Backoff when the consumer is not ready (default 60) |
| `configData.indexer.hosts` | Indexer endpoint URLs |
| `configData.indexer.index` / `.indices` | Index or indices to read from |
| `configData.indexer.consumerStatusIndex` / `.consumerStatusId` | Consumer document to validate. The index must be a **concrete** name — an alias or wildcard is rejected at registration |
| `configData.indexer.pageSize` | Documents per PIT page (default 100) |
| `configData.indexer.numSlices` | Parallel PIT slices for a full load (default 1; the Vulnerability Scanner uses 2) |
| `configData.indexer.requiredDocumentIds` | Documents that must exist before a full load is attempted |

The Indexer connection parameters come from the manager's `<indexer>` XML block (see [Indexer Configuration](configuration.md)). Connectors are shared: registrations that talk to the same indexer with the same credentials reuse one session and therefore one health-monitor thread.

## On-demand updates

### Vulnerability Scanner (`POST /ondemand`)

Topics registered with `ondemand: true` can be triggered explicitly over the manager-local
`queue/sockets/vd-http.sock` Unix socket (served by the vulnerability scanner's shared HTTP-over-UDS
server).

```bash
curl --unix-socket /var/wazuh-manager/queue/sockets/vd-http.sock \
     -X POST -d '{"topic":"<name>","offset":-1}' http://localhost/ondemand
```

Request body: `{"topic": "<name>", "offset": -1|0}` — `offset` is optional; `-1` (default)
keeps the current cursor, `0` restarts the content from scratch. The body is capped at 4 KiB
(a larger declared `Content-Length` is rejected with `413` before any body byte is read).

| Status | Body | Meaning |
|---|---|---|
| `200` | `{"status":"ok"}` | The update ran **to completion** (the response is deferred until it finishes) |
| `400` | `{"error":"missing_required_fields"\|"invalid_topic"\|"invalid_offset"\|"invalid_request",...}` | Malformed request; not retryable |
| `404` | `{"error":"unknown_topic",...}` | No such registered on-demand topic |
| `409` | `{"error":"update_in_progress",...}` | An update for that topic is already running — retry later |
| `500` | `{"error":"update_failed",...}` | The update itself failed; retryable |
| `503` | `{"error":"ondemand_queue_full"\|"shutting_down",...}` | The short execution lane is full, or the module is stopping — retry later |

### Engine

The Engine exposes its own triggers on the API socket; both answer as soon as the request is
queued, and progress is read from `GET /status`:

| Endpoint | Effect |
|---|---|
| `POST /content/ruleset/update` | Runs a cycle now for every tracked ruleset space |
| `POST /content/ioc/sync` | Runs a cycle now for every tracked IoC type |

Requests are executed by a bounded lane (queue of 4, two workers) so a burst of triggers sheds
explicitly instead of piling up; concurrent triggers for the *same* topic serialize through the
`409` above.

Every rejection is logged under the `wazuh-manager-modulesd:content-updater` tag, **throttled**:
one line per 90-second window carrying the number of occurrences it stands for, so a storm of
triggers cannot flood `wazuh-manager.log`. Shutdown is the exception — its per-request `503`s are
summarised in a single line reporting how many queued updates were shed.

## Key source files

| File | Purpose |
|------|---------|
| `include/contentTypes.hpp` | The delivery contract: session, page, commit and cycle outcome types |
| `include/contentSink.hpp` | `IContentSink` — where content goes and who decides it is safe to keep |
| `include/contentTokenStore.hpp` | `IContentTokenStore` — where a topic's change-detection token lives |
| `src/components/pitSession.hpp` | Owns the PIT and the in-snapshot consumer validation |
| `src/components/consumerGate.hpp` | Cheap, bounded, cached pre-flight readiness probe |
| `src/components/changeDetector.hpp` | Cursor and content-hash change detection |
| `src/components/pitPaginator.hpp` | `search_after` pagination, optionally sliced |
| `src/components/contentCycle.hpp` | Runs one cycle and returns its outcome |
| `README.md` | Developer-oriented usage guide |
| `doc/components/EXECUTION_CONTEXT.md` | Configuration validation reference |

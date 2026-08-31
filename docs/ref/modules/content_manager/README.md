# Content Manager

The Content Manager is a shared library that fetches CTI (Cyber Threat Intelligence) data from the Wazuh Indexer and delivers it page-by-page to a registered callback. It is used by the Vulnerability Scanner to keep its local CVE database up to date.

Source: `src/shared_modules/content_manager/`

## How it works

The module runs a two-stage pipeline on each scheduled or on-demand execution:

```
IndexerDownloader  →  UpdateIndexerCursor
```

**IndexerDownloader** — fetches CVE documents from the Indexer using Point-In-Time (PIT) pagination:

- **Initial load** (no cursor stored): fetches all documents from `.wazuh-threatintel-vulnerabilities` using `match_all`, sorted by `(offset, _id)`, paginated with PIT + `search_after`.
- **Incremental update** (cursor stored): fetches only documents where `offset > lastCursor`.
- Supports parallel sliced PIT (`numSlices`) to speed up the initial load.
- If `consumerStatusIndex` is configured, the downloader polls the consumer status document and waits until the status is `idle` before starting.
- At the end of each cycle it signals `indexer_complete` with a `changed` flag. Consumers use this flag to decide whether to trigger a downstream action (e.g. a full agent rescan).

**UpdateIndexerCursor** — persists the final cursor value to RocksDB so the next run resumes from where the previous one ended.

## State storage

| Path | Contents |
|------|----------|
| `queue/vd/vd_updater/rocksdb` | RocksDB database storing the current fetch cursor (`CURRENT_OFFSET`) |

## Indexer indices

| Index | Role |
|-------|------|
| `.wazuh-threatintel-vulnerabilities` | CVE documents (source of feed data) |
| `.wazuh-cti-consumers` | Consumer status document polled before each update |

## Configuration

The module is configured programmatically by its caller (the Vulnerability Scanner engine), not via `wazuh-manager.conf` directly. Relevant parameters:

| Parameter | Description |
|-----------|-------------|
| `topicName` | Label for logging |
| `interval` | Seconds between scheduled executions |
| `ondemand` | If `true`, also runs on explicit request |
| `configData.contentSource` | Must be `indexer` |
| `configData.databasePath` | Path to the RocksDB cursor database |
| `configData.indexer.hosts` | Indexer endpoint URLs |
| `configData.indexer.index` | Index to read from |
| `configData.indexer.pageSize` | Documents per PIT page (default 100) |
| `configData.indexer.numSlices` | Parallel PIT slices for initial load (default 2) |

The Indexer connection parameters come from the manager's `<indexer>` XML block (see [Indexer Configuration](configuration.md)).

## On-demand updates (`POST /ondemand`)

Topics registered with `ondemand: true` can be triggered explicitly over the manager-local
`queue/sockets/vd-http.sock` Unix socket (served by the vulnerability scanner's shared HTTP-over-UDS
server, where this module lives). This replaces the former `queue/sockets/updater-ondemand`
socket and its `GET /ondemand/<topic>?offset=N` route.

```bash
curl --unix-socket /var/wazuh-manager/queue/sockets/vd-http.sock \
     -X POST -d '{"topic":"<name>","offset":-1}' http://localhost/ondemand
```

Request body: `{"topic": "<name>", "offset": -1|0}` — `offset` is optional; `-1` (default)
keeps the current offset, `0` restarts the content from scratch. The body is capped at 4 KiB
(a larger declared `Content-Length` is rejected with `413` before any body byte is read).

| Status | Body | Meaning |
|---|---|---|
| `200` | `{"status":"ok"}` | The update ran **to completion** (the response is deferred until it finishes) |
| `400` | `{"error":"missing_required_fields"\|"invalid_topic"\|"invalid_offset"\|"invalid_request",...}` | Malformed request; not retryable |
| `404` | `{"error":"unknown_topic",...}` | No such registered on-demand topic |
| `409` | `{"error":"update_in_progress",...}` | An update for that topic is already running (the old socket answered `200` to this case) — retry later |
| `500` | `{"error":"update_failed",...}` | The update itself failed; retryable |
| `503` | `{"error":"ondemand_queue_full"\|"shutting_down",...}` | The short execution lane is full, or the module is stopping — retry later |

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
| `src/components/IndexerDownloader.hpp` | PIT pagination, sliced fetch, cursor tracking |
| `src/components/updateIndexerCursor.hpp` | Persists cursor to RocksDB after each cycle |
| `src/components/executionContext.hpp` | Execution context and pipeline state |
| `README.md` | Developer-oriented usage guide |
| `doc/components/INDEXER_DOWNLOADER.md` | Detailed IndexerDownloader reference |

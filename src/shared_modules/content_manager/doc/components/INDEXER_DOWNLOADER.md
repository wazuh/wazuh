# Indexer Downloader stage

## Details

The [Indexer Downloader](../../src/components/IndexerDownloader.hpp) stage is part of the Content Manager orchestration and downloads content directly from the Wazuh Indexer using Point-In-Time (PIT) pagination. It is used by the Vulnerability Scanner to fetch its feed from the `.wazuh-threatintel-vulnerabilities` index.

Content is delivered synchronously to the `fileProcessingCallback` as structured `nlohmann::json` objects, page by page (see [Page messages](#page-messages)).

Every run loops until it completes, fails, or the stop condition is signalled:

1. read the stored cursor and choose the mode;
2. wait for the [consumer readiness gate](#consumer-readiness-gate);
3. for an initial load, wait for the [global maps](#global-maps-wait);
4. download (initial load or incremental update);
5. send the [completion signal](#completion-signal); if the consumer rejects the result, invalidate the cursor, wait 30 seconds and start again at step 1.

### Modes of operation

The downloader selects its mode based on the cursor stored in the RocksDB database (`CURRENT_OFFSET` column):

#### Initial load (no cursor, or cursor == "0")

Triggered on the first run or when no valid cursor exists. A stored cursor that is not an integer is logged as a warning (`stored cursor '<value>' is not a valid integer — falling back to initial load.`) and treated as absent. Downloads all documents from the index using a `match_all` query, sorted by `(offset ASC, _id ASC)` and paginated with PIT + `search_after`.

If the index returns zero documents (not yet populated), or the download throws, the downloader retries the whole load from the beginning every 30 seconds until it gets data or a stop condition is signalled. The first two failed attempts log at debug level; from the third on, at warning level.

#### Incremental update (cursor stored)

Triggered on subsequent runs. Downloads only documents whose `offset` field is strictly greater than the stored cursor, using a range query `{ "range": { "offset": { "gt": <lastCursor> } } }` with the same PIT + `search_after` pagination. An incremental update is always sequential, whatever `numSlices` says, and is not retried internally: an exception fails the run, and the next scheduled run resumes from the stored cursor.

If the range query returns zero documents, the completion signal carries `changed: false` (see [Completion signal](#completion-signal) below).

### Consumer readiness gate

If both `consumerStatusIndex` and `consumerStatusId` are configured (non-empty), the downloader reads the `status` field of that document before every run; otherwise the gate is skipped:

- missing document, empty `status`, or `status = running`: wait 1 minute and retry (logged at info)
- `status = failed`: wait 1 minute and retry (logged at debug for the first two, then at warning)
- `status = ready`: start the download
- any other value: wait 1 minute and retry (logged as a warning with the received status)
- the query itself fails (indexer unreachable): wait 1 minute and retry (debug for the first two, then warning)

This gate answers only one question: whether it is safe to start reading from Indexer. It does not replace the consumer-side validation of the downloaded local feed.

### Global maps wait

Before an initial load, the downloader waits until the documents `FEED-GLOBAL`, `OSCPE-GLOBAL` and `CNA-MAPPING-GLOBAL` all exist in the feed index, polling every 30 seconds (`Global-map documents not yet indexed in '<index>' (<n>/3 found)`). Incremental updates skip this wait.

### PIT pagination

Each download cycle (initial or incremental) opens a single Point-In-Time on the target index with a keep-alive of `5m`. All page requests within the cycle use this PIT, ensuring a consistent snapshot of the index throughout the download. The PIT is always deleted when the cycle finishes, even in error cases (a failed deletion is only logged). Pagination stops at the first page shorter than `pageSize`.

#### Sequential fetch (`numSlices` = 1)

```
createPointInTime(index, "5m")
  → while pages remain:
      search(pit, pageSize, query, sort, searchAfter, sourceFilter)
      → processPage() → fileProcessingCallback(json message)
      → if the callback answered "flushed": persistCursor(highestOffsetSeen)
  → deletePointInTime(pit)
```

#### Parallel fetch with sliced PIT (`numSlices` > 1)

Used by the initial load only, when `numSlices` is greater than 1. The downloader uses OpenSearch's slice API to divide the document set into N disjoint subsets via `hash(_id) % numSlices`. Each slice paginates independently with `search_after` on a shared PIT, and all slices run concurrently in separate threads, each with its own `IndexerConnectorSync`.

The `fileProcessingCallback` is serialized via a mutex (`m_callbackMutex`) so that only one thread processes a page at a time — this ensures safe writes to RocksDB and consistent global state. The speedup comes from overlapping network I/O with processing: while one thread processes its page, the others fetch their next pages concurrently.

```
createPointInTime(index, "5m")
  → spawn N threads, each with slice {id: i, max: N}:
      while pages remain in this slice:
          search(pit, pageSize, query, sort, searchAfter, sourceFilter, slice)
          → lock(m_callbackMutex)
          → processPage() → fileProcessingCallback(json message)
  → join all threads
  → if no slice failed and no stop was requested: persistCursor(max offset across all slices)
  → deletePointInTime(pit)
```

A failed slice fails the whole load (`<n> slice(s) failed: <first error>`), which the initial load retries after 30 seconds. A stop request during a sliced load persists no cursor: a per-slice offset is not a safe resume point, so the next run performs the initial load again.

### Source field filtering

Each search request includes a `_source.excludes` filter (`getSourceFilter()`) that removes CVE5 fields not used by the scan pipeline (descriptions, references, credits, timeline, unused CVSS sub-fields, etc.). Excludes are used rather than includes because the non-CVE documents (`FEED-GLOBAL`, `OSCPE-GLOBAL`, `CNA-MAPPING-GLOBAL`, `TID-*`) do not share the CVE5 structure.

### Cursor persistence

The cursor is the highest `offset` seen, stored as a string in the `current_offset` column of the updater RocksDB database:

- **Sequential download:** after a page whose callback answered `"flushed"` (the consumer has durably written everything up to it), that page's cursor is persisted. A stop request leaves `context.data["cursor"]` at the last flushed cursor, so the next run resumes from data the consumer really holds.
- **Sliced download:** the cursor is persisted only after every slice completed (see above).
- **End of run:** `context.data["cursor"]` carries the final cursor, which `UpdateIndexerCursor` persists.
- If the **Indexer** fails during an initial load, `initialLoad()` catches the exception, waits 30 seconds, and retries the full download from scratch. During an incremental update the exception fails the run.
- If the consumer rejects the completion signal, the cursor is reset to `"0"` (forcing an initial load) and the run starts again after 30 seconds.

### Completion signal

After all pages are processed, the downloader sends an `indexer_complete` message to the `fileProcessingCallback`:

```json
{
    "type": "indexer_complete",
    "cursor": "<highestOffsetSeen>",
    "changed": true,
    "data": []
}
```

The `changed` field is `true` if at least one document was fetched in this cycle, `false` otherwise (e.g. incremental update with no new data). Consumers use this flag to decide whether to trigger downstream actions such as a full agent rescan. The consumer answers with the success flag of the `FileProcessingResult`: `false` means the downloaded feed is not usable, and the downloader invalidates the cursor and retries a full reload after 30 seconds (logged at warning level from the third consecutive rejection). The signal is not sent when a stop was requested.

### Page messages

Each page is delivered as:

```json
{
    "type": "indexer",
    "cursor": "<highestOffsetInThisPage>",
    "data": [
        {
            "offset": 1042,
            "resource": "CVE-2026-23713",
            "payload": "<the hit's _source.document, serialized>",
            "type": "create"
        }
    ]
}
```

- `resource` is the hit's `_id` (`CVE-…`, `TID-…`, `FEED-GLOBAL`, `OSCPE-GLOBAL`, `CNA-MAPPING-GLOBAL`).
- `type` is `delete` for a CVE whose `document.cveMetadata.state` is `REJECTED`, `create` for every other document.
- Documents whose `_source.type` is `TCPE` or `TVENDORS` are skipped.
- A callback that returns failure (`std::get<2>` false) aborts the download.

## Configuration

The `indexer` sub-object must be present under `configData` when `contentSource` is `indexer`:

| Field | Type | Description |
|-------|------|-------------|
| `index` | string | Target index name (e.g. `.wazuh-threatintel-vulnerabilities`) |
| `consumerStatusIndex` | string | Index containing the consumer status document to poll before downloading (optional) |
| `consumerStatusId` | string | Consumer status document id to poll before downloading (optional) |
| `pageSize` | integer | Documents per page. Default: `100`; a `0` is replaced by `100` with a warning. The Vulnerability Scanner limits it to 1–10000 (`pageSize` of `<vulnerability-detection>`) |
| `numSlices` | integer | Number of parallel PIT slices for the initial load. Default: `2`. `1` selects sequential mode. The Vulnerability Scanner limits it to 1–32 |
| `hosts` | array | Indexer host URLs (e.g. `["https://127.0.0.1:9200"]`) |
| `ssl.certificate_authorities` | array | CA certificate paths |
| `ssl.certificate` | string | Client certificate path (optional) |
| `ssl.key` | string | Client key path (optional) |

The connection keys are passed unchanged to `IndexerConnectorSync`. Credentials are not read from this object: the connector reads `username`/`password` from the `indexer` column family of the keystore.

Example:

```json
{
    "topicName": "vulnerability_feed_manager",
    "interval": 3600,
    "ondemand": true,
    "configData": {
        "consumerName": "Wazuh VulnerabilityDetector",
        "contentSource": "indexer",
        "databasePath": "queue/vd/vd_updater/rocksdb",
        "offset": 0,
        "indexer": {
            "hosts": ["https://127.0.0.1:9200"],
            "ssl": {
                "certificate_authorities": ["etc/certs/root-ca.pem"],
                "certificate": "etc/certs/indexer-connector.pem",
                "key": "etc/certs/indexer-connector-key.pem"
            },
            "index": ".wazuh-threatintel-vulnerabilities",
            "consumerStatusIndex": ".wazuh-cti-consumers",
            "consumerStatusId": "cti:catalog:consumer:vulnerabilities",
            "pageSize": 100,
            "numSlices": 2
        }
    }
}
```

## Relation with the UpdaterContext

The context fields related to this stage are:

- `configData`
  + `indexer`: Wazuh Indexer connection and index configuration (required).
- `spRocksDB`: Used to read and persist the cursor (`CURRENT_OFFSET` column).
- `spStopCondition`: Checked between pages and during every wait and retry loop to abort cleanly on shutdown.
- `data["cursor"]`: Set to the highest offset seen after each cycle. Read by `UpdateIndexerCursor` to persist the final cursor value.
- `fileProcessingCallback`: Called once per page with an `"indexer"` JSON object, and once at the end with an `"indexer_complete"` JSON object. Messages are passed as `nlohmann::json` to avoid overhead.
- `updateCallbacks`: `onStart` at the start of every download attempt, `onFailure` after a failed initial-load attempt and after a rejected completion signal.

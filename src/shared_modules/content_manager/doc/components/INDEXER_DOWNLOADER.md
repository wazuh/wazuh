# Indexer Downloader stage

## Details

The [Indexer Downloader](../../src/components/IndexerDownloader.hpp) stage is part of the Content Manager orchestration and downloads content directly from the Wazuh Indexer using Point-In-Time (PIT) pagination. It is used by the Vulnerability Detection module to fetch CVE data from the `.cti-cves` index, replacing the CTI API as the CVE data source.

Content is delivered synchronously to the `fileProcessingCallback` as structured `nlohmann::json` objects page by page.

### Modes of operation

The downloader selects its mode based on the cursor stored in the RocksDB database (`CURRENT_OFFSET` column):

#### Initial load (no cursor, or cursor == "0")

Triggered on the first run or when no valid cursor exists. Downloads all documents from the index using a `match_all` query, sorted by `(offset ASC, _id ASC)` and paginated with PIT + `search_after`.

If the index returns zero documents (not yet populated), the downloader retries every 30 seconds until data is available or a stop condition is signalled.

#### Incremental update (cursor stored)

Triggered on subsequent runs. Downloads only documents whose `offset` field is strictly greater than the stored cursor, using a range query `{ "range": { "offset": { "gt": <lastCursor> } } }` with the same PIT + `search_after` pagination.

If the range query returns zero documents, the cycle completes without triggering a rescan on the consumer side (see [Completion signal](#completion-signal) below).

### PIT pagination

Each download cycle (initial or incremental) opens a single Point-In-Time on the target index with a keep-alive of `5m`. All page requests within the cycle use this PIT, ensuring a consistent snapshot of the index throughout the download. The PIT is always deleted when the cycle finishes, even in error cases.

#### Sequential fetch (`numSlices` = 1)

```
createPointInTime(index, "5m")
  → while pages remain:
      search(pit, pageSize, query, sort, searchAfter, sourceFilter)
      → processPage() → fileProcessingCallback(json message)
      → persistCursor(highestOffsetSeen)
  → deletePointInTime(pit)
```

#### Parallel fetch with sliced PIT (`numSlices` > 1)

When `numSlices` is set to a value greater than 1, the downloader uses OpenSearch's slice API to divide the document set into N disjoint subsets via `hash(_id) % numSlices`. Each slice paginates independently with `search_after` on a shared PIT, and all slices run concurrently in separate threads.

The `fileProcessingCallback` is serialized via a mutex (`m_callbackMutex`) so that only one thread processes a page at a time — this ensures safe writes to RocksDB and consistent global state. The speedup comes from overlapping network I/O with processing: while one thread processes its page, the others fetch their next pages concurrently.

```
createPointInTime(index, "5m")
  → spawn N threads, each with slice {id: i, max: N}:
      while pages remain in this slice:
          search(pit, pageSize, query, sort, searchAfter, sourceFilter, slice)
          → lock(m_callbackMutex)
          → processPage() → fileProcessingCallback(json message)
  → join all threads
  → persistCursor(max offset across all slices)
  → deletePointInTime(pit)
```

Sliced PIT works correctly on single-shard indices, producing even distribution regardless of shard count.

> Increasing `numSlices` does not necessarily improve wall-clock time. In benchmark runs, higher slice counts increased memory usage noticeably and provided little or no speed benefit beyond `2` slices. Benchmark your environment before raising this value.

### Source field filtering

Each search request includes a `_source.excludes` filter that removes CVE5 fields not used by the scan pipeline (descriptions, references, credits, timeline, etc.). This reduces the JSON payload per CVE document by ~34%, lowering network transfer, JSON parsing overhead, and peak memory usage during the initial load.

### Cursor persistence

After each page is successfully processed by the callback, the highest `offset` value seen in that page is persisted to the `CURRENT_OFFSET` column of the updater RocksDB database. This ensures that a restart mid-download resumes correctly:

- If the **module** restarts mid-download: the stored cursor reflects pages already committed to the feed database. The next run performs an incremental update from that cursor, fetching only the remaining documents.
- If the **Indexer** restarts mid-download: the current `fetchWithPit()` call throws, `initialLoad()` catches it, waits 30 seconds, and retries the full download from scratch. The partial cursor written to RocksDB is superseded once the retry completes successfully.

### Completion signal

After all pages are processed, the downloader sends an `indexer_complete` message to the `fileProcessingCallback`:

```json
{
    "type": "indexer_complete",
    "cursor": "<highestOffsetSeen>",
    "changed": true
}
```

The `changed` field is `true` if at least one document was fetched in this cycle, `false` otherwise (e.g. incremental update with no new data). Consumers use this flag to decide whether to trigger downstream actions such as a full agent rescan.

## Configuration

The `indexer` sub-object must be present under `configData` when `contentSource` is `indexer`:

| Field | Type | Description |
|-------|------|-------------|
| `index` | string | Target index name (e.g. `.cti-cves`) |
| `pageSize` | integer | Documents per page. Default: `250` |
| `numSlices` | integer | Number of parallel PIT slices for initial load. Default: `2`. Set to `1` for sequential mode. Higher values can increase memory usage with limited time savings |
| `hosts` | array | Indexer host URLs (e.g. `["https://localhost:9200"]`) |
| `username` | string | Indexer username |
| `password` | string | Indexer password |
| `ssl.certificate_authorities` | array | CA certificate paths |
| `ssl.certificate` | string | Client certificate path (optional) |
| `ssl.key` | string | Client key path (optional) |

Example:

```json
{
    "topicName": "vulnerability_feed_manager",
    "interval": 3600,
    "ondemand": true,
    "configData": {
        "consumerName": "Wazuh VulnerabilityDetector",
        "contentSource": "indexer",
        "databasePath": "queue/vd_updater/rocksdb",
        "offset": 0,
        "indexer": {
            "hosts": ["https://localhost:9200"],
            "username": "admin",
            "password": "admin",
            "ssl": {
                "certificate_authorities": ["/etc/wazuh-indexer/certs/root-ca.pem"],
                "certificate": "",
                "key": ""
            },
            "index": ".cti-cves",
            "pageSize": 250,
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
- `spStopCondition`: Checked during the initial-load retry loop to abort cleanly on shutdown.
- `data["cursor"]`: Set to the highest offset seen after each cycle. Read by `UpdateIndexerCursor` to persist the final cursor value.
- `fileProcessingCallback`: Called once per page with an `"indexer"` JSON object, and once at the end with an `"indexer_complete"` JSON object. Messages are passed as `nlohmann::json` to avoid overhead.

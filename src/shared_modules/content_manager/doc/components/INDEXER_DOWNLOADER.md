# Indexer Downloader stage

## Details

The [Indexer Downloader](../../src/components/IndexerDownloader.hpp) stage is part of the Content Manager orchestration and downloads content directly from the Wazuh Indexer using Point-In-Time (PIT) pagination. It is used by the Vulnerability Detection module to fetch CVE data from the `.cti-cves` index, replacing the CTI API as the CVE data source.

Content is delivered synchronously to the `fileProcessingCallback` page by page, without writing intermediate files to disk.

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

```
createPointInTime(index, "5m")
  → while pages remain:
      search(pit, pageSize, query, sort, searchAfter)
      → processPage() → fileProcessingCallback("indexer" message)
      → persistCursor(highestOffsetSeen)
  → deletePointInTime(pit)
```

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
| `pageSize` | integer | Documents per page. Default: `1000` |
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
            "pageSize": 1000
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
- `fileProcessingCallback`: Called once per page with an `"indexer"` message, and once at the end with an `"indexer_complete"` message.

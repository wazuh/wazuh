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
| `configData.indexer.pageSize` | Documents per PIT page (default 250) |
| `configData.indexer.numSlices` | Parallel PIT slices for initial load (default 2) |

The Indexer connection parameters come from the manager's `<indexer>` XML block (see [Indexer Configuration](../../configuration/indexer.md)).

## Key source files

| File | Purpose |
|------|---------|
| `src/components/IndexerDownloader.hpp` | PIT pagination, sliced fetch, cursor tracking |
| `src/components/updateIndexerCursor.hpp` | Persists cursor to RocksDB after each cycle |
| `src/components/executionContext.hpp` | Execution context and pipeline state |
| `README.md` | Developer-oriented usage guide |
| `doc/components/INDEXER_DOWNLOADER.md` | Detailed IndexerDownloader reference |

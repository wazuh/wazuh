# Content Manager

The Content Manager is a module that is in charge of obtaining the Wazuh Content from the Wazuh Indexer and maintaining periodic updates.

## Usage

The input configuration of the Content Manager is described below:

- `topicName`: Topic name, used to represent the actions being executed.
- `interval`: Interval, in seconds, between each action execution.
- `ondemand`: If `true`, the module will be executed on demand.
- `configData`: Configuration data to create the orchestration of the module.
  + `consumerName`: Name of the Content Manager caller (e.g. `Wazuh VulnerabilityDetector`).
  + `contentSource`: Source of the content. Must be `indexer`. See the [use cases section](#use-cases) for more information.
  + `databasePath`: Path for the RocksDB database. The database stores the last Indexer cursor used to resume incremental fetches across restarts.
  + `indexer`: _(Required when `contentSource` is `indexer`)_ Wazuh Indexer connection sub-configuration. See the [Indexer Downloader documentation](./doc/components/INDEXER_DOWNLOADER.md) for details.

> The Content Manager counts with a [test tool](./testtool/main.cpp) that can be used to perform tests, try out different configurations, and to better understand the module.

## Pipeline

The Content Manager runs a two-stage pipeline for each scheduled or on-demand execution:

```
IndexerDownloader  →  UpdateIndexerCursor
```

- **IndexerDownloader**: Fetches CVE documents from the Wazuh Indexer using Point-In-Time (PIT) pagination. Performs a full initial load on the first run and incremental updates on subsequent runs. Supports parallel fetching via sliced PIT (`numSlices` config). Delivers each page as a structured `nlohmann::json` object directly to the `fileProcessingCallback`. Sends an `indexer_complete` signal at the end of each cycle. See [INDEXER_DOWNLOADER.md](./doc/components/INDEXER_DOWNLOADER.md).
- **UpdateIndexerCursor**: Persists the final cursor value from the `indexer_complete` signal to the updater RocksDB database so the next run resumes from where the previous one ended.

## Use cases

### Download from Wazuh Indexer

The Content Manager fetches CVE data directly from the Wazuh Indexer using Point-In-Time (PIT) pagination. This is the data source used by the Vulnerability Detection module.

The downloader automatically selects its mode based on the persisted cursor:

- **Initial load** (no cursor stored): Downloads all documents from the index using `match_all`, sorted by `(offset, _id)`, paginated with PIT + `search_after`. Retries every 30 seconds if the index is empty.
- **Incremental update** (cursor stored): Downloads only documents with `offset > lastCursor` using the same PIT + `search_after` strategy.

After all pages are processed, the downloader signals completion via `indexer_complete`, including a `changed` flag that indicates whether any documents were fetched. Consumers use this flag to decide whether to trigger downstream actions (e.g. a full agent rescan).

```json
{
    "topicName": "vulnerability_feed_manager",
    "interval": 3600,
    "ondemand": true,
    "configData": {
        "consumerName": "Wazuh VulnerabilityDetector",
        "contentSource": "indexer",
        "databasePath": "queue/vd_updater/rocksdb",
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

For detailed information about this component, see the [Indexer Downloader documentation](./doc/components/INDEXER_DOWNLOADER.md).

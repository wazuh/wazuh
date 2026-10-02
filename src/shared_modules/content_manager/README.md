# Content Manager

The Content Manager is a shared library that downloads content from the Wazuh Indexer for a registered
consumer and keeps it updated, on a schedule and on demand. Its one production consumer is the
Vulnerability Scanner, which registers the topic `vulnerability_feed_manager`
([vulnerabilityScannerFacade.cpp](../../wazuh_modules/vulnerability_scanner/src/vulnerabilityScannerFacade.cpp)).

Operator-facing behaviour (indices, state on disk, logs, configuration) is documented in the published
reference, [docs/ref/modules/content_manager/README.md](../../../docs/ref/modules/content_manager/README.md).
This README covers the library's interface and internals.

## Loading and registration

- `wazuh-manager-modulesd` loads `libcontent_manager.so` through the `content_manager` module
  ([wm_content_manager.c](../../wazuh_modules/src/wm_content_manager.c)), which calls the exported
  `content_manager_start(callbackLog)` / `content_manager_stop()` ([content_manager.h](include/content_manager.h)).
  Start only installs the log function; stop drops every registered provider.
- A consumer creates a `ContentRegister(topicName, parameters, fileProcessingCallback, updateCallbacks)`
  ([contentRegister.hpp](include/contentRegister.hpp)). Destroying it unregisters the topic.
  - `interval` present: a scheduler thread runs the update **immediately**, then every `interval` seconds
    (`changeSchedulerInterval()` changes it). A run that finds one already in progress is skipped.
  - `ondemand: true`: the topic is registered with the on-demand lane (see [On demand](#on-demand)).
- `getCurrentOffset()` returns the cursor stored in the topic's RocksDB database (0 when none).

## Input configuration

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

This is the object the Vulnerability Scanner builds (`buildUpdaterConfig` in
`vulnerabilityScannerFacade.cpp`): `interval` from `feed-update-interval`, `pageSize`/`numSlices` from
`<vulnerability-detection>`, and the `indexer` object copied from the manager's `indexer` section.

| Field | Read by | Notes |
|---|---|---|
| `topicName` | `ActionOrchestrator` | Required. Names the topic and its database (`<databasePath>/updater_<topicName>_metadata`). |
| `interval` | `ContentRegister` | Optional; seconds between scheduled runs. |
| `ondemand` | `ContentRegister` | Optional; registers the topic with the on-demand lane. |
| `configData.consumerName` | `ExecutionContext` | Required, non-empty (`Missing or empty consumerName` otherwise). |
| `configData.databasePath` | `ExecutionContext` | Directory of the RocksDB database; created if absent. Without it no cursor is stored. |
| `configData.offset` | `ExecutionContext` | Required when `databasePath` is set (read with `at()`); must be non-negative. Replaces the stored cursor when greater. |
| `configData.contentSource` | `ExecutionContext` | The pipeline is always the Indexer one; any value other than `indexer` only makes `ExecutionContext` create the unused `outputFolder` (`downloads/`, `contents/`). |
| `configData.indexer` | `IndexerDownloader` | Required. Connection keys as for `IndexerConnectorSync` (credentials come from the keystore, never from this object), plus the fields of the [Indexer Downloader](doc/components/INDEXER_DOWNLOADER.md#configuration). |

## Pipeline

`ExecutionContext` runs once, when the provider is created
([EXECUTION_CONTEXT.md](doc/components/EXECUTION_CONTEXT.md)). Every run then executes the chain built
by [factoryContentUpdater.hpp](src/components/factoryContentUpdater.hpp):

```
IndexerDownloader  →  UpdateIndexerCursor
```

- **IndexerDownloader** waits for the consumer-readiness document, chooses an initial load or an
  incremental update from the stored cursor, pages through the index with PIT + `search_after`, and
  hands every page to `fileProcessingCallback`, then sends the `indexer_complete` signal. See
  [INDEXER_DOWNLOADER.md](doc/components/INDEXER_DOWNLOADER.md).
- **UpdateIndexerCursor** ([updateIndexerCursor.hpp](src/components/updateIndexerCursor.hpp)) writes
  `context.data["cursor"]` to the `current_offset` column; an absent or empty cursor is not written.

A run with on-demand `offset` `0` first writes `"0"` to `current_offset`, which makes the downloader
perform an initial load ([actionOrchestrator.hpp](src/actionOrchestrator.hpp)). An exception from the
chain calls `updateCallbacks.onFailure` and is logged as `Action for '<topic>' failed: <error>.`
([action.hpp](src/action.hpp)).

## Callback contract

`FileProcessingCallback` is `std::function<FileProcessingResult(nlohmann::json message)>`, with
`FileProcessingResult = std::tuple<int, std::string, bool>` ([sharedDefs.hpp](include/sharedDefs.hpp)):

- `std::get<2>` — success. A page whose callback returns `false` aborts the download; an
  `indexer_complete` whose callback returns `false` means "the downloaded feed is not usable": the
  downloader invalidates the cursor and retries a full reload after 30 seconds.
- `std::get<1>` — `"flushed"` when the consumer has durably flushed everything up to this page. Only then
  does a sequential download persist the page's cursor.

`ContentUpdateCallbacks{onStart, onFailure}` report the lifecycle of each attempt; an exception from
either is logged and swallowed.

## On demand

The library has no socket of its own. The Vulnerability Scanner registers `POST /ondemand` on
`vd-http.sock` and forwards each request to `content_manager::dispatchOnDemand(topic, offset, responder)`
([contentOnDemand.hpp](include/contentOnDemand.hpp)). `OnDemandManager`
([onDemandManager.hpp](src/onDemandManager.hpp)) answers unknown topics (`404`) and a full lane or a
stopping lane (`503`) inline; accepted requests wait in a queue of 4 slots served by 2 workers, and the
response is sent when the run finishes (`200`), or `409` when the topic's update was already running.
The route's operator contract is in the
[Vulnerability Scanner API reference](../../../docs/ref/modules/vulnerability-scanner/api-reference.md#post-ondemand).

## Test tool

[testtool/main.cpp](testtool/main.cpp) registers a topic with a hard-coded configuration and triggers it
through `dispatchOnDemand`. That configuration still describes a `contentSource: "api"` provider and has
no `indexer` object, so the downloader fails until it is edited to carry one.

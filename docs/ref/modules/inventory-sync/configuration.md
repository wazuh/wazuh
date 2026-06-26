# Configuration

Inventory Sync does not use its own `<inventory_sync>` block in `wazuh-manager.conf`, but it is not configuration-free. At startup, the manager wrapper builds a JSON configuration object and passes it into the shared library.

## Configuration sources

The runtime configuration passed to Inventory Sync contains:

- **`indexer`**: duplicated from the manager indexer configuration.
- **`clusterName`**: the manager cluster name.
- **`clusterNodeName`**: the local manager node name.
- **`maxSessions`**: the session cap derived from internal options.
- **`queueSize`**: the input worker queue cap derived from internal options.
- **`dataValueQuota`**: the global `DataValue` quota derived from internal options.
- **`indexerBulkSize`**: the indexer bulk-size threshold (bytes) derived from internal options. Forwarded to the Indexer Connector as `max_bulk_size`.
- **`indexerFlushInterval`**: the indexer periodic flush interval (seconds) derived from internal options. Forwarded to the Indexer Connector as `flush_interval_seconds`.

The module refuses to start if `clusterName` is missing.

## Indexer configuration

Inventory Sync depends on the manager indexer configuration because all indexing, delete-by-query, search, and update-by-query operations are delegated to the Indexer Connector.

Example configuration payload passed to the module:

```json
{
  "indexer": {
    "hosts": ["https://127.0.0.1:9200"],
    "ssl": {
      "certificate_authorities": [
        "/var/wazuh-manager/etc/certs/root-ca.pem"
      ],
      "certificate": "/var/wazuh-manager/etc/certs/manager.pem",
      "key": "/var/wazuh-manager/etc/certs/manager-key.pem"
    }
  },
  "clusterName": "wazuh",
  "clusterNodeName": "node01",
  "maxSessions": 1000,
  "queueSize": 10000,
  "dataValueQuota": 500000,
  "indexerBulkSize": 10485760,
  "indexerFlushInterval": 20
}
```

## Internal options

### Maximum sessions

Inventory Sync reads the session cap from the internal option `wazuh_modules.max_sessions`.

Current manager-side behavior:

- Allowed range: `1` to `100000`.
- Default on manager builds: `1000`.
- New Start messages are rejected when the active session count reaches that limit.

### Input worker queue size

Inventory Sync reads the input worker queue cap from the internal option `wazuh_modules.inventory_sync_queue_size`.

The cap is applied to the queue that buffers incoming router messages before they reach the worker threads.

Current manager-side behavior:

- Allowed range: `100` to `1000000`.
- Default on manager builds: `10000`.
- When the queue is full, the incoming message is dropped.
- A warning is logged for the first drop and is then suppressed for the next `90` seconds to avoid log flooding.

### Global DataValue quota

Inventory Sync reads the global `DataValue` quota from the internal option `wazuh_modules.inventory_sync_data_value_quota`.

The quota bounds the total number of `DataValue` items that all active sessions can collectively handle. When a Start message arrives, the value declared in its `size` field is reserved from the quota; when the session ends (success, error, stale cleanup, or timeout), the reservation is returned.

Current manager-side behavior:

- Allowed range: `1` to `1000000000`.
- Default on manager builds: `500000`.
- If the requested `size` exceeds the remaining quota, the Start message is rejected with `Status_Offline` (the agent will retry later, mirroring the `max_sessions` rejection shape).
- Quota-rejection events are always logged (no rate limiting).

### Indexer bulk-size threshold

Inventory Sync reads the indexer bulk-size threshold from the internal option `wazuh_modules.inventory_sync_indexer_bulk_size_bytes`.

The value is forwarded to the Indexer Connector as the `max_bulk_size` field of its JSON configuration and bounds the NDJSON payload size accumulated in the bulk buffer before a synchronous flush to `wazuh-indexer` is triggered. It applies independently of any other connector instance (the vulnerability scanner module has its own equivalent option, `wazuh_modulesd.indexer_bulk_size_bytes`).

Current manager-side behavior:

- Allowed range: `4096` to `104857600` (4 KB to 100 MB).
- Default on manager builds: `10485760` (10 MB).
- The lower bound is set well above the worst-case per-item JSON overhead (`{"index":{"_index":"...","_id":"..."}}` plus a 32 B version slot ≈ 65 B baseline, before index name and `_id`). Smaller values would not crash the connector — the size check in `bulkIndex` / `bulkDelete` is gated by a `!m_bulkData.empty()` precondition — but they degrade the connector into "one HTTP request per document", which is rarely desirable.

### Indexer flush interval

Inventory Sync reads the indexer periodic flush interval from the internal option `wazuh_modules.inventory_sync_indexer_flush_interval`.

The value is forwarded to the Indexer Connector as the `flush_interval_seconds` field of its JSON configuration and drives the background timer that flushes the bulk buffer when the size threshold has not been reached. It applies independently of any other connector instance (the vulnerability scanner module has its own equivalent option, `wazuh_modulesd.indexer_flush_interval`).

Current manager-side behavior:

- Allowed range: `1` to `3600` (1 second to 1 hour).
- Default on manager builds: `20` seconds.
- When the timer fires on an empty buffer, no HTTP request is issued.

## Operational constants

The current implementation also relies on fixed runtime constants.

| Parameter                                 | Current behavior                                        |
| ----------------------------------------- | ------------------------------------------------------- |
| Router topic                              | `inventory-states`                                      |
| Subscriber id                             | `inventory-sync-module`                                 |
| RocksDB path                              | `inventory_sync/`                                       |
| Worker threads                            | `std::thread::hardware_concurrency()`                   |
| Session activity window                   | `DEFAULT_TIME = 10 minutes`                             |
| Stale session cleanup threshold           | `20 minutes` without activity                           |
| Cleanup sweep interval                    | `10 minutes`                                            |
| Wait for metadata or group reconciliation | up to `60 seconds` for other sessions of the same agent |

## Session storage

Inventory Sync stores in-flight session data in RocksDB under `inventory_sync/`.

Storage conventions:

- `DataValue` entries use `{session}_{seq}`.
- `DataContext` entries use `{session}_{seq}_context`.
- Session data is deleted after successful completion, error handling, or stale-session cleanup.
- The RocksDB directory is cleared when the module starts.

## Router dependency

The module subscribes to the Router and expects FlatBuffer messages on `inventory-states`.

That means Inventory Sync depends on:

- the Router being active on the manager,
- agents emitting the synchronization protocol,
- and the response path being available so `StartAck`, `EndAck`, and retransmission messages can be returned.

## Vulnerability Scanner interaction

No dedicated Inventory Sync configuration flag enables or disables vulnerability processing. Instead:

- the session Start message carries the `option` field (`Sync`, `VDFirst`, or `VDSync`),
- Inventory Sync checks whether the Vulnerability Scanner is initialized,
- and then it either triggers or skips the downstream scan.

## Verifying the indexer connection

Before troubleshooting Inventory Sync, verify that the Wazuh Indexer is healthy:

```console
curl --cacert <root_ca> --cert <manager_cert> --key <manager_key> \
  https://<indexer-host>:9200/_cluster/health
```

A healthy indexer is required for:

- session acceptance,
- bulk indexing,
- delete-by-query,
- update-by-query,
- and checksum validation searches.

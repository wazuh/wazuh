# Configuration

Inventory Sync does not use its own `<inventory_sync>` block in `wazuh-manager.conf`, but it is not configuration-free. At startup, the manager wrapper builds a JSON configuration object and passes it into the shared library.

## Configuration sources

The runtime configuration passed to Inventory Sync contains:

- **`indexer`**: duplicated from the manager indexer configuration.
- **`clusterName`**: the manager cluster name.
- **`clusterNodeName`**: the local manager node name.
- **`maxSessions`**: the session cap derived from internal options.

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
  "maxSessions": 1000
}
```

## Internal options

### Maximum sessions

Inventory Sync reads the session cap from the internal option `wazuh_modules.max_sessions`.

Current manager-side behavior:

- Allowed range: `1` to `100000`.
- Default on manager builds: `1000`.
- New Start messages are rejected when the active session count reaches that limit.

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

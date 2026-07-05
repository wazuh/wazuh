# Indexer Connector

The Indexer Connector is a shared library (`libindexer_connector`) that handles all data indexing operations between the Wazuh Manager and the Wazuh Indexer (OpenSearch). It is the Filebeat replacement introduced in Wazuh 5.0.

Source: `src/shared_modules/indexer_connector/`

For configuration options see [Indexer Configuration](../../configuration/indexer.md).

## Overview

The Indexer Connector is not a standalone daemon. It is linked into the processes that need to write to or query the Indexer:

- **Vulnerability Scanner** — indexes CVE detections into `wazuh-states-vulnerabilities`
- **Inventory Sync** — indexes agent state into `wazuh-states-inventory-*` and `wazuh-states-fim-*`
- **Engine** — indexes SCA results and other engine-generated events

The library provides two classes depending on the use case:

| Class | Mode | Queue | Use case |
|-------|------|-------|----------|
| `IndexerConnectorSync` | Synchronous | In-memory (up to 10 MB) | Low-latency, bounded writes |
| `IndexerConnectorAsync` | Asynchronous | RocksDB (`queue/indexer/<id>/`) | Write-ahead queue, survives restarts |

## How it works

1. The caller instantiates a connector with a JSON configuration (derived from the `<indexer>` XML block).
2. Credentials (`username`/`password`) are read from the RocksDB keystore (`queue/keystore/`).
3. A background health-monitor thread polls `/_cat/health` on all configured hosts every 60 seconds and marks nodes available or unavailable.
4. A server-selector performs round-robin load balancing across available nodes.
5. Documents are accumulated (sync: in memory; async: in RocksDB) and flushed as OpenSearch Bulk API requests.

### Sync flush behavior

- Buffer up to 10 MB of serialized events before flushing (configurable: `wazuh_modules.indexer_bulk_size_bytes` for Vulnerability Scanner, `wazuh_modules.inventory_sync_indexer_bulk_size_bytes` for Inventory Sync).
- Flush automatically after 20 seconds of inactivity (configurable: `wazuh_modules.indexer_flush_interval` for Vulnerability Scanner, `wazuh_modules.inventory_sync_indexer_flush_interval` for Inventory Sync).
- If the indexer returns HTTP 413 (payload too large), the batch is split and retried.
- Version conflicts at the document level are handled per-document.

### Async flush behavior

- Events are queued to RocksDB immediately and flushed by a background thread.
- Up to 25,000 documents per flush batch (configurable via `analysisd.indexer_bulk_size`).
- Flush automatically after 20 seconds of inactivity (configurable via `analysisd.indexer_flush_interval`).
- If `max_queue_size` is set, events that exceed the limit are dropped and counted.
- The queue survives manager restarts.

## Indices

| Index | Written by |
|-------|------------|
| `wazuh-states-vulnerabilities` | Vulnerability Scanner |
| `wazuh-states-inventory-system` | Inventory Sync |
| `wazuh-states-inventory-hardware` | Inventory Sync |
| `wazuh-states-inventory-packages` | Inventory Sync |
| `wazuh-states-inventory-hotfixes` | Inventory Sync (Windows) |
| `wazuh-states-inventory-processes` | Inventory Sync |
| `wazuh-states-inventory-ports` | Inventory Sync |
| `wazuh-states-inventory-interfaces` | Inventory Sync |
| `wazuh-states-inventory-protocols` | Inventory Sync |
| `wazuh-states-inventory-networks` | Inventory Sync |
| `wazuh-states-inventory-users` | Inventory Sync |
| `wazuh-states-inventory-groups` | Inventory Sync |
| `wazuh-states-inventory-services` | Inventory Sync |
| `wazuh-states-inventory-browser-extensions` | Inventory Sync |
| `wazuh-states-fim-files` | Inventory Sync (FIM) |
| `wazuh-states-fim-registry-keys` | Inventory Sync (FIM, Windows) |
| `wazuh-states-fim-registry-values` | Inventory Sync (FIM, Windows) |
| `wazuh-states-sca` | Engine (SCA) |
| `wazuh-threatintel-*` | Read-only (Content Manager) |

## Key source files

| File | Purpose |
|------|---------|
| `include/indexerConnector.hpp` | Public API: `IndexerConnectorSync`, `IndexerConnectorAsync` |
| `src/indexerConnectorSyncImpl.hpp` | Sync implementation: in-memory buffer, bulk flush, 413 splitting |
| `src/indexerConnectorAsyncImpl.hpp` | Async implementation: RocksDB queue, background flusher |
| `src/serverSelector.hpp` | Round-robin load balancer with health tracking |
| `src/monitoring.hpp` | Background health-monitor thread (60s interval) |
| `testtool/` | CLI test tool: `push-events`, `export-policy`, `generate-full-policy` |

## Test tool

```bash
# Build
make indexer_connector_tool -j$(nproc)

# Push events to an index (sync)
./indexer_connector_tool push-events -c config.json -e events.json

# Push events (async)
./indexer_connector_tool push-events -c config.json -e events.json -m async -w 5
```

See `testtool/README.md` for the full reference.

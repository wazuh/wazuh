# Indexer Connector

The Indexer Connector is a shared library (`libindexer_connector`) that handles all data indexing operations between the Wazuh Manager and the Wazuh Indexer (OpenSearch). It is the Filebeat replacement introduced in Wazuh 5.0.

Source: `src/shared_modules/indexer_connector/`

For configuration options see [Indexer Configuration](configuration.md).

## Overview

The Indexer Connector is not a standalone daemon. It is linked into the processes that need to write to or query the Indexer:

- **Vulnerability Scanner** — indexes CVE detections into `wazuh-states-vulnerabilities`
- **Inventory Sync Server** — indexes agent state into `wazuh-states-inventory-*` and `wazuh-states-fim-*`
- **Engine** — indexes SCA results and other engine-generated events

The library provides two classes depending on the use case:

| Class | Mode | Queue | Use case |
|-------|------|-------|----------|
| `IndexerConnectorSync` | Synchronous | In-memory (up to 10 MB) | Low-latency, bounded writes |
| `IndexerConnectorAsync` | Asynchronous | In-memory (byte-bounded via `max_queue_bytes`) | Non-blocking writes; buffered events are discarded on shutdown |

## How it works

1. The caller instantiates a connector with a JSON configuration (derived from the `<indexer>` XML block).
2. Credentials (`username`/`password`) are read from the RocksDB keystore (`queue/keystore/`).
3. A background health-monitor thread polls `/_cat/health` on all configured hosts every 60 seconds and marks nodes available or unavailable.
4. A server-selector performs round-robin load balancing across available nodes.
5. Documents are accumulated in memory (both sync and async) and flushed as OpenSearch Bulk API requests.

### Sync flush behavior

- Buffer up to 10 MB of serialized events before flushing (configurable: `wazuh_modules.indexer_bulk_size_bytes` for Vulnerability Scanner, `wazuh_modules.inventory_sync_server_indexer_sync_max_bulk_size` for Inventory Sync Server).
- Flush automatically after 20 seconds of inactivity (configurable: `wazuh_modules.indexer_flush_interval` for Vulnerability Scanner; the Inventory Sync Server deliberately overrides its periodic flush — its ingestion workers own every flush, see its [configuration reference](../inventory-sync-server/configuration.md)).
- If the indexer returns HTTP 413 (payload too large), the batch is split and retried.
- Version conflicts at the document level are handled per-document.

### Async flush behavior

- Events are queued in memory immediately and flushed by a background thread.
- Up to `analysisd.indexer_bulk_max_bytes` bytes per flush batch (default 8 MB; always takes at least one item, even if it exceeds the threshold on its own).
- Flush automatically after 20 seconds of inactivity (configurable via `analysisd.indexer_flush_interval`).
- If the queue exceeds `analysisd.indexer_queue_max_bytes` (default 64 MB, maps to `max_queue_bytes` in the connector config), new events are dropped and counted until it drains.
- The queue is in-memory only: buffered events are discarded (not retried) if the manager stops or restarts.

### Retry and backoff behavior

Both connectors retry transient failures (HTTP 429 Too Many Requests, connection errors, and - async only - HTTP 409 document version conflicts) using an exponential backoff with jitter (`IndexerExponentialBackoff`, `src/exponentialBackoff.hpp`). Other errors are not retried:

- HTTP 413 (Payload Too Large) is handled separately: the batch is split (sync) or the bulk-size threshold is halved (async) and resent immediately, with no backoff delay.
- Sync: an HTTP 409 at the request level, or any other status code, drops the current batch and throws immediately (no retry). Delete-by-query is the exception — see [Delete-by-query](#delete-by-query) below.
- Async: a per-item `cluster_block_exception` inside an HTTP 200 response (cluster refusing writes) is treated as already failed permanently - those items are discarded (not retried), and the backoff is applied only to the *next* bulk send, not to the batch that already got a response. Any other per-item error, or a status code that isn't retried above, is logged and discarded.

**How the delay scales:**

- **1st failure** - sleeps exactly the base delay (`RetryDelay`, fixed at 1 second) - deterministic, no jitter, so the very first retry is never faster than configured.
- **Each subsequent consecutive failure** - doubles the delay, capped at `analysisd.indexer_max_retry_delay` (`max_retry_delay_seconds` in the connector config; default 15s, range 1-3600), and sleeps a random value between the *previous* step and the new capped step (jitter avoids many managers retrying in lockstep).
- **On success** (or, for async, a response confirmed not cluster-blocked) - the failure counter resets, so the next failure starts again from the base delay.

Example with the defaults (base = 1s, max = 15s):

| Consecutive failure | Delay slept |
|---|---|
| 1st | exactly 1s |
| 2nd | random between 1s and 2s |
| 3rd | random between 2s and 4s |
| 4th | random between 4s and 8s |
| 5th and beyond | random between 8s and 15s (capped) |

### Delete-by-query

`IndexerConnectorSync` also exposes the operation the manager's whole-agent deletion is built on. It
behaves differently from the bulk paths above, because a deletion that reports success it did not
achieve leaves documents nothing will ever overwrite:

- **`deleteByQuery(index, agentId, clusterName)`** stages one query per index; the following
  `flush()` sends them. Queries are sent with `conflicts: "proceed"`, so a document whose version
  moved between the query's search and delete phases is skipped instead of aborting the whole run.
- **A `200` is not automatically success.** The response is inspected, and the flush throws when it
  reports per-shard `failures` or a non-zero `version_conflicts` — the two ways a `200` can leave
  matching documents in place. Callers treat that as retriable.
- **Staged queries are dropped when a flush fails**, so a later flush cannot re-fire them after the
  caller already retried and succeeded (which would delete documents written in between).
- HTTP-level `404`, `409` and `429` on a delete-by-query are tolerated (logged at debug) rather than
  raised: a missing index has nothing to delete, and the other two are retried by re-running the
  deletion.
- **A delete-by-query is a SEARCH**, so it only sees documents that are already searchable. Callers
  that need it to cover writes of the last few seconds must refresh the index themselves — the
  connector does not do it for them, and `refresh()` requires `indices:admin/refresh`, which is not
  part of the `crud`/`write` action groups. The manager's whole-agent deletion accepts that window
  rather than requiring the privilege; see the
  [inventory-sync-server deletion semantics](../inventory-sync-server/api-reference.md#whole-agent-deletion-semantics).

## Indices

| Index | Written by |
|-------|------------|
| `wazuh-states-vulnerabilities` | Vulnerability Scanner |
| `wazuh-states-inventory-system` | Inventory Sync Server |
| `wazuh-states-inventory-hardware` | Inventory Sync Server |
| `wazuh-states-inventory-packages` | Inventory Sync Server |
| `wazuh-states-inventory-hotfixes` | Inventory Sync Server (Windows) |
| `wazuh-states-inventory-processes` | Inventory Sync Server |
| `wazuh-states-inventory-ports` | Inventory Sync Server |
| `wazuh-states-inventory-interfaces` | Inventory Sync Server |
| `wazuh-states-inventory-protocols` | Inventory Sync Server |
| `wazuh-states-inventory-networks` | Inventory Sync Server |
| `wazuh-states-inventory-users` | Inventory Sync Server |
| `wazuh-states-inventory-groups` | Inventory Sync Server |
| `wazuh-states-inventory-services` | Inventory Sync Server |
| `wazuh-states-inventory-browser-extensions` | Inventory Sync Server |
| `wazuh-states-fim-files` | Inventory Sync Server (FIM) |
| `wazuh-states-fim-registry-keys` | Inventory Sync Server (FIM, Windows) |
| `wazuh-states-fim-registry-values` | Inventory Sync Server (FIM, Windows) |
| `wazuh-states-sca` | Engine (SCA) |
| `wazuh-agent-config` | Inventory Sync Server (`POST /config`, one document per agent) |
| `wazuh-agent-stats` | Inventory Sync Server (`POST /stats`, one document per agent) |
| `wazuh-threatintel-*` | Read-only (Content Manager) |

## Key source files

| File | Purpose |
|------|---------|
| `include/indexerConnector.hpp` | Public API: `IndexerConnectorSync`, `IndexerConnectorAsync` |
| `src/indexerConnectorSyncImpl.hpp` | Sync implementation: in-memory buffer, bulk flush, 413 splitting |
| `src/indexerConnectorAsyncImpl.hpp` | Async implementation: in-memory bulk queue, background flusher |
| `src/exponentialBackoff.hpp` | Exponential backoff with jitter, shared by both retry paths |
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

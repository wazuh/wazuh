# Indexer Connector

> **Replaced in modulesd by the [Indexer Client](../indexer_client/README.md).** The Inventory Sync Server, the Vulnerability Scanner and the Content Manager no longer link `libindexer_connector`, and the library has no other consumer than the engine. This page is a bridge: it keeps what the engine still depends on, and points to the new reference for everything else. `IndexerConnectorSync` stays in the library but no manager component uses it any more: its flush and delete-by-query behavior is not described here, and the «Sync» rows below are kept for reference only.

The Indexer Connector is a shared library (`libindexer_connector`) that the engine (`wazuh-manager-analysisd`) uses to write its processed events to the Wazuh Indexer (OpenSearch). It was the Filebeat replacement introduced in Wazuh 5.0.

Source: `src/shared_modules/indexer_connector/`

## Where things moved

| What | Where |
|---|---|
| The `<indexer>` section (hosts, TLS), credentials, certificates and the options of the runtime | [Indexer Client Configuration](../indexer_client/configuration.md) (the old page at [Configuration](configuration.md) is a pointer) |
| Module overview, buckets, node health, logs, troubleshooting | [Indexer Client](../indexer_client/README.md) |
| Metrics | [Indexer Client Metrics](../indexer_client/metrics.md) |
| The indices each component reads or writes | [Indexer Client](../indexer_client/README.md#who-uses-it), and each consumer's page |
| The engine's own indexer options (`analysisd.indexer_*`) | [Engine configuration](../engine/configuration.md) |

The Python framework does not use this library: its indexer client reads the same `indexer` section, and the same keystore credentials through the `keystore_server` socket (see [Keystore](../keystore/README.md#keystore_server)).

## How it works

1. The caller instantiates a connector with a JSON configuration built from the `indexer` section of `wazuh-manager.conf` (see [Indexer Client Configuration](../indexer_client/configuration.md)). A connector without `hosts` fails (`No hosts found in the configuration`), and so does one whose single CA file does not exist (`The CA root certificate file: '<path>' does not exist.`). With several CA files, they are concatenated into `tmp/root-ca-merged.pem` under the manager home.
2. Credentials (`username`/`password`) are read once per process from the `indexer` column family of the [keystore](../keystore/README.md) and cached: changing them takes a restart. If either is empty, the connector fails with `No indexer credentials found in the keystore. ...`.
3. A background health-monitor thread polls `GET /_cat/health` on every configured host (5-second timeout) every `monitoring_interval_seconds` (default 10; the engine sets it from `analysisd.indexer_monitoring_interval`, range 1–3600). A host answering `green` or `yellow` is available. A host answering HTTP 429 (for example a tripped circuit breaker) is throttled: it stays in rotation and the requests sent to it back off on their own 429s; this is logged once as `Indexer node '<host>' is throttling requests (<reason>); it stays in rotation and requests back off.`, with a warning when the breaker reports `PERMANENT` durability, and as `Indexer node '<host>' accepts requests again.` when it clears. Any other answer or error (a transport failure, 401/403, any other 4xx, a 5xx, a red cluster) marks it unavailable, logged once as `Indexer node '<host>' is no longer available. Reason: <reason>` (a `401` gives `Unauthorized - Check indexer credentials`, with the indexer's error type and reason in parentheses after `Unauthorized` when its answer carries them) and again as `Indexer node '<host>' is available again.` when it recovers. An unreachable host does not fail the construction.
4. A server-selector performs round-robin load balancing across available nodes. Selection has no side effects: availability probes (`isAvailable()`, true while some host is not down, and the stricter `hasAvailableServer()`, true only while some host is neither down nor throttled) never advance the round-robin cursor, and a host is consumed from the rotation only by the request actually sent to it, so traffic distributes uniformly across healthy nodes. When every host is down, a request fails with `No available server. Unavailable nodes: <host>: <reason>` (an `IndexerConnectorException`, like every other connector failure); the background flush thread logs it as a warning, `Error processing bulk: No available server. …`.
5. Documents are accumulated in memory (both sync and async) and flushed as OpenSearch Bulk API requests.


### Async flush behavior

- Events are queued in memory immediately and flushed by a background thread.
- The queue is **FIFO**, and a batch that fails is retried from its front, so operations are applied
  in the order they were queued. That is what makes `deleteById()` usable to remove a document whose
  own `index()` may still be pending: the delete is applied after it, never before. A caller that
  needs that ordering cannot get it from another connector, and a `_delete_by_query` would not even
  see a document that has not been refreshed yet.
- A `deleteById()` of a document that is not there is a per-item `404 not_found`, which is not an
  error and is not reported: deletes are idempotent.
- Up to `analysisd.indexer_bulk_max_bytes` bytes per flush batch (default 8 MB; always takes at least one item, even if it exceeds the threshold on its own).
- A batch is sent as soon as the queue holds `bulk_max_bytes`, and otherwise at least every 20 seconds (configurable via `analysisd.indexer_flush_interval`, range 1–3600).
- If the queue exceeds `analysisd.indexer_queue_max_bytes` (default 64 MB, maps to `max_queue_bytes` in the connector config), new events are dropped and counted until it drains. The same counter (`getDroppedEvents()`, published by the engine as `indexer.events.dropped`) also counts the events of batches discarded after an indexer response (see below).
- The queue is in-memory only: buffered events are discarded (not retried) if the manager stops or restarts.

### Retry and backoff behavior

Both connectors retry transient failures using an exponential backoff with jitter (`IndexerExponentialBackoff`, `src/shared_modules/indexer_connector/src/exponentialBackoff.hpp`). What counts as transient depends on the connector, because a `_bulk` request answered 502 or 504 may have reached the indexer, and resending it is only safe when every operation carries an `_id`:

| Status of the `_bulk` request | Sync | Async |
|---|---|---|
| 429, or no HTTP response (timeout, connection refused, TLS failure) | retried within the budget below | retried, without an attempt limit |
| 503 Service Unavailable | retried within the budget below | sent up to 10 times: the 10th consecutive 503 answer to the batch at the head of the queue discards it |
| 502 Bad Gateway, 504 Gateway Timeout | retried within the budget below | discarded, not retried |
| 409 at the request level | drops the batch and throws | retried |
| 413 Payload Too Large | batch split and resent | bulk-size threshold halved and resent |
| 500 and any other status | drops the batch and throws | discarded, not retried |

- HTTP 413: sync resends the split halves immediately, with no backoff delay; async halves the threshold, requeues the batch and resends it after the queue's backoff delay. In async, once the threshold cannot be halved any further the batch is discarded (logged once, not counted).
- Async does not resend 502/504: the engine writes to data streams with `create` actions that carry no `_id`, so a resend would duplicate events. A 500 is never retried by either connector, because it may be deterministic for that payload and would block the queue head.
- Async counts every batch discarded for its `_bulk` status (500, 502, 504, any other status, or 503 retries exhausted): its events add to `getDroppedEvents()`. The 413 batch that cannot be halved further and the failed items of an HTTP 200 response are not counted there. The first discard of a window (the first one, or the first after a window that closed with nothing to summarize) logs a `WARNING` (`Discarding N event(s): bulk request answered HTTP <status>[ on 10 consecutive attempts]. Further discards are summarized every 30 seconds.`). Later discards are accumulated and summarized in one `WARNING` line at most every 30 seconds, broken down by cause (`Discards continue: …`). Each discard is also logged at debug level 1. The summary is evaluated on the next discard or the next successful response, so `getDroppedEvents()` is the reliable figure.
- After an async batch is discarded for exhausting its 503 retries, the backoff stays at its last delay (only a healthy response resets it). Each async retry also waits for the next flush (`flush_interval_seconds`, 20 seconds in the engine) after its backoff delay, unless the requeued batch already fills the bulk threshold. With the defaults, the first batch is discarded about 4 to 5 minutes after the 503 answers start. Under a persistent 503 every following batch then takes about 9 times (maximum delay + flush interval), about 5 minutes, to be discarded. The 503 limit counts only 503 answers to `_bulk`: when the health probe also fails, the node leaves the rotation and the queue keeps waiting without spending it.
- Async: a per-item `cluster_block_exception` inside an HTTP 200 response (cluster refusing writes) is treated as already failed permanently. Those items are discarded (not retried), and the backoff is applied only to the *next* bulk send, not to the batch that already got a response. Any other per-item error is logged and discarded.

**How the delay scales:**

- **1st failure** - sleeps a random value between the base delay (`RetryDelay`, fixed at 1 second) and 1.5 times it, never above the cap - so the very first retry is never faster than configured, and connectors that failed in the same instant (one 429 seen by all of them) do not retry in lockstep.
- **Each subsequent consecutive failure** - doubles the delay, capped at `analysisd.indexer_max_retry_delay` (`max_retry_delay_seconds` in the connector config; default 15s, range 1-3600), and sleeps a random value between the *previous* step and the new capped step (jitter avoids many managers retrying in lockstep).
- **On success** (or, for async, a response confirmed not cluster-blocked) - the failure counter resets, so the next failure starts again from the base delay.

Example with the defaults (base = 1s, max = 15s):

| Consecutive failure | Delay slept |
|---|---|
| 1st | random between 1s and 1.5s |
| 2nd | random between 1s and 2s |
| 3rd | random between 2s and 4s |
| 4th | random between 4s and 8s |
| 5th and beyond | random between 8s and 15s (capped) |

The indexer's `Retry-After` header is not honored — the transport does not expose response headers (tracked in #38942).

# Indexer Connector

The Indexer Connector is a shared library (`libindexer_connector`) that handles all data indexing operations between the Wazuh Manager and the Wazuh Indexer (OpenSearch). It is the Filebeat replacement introduced in Wazuh 5.0.

Source: `src/shared_modules/indexer_connector/`

For configuration options see [Indexer Configuration](configuration.md).

## Overview

The Indexer Connector is not a standalone daemon. It is linked into the processes that need to write to or query the Indexer:

- **Vulnerability Scanner** (`wazuh-manager-modulesd`) — indexes detections into `wazuh-states-vulnerabilities`, and reads its feed through the [Content Manager](../content_manager/README.md)
- **Inventory Sync Server** (`wazuh-manager-modulesd`) — indexes the agents' state (inventory, FIM, SCA) and the `wazuh-agent-config`/`wazuh-agent-stats` documents
- **Engine** (`wazuh-manager-analysisd`) — indexes processed events through its outputs, and reads its content from the `wazuh-threatintel-*` indices

The Python framework does not use this library: its indexer client reads the same `indexer` section, and the same keystore credentials through the `keystore_server` socket (see [Keystore](../keystore/README.md#keystore_server)).

The library provides these classes:

| Class | Mode | Queue | Use case |
|-------|------|-------|----------|
| `IndexerConnectorSync` | Synchronous | In-memory staging buffer (flushed at `max_bulk_size`, default 10 MB) | Bounded writes the caller flushes and answers for; searches, PIT, by-query operations |
| `IndexerConnectorAsync` | Asynchronous | In-memory (byte-bounded via `max_queue_bytes`; unlimited when 0) | Non-blocking writes; buffered events are discarded on shutdown |
| `IndexerSession` | — | — | One health monitor and one credential read shared by several connectors of the same process |

## How it works

1. The caller instantiates a connector with a JSON configuration built from the `indexer` section of `wazuh-manager.conf` (see [Configuration](configuration.md)). A connector without `hosts` fails (`No hosts found in the configuration`), and so does one whose single CA file does not exist (`The CA root certificate file: '<path>' does not exist.`). With several CA files, they are concatenated into `tmp/root-ca-merged.pem` under the manager home.
2. Credentials (`username`/`password`) are read once per process from the `indexer` column family of the [keystore](../keystore/README.md) and cached: changing them takes a restart. If either is empty, the connector fails with `No indexer credentials found in the keystore. ...`.
3. A background health-monitor thread polls `GET /_cat/health` on every configured host (5-second timeout) every `monitoring_interval_seconds` (default 10; the engine sets it from `analysisd.indexer_monitoring_interval`, range 1–3600). A host answering `green` or `yellow` is available. A host answering HTTP 429 (for example a tripped circuit breaker) is throttled: it stays in rotation and the requests sent to it back off on their own 429s; this is logged once as `Indexer node '<host>' is throttling requests (<reason>); it stays in rotation and requests back off.`, with a warning when the breaker reports `PERMANENT` durability, and as `Indexer node '<host>' accepts requests again.` when it clears. Any other answer or error (a transport failure, 401/403, any other 4xx, a 5xx, a red cluster) marks it unavailable, logged once as `Indexer node '<host>' is no longer available. Reason: <reason>` (a `401` gives `Unauthorized - Check indexer credentials`, with the indexer's error type and reason in parentheses after `Unauthorized` when its answer carries them) and again as `Indexer node '<host>' is available again.` when it recovers. An unreachable host does not fail the construction.
4. A server-selector performs round-robin load balancing across available nodes. Selection has no side effects: availability probes (`isAvailable()`, true while some host is not down, and the stricter `hasAvailableServer()`, true only while some host is neither down nor throttled) never advance the round-robin cursor, and a host is consumed from the rotation only by the request actually sent to it, so traffic distributes uniformly across healthy nodes. When every host is down, a request fails with `No available server. Unavailable nodes: <host>: <reason>` (an `IndexerConnectorException`, like every other connector failure); the background flush thread logs it as a warning, `Error processing bulk: No available server. …`.
5. Documents are accumulated in memory (both sync and async) and flushed as OpenSearch Bulk API requests.

### Sync flush behavior

- Buffer up to `max_bulk_size` bytes of serialized events (default 10 MB) before flushing.
- A background thread flushes whatever is staged every `flush_interval_seconds` (default 20).
- `flush_interval_seconds = 0` means **no background flush thread at all**: the connector is never created with one and every flush is the caller's. Use it when the caller has to answer for a failed flush — a timer flush that fails discards the staging buffer and has no caller to report to, so a later `flush()` finds an empty buffer and returns success for data that never landed. The Inventory Sync Server sets it this way: its ingestion workers own every flush.
- Each consumer sets these values from its own internal options: the Vulnerability Scanner's are in its [Internal Options](../vulnerability-scanner/configuration.md#internal-options), the Inventory Sync Server's in its [configuration reference](../inventory-sync-server/configuration.md).
- If the indexer returns HTTP 413 (payload too large), the batch is split and retried.
- Version conflicts at the document level are handled per-document.
- A `bulkDelete()` of a document that is not there is a per-item `404 not_found` with no `error`, and it counts as done:
  deletes are idempotent, so it does not fail the batch. When the bulk response reports errors for other items, these
  deletes are counted as `already-absent deletes` in the `Bulk operation summary` line. A delete on an index that does not
  exist (`index_not_found_exception`) still fails the batch.

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
- Sync resends 502/504 because every production caller (inventory sync, vulnerability detection) passes a document `_id`, so a resend overwrites instead of duplicating. A `bulkIndex()` without an `_id` is not idempotent on resend, after a 502/504 or after a transport failure alike.
- Async does not resend 502/504: the engine writes to data streams with `create` actions that carry no `_id`, so a resend would duplicate events. A 500 is never retried by either connector, because it may be deterministic for that payload and would block the queue head.
- Async counts every batch discarded for its `_bulk` status (500, 502, 504, any other status, or 503 retries exhausted): its events add to `getDroppedEvents()`. The 413 batch that cannot be halved further and the failed items of an HTTP 200 response are not counted there. The first discard of a window (the first one, or the first after a window that closed with nothing to summarize) logs a `WARNING` (`Discarding N event(s): bulk request answered HTTP <status>[ on 10 consecutive attempts]. Further discards are summarized every 30 seconds.`). Later discards are accumulated and summarized in one `WARNING` line at most every 30 seconds, broken down by cause (`Discards continue: …`). Each discard is also logged at debug level 1. The summary is evaluated on the next discard or the next successful response, so `getDroppedEvents()` is the reliable figure.
- After an async batch is discarded for exhausting its 503 retries, the backoff stays at its last delay (only a healthy response resets it). Each async retry also waits for the next flush (`flush_interval_seconds`, 20 seconds in the engine) after its backoff delay, unless the requeued batch already fills the bulk threshold. With the defaults, the first batch is discarded about 4 to 5 minutes after the 503 answers start. Under a persistent 503 every following batch then takes about 9 times (maximum delay + flush interval), about 5 minutes, to be discarded. The 503 limit counts only 503 answers to `_bulk`: when the health probe also fails, the node leaves the rotation and the queue keeps waiting without spending it.
- Async: a per-item `cluster_block_exception` inside an HTTP 200 response (cluster refusing writes) is treated as already failed permanently. Those items are discarded (not retried), and the backoff is applied only to the *next* bulk send, not to the batch that already got a response. Any other per-item error is logged and discarded.
- Sync: delete-by-query has its own rules — see [Delete-by-query](#delete-by-query) below.

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

**Retries are bounded (sync).** Every sync retry loop carries a budget: at most `max_retry_attempts`
failed attempts (default 5) and a wall-clock deadline of `max_retry_duration_seconds` (default 15s)
per operation, whichever is spent first; the chunks of a `413` split draw from their flush's budget,
so a split cannot multiply it. On exhaustion the operation throws instead of retrying —
the batch is dropped and the caller retries by re-staging, the same contract as any other terminal
failure. `0` disables the corresponding bound. Without the budget, a persistent 429 (or 502/503/504 on a bulk flush), or an
unreachable indexer blocks the flushing worker (and, in inventory sync, the shard behind it) forever,
long after the caller's response window closed. The deadline only gates the sleeps: one in-flight
request can still overshoot it by up to `request_timeout_seconds`. The indexer's `Retry-After`
header is not honored — the transport does not expose response headers (tracked in #38942).

### Delete-by-query

`IndexerConnectorSync` also exposes the operation the manager's whole-agent deletion is built on. It
behaves differently from the bulk paths above, because a deletion that reports success it did not
achieve leaves documents nothing will ever overwrite:

- **`deleteByQuery(index, agentId, clusterName)`** stages one query per index; the following
  `flush()` sends them. Queries are sent with `conflicts: "proceed"`, so a document whose version
  moved between the query's search and delete phases is skipped instead of aborting the whole run.
- **A `200` is not automatically success.** The response is inspected, and the flush throws when it
  reports per-shard `failures`, or when its body cannot be parsed at all. Callers treat that as
  retriable.
- **A version conflict is retried, not raised.** The skips `proceed` tallies in `version_conflicts`
  are the other way a `200` leaves matching documents in place, but unlike a shard failure the
  condition clears itself: a write the indexer has acknowledged but not yet refreshed makes every
  document it touched conflict, so a delete issued right after a bulk of the same documents collides
  with it. `refresh_interval` is not uniform across the state indices: 2s for most of them, 5s for
  `wazuh-states-sca`. The operation is re-run, which is idempotent, on its own count of 3 attempts
  and its own backoff (3s, then up to 6s: the second delay is drawn uniformly from `[base, 2*base]`,
  so the base has to be 3s for the cumulative wait to clear a 5s segment on every draw), so the
  budget above stays intact for a 429 that follows; the wall bound is shared, and one allowance
  covers a whole flush rather than each index in it. Conflicts that outlive it fail the operation
  under `Category::ConflictsExhausted` rather than `DocumentRejected`: the documents left behind are
  consistent, a competing writer of the same documents was still running (a duplicate of the
  caller's own session, a late flush on another node), and the caller can answer a retryable status
  with a delay instead of a failure. A stop that cuts a retry wait short fails it the same way. The
  warning names the attempts actually made against the allowance.
- **Staged queries are dropped when a flush fails**, so a later flush cannot re-fire them after the
  caller already retried and succeeded (which would delete documents written in between).
- HTTP-level `404` is tolerated (a missing index has nothing to delete), `429` is retried with the
  same backoff as the bulk paths, and anything else — a request-level `409` included — fails the
  flush: an unconfirmed delete is never reported as applied.
- **`executeUpdateByQuery` follows the same contract**, conflict retry included: a `200` whose body
  tallies `failures`, cannot be parsed, or lacks the `updated`/`total` counters fails the call
  instead of confirming it. Two callers share this path — the sync server's metadata/group
  reconciliation and the vulnerability scanner's `host.os` update against
  `wazuh-states-vulnerabilities` — so a retried query must be cheap to re-run. That is the caller's
  side of the contract, met either by a version gate that stops matching what the previous attempt
  applied or by a script that compares first and goes `ctx.op = 'noop'` when the document already
  matches; without one of the two, a retry rewrites everything the previous attempt just wrote.
- **A delete-by-query is a SEARCH**, so it only sees documents that are already searchable. Callers
  that need it to cover writes of the last few seconds must refresh the index themselves — the
  connector does not do it for them, and `refresh()` requires `indices:admin/refresh`, which is not
  part of the `crud`/`write` action groups. The manager's whole-agent deletion accepts that window
  rather than requiring the privilege; see the
  [inventory-sync-server deletion semantics](../inventory-sync-server/api-reference.md#whole-agent-deletion-semantics).

## Indices

| Index | Used by |
|-------|---------|
| `wazuh-states-vulnerabilities` | Vulnerability Scanner (writes) |
| `wazuh-states-inventory-*`, `wazuh-states-fim-*`, `wazuh-states-sca`, `wazuh-states-sca-*` | Inventory Sync Server (writes the indices agents synchronize; an agent session may target only these names, plus `wazuh-states-vulnerabilities`, which it may clean but never write) |
| `wazuh-agent-config`, `wazuh-agent-stats` | Inventory Sync Server (`POST /config`, `POST /stats`: one document per agent) |
| `wazuh-states-*`, `wazuh-agent-config`, `wazuh-agent-stats` | Inventory Sync Server (on agent deletion: delete-by-query on `wazuh-states-*`, delete by document id on the two `wazuh-agent-*` indices) |
| `.wazuh-threatintel-vulnerabilities`, `.wazuh-cti-consumers` | Content Manager (reads, for the Vulnerability Scanner) |
| `wazuh-threatintel-*` (kvdbs, decoders, filters, integrations, policies, enrichments) | Engine (reads its content) |

Which agent module feeds which index family is described in the
[Inventory Sync Server reference](../inventory-sync-server/README.md).

## Key source files

| File | Purpose |
|------|---------|
| `src/shared_modules/indexer_connector/include/indexerConnector.hpp` | Public API: `IndexerConnectorSync`, `IndexerConnectorAsync`, `IndexerSession` |
| `src/shared_modules/indexer_connector/src/indexerConnectorSyncImpl.hpp` | Sync implementation: in-memory buffer, bulk flush, 413 splitting, by-query operations |
| `src/shared_modules/indexer_connector/src/indexerConnectorAsyncImpl.hpp` | Async implementation: in-memory bulk queue, background flusher |
| `src/shared_modules/indexer_connector/src/exponentialBackoff.hpp` | Exponential backoff with jitter, shared by both retry paths |
| `src/shared_modules/indexer_connector/src/serverSelector.hpp` | Round-robin load balancer with health tracking |
| `src/shared_modules/indexer_connector/src/monitoring.hpp` | Background health-monitor thread (default 10 s interval) |
| `src/shared_modules/indexer_connector/src/indexerTransport.cpp` | TLS material and keystore credentials |
| `src/shared_modules/indexer_connector/testtool/` | CLI test tool: `push-events`, `export-policy`, `generate-full-policy` |

## Test tool

`indexer_connector_tool` is a developer tool built in the build tree
(`cmake --build src/build --target indexer_connector_tool`, output `src/build/bin/indexer_connector_tool`);
it is not installed with the manager. Its reference is
`src/shared_modules/indexer_connector/testtool/README.md`.

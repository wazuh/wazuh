# Indexer Connector

The Indexer Connector is a shared library (`libindexer_connector`) that handles all data indexing operations between the Wazuh Manager and the Wazuh Indexer (OpenSearch).

Source: `src/shared_modules/indexer_connector/`

For configuration options see [Indexer Configuration](configuration.md).

## Overview

The Indexer Connector is not a standalone daemon. It is linked into the processes that need to write to or query the Indexer:

- **Vulnerability Scanner** (`wazuh-manager-modulesd`) — indexes detections into `wazuh-states-vulnerabilities`, and reads its feed through the [Content Manager](../content_manager/README.md)
- **Inventory Sync Server** (`wazuh-manager-modulesd`) — indexes the agents' state (inventory, FIM, SCA) and the `wazuh-agent-config`/`wazuh-agent-stats` documents
- **Engine** (`wazuh-manager-analysisd`) — wraps `IndexerConnectorAsync` in its `wiconnector` module (`src/engine/source/wiconnector/`) to index processed events through its outputs and to read its content from the `wazuh-threatintel-*` indices

The Python framework does not use this library: its indexer client reads the same `indexer` section, and the same keystore credentials through the `keystore_server` socket (see [Keystore](../keystore/README.md#keystore_server)), again for every client it builds.

The library provides these classes:

| Class | Mode | Queue | Use case |
|-------|------|-------|----------|
| `IndexerConnectorSync` | Synchronous | In-memory staging buffer (flushed at `max_bulk_size`, default 10 MB) | Bounded writes the caller flushes and answers for; searches, PIT, by-query operations |
| `IndexerConnectorAsync` | Asynchronous | In-memory (byte-bounded via `max_queue_bytes`; unlimited when 0) | Non-blocking writes; buffered events are discarded on shutdown |
| `IndexerSession` | — | — | One health monitor and one credential read shared by several connectors of the same process |

## How it works

1. The caller instantiates a connector with a JSON configuration built from the `indexer` section of `wazuh-manager.conf` (see [Configuration](configuration.md)). A connector without `hosts` fails (`No hosts found in the configuration`), and so does one whose single CA file does not exist (`The CA root certificate file: '<path>' does not exist.`). With several CA files, they are concatenated into `tmp/root-ca-merged.pem` under the manager home.
2. Credentials (`username`/`password`) are read once per process from the `indexer` column family of the [keystore](../keystore/README.md) and cached: changing them takes a restart. If either is empty, the connector fails with `No indexer credentials found in the keystore. ...`.
3. A background health-monitor thread polls `GET /_cluster/health/wazuh-*,.wazuh-*` on every configured host (5-second timeout) every `monitoring_interval_seconds` (default 10; the engine sets it from `analysisd.indexer_monitoring_interval`, range 1–3600). A host answering `green` or `yellow` is available. The probe asks only about the indices this manager reads and writes (`wazuh-*` for what it writes, `.wazuh-*` for what it reads; a wildcard resolves a data stream to its backing indices), so an unassigned primary in an index the manager does not use no longer makes every host unavailable — while a manager index losing its primary still does. The pattern is fixed, not configurable: a pattern matching nothing would answer `green` for an empty index list and report healthy forever. An answer that is not a JSON object carrying a `status` string marks the host unavailable with a reason naming the problem. A host answering HTTP 429 (for example a tripped circuit breaker) is throttled: it stays in rotation and the requests sent to it back off on their own 429s; this is logged once as `Indexer node '<host>' is throttling requests (<reason>); it stays in rotation and requests back off.`, with a warning when the breaker reports `PERMANENT` durability, and as `Indexer node '<host>' accepts requests again.` when it clears. Any other answer or error (a transport failure, 401/403, any other 4xx, a 5xx, a red cluster) marks it unavailable, logged once as `Indexer node '<host>' is no longer available. Reason: <reason>` (a `401` gives `Unauthorized - Check indexer credentials`, with the indexer's error type and reason in parentheses after `Unauthorized` when its answer carries them) and again as `Indexer node '<host>' is available again.` when it recovers. An unreachable host does not fail the construction.
4. A server-selector performs round-robin load balancing across available nodes. Selection has no side effects: availability probes (`isAvailable()`, true while some host is not down, and the stricter `hasAvailableServer()`, true only while some host is neither down nor throttled) never advance the round-robin cursor, and a host is consumed from the rotation only by the request actually sent to it, so traffic distributes uniformly across healthy nodes. When every host is down, a request fails with `No available server. Unavailable nodes: <host>: <reason>` (an `IndexerConnectorException`, like every other connector failure); the background flush thread logs it as a warning, `Error processing bulk: No available server. …`.
5. Documents are accumulated in memory (both sync and async) and flushed as OpenSearch Bulk API requests.

### Sync flush behavior

- Buffer up to `max_bulk_size` bytes of serialized events (default 10 MB) before flushing.
- A background thread flushes whatever is staged every `flush_interval_seconds` (default 20).
- `flush_interval_seconds = 0` means **no background flush thread at all**: the connector is never created with one and every flush is the caller's. Use it when the caller has to answer for a failed flush — a timer flush that fails discards the staging buffer and has no caller to report to, so a later `flush()` finds an empty buffer and returns success for data that never landed. The Inventory Sync Server sets it this way: its ingestion workers own every flush.
- Each consumer sets these values from its own internal options: the Vulnerability Scanner's are in its [Internal Options](../vulnerability-scanner/configuration.md#internal-options), the Inventory Sync Server's in its [configuration reference](../inventory-sync-server/configuration.md).
- If the indexer returns HTTP 413 (payload too large), the batch is split and retried.
- Version conflicts at the document level are handled per item, by operation. A versioned `bulkIndex()` is a scripted `update` whose action carries `retry_on_conflict`, so the indexer re-reads the document and re-runs the script when a concurrent write moved it; a `409` that survives those retries means the write was refused and fails the flush. `bulkDelete()` and an unversioned `bulkIndex()` send no version, so their items cannot answer `409`.
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
- Up to `bulk_max_bytes` bytes per flush batch (connector default 4 MB; the engine sets it from `analysisd.indexer_bulk_max_bytes`, default 8 MB). A batch always takes at least one item, even if it exceeds the threshold on its own.
- A batch is sent as soon as the queue holds `bulk_max_bytes`, and otherwise at least every `flush_interval_seconds` (default 20; the engine sets it from `analysisd.indexer_flush_interval`, range 1–3600).
- If the queue exceeds `max_queue_bytes` (connector default 0, unlimited; the engine sets it from `analysisd.indexer_queue_max_bytes`, default 64 MB), new events are dropped and counted until it drains. The same counter (`getDroppedEvents()`, published by the engine as `indexer.events.dropped`) also counts the events of batches discarded after an indexer response (see below).
- The queue is in-memory only: buffered events are discarded (not retried) if the manager stops or restarts.
- `indexDataStream(index, id, data)` queues a data stream document with an optional `_id`; the two-argument overload is unchanged. An empty `id` queues the action `{"create":{"_index":"<index>"}}`; a non-empty `id` queues `{"create":{"_index":"<index>","_id":"<id, JSON-escaped>"}}`. An `id` longer than 512 bytes throws `IndexerConnectorException` and nothing is queued. The `id` must be valid UTF-8: it is JSON-escaped but not validated, and an invalid one makes the indexer reject the whole bulk. Each queued engine document is 36 bytes larger (`,"_id":"<27 chars>"` in its action line), so `analysisd.indexer_queue_max_bytes` and a bulk hold slightly fewer events.
- A `create` item answered `409` with `error.type` `version_conflict_engine_exception` inside a 2xx `_bulk` response means the document was already there (an earlier attempt was applied after a timeout or a connection loss). It counts as applied, adds to `getDeduplicatedEvents()` (total since start; these items are not added to `getDroppedEvents()`) and is not logged per document. One `WARNING` is logged per streak, and its `N` is the count of the `_bulk` response that started the streak, not of the whole streak: the total is `getDeduplicatedEvents()` (published by the engine as `indexer.events.deduplicated`). It is logged again only after a 2xx `_bulk` response whose items include none of them (an HTTP error answer, or a response whose items cannot be matched with the batch, does not end the streak; the 409 items of such a response are not counted): `Indexer already had N document(s) of a resent bulk (an earlier attempt was applied after a timeout or connection loss); they were not indexed twice.`

### Retry and backoff behavior

Both connectors retry transient failures using an exponential backoff with jitter (`IndexerExponentialBackoff`, `src/shared_modules/indexer_connector/src/exponentialBackoff.hpp`). What counts as transient depends on the connector, because a `_bulk` request answered 502 or 504 may have reached the indexer, and resending it is only safe when every operation carries an `_id`:

| Status of the `_bulk` request | Sync | Async |
|---|---|---|
| 200 with per-item 429 or `cluster_block_exception` | flush fails; caller must re-stage and retry | only rejected items requeued at the front in their original order, with backoff and no attempt limit (see below) |
| 429, or no HTTP response (timeout, connection refused, TLS failure) | retried within the budget below | retried, without an attempt limit |
| 503 Service Unavailable | retried within the budget below | sent up to 10 times: the 10th consecutive 503 answer to the batch at the head of the queue discards it |
| 502 Bad Gateway, 504 Gateway Timeout | retried within the budget below | discarded, not retried |
| 409 at the request level | drops the batch and throws | retried |
| 413 Payload Too Large | batch split and resent | bulk-size threshold halved and resent |
| 500 and any other status | drops the batch and throws | discarded, not retried |

- HTTP 413: sync resends the split halves immediately, with no backoff delay; async halves the threshold, requeues the batch and resends it after the queue's backoff delay. In async, once the threshold cannot be halved any further the batch is discarded (logged once, not counted).
- Sync resends 502/504 because every production caller (inventory sync, vulnerability detection) passes a document `_id`, so a resend overwrites instead of duplicating. A `bulkIndex()` without an `_id` is not idempotent on resend, after a 502/504 or after a transport failure alike.
- Async does not resend 502/504. The engine writes every data stream document with its own `_id` (`indexDataStream(index, id, data)`, see above), and every async resend (no response, 503, 413, and the requeue of an item rejected with a 429 or a `cluster_block_exception`) sends the same serialized action with the same `_id`, so it is idempotent within the data stream's backing index. A resend that crosses a rollover of the data stream can still duplicate the document (known, accepted limit). Resending 502/504 would now be safe for those writes, but the policy is unchanged by decision (a separate change); `indexDataStream(index, data)` without an `_id` stays non-idempotent. A 500 is never retried by either connector, because it may be deterministic for that payload and would block the queue head.
- Async counts every batch discarded for its `_bulk` status (500, 502, 504, any other status, or 503 retries exhausted): its events add to `getDroppedEvents()`. The 413 batch that cannot be halved further and the items an HTTP 200 response failed with a non-retryable error are not counted there. Items it rejected with a `cluster_block_exception` or a `429` are requeued, not dropped (see below). The first discard of a window (the first one, or the first after a window that closed with nothing to summarize) logs a `WARNING` (`Discarding N event(s): bulk request answered HTTP <status>[ on 10 consecutive attempts]. Further discards are summarized every 30 seconds.`). Later discards are accumulated and summarized in one `WARNING` line at most every 30 seconds, broken down by cause (`Discards continue: …`). Each discard is also logged at debug level 1. The summary is evaluated on the next discard or the next successful response, so `getDroppedEvents()` is the reliable figure.
- After an async batch is discarded for exhausting its 503 retries, the backoff stays at its last delay (only a healthy response resets it). Each async retry, including the resend of requeued items, also waits for the next flush (`flush_interval_seconds`, 20 seconds in the engine) after its backoff delay, unless the requeued data already fills the bulk threshold. With the defaults, the first batch is discarded about 4 to 5 minutes after the 503 answers start. Under a persistent 503 every following batch then takes about 9 times (maximum delay + flush interval), about 5 minutes, to be discarded. The 503 limit counts only 503 answers to `_bulk`: when the health probe also fails, the node leaves the rotation and the queue keeps waiting without spending it.
- Async: an HTTP 200 response can reject single items. When it reports errors, its items are classified before the next batch is taken. An item rejected with a `cluster_block_exception` (the index or cluster refusing writes, for example during a Security Analytics write block) or with a per-item `status` 429 (`circuit_breaking_exception`, `es_rejected_execution_exception`: the indexer shedding load under heap or thread-pool pressure) was not written, so it goes back to the **front** of the queue, in its original order and ahead of newer events, and the next send is backed off. Items the indexer wrote and items that failed with any other error are never resent: a data stream document written without an `_id` would be duplicated. Requeued items are not added to `getDroppedEvents()` and are retried without an attempt limit; `getRequeuedEvents()` (published by the engine as `indexer.events.requeued`) counts every requeue, so an item requeued three times counts three. The first requeue of a window logs a `WARNING` (`Indexer rejected N document(s) in this batch (cluster_block_exception: N, HTTP 429: N); requeued for retry. Backing off future sends. Further requeues are summarized every 30 seconds.`); later ones are summarized in one `WARNING` at most every 30 seconds (`Requeues continue: …`), and each one is logged at debug level 1. A requeued item gets no per-document `WARNING`.
- Async, consequence of retrying without a limit: one queue serves every index the connector writes to. While one index keeps refusing writes, every send is backed off (up to `max_retry_delay_seconds`) and the requeued items go first in every batch, so the events of every other index slow down too, and stop once the requeued items fill the bulk threshold. The queue then fills up to `max_queue_bytes` and **new** events are refused and counted in `getDroppedEvents()`; requeued items are never dropped for size. With `max_queue_bytes = 0` (unlimited) the memory grows for as long as the rejections last.
- Async, known limitation: each item is judged on its own. When one batch holds several operations on the same document (`_index` and `_id`) and the indexer rejects an earlier one but writes a later one, the earlier one is still resent, after the later one, so it can overwrite the newer document or recreate a deleted one. It concerns callers that write documents by `_id` with `index` or `delete` actions; data stream writes are `create` actions, without an `_id` or with one unique to each write, and are not affected.
- Async: a response that reports errors but whose items cannot be matched with the batch (it cannot be parsed, has no `items` array, or its item count differs from the batch) requeues nothing and leaves the backoff as it is: the delivery of that batch is unknown. It logs a `WARNING` (`Indexer bulk response reports errors but could not be classified (<reason>): N document(s) were not requeued and their delivery is unknown. Further occurrences are summarized every 30 seconds.`), then at most one `Unclassified bulk responses continue: …` summary every 30 seconds.
- Async: a `create` item with `409` `version_conflict_engine_exception` is not an error: it is counted as deduplicated (see Async flush behavior), never requeued and not logged per document. A 409 on an `index` or `delete` item, or with any other `error.type`, is a per-item error handled by the next rule.
- Async: any other per-item error is logged with its document and discarded, not counted.
- Sync: delete-by-query has its own rules — see [Delete-by-query](#delete-by-query) below.

**Search and update-by-query (sync).** `executeSearchQuery` — and so every page of
`executeSearchQueryWithPagination` — and `executeUpdateByQuery` retry the same transient conditions as a
sync `_bulk` flush, each drawing on the budget below:

| Status of the `_search` / `_update_by_query` request | Behavior |
|---|---|
| 429, or no HTTP response (timeout, connection refused, TLS failure) | retried within the budget below |
| 502 Bad Gateway, 503 Service Unavailable, 504 Gateway Timeout | retried within the budget below, each attempt against the next host (`m_selector->getNext()`) |
| 404 with `index_not_found_exception` in the body | not retried: throws, logged at debug level 2 (the caller decides what a missing index means) |
| 409 at the request level (`executeUpdateByQuery` only) | not retried: throws `Update by query version conflict` |
| 500 and any other status | not retried: throws at once |

- A search is a read, so re-running it is idempotent. An update-by-query is re-run under
  `conflicts=proceed` plus the caller-side idempotency contract described in
  [Delete-by-query](#delete-by-query); its own version-conflict allowance is separate from this budget.
- 500 stays out of the retried set for the same reason as on `_bulk`: it may be deterministic, and
  retrying it would only spend the budget.
- A search answered with a 2xx whose body is not JSON (a proxy's HTML page, a truncated body) is not a
  transport failure either, and is not retried: it throws at once (see the error contract below). The
  HTTP layer forwards an exception thrown while handling a response to `onError` with status `-1`, so
  the search parses inside its success callback and raises the failure itself.
- Retried attempts are logged at debug level 2 and never warn. When the budget is spent the operation
  throws `Search query retry budget exhausted` / `Update by query retry budget exhausted`
  (`Category::RetryExhausted`, `statusCode() == 0`).

**How the delay scales:**

- **1st failure** - sleeps a random value between the base delay (`RetryDelay`, fixed at 1 second) and 1.5 times it, never above the cap - so the very first retry is never faster than configured, and connectors that failed in the same instant (one 429 seen by all of them) do not retry in lockstep.
- **Each subsequent consecutive failure** - doubles the delay, capped at `max_retry_delay_seconds` (default 15 s; the engine sets it from `analysisd.indexer_max_retry_delay`, range 1-3600), and sleeps a random value between the *previous* step and the new capped step (jitter avoids many managers retrying in lockstep).
- **On success** (or, for async, a response with no cluster-blocked or 429 item) - the failure counter resets, so the next failure starts again from the base delay. An async response whose items cannot be classified neither resets nor extends it.

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
failure. `0` disables the corresponding bound. Without the budget, a persistent 429 or 502/503/504, or an
unreachable indexer blocks the flushing worker (and, in inventory sync, the shard behind it) forever,
long after the caller's response window closed. The deadline only gates the sleeps: one in-flight
request can still overshoot it by up to `request_timeout_seconds`. The indexer's `Retry-After`
header is not honored — the transport hands the connector only the status code and the body of an
error response.

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
- HTTP-level `404` is tolerated by delete-by-query (a missing index has nothing to delete, nothing is
  thrown), `429` is retried with the same backoff as the bulk paths, and anything else — a
  request-level `409` included — fails the flush: an unconfirmed delete is never reported as applied.
- **`executeSearchQuery` and `executeUpdateByQuery` do not tolerate a `404`**: they still throw on any
  failure. A missing index is recognised from **both** facts together — status `404` **and**
  `index_not_found_exception` in the body (`isIndexNotFound`) — so a `400`/`500` that merely carries the
  type as `caused_by` is a real failure, not an empty dataset. A missing index is logged at debug level 2
  instead of a warning, because the caller decides what it means (for the vulnerability scanner it is an
  empty dataset); every other **non-retried** failure (`403`, `500`, any other 4xx) keeps the connector's
  warning. The retried conditions (`429`, `502`/`503`/`504`, no HTTP response) never warn: each attempt is
  logged at debug level 2, and a spent budget throws the retry-exhausted exception described below — see
  [Retry and backoff behavior](#retry-and-backoff-behavior).
- **A missing index on `executeUpdateByQuery` keeps the pending notify callbacks.** Nothing was written,
  so the session that registered them is not broken: they still fire on the caller's
  `invokePendingCallbacks()`, exactly as on the filtered-indices no-op. Dropping them would hang a session
  on an update the caller treats as a no-op (the scanner's `host.os` refresh on a fresh install). Any
  *other* failure still clears them — a failed write must never notify the session as if it had been
  applied.
- **Error contract of `executeSearchQuery` / `executeUpdateByQuery`**: the exception text is
  `Search query failed (status N): <transport error> - <response body truncated to 256 bytes>` and
  `Update by query failed (status N): <transport error> - <response body truncated to 256 bytes>`
  respectively (the ` - <body>` suffix is present only when the response has a body: a transport failure
  carries just the transport error), and `statusCode()` carries `N`. OpenSearch puts the error type (e.g.
  `index_not_found_exception`) near the start of the body, so it survives the truncation; consumers such
  as the scanner's `IndexerErrorHelper` rely on it. **A spent retry budget is the one failure that does not
  take that shape**: it throws `Search query retry budget exhausted` / `Update by query retry budget
  exhausted` under `Category::RetryExhausted`, with no status in the text and `statusCode() == 0`, and the
  connector logs no warning for it (every attempt was logged at debug level 2). A consumer that classifies
  by text must treat it as a failed read and must not look for a status in it. `executeUpdateByQuery` also
  throws `Update by query version conflict` on a request-level `409`, which is a warning and is not
  retried. `executeSearchQuery` throws `Search query returned an invalid response: <parse error> -
  <response body truncated to 256 bytes>` (`Category::Other`, `statusCode() == 0`, logged as a warning,
  not retried) when a 2xx body is not valid JSON.
- **`executeUpdateByQuery` keeps the conflict retry** and also fails closed: a `200` whose body
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

### Searches and points in time

Point-in-time (PIT) creation and searches are reads the caller takes as the whole answer: the engine
builds a content space from them, the vulnerability feed advances its cursor past them, the
vulnerability scanner reads an agent's inventory and stored findings, `inventory_sync_server`
computes a checksum over an agent's documents, and the feed downloader polls for its consumer
status and the feed's global-map documents. By default
the indexer answers them even when some shards cannot take part, for example while the node that
holds them is stopping: it replies `200`, leaves those shards' documents out and reports a smaller
`hits.total`. Both connectors therefore ask the indexer to refuse instead:

- **PIT creation sends `allow_partial_pit_creation=false`.** Without it, a PIT created while a shard
  is unavailable simply leaves that shard out of the snapshot, and every later search on that PIT
  reports a complete answer over the shards it has (`_shards.failed` 0), so the gap cannot be seen
  afterwards. With it, the indexer answers `503` (`search_phase_execution_exception`, phase
  `create_pit`).
- **Both connectors' PIT searches send `allow_partial_search_results=false`.** `IndexerConnectorAsync`
  also sends it when searching an index or alias. A search that loses a shard, for instance on a PIT
  opened before the node stopped, then fails with `500` (`search_phase_execution_exception`) instead of
  returning the other shards' documents.
- **The synchronous searches without a PIT send it too.** `IndexerConnectorSync::executeSearchQuery()`
  and `executeSearchQueryWithPagination()` send `allow_partial_search_results=false` on every request,
  so each page is complete or the call throws. With the node that holds a shard already stopped, the
  indexer answers `503`. A paginated walk that is refused on a later page throws from that page: the
  callback has already run for the earlier ones, and the walk must be treated as incomplete.
- **HTTP errors keep their status.** A failed PIT creation or search, with or without a PIT, carries
  the indexer's status in `statusCode()`, so a `404` still means a missing index or document and a
  refusal is reported as the `503`/`500` it is.
- **Nothing is retried here except a `429`.** `IndexerConnectorSync` repeats a search answered `429`
  within its retry budget; every other failure, a refusal included, goes to the caller without a
  retry. The PIT callers repeat the whole read (the engine's content sync, the vulnerability feed's
  page retry). What each caller of the synchronous searches does with a refusal: the vulnerability scanner fails the scan (a feed-update
  rescan marks the agent's scan as incomplete; the baseline's probe of the indices a scan reads takes it as "cannot be read" and does
  not count that pass against the agents); the `inventory_sync_server` checksum answers a generic `503` without `Retry-After`
  when the indexer answered `5xx`; the feed downloader's polls count the refusal as a failed query and keep waiting, with no
  limit.
- **A red cluster gets no request at all.** The health monitor takes a node whose cluster reports
  `red` out of rotation, so the call fails earlier with `No available server`. A refusal is only
  possible between a node leaving and the next health check (`monitoring_interval_seconds`).

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

# Indexer Client Metrics

The Indexer Client does not have an endpoint of its own. The library publishes its counters as typed snapshots, and each process that uses it registers them, by pull, in its own metrics registry: the two modulesd modules read through each module's `GET /metrics` over its local socket, and the engine through its metrics API.

| Module | Read through | What it publishes |
|---|---|---|
| [Inventory Sync Server](../inventory-sync-server/metrics.md#indexer-client-buckets--indexer_clientbucketinventory_sync_serverbucket) | `GET /metrics` on `queue/sockets/inventory-sync-http.sock` | Its two buckets, and modulesd's runtime, node, query and PIT metrics **once per process** |
| [Vulnerability Scanner](../vulnerability-scanner/metrics.md#indexer-client-bucket--indexer_clientbucketvulnerability_scannervd_states) | `GET /metrics` on `queue/sockets/vd-http.sock` | Its `vd-states` bucket only |
| [Engine](../engine/README.md#indexer-client-metrics) (`wazuh-manager-analysisd`, or the engine inside wazuh-indexer) | The engine API's `/metrics/*` (fastmetrics) | Its `events` and `raw` buckets, and the engine's own runtime, node, query and PIT metrics |

```bash
curl -s --unix-socket /var/wazuh-manager/queue/sockets/inventory-sync-http.sock http://localhost/metrics
```

## Names

Lowercase, dotted, no labels. `<consumer>` and `<bucket>` are sanitized: lowercased, every character outside `[a-z0-9_]` becomes `_` (`vulnerability_scanner` and `vd-states` give `vulnerability_scanner` and `vd_states`; `agent-state` gives `agent_state`). `<i>` of a node is its position in `<indexer><hosts>`, counting from 0.

| Prefix | Published by | Scope | Count |
|---|---|---|---|
| `indexer_client.bucket.<consumer>.<bucket>.` | Inventory Sync Server (`inventory_sync_server.inventory`, `inventory_sync_server.agent_state`), Vulnerability Scanner (`vulnerability_scanner.vd_states`), engine (`analysisd.events`, `analysisd.raw`) | One bucket | 51 per bucket |
| `indexer_client.runtime.` | Inventory Sync Server (modulesd), engine | The process | 7 |
| `indexer_client.query.` | Inventory Sync Server (modulesd), engine | Every query of the process, any consumer; never reset | 8 |
| `indexer_client.pit.` | Inventory Sync Server (modulesd), engine | Every point in time of the process; never reset | 10 |
| `indexer_client.node.<i>.` | Inventory Sync Server (modulesd), engine | One indexer host | 31 per host |

The engine and modulesd are separate processes, each with its own runtime, so the same runtime name read from each describes a different process. `indexer_client.client.<consumer>.` (`callbacks_skipped`, `callback_overruns`, `callback_max_duration_ms`) exists in the library and is **not** published by any of them.

The bucket metrics read 0 while the module has no live `Client` (it failed to start, or it has stopped), and return to 0 if the `Client` is rebuilt. The engine's keep the last snapshot taken once it has shut its writes down. The runtime, node, query and PIT metrics come from the runtime's snapshot, so they are there, with real values, whether or not a `Client` is alive.

The names, kinds and meaning of every metric are the library's catalog (`src/shared_modules/indexer_client/README.md`, section "Metrics"); they are not copied here. The families:

- **Bucket**: `accepted`, `ok`, `late_results`; closed per-cause sets `rejected.<cause>` (8), `dropped.<cause>` (4), `failed.<cause>` (7), `retries.<cause>` (5); `retained_bytes`, `charge_bytes`, `quota_bytes` (gauges); `bulk_requests`, `bulk_bytes`; and the latency histogram `latency.le_1` ... `latency.le_32768`, `latency.le_inf`, `latency.sum_micros`, `latency.count` (cumulative, milliseconds, of the `_bulk` responses that carried an HTTP answer).
- **Runtime**: `network_threads`, `cpu_threads`, `clients`, `global_charge_bytes`, `global_quota_bytes`, `retained_bytes`, `usage_errors`.
- **Query**: `requests`, `failovers`, `throttles`, `unavailable`, `too_large`, `conflict_retries`, `response_bytes_in_flight`, `peak_response_bytes_in_flight`.
- **PIT**: `open`, `reserved`, `deletes_pending`, `created`, `deletes_confirmed`, `deletes_expired`, `delete_retries`, `expired`, `stale`, `refused_full`.
- **Node**: `state` (0 available, 1 throttled, 2 down), `transitions`, `window`, `bulk_target_bytes`, `pace_ms`, `requests`, `throttled`, `server_5xx`, `failures`, `decreases.429`, `decreases.throttled`, `decreases.latency`, and the same latency histogram.

## What to read for what

| Question | Metrics | Then |
|---|---|---|
| Is the indexer reachable? | `indexer_client.node.<i>.state` (2 = down), `transitions` | [Node health](README.md#node-health); the log lines `Indexer node '<host>' ...` |
| Do `/stats` and `/config` answer `503`? | `...agent_state.rejected.queue_full`, `retained_bytes` against `quota_bytes` | The indexer first; then `inventory_sync_server_indexer_async_max_queue_bytes` ([configuration](../inventory-sync-server/configuration.md)) |
| Do scans slow down on writes? | `...vd_states.rejected.submit_timeout`, `retained_bytes` against `quota_bytes` | The indexer first; then `wazuh_modules.indexer_bulk_size_bytes` |
| Is the runtime as a whole out of memory budget? | `indexer_client.runtime.global_charge_bytes` against `global_quota_bytes` | [`global_quota_bytes`](configuration.md#the-wazuh_modulesindexer_client_-family) |
| Are writes failing for good? | `failed.item_permanent`, `failed.client_4xx`, `failed.retry_exhausted` of the bucket | The bucket's WARN summary line names the cause and the item error type (for example `item_permanent/mapper_parsing_exception`) |
| Is the indexer throttling the manager? | `indexer_client.node.<i>.throttled`, `decreases.429`, `indexer_client.query.throttles` | The indexer's resources; the runtime already backs off by itself |
| Are conflicts being retried? | `indexer_client.query.conflict_retries` (the Inventory Sync Server's `sync.indexer.conflict.retries` is the same value) | Another writer of the same documents; see the module's [metrics](../inventory-sync-server/metrics.md) |
| Are point-in-time contexts leaking? | `indexer_client.pit.open`, `deletes_pending`, `deletes_expired`, `refused_full` | `wazuh_modules.indexer_client_max_open_pits` |

Most of these are diagnostic: the numbers have no setting of their own beyond the [`indexer_client_*` family](configuration.md#the-wazuh_modulesindexer_client_-family) and the consumers' bucket options.

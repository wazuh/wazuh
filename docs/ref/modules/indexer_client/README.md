# Indexer Client

The Indexer Client is the shared library (`libindexer_client`) through which `wazuh-manager-modulesd` reads from and writes to the Wazuh Indexer (OpenSearch). It replaces the previous Indexer Connector library: the [Inventory Sync Server](../inventory-sync-server/README.md), the [Vulnerability Scanner](../vulnerability-scanner/README.md) and the [Content Manager](../content_manager/README.md) feed reads do not link the old library, which no longer exists.

Source: `src/shared_modules/indexer_client/` (developer reference: its `README.md`). Operator pages: [Configuration](configuration.md) and [Metrics](metrics.md).

The library is not a daemon. modulesd starts **one runtime** with its own threads, and every consumer takes a handle (`Client`) on it.

## Who uses it

| Process | Component | Consumer name | Buckets | What goes through it |
|---|---|---|---|---|
| `wazuh-manager-modulesd` | Inventory Sync Server | `inventory_sync_server` | `inventory`, `agent-state` | Agent state writes (`/stateful`), `/stats` and `/config` documents, agent deletion, the by-query operations, and the Vulnerability Scanner's scan lane reads |
| `wazuh-manager-modulesd` | Vulnerability Scanner | `vulnerability_scanner` | `vd-states` | Detections written to `wazuh-states-vulnerabilities`; the reads of its scans; the CVE feed download (the [Content Manager](../content_manager/README.md) reads `.wazuh-threatintel-vulnerabilities` and `.wazuh-cti-consumers` through the scanner's `Client`) |
| `wazuh-manager-analysisd` (engine) | Engine | `analysisd` | — | Its event writes and its reads (content, remote configuration) go through a runtime of its own. The engine side is documented with the engine: see [Engine](#engine) |

The Python framework does not use the library: it reads the same `indexer` section and the same keystore credentials through the `keystore_server` socket (see [Keystore](../keystore/README.md#keystore_server)).

## How it works

1. **Ownership.** modulesd loads `libwm_indexer_runtime.so` at run time and owns the runtime from its main thread. The runtime exists only when a consumer does: the Inventory Sync Server is configured, or the Vulnerability Scanner is enabled. Without one, the options are still validated but no thread or probe is created.
2. **Validation before the fork.** While modulesd reads its configuration (and so in `wazuh-manager-modulesd -t`), the `wazuh_modules.indexer_client_*` internal options and the `<indexer>` section are validated. A bad value stops modulesd: `Invalid indexer client configuration: <reason>`, naming the offending key.
3. **Start.** After the startup gate and before any module thread, modulesd reads the indexer `username` and `password` from the [keystore](../keystore/README.md), loads the TLS files into memory and starts the runtime: `Indexer client runtime started.` A failure here is logged and modulesd **goes on without a runtime**; the modules that need it report their own failure and retry on their heartbeat, but the runtime is not retried until modulesd restarts (see [Troubleshooting](#troubleshooting)).
4. **Threads.** The runtime owns `network_threads` I/O threads and `cpu_threads` pool threads, shared by every consumer (defaults 1 and 2). No bucket or `Client` creates threads.
5. **Buckets.** Each consumer declares its buckets: a queue with its own memory quota, retry policy, overflow policy and `_bulk` size. All the quotas draw from one runtime-wide ceiling, `wazuh_modules.indexer_client_global_quota_bytes` (256 MiB by default).
6. **Every write has a final answer.** A write ends `Ok`, `Failed` (with one cause) or `Dropped`; the consumer turns it into its own answer (for the Inventory Sync Server, the HTTP status the agent gets).

### Buckets

| Bucket | Consumer | When the quota is full | Retries | Memory quota | `_bulk` size |
|---|---|---|---|---|---|
| `inventory` | `inventory_sync_server` | The writer waits up to 2 s, then the write fails | `inventory_sync_server_indexer_sync_max_retry_attempts` (default 5, `0` = unlimited) and `…_sync_max_retry_duration_seconds` (default 15 s) | `max(64 MiB, bulk + 2 KiB + 1 MiB)`, clipped to what the global quota leaves after `agent-state` | `inventory_sync_server_indexer_sync_connector_max_bulk_size` (default 10 MiB) |
| `agent-state` (ordered: operations on one document are never in flight together) | `inventory_sync_server` | Refused at once (`503` to the agent) | Without an attempt or duration limit: an outage is buffered, bounded by the quota | `inventory_sync_server_indexer_async_max_queue_bytes`, at most a quarter of the global quota | `inventory_sync_server_indexer_async_bulk_max_bytes` (default 4 MiB) |
| `vd-states` | `vulnerability_scanner` | The writer waits up to 2 s, then the write fails | `indexer_max_retry_attempts` (default 5) and `indexer_max_retry_duration_seconds` (default 15 s) | 64 MiB, at most a quarter of the global quota (at least 16 KiB) | `indexer_bulk_size_bytes` (default 10 MiB) |

The option names are the internal options `wazuh_modules.<name>`. All three treat a version conflict (`409`) on a write as success and retry an ambiguous `5xx` (see below). The per-option semantics, ranges and the way an option that does not fit is clipped are in the consumers' pages: [Inventory Sync Server configuration](../inventory-sync-server/configuration.md#indexer-client-buckets-indexer_sync_-and-indexer_async_) and [Vulnerability Scanner configuration](../vulnerability-scanner/configuration.md#indexer_bulk_size_bytes).

### What the library does with a status

| Answer to a `_bulk` | What happens |
|---|---|
| No answer (timeout, connection refused, TLS failure) | The batch goes to another node when there is one, otherwise it is retried with backoff |
| `429` | The node is marked throttled and a `Retry-After` parks it (capped by `retry_after_max_ms`); the batch does not spend an attempt |
| `503`, `408`, `401`, `403` | Retried with backoff within the bucket's budget (a `401`/`403` also marks the node down on the next probe) |
| `500`, `502`, `504` | Retried, because the three buckets above keep `onAmbiguous5xx = Retry`: the batch may have been applied, and every operation they send carries its `_id`, so a resend overwrites |
| `413` | The batch is split in halves and resent; one operation that is still too large fails |
| Any other `4xx` or a `3xx` | The whole batch fails, not retried |
| `2xx` | Every item is read on its own: `created`/`updated`/`noop`/`deleted` are success; a delete of a missing document is success; `409` follows the bucket's conflict policy; `429`, `5xx` and `cluster_block_exception` items are retried; any other item error (a mapping rejection, a missing index) fails that operation only and is never retried |

The retry delay is exponential from 1 s to 15 s with jitter. The library README has the full classification (`Response classification and retry lane`, `Ambiguous 5xx`).

### Node health

Each configured host is in one of three states: `Available`, `Throttled` (it answered `429`) or `Down`. Every host starts `Down` until the first probe round.

- Every `probe_interval_ms` (10 s) the runtime sends `GET /_cluster/health?local=true` to each host, with a `probe_timeout_ms` (5 s) timeout. `green` or `yellow` is available. `red` marks **every** node down (`Indexer cluster health is red: every node is marked down.`). `429` is throttled, `401` and `403` are down (`HTTP <status>: check indexer credentials / permissions`), any other answer or failure is down.
- The data path also reports: a failed request degrades its node at once, and only a probe brings a node back to `Available`.
- Requests go round-robin to the available nodes; a throttled node is used only when none is available, and a parked node (a `Retry-After`) is skipped.
- Gates: the Inventory Sync Server answers `503` when **no** host is usable (not down); the Vulnerability Scanner admits work only while some host is **available** (the stricter rule).

Because the probe starts when the runtime does, **the indexer is free to start after the manager**: an unreachable host does not stop modulesd or the modules.

### Start and stop

Shutdown shares one deadline with the rest of modulesd. On `wazuh-manager-control stop` or `restart`, modulesd fixes the runtime's deadline at 25 s after the stop began, then asks every module to stop; each consumer closes admission (new writes are refused), lets what is queued drain, and gives up what is left at the deadline minus twice `callback_budget_ms`. After the module threads end (28 s in total), modulesd joins the runtime threads.

What is queued but not yet sent when the deadline passes is dropped and counted (`dropped.shutdown`, `dropped.client_closed`): the queues are in memory only. The Inventory Sync Server's `/stateful` batches are answered `503` without flushing and the agents re-send on their next cycle; see its [shutdown description](../inventory-sync-server/architecture.md#shutdown).

## Credentials and certificates

The credentials are the `indexer` family of the [keystore](../keystore/README.md) (`username`, `password`), read **once**, when the runtime starts. The TLS files are read once as well. Rotating either takes a modulesd restart. The full contract, the files and their modes are in [Configuration](configuration.md#indexer-credentials) and [Certificates](configuration.md#certificates).

The client pair is still named `indexer-connector.pem` and `indexer-connector-key.pem`. The name is historical: it is the contract of the credential resolver, of the installer's configuration template and of [Credentials](../../getting-started/credentials.md), and it does not change with the library.

## Logs

Every line of the library carries the tag `wazuh-manager-modulesd:indexer-client` in `/var/wazuh-manager/logs/wazuh-manager.log`; the log level of modulesd applies. The runtime logs only on a change (an edge) and summarizes the rest:

| Level | Line | Meaning |
|---|---|---|
| INFO | `Indexer client runtime started.` | The runtime is up |
| INFO | `Indexer node '<host>' is available.` | A node became available (also the first line per node) |
| INFO | `Indexer node '<host>' is throttled (HTTP 429).` | A node answered `429` |
| WARN | `Indexer node '<host>' is no longer available. Reason: <reason>` | A node went down; logged again only if its reason changes |
| ERROR | `Indexer cluster health is red: every node is marked down.` | A probe round reported `red` |
| WARN | `Every indexer node rejects the TLS handshake with the configured CA (curl <code>): if the indexer CA was rotated, update <indexer><ssl> and restart the manager.` | Every node is down with a TLS error |
| WARN | `Indexer client bucket '<consumer>/<bucket>' reached 80% of its quota (<charge> of <quota> bytes charged).` | A bucket is filling; once per crossing |
| WARN | `Indexer client bucket '<consumer>/<bucket>' has no room for new operations (...): its overflow policy '<policy>' applies.` | The first admission the bucket's quota refused |
| WARN | `Indexer client global quota is full (<charge> of <cap> bytes charged): every bucket applies its overflow policy.` | The runtime-wide ceiling is reached |
| INFO | `Indexer client bucket '<consumer>/<bucket>' in the last <n> s: <a> accepted, <o> ok, <f> failed, <d> dropped.` | Every `log_summary_interval_ms` (60 s), for each bucket with activity |
| WARN | `Indexer client bucket '<consumer>/<bucket>' unsuccessful operations in the last <n> s: <cause>[/<item error type>]=<count>, ...` | The bucket had failed or dropped operations; at most one line per bucket and interval |
| WARN | `Indexer client bucket '<consumer>/<bucket>' got an ambiguous HTTP <status> ...` | Only for a bucket with `onAmbiguous5xx = fail` (none of the three above) |

The library README lists the full set of lines. It never logs a document body, an id, a URL or a password.

## Troubleshooting

| Symptom | Cause | What to do |
|---|---|---|
| modulesd does not start, or `wazuh-manager-modulesd -t` fails with `Invalid indexer client configuration: <reason>` | A key under `wazuh_modules.indexer_client_` is unknown, empty, not an unsigned decimal or out of range, or `<indexer>` is invalid | Fix the key the reason names in `/etc/wazuh-manager/wazuh-manager-internal-options.conf` or the `<indexer>` section ([Configuration](configuration.md)) |
| `The indexer client runtime did not start: invalid_config: indexer host '<url>' uses https but no ssl.certificate_authorities is configured` | An `https` host without a CA | Add `<certificate_authorities>` to `<indexer><ssl>` and restart the manager |
| `... invalid_config: ssl.certificate_authorities '<path>': cannot read: ...` (or `malformed PEM content`, `holds no PEM certificate`) | A CA file is missing, unreadable or not PEM | Fix the file or the path; relative paths resolve against `/var/wazuh-manager` |
| `... invalid_config: ssl.certificate '<path>': configured without ssl.key (both or neither)` and the key variants | Only one of the client certificate and key is set, the key is encrypted or does not match the first certificate | Set both, with an unencrypted PEM key that matches the certificate |
| `... cannot read the indexer credentials from the keystore: ...` or `invalid_config: indexer credentials missing: user` / `password` | The keystore has no `indexer` `username` or `password` | Run the [credential resolver](../../getting-started/credentials.md) or write them with `wazuh-manager-keystore` |
| `Unable to load libwm_indexer_runtime.so (...); the installation is broken.` | The library is missing or has an unresolved symbol | Reinstall the manager |
| The Inventory Sync Server logs `no indexer_client runtime in this process`, and the scanner does not start | The runtime did not start (any row above); its error is earlier in the log | Fix the cause and **restart the manager**: the runtime is not retried |
| `Indexer node '<host>' is no longer available. Reason: HTTP 401: check indexer credentials / permissions` | The indexer refused the manager's account | Compare `wazuh-manager-keystore -f indexer -k username` and the password with the indexer's user; restart after changing them |
| `... Reason: connect (curl 7)`-style reasons, then `/stats` and `/config` answer `503` | The host is unreachable | Check the host, port and firewall; the node returns by itself when a probe succeeds |
| A bucket logs `has no room for new operations`, or `rejected.queue_full` grows in [Metrics](metrics.md) | The indexer is slower than the writers, or down for longer than the quota buffers | Check the indexer first; raise the bucket's quota or `global_quota_bytes` only if it is up |

To check by hand what the library checks, use the commands of [Verifying connectivity](configuration.md#verifying-connectivity).

## Engine

The engine (`wazuh-manager-analysisd`) runs a runtime of its own, in its own process (options `analysisd.indexer_client_*`, log tag `wazuh-manager-analysisd:indexer-client`), for its event writes and for the reads of its content and remote configuration (see [Engine configuration](../engine/configuration.md)). This page covers modulesd and the library. The `<indexer>` section and the credentials described here are shared with it.

## See also

- [Configuration](configuration.md) - the `<indexer>` section, credentials, certificates and the `indexer_client_*` options
- [Metrics](metrics.md) - the `indexer_client.*` metrics and where they are published
- [Inventory Sync Server](../inventory-sync-server/README.md) and [Vulnerability Scanner](../vulnerability-scanner/README.md) - the consumers
- `src/shared_modules/indexer_client/README.md` - developer reference

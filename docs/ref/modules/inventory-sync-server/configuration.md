# Inventory Sync Server Configuration

The Inventory Sync Server module has no XML configuration block of its own. It is registered
unconditionally and reads the `<indexer>` block for its connection to the indexer; everything else is
tuned through internal options.

## Configuration Sources

| Source | What it provides |
|---|---|
| `<indexer>` in the manager configuration | Indexer hosts and TLS material |
| `<cluster>` in the manager configuration | The cluster name stamped onto every document |
| Internal options | Every transport and indexer-bucket tunable listed below, plus the `indexer_client_*` family of the shared runtime |

Three values are deliberately NOT configurable:

- **The socket path** is fixed at `queue/sockets/inventory-sync-http.sock`, relative to the installation
  directory. Internal options can only carry integers, so there is no mechanism to set a path; remoted
  and modulesd both run with the installation directory as their working directory and resolve the same
  relative path.
- **The socket mode** is fixed at `0660`. It was an internal option and that was a trap: the value is a
  raw permission mode, but internal options are parsed as DECIMAL, so writing the documented `0660`
  produced decimal 660 -- out of range, killing the daemon -- while a value that did fit, say `440`, was
  applied as decimal 440, i.e. `0670`, silently granting the group write access on a socket the operator
  was trying to restrict.
- **The maximum header count** is fixed at 32, because it is a term of the memory ceiling the in-flight
  byte budget charges for. See `max_inflight_bytes` below.

---

## Internal Options

**Configuration file:** `/etc/wazuh-manager/wazuh-manager-internal-options.conf`

**Internal Options prefix:** `wazuh_modules.inventory_sync_server_*`

Internal options provide advanced tuning for the transport, admission control and the indexer
connectors.

An option present in `wazuh-manager-internal-options.conf` but out of its allowed range -- or
non-numeric -- prevents `wazuh-manager-modulesd` from starting, and is reported by
`wazuh-manager-modulesd -t`. Values are parsed as decimal; a leading zero does not mean octal.

The shipped `wazuh-manager-internal-options.conf` carries only a comment header: every default below
is compiled into the module. Add a line only to override one. The file is never overwritten during
upgrades.

### Transport

### wazuh_modules.inventory_sync_server_io_threads

0 sizes the reactor from the host or cgroup.

```ini
wazuh_modules.inventory_sync_server_io_threads=0
```

- **Default value:** `0` (the host's CPU count)
- **Allowed values:** 0 to 128
- **Note:** 0 sizes the reactor from the host or cgroup. Each connection runs on its own strand, so these do parallelise.

### wazuh_modules.inventory_sync_server_concurrent_accepts

Accept operations kept in flight.

```ini
wazuh_modules.inventory_sync_server_concurrent_accepts=2
```

- **Default value:** `2`
- **Allowed values:** 0 to 64
- **Note:** Accept operations kept in flight. A failed accept is logged and re-armed, so this is a throughput knob, not a reliability one.

### wazuh_modules.inventory_sync_server_buffer_size

Per-connection read buffer, in bytes.

```ini
wazuh_modules.inventory_sync_server_buffer_size=8192
```

- **Default value:** `8192` (8 KiB)
- **Allowed values:** 0 to 1048576
- **Note:** Per-connection read buffer, in bytes. Counted in the per-request memory charge.

### wazuh_modules.inventory_sync_server_max_body_size

Request body cap in bytes; over it the request is answered `413`.

```ini
wazuh_modules.inventory_sync_server_max_body_size=0
```

- **Default value:** `0` (no cap of its own)
- **Allowed values:** 0 to 536870912
- **Note:** With no explicit cap the effective limit is still finite: a request must fit the in-flight
  byte budget, so the derived cap is `max_inflight_bytes` minus the per-request overhead
  (≈268 MB with the default 256 MiB budget), and a body over it is answered `413`. Set a value only to
  cap bodies BELOW what the budget already allows. Remoted caps its own inbound side, so an oversized
  session normally never reaches this socket.

### wazuh_modules.inventory_sync_server_max_url_size

Max request-target size in bytes; over it `414`.

```ini
wazuh_modules.inventory_sync_server_max_url_size=2048
```

- **Default value:** `2048`
- **Allowed values:** 0 to 65536
- **Note:** Max request-target size in bytes; over it `414`.

### wazuh_modules.inventory_sync_server_max_header_name_size

Max header name size in bytes; over it `431`.

```ini
wazuh_modules.inventory_sync_server_max_header_name_size=256
```

- **Default value:** `256`
- **Allowed values:** 0 to 65536
- **Note:** Max header name size in bytes; over it `431`. Counted in the per-request memory charge.

### wazuh_modules.inventory_sync_server_max_header_value_size

Max header value size in bytes; over it `431`.

```ini
wazuh_modules.inventory_sync_server_max_header_value_size=8192
```

- **Default value:** `8192` (8 KiB)
- **Allowed values:** 0 to 1048576
- **Note:** Max header value size in bytes; over it `431`. Counted in the per-request memory charge.

### wazuh_modules.inventory_sync_server_header_timeout

Seconds from accept to a complete request head.

```ini
wazuh_modules.inventory_sync_server_header_timeout=10
```

- **Default value:** `10`
- **Allowed values:** 0 to 3600
- **Note:** Seconds from accept to a complete request head. Bounds a slowloris.

### wazuh_modules.inventory_sync_server_body_timeout

Seconds from the head to a complete body.

```ini
wazuh_modules.inventory_sync_server_body_timeout=30
```

- **Default value:** `30`
- **Allowed values:** 0 to 3600
- **Note:** Seconds from the head to a complete body.

### wazuh_modules.inventory_sync_server_response_timeout

Seconds from handler dispatch to a delivered response.

```ini
wazuh_modules.inventory_sync_server_response_timeout=300
```

- **Default value:** `300`
- **Allowed values:** 0 to 3600
- **Note:** Seconds from handler dispatch to a delivered response. This is a LEAK BACKSTOP for a handler that lost its responder, not a quality-of-service deadline: remoted sets its own, shorter deadline and gives up first.

### wazuh_modules.inventory_sync_server_write_timeout

Seconds allowed to write one response.

```ini
wazuh_modules.inventory_sync_server_write_timeout=10
```

- **Default value:** `10`
- **Allowed values:** 0 to 3600
- **Note:** Seconds allowed to write one response.

### wazuh_modules.inventory_sync_server_drain_timeout

Seconds `stop()` waits for already-dispatched requests to answer before their connections are force-closed.

```ini
wazuh_modules.inventory_sync_server_drain_timeout=2
```

- **Default value:** `2`
- **Allowed values:** 0 to 10
- **Note:** Seconds `stop()` waits for already-dispatched requests to answer before their connections are force-closed. Capped at 10 because modulesd gives the WHOLE daemon 30 s to shut down, and this module's drain is only one part of that.

### wazuh_modules.inventory_sync_server_max_parallel_connections

Max simultaneous connections; over it `503` and close.

```ini
wazuh_modules.inventory_sync_server_max_parallel_connections=1024
```

- **Default value:** `1024`
- **Allowed values:** 0 to 65536
- **Note:** Max simultaneous connections; over it `503` and close. Every connection and every deferred reply costs a file descriptor out of a limit shared with all of modulesd, so setting this above modulesd's effective descriptor limit (`wazuh_modules.rlimit_nofile`, capped by the hard limit the process starts with) logs a warning and guarantees failures before the cap is reached. Live occupancy is visible as `server.sessions.live` in [`GET /metrics`](metrics.md#transport--server) (the cap itself has no shed counter: a hit shows in the logs and as `live` pinned at the cap).

### wazuh_modules.inventory_sync_server_max_inflight_bytes

Total in-flight request payload bytes; over it `503`.

```ini
wazuh_modules.inventory_sync_server_max_inflight_bytes=268435456
```

- **Default value:** `268435456` (256 MiB)
- **Allowed values:** `0` (unlimited) or 1 to 2147483647
- **Note:** Total in-flight request payload bytes; over it `503`. Reserved from the declared `Content-Length` at headers-complete, BEFORE the body is read, so it bounds the read-phase peak too. Raised automatically to at least one maximum-size request, so a too-small value cannot reject everything. Live occupancy is visible as `server.budget.*` in [`GET /metrics`](metrics.md#transport--server), and the cumulative shed count as `server.rejected.budget`.

### wazuh_modules.inventory_sync_server_reserved_control_connections

Accept headroom the data plane can never consume.

```ini
wazuh_modules.inventory_sync_server_reserved_control_connections=64
```

- **Default value:** `64`
- **Allowed values:** 0 to 256 (`0`/absent: the default; clamped to at most a quarter of `max_parallel_connections`)
- **Note:** The route-class model's decisive knob: the data class's session cap resolves to `max_parallel_connections` minus this reserve, so a saturated `POST /stateful` plane alone can never fill the accept queue — control-class requests (agent deletions and on-demand scans) and liveness probes always find a slot. Per-class occupancy is visible as `server.sessions.{data,control,liveness}` in [`GET /metrics`](metrics.md#transport--server).

### wazuh_modules.inventory_sync_server_control_max_body_bytes

Declared-length cap of control-class requests; over it `413`.

```ini
wazuh_modules.inventory_sync_server_control_max_body_bytes=65536
```

- **Default value:** `65536` (64 KiB)
- **Allowed values:** 0 to 1048576 (`0`/absent: the default)
- **Note:** Control-class requests (`POST /_internal/agents/delete` and `POST /_internal/vd/scan`) carry only a small JSON body naming the agent (`{"agent_id":"7"}`), so anything above this cap is a client error answered `413` from the declared length, before a single body byte is read. Control-class requests are exempt from the in-flight byte budget; this cap is what bounds them instead.

### wazuh_modules.inventory_sync_server_control_max_sessions

Concurrent control-class sessions; over it `503`.

```ini
wazuh_modules.inventory_sync_server_control_max_sessions=256
```

- **Default value:** `256`
- **Allowed values:** 0 to 1024 (`0`/absent: the default)
- **Note:** Bounds the control class's own concurrency (its exemption from the byte budget must not become unbounded admission). Sized an order of magnitude above the realistic concurrency of the manager-local clients; a persistent hit means a client is leaking connections — watch `server.sessions.control` in [`GET /metrics`](metrics.md#transport--server).

---

### Sync pipeline and VD lane

These tune the `POST /stateful` ingestion path behind the transport: the sharded ingestion workers,
the pipeline's own admission queue, and the vulnerability-detection scan lane.

### wazuh_modules.inventory_sync_server_sync_workers

Sharded ingestion workers applying accepted sessions.

```ini
wazuh_modules.inventory_sync_server_sync_workers=0
```

- **Default value:** `0` (half the host's cores, minimum 1)
- **Allowed values:** 0 to 64
- **Note:** Sessions land on `hash(agentId) % workers`, so one agent's sessions are always applied in
  order by the same worker. More workers spread distinct agents, not one agent's backlog. Sizing
  evidence in [`GET /metrics`](metrics.md#sync-pipeline--syncpipeline-syncshardi-syncsessionduration):
  the per-shard `sync.shard.<i>.depth`/`.bytes` gauges show skew, and the
  `sync.session.duration.*` histograms show queue wait.

### wazuh_modules.inventory_sync_server_sync_queue_bytes

Admission cap, in bytes, for sessions accepted by the transport but not yet applied by a worker.

```ini
wazuh_modules.inventory_sync_server_sync_queue_bytes=67108864
```

- **Default value:** `67108864` (64 MiB)
- **Allowed values:** 1048576 to 1073741824
- **Note:** A single GLOBAL byte counter across all shards, checked at enqueue: a session that would
  push the total over the cap is shed with a bare `503` (expected backpressure — the agent retries).
  This is a second, smaller gate behind `max_inflight_bytes`: the transport budget bounds bytes being
  READ, this bounds bytes WAITING for a worker. Sheds count as `sync.pipeline.shed.total` in
  [`GET /metrics`](metrics.md#sync-pipeline--syncpipeline-syncshardi-syncsessionduration).

### wazuh_modules.inventory_sync_server_vd_feed_retry_after_seconds

`Retry-After` value, in seconds, answered with `503` while the vulnerability feed is not ready (or the
scanner is enabled here but still starting up).

```ini
wazuh_modules.inventory_sync_server_vd_feed_retry_after_seconds=10
```

- **Default value:** `10`
- **Allowed values:** 10 to 1800
- **Note:** Only VD sessions (and on-demand scans that reach a lane worker while the feed is not ready)
  get this header; the agent re-sends the same session after the delay.
  The minimum is 10 because a smaller value tells the whole fleet to hammer the endpoint. This
  setting fixes the header **value** only — how often it fires is driven by the CVE-feed download
  state and is visible as `vd.retry_after.total` in
  [`GET /metrics`](metrics.md#vulnerability-detection-lane--vd).

### wazuh_modules.inventory_sync_server_vd_workers

Workers on the vulnerability-detection scan lane.

```ini
wazuh_modules.inventory_sync_server_vd_workers=0
```

- **Default value:** `0` (half the host's cores, minimum 1)
- **Allowed values:** 0 to 64
- **Note:** More workers let scans for different agents run at the same time instead of queueing
  behind each other. Lane occupancy and end-to-end time are `vd.lane.depth` and `vd.lane.time` in
  [`GET /metrics`](metrics.md#vulnerability-detection-lane--vd).

### wazuh_modules.inventory_sync_server_vd_scan_queue_slots

Sessions and on-demand scan requests allowed to wait for a VD worker.

```ini
wazuh_modules.inventory_sync_server_vd_scan_queue_slots=0
```

- **Default value:** `0` (twice `vd_workers`)
- **Allowed values:** 0 to 256
- **Note:** A VD session (or an on-demand scan) arriving with the queue full is answered `503` ("scan capacity exhausted") —
  scans run synchronously inside the request, so queueing more than the lane can drain only trades a
  fast `503` for a slow timeout. Refusals count as `vd.capacity.503.total` in
  [`GET /metrics`](metrics.md#vulnerability-detection-lane--vd).

---

### wazuh_modules.inventory_sync_server_max_sessions_per_agent

Sessions one agent may have admitted and not yet answered, across the sync pipeline and the
vulnerability-detection scan lane.

```ini
wazuh_modules.inventory_sync_server_max_sessions_per_agent=2
```

- **Default value:** `2`
- **Allowed values:** 1 to 1024
- **Note:** A session past it is answered `503` before anything is queued, and counted as
  `sync.agent_busy.total` in [`GET /metrics`](metrics.md#sync-pipeline--syncpipeline-syncshardi-syncsessionduration). A session stays counted
  until it is answered, which can be after remoted has stopped waiting for it: remoted gives up at
  `remoted.downstream_stateful_response_timeout` (20 s by default) and the agent re-sends, while this
  module keeps applying the first copy. The default of 2 is the session being applied plus one such
  re-send. Further copies are refused rather than queued behind work that is already in progress,
  so one agent cannot fill `sync_queue_bytes` or the scan lane for the rest of the fleet.
- **Note:** A rising count usually means a slow indexer or vulnerability scanner, not a broken
  agent: the agents re-send faster than their sessions are applied. Raising the value only queues
  more duplicates.

---

### wazuh_modules.inventory_sync_server_session_query_batch_size

Indexer search page size of the checksum verification (`ModuleCheck` sessions), which pages the agent's
documents with `search_after`.

```ini
wazuh_modules.inventory_sync_server_session_query_batch_size=0
```

- **Default value:** `0` (1000 documents)
- **Allowed values:** `0` (module default), or `100` to `10000` (the indexer rejects pages above `index.max_result_window`, default `10000`); `1`–`99` is rejected at startup
- **Note:** Larger pages mean fewer round-trips to the indexer but a bigger response held in memory
  per query.

---

### Indexer client buckets (`indexer_sync_*` and `indexer_async_*`)

The module reaches the indexer through **one** `indexer_client` `Client` (the library's runtime,
configured by the [`indexer_client_*` family](#the-wazuh_modulesindexer_client_-family) below) with
two buckets. The two option prefixes of the module configure one bucket each and are **not
interchangeable**:

- `indexer_sync_*` feeds the `inventory` bucket: everything the ingestion pipeline, the VD scan lane
  and the by-query operations send. Every worker shares it.
- `indexer_async_*` feeds the `agent-state` bucket: `POST /stats`, `POST /config` and the by-id
  deletes of an agent deletion. It is an *ordered* bucket (a delete is not sent before the earlier
  operations of the same agent resolve), a full quota is refused with a `503` instead of waiting, and
  retries have **no** limit of attempts or duration (an indexer outage is buffered, bounded by the
  quota): the behavior of the previous asynchronous queue.
- Since 5.x there is no separate asynchronous connector or session. The option names are kept so that
  existing configurations do not abort the daemon; the ones that no longer have an effect are marked
  **Ignored** below.

Keep the `indexer_sync_` / `indexer_async_` prefixes intact. The per-request timeout of both buckets is
not an option of either family: it is `wazuh_modules.indexer_client_request_timeout_ms`.

**How the two buckets share the memory quota.** The runtime has one byte quota,
`wazuh_modules.indexer_client_global_quota_bytes` (256 MiB by default), that every bucket of every
consumer draws from. `agent-state` is sized first and `inventory` gets what is left:

- `agent-state` quota = `max_queue_bytes` (`0` means a quarter of the global quota), raised to at least
  `bulk_max_bytes + 6 KiB` and 16 KiB (so the two deletes of an agent deletion fit together), and
  **capped at a quarter of the global quota** (at least 16 KiB, never above half of it).
- `inventory` quota = `max(64 MiB, connector_max_bulk_size + 2 KiB + 1 MiB)`, clamped to the global
  quota minus the `agent-state` quota. A full `agent-state` can therefore never leave `/stateful`
  without quota.
- A value that does not fit is clipped and the module logs a `WARNING` at startup naming the value it
  used instead. With the default global quota (256 MiB) and the default `max_queue_bytes` (64 MiB) the
  two coincide and nothing is clipped.

#### `inventory` bucket (`indexer_sync_*`)

#### wazuh_modules.inventory_sync_server_indexer_sync_max_bulk_size

The ingestion pipeline's group-commit threshold, measured in **request payload bytes** (wire
FlatBuffer size): a worker flushes its open batch once the staged sessions reach this many bytes.

```ini
wazuh_modules.inventory_sync_server_indexer_sync_max_bulk_size=10485760
```

- **Default value:** `10485760` (10 MiB)
- **Allowed values:** 4096 to 104857600
- **Note:** Unchanged in meaning. It does not reach the indexer client: the size of the actual
  `_bulk` requests is capped separately by
  `inventory_sync_server_indexer_sync_connector_max_bulk_size` below. The group-commit behavior this
  option drives is visible as `sync.bulk.*` in
  [`GET /metrics`](metrics.md#group-commit--syncbulk); the real request traffic is
  `sync.indexer.bulk.*`.

#### wazuh_modules.inventory_sync_server_indexer_sync_connector_max_bulk_size

`bulk.maxBytes` of the `inventory` bucket: the serialized NDJSON bytes of one `_bulk` request.

```ini
wazuh_modules.inventory_sync_server_indexer_sync_connector_max_bulk_size=10485760
```

- **Default value:** `10485760` (10 MiB)
- **Allowed values:** 4096 to 104857600
- **Note:** Measured in a different unit from the group-commit threshold above (serialized NDJSON,
  which the manager's metadata overlay inflates past the wire FlatBuffer size). Keep it at or below
  the indexer's `http.max_content_length`. The bucket's memory quota is derived from it:
  `max(64 MiB, bulk + 2 KiB + 1 MiB)`, clamped to
  `wazuh_modules.indexer_client_global_quota_bytes` **minus the quota of the `agent-state` bucket**
  (see the sharing rule above). If what is left cannot hold one bulk, the bulk size is clipped to fit
  and a `WARNING` is logged at startup. One group commit can still
  produce several `_bulk` requests: compare `sync.indexer.bulk.requests` with `sync.bulk.flushes`
  in [`GET /metrics`](metrics.md#group-commit--syncbulk).

#### wazuh_modules.inventory_sync_server_indexer_sync_max_retry_attempts

Retry policy of the `inventory` bucket and of the module's queries: maximum attempts.

```ini
wazuh_modules.inventory_sync_server_indexer_sync_max_retry_attempts=5
```

- **Default value:** `5`
- **Allowed values:** 0 to 1000
- **Note:** `0` means no attempts bound (retries are then limited only by
  `max_retry_duration_seconds`); `1` is a single attempt with no retry. The by-query version-conflict
  allowance is separate and is bounded by the retry duration.

#### wazuh_modules.inventory_sync_server_indexer_sync_max_retry_duration_seconds

Retry policy of the bucket and of its queries: wall-clock retry duration, `d` below.

```ini
wazuh_modules.inventory_sync_server_indexer_sync_max_retry_duration_seconds=15
```

- **Default value:** `15`
- **Allowed values:** 0 to 3600
- **Note:** every call stays bounded by its budget, so `0` here behaves like the default: retries of
  writes and immediate queries last `min(d, budget - 3 s)` (at most 15 s), those of the deletion
  by-query `min(d, deletion budget - 3 s)`, and `0` uses 15 s for both. Besides the retries, `d`
  fixes the module's time budgets:
  - `/stateful` batches and each query of an immediate session: `clamp(d + 3 s, 5 s, 18 s)`
    (18 s when `d` is `0`). The cap keeps the answer under remoted's 20 s response window, so a
    larger `d` does not make the agent wait longer.
  - Whole-agent deletion by-query: `min(3 * d + 25 s, 540 s)` (70 s by default and when `d` is
    `0`).
  - The `Retry-After` of the `503` answered when a by-query's version-conflict allowance runs out is
    `d` (15 when the deadline is disabled), as before.

  When a budget expires, the sessions of the batch that were not yet resolved are answered `503`;
  those already resolved keep their code. Time spent queued does not count.

#### wazuh_modules.inventory_sync_server_indexer_sync_max_retry_delay_seconds

Retry policy of the bucket and of its queries: ceiling of the backoff delay.

```ini
wazuh_modules.inventory_sync_server_indexer_sync_max_retry_delay_seconds=15
```

- **Default value:** `15`
- **Allowed values:** 1 to 3600

#### wazuh_modules.inventory_sync_server_indexer_sync_flush_interval_seconds

**Ignored.** The workers own every flush; the value has no effect.

```ini
wazuh_modules.inventory_sync_server_indexer_sync_flush_interval_seconds=20
```

- **Default value:** `20` (ignored)
- **Allowed values:** 1 to 3600
- **Note:** Kept so existing configurations do not abort the daemon. A value other than the default
  logs a `WARNING` once at startup.

#### wazuh_modules.inventory_sync_server_indexer_sync_request_timeout_seconds

**Ignored.** The per-request timeout is `wazuh_modules.indexer_client_request_timeout_ms`.

```ini
wazuh_modules.inventory_sync_server_indexer_sync_request_timeout_seconds=60
```

- **Default value:** `60` (ignored)
- **Allowed values:** 1 to 3600
- **Note:** A value other than the default logs a `WARNING` once at startup.

#### `agent-state` bucket (`indexer_async_*`)

Since 5.x only three of these options act; the rest are **ignored** and, when set to anything but their
default, make the module log one `WARNING` at startup.

#### wazuh_modules.inventory_sync_server_indexer_async_bulk_max_bytes

`bulk.maxBytes` of the `agent-state` bucket: the serialized NDJSON bytes of one `_bulk` request.

```ini
wazuh_modules.inventory_sync_server_indexer_async_bulk_max_bytes=4194304
```

- **Default value:** `4194304` (4 MiB)
- **Allowed values:** 4096 to 104857600
- **Note:** Clipped to `quota - 6 KiB` (or half the quota when the quota is smaller than 6 KiB) when it
  does not fit the bucket's quota, with a `WARNING`. A `/stats` or `/config` document is a few KiB, so
  this rarely matters; the by-id deletes of an agent deletion travel in the same bucket.

#### wazuh_modules.inventory_sync_server_indexer_async_max_queue_bytes

The memory quota of the `agent-state` bucket: how many bytes of `/stats`, `/config` and by-id delete
operations can be waiting (queued or in flight) before the bucket refuses more.

```ini
wazuh_modules.inventory_sync_server_indexer_async_max_queue_bytes=67108864
```

- **Default value:** `67108864` (64 MiB)
- **Allowed values:** `0` or 1 to 2147483647
- **Note:** `0` no longer means "unlimited": it means a quarter of
  `wazuh_modules.indexer_client_global_quota_bytes`. Whatever the value, the quota is raised to at
  least `bulk_max_bytes + 6 KiB` and 16 KiB, and **capped at a quarter of the global quota** (a
  `WARNING` says so when the request is cut), because the `inventory` bucket uses everything else
  (see the sharing rule above). When the quota is full the module answers `/stats` and `/config` with
  `503` (the agent re-sends its next report) and an agent deletion with `503` (the dispatcher retries).
  This is the only bound of the bucket's memory: its retries have no limit.

#### wazuh_modules.inventory_sync_server_indexer_async_max_retry_delay_seconds

Ceiling of the backoff delay of the `agent-state` bucket.

```ini
wazuh_modules.inventory_sync_server_indexer_async_max_retry_delay_seconds=15
```

- **Default value:** `15`
- **Allowed values:** 1 to 3600
- **Note:** The bucket retries a failed `_bulk` (or an ambiguous `5xx`) **without a limit of attempts or
  duration**, as the previous asynchronous queue did; this value is only the longest wait between two
  attempts. Operations the retry cannot clear are bounded by the quota and, for a deletion, by its
  [budget](architecture.md#agent-deletion).

#### wazuh_modules.inventory_sync_server_indexer_async_flush_interval_seconds

**Ignored.** The bucket sends when its `_bulk` fills or after its fixed maximum age of 5 s; there is no
setting for it.

```ini
wazuh_modules.inventory_sync_server_indexer_async_flush_interval_seconds=20
```

- **Default value:** `20` (ignored)
- **Allowed values:** 1 to 3600
- **Note:** Kept so existing configurations do not abort the daemon. A value other than the default
  logs a `WARNING` once at startup.

#### wazuh_modules.inventory_sync_server_indexer_async_request_timeout_seconds

**Ignored.** The per-request timeout is `wazuh_modules.indexer_client_request_timeout_ms`.

```ini
wazuh_modules.inventory_sync_server_indexer_async_request_timeout_seconds=60
```

- **Default value:** `60` (ignored)
- **Allowed values:** 1 to 3600
- **Note:** A value other than the default logs a `WARNING` once at startup.

#### wazuh_modules.inventory_sync_server_indexer_async_logger_queue_size

**Ignored.** The indexer client has no logging queue to size.

```ini
wazuh_modules.inventory_sync_server_indexer_async_logger_queue_size=8
```

- **Default value:** `8` (ignored)
- **Allowed values:** 1 to 65536
- **Note:** A value other than the default logs a `WARNING` once at startup.

#### wazuh_modules.inventory_sync_server_indexer_async_logger_threads

**Ignored.** The indexer client has no logging threads; its threads are
`wazuh_modules.indexer_client_network_threads` and `wazuh_modules.indexer_client_cpu_threads`, shared
by every consumer of modulesd.

```ini
wazuh_modules.inventory_sync_server_indexer_async_logger_threads=1
```

- **Default value:** `1` (ignored)
- **Allowed values:** 1 to 64
- **Note:** A value other than the default logs a `WARNING` once at startup.

#### Shared session

#### wazuh_modules.inventory_sync_server_indexer_monitoring_interval_seconds

**Ignored.** There is no shared session or health monitor of the module any more: the runtime probes
every indexer host itself, every `wazuh_modules.indexer_client_probe_interval_ms`.

```ini
wazuh_modules.inventory_sync_server_indexer_monitoring_interval_seconds=10
```

- **Default value:** `10` (ignored)
- **Allowed values:** 1 to 3600
- **Note:** A value other than the default logs a `WARNING` once at startup. The module's availability
  gate (`/stateful`, `/stats`, `/config`, the deletion) is the runtime's node health: the answer is
  `503` when no host is usable.

### The `wazuh_modules.indexer_client_*` family

**Internal Options prefix:** `wazuh_modules.indexer_client_*`

The `indexer_client` runtime is owned by `wazuh-manager-modulesd` and shared by every module that
reaches the indexer through it (today this one). Its tunables are not options of this module: they are
this family, read from the same file as the rest of this page,
`/etc/wazuh-manager/wazuh-manager-internal-options.conf`, together with the `<indexer>` block of the
manager configuration (hosts and TLS), which is the only place the connection itself is configured.

- Every value is an unsigned decimal integer; a leading zero does not mean octal. The shipped file
  carries none of them: the defaults are compiled in, and a line is only needed to override one.
- **The family is validated in full** by `wazuh-manager-modulesd -t` and again at startup, before any
  module thread exists, and a failure is logged with the offending key: a value outside its range, a
  value that is not an unsigned decimal integer, an empty value, **or a key under the prefix that is not
  listed here (a typo is an error, not an ignored line)**. In every case modulesd refuses to start. A
  key that is not under the `wazuh_modules.indexer_client_` prefix is not read.
- The runtime starts only when a consumer exists (inventory sync); with none, the options are still
  validated but no threads or probes are created.
- The library reference (`src/shared_modules/indexer_client/README.md`) owns the semantics; this table
  is the operator's copy of its schema, `kSchema` in `src/shared_modules/indexer_client/src/config/runtimeConfig.cpp`.
  Every minimum is 1 except `log_summary_interval_ms`, whose minimum is 1000; bounds are inclusive.

| Name (after the prefix) | Unit | Allowed values | Default |
|---|---|---|---|
| `network_threads` | count | 1 to 64 | 1 |
| `cpu_threads` | count | 1 to 64 | 2 |
| `global_quota_bytes` | bytes | 1 to 68719476736 (64 GiB) | 268435456 (256 MiB) |
| `max_response_bytes` | bytes | 1 to 1073741824 (1 GiB) | 67108864 (64 MiB) |
| `drr_quantum_bytes` | bytes | 1 to 67108864 (64 MiB) | 1048576 (1 MiB) |
| `request_timeout_ms` | ms | 1 to 3600000 (1 h) | 60000 |
| `probe_timeout_ms` | ms | 1 to 300000 (5 min) | 5000 |
| `probe_interval_ms` | ms | 1 to 3600000 (1 h) | 10000 |
| `drain_ms` | ms | 1 to 600000 (10 min) | 10000 |
| `ambiguous_retry_window_ms` | ms | 1 to 3600000 (1 h) | 30000 |
| `latency_target_ms` | ms | 1 to 600000 (10 min) | 2000 |
| `pace_initial_ms` | ms | 1 to 60000 (1 min) | 100 |
| `pace_relax_after` | count | 1 to 1000000 | 20 |
| `retry_after_max_ms` | ms | 1 to 3600000 (1 h) | 60000 |
| `callback_budget_ms` | ms | 1 to 60000 (1 min) | 200 |
| `max_open_pits` | count | 1 to 10000 | 64 |
| `log_summary_interval_ms` | ms | 1000 to 3600000 (1 h) | 60000 |
| `node_window_max` | count | 1 to 64 | 4 |
| `bulk_min_bytes` | bytes | 1 to 33554432 (32 MiB) | 65536 (64 KiB) |

The ones this module's operator reaches for:

- `request_timeout_ms` — the per-request timeout of every bucket; it also sets the window of the
  [post-deletion sweep](architecture.md#the-post-deletion-sweep) (`request_timeout_ms + 5 s`).
- `global_quota_bytes` — the memory ceiling that `max_queue_bytes` and the `inventory` quota are carved
  from (see the sharing rule at the top of this section).
- `ambiguous_retry_window_ms` — the longest an `agent-state` bucket stays pinned to one indexer node
  after an ambiguous `5xx`, during which it sends only the pinned operations (see
  [Effects to know](architecture.md#effects-to-know)).
- `probe_interval_ms`, `probe_timeout_ms` — the host health probe that replaces the module's
  `indexer_monitoring_interval_seconds`.

---

## Configuration Examples

### Bounding memory on a busy manager

```ini
wazuh_modules.inventory_sync_server_max_inflight_bytes=134217728
wazuh_modules.inventory_sync_server_max_parallel_connections=512
```

The byte budget is the knob that bounds memory; the connection cap is the one that bounds file
descriptors. Keep the connection cap below `wazuh_modules.rlimit_nofile`, which is shared with every
other module.

### Shortening the shutdown

```ini
wazuh_modules.inventory_sync_server_drain_timeout=1
```

Only worth changing if `wazuh-manager-control restart` is being slowed by deferred replies that will
never land.

---

## Troubleshooting

### The module logs that it cannot use or bind its socket path

The path is fixed, so the fault is always on disk. Check `/var/wazuh-manager/queue/sockets/`:

- `cannot use its socket path`: checked once when the module starts — the parent directory is
  missing or not writable, or a file that is not a socket sits at the path.
  `wazuh-manager-modulesd` exits instead of running without inventory ingress. This happens after
  `wazuh-manager-control start` has already reported success, so it shows in `status` and in
  `logs/wazuh-manager.log`.
- `could not bind`: the start-time check passed but the bind itself failed later, when the socket
  is opened (after the indexer objects are built). The module keeps running and retries every 60 s.

### `/stats` and `/config` answer 503

Either no configured indexer host is healthy (check the `<indexer>` hosts and that the indexer is
running; expected while the indexer starts up after the manager), or the `agent-state` bucket refused
the report because its quota is full or the module is stopping. Before 5.x a report the queue could not
take was acknowledged with `200` and lost; it is now a `503` and the agent re-sends. Raise
`indexer_async_max_queue_bytes` only if the indexer is up and the refusals persist (the bucket is
capped at a quarter of `indexer_client_global_quota_bytes`).

### Requests are answered 503 under load

Five gates shed with a `503`, in the order a `POST /stateful` request meets them — each with its
own evidence in [`GET /metrics`](metrics.md):

1. **Connection cap** (`max_parallel_connections`) — too many simultaneous connections. No shed
   counter; `server.sessions.live` pinned at the cap is the signature.
2. **In-flight byte budget** (`max_inflight_bytes`) — too many request bytes being read at once.
   Counted in `server.rejected.budget`; watch the `server.budget.*` levels alongside it (available
   near 0, inflight near the cap).
3. **Per-agent pending sessions** (`max_sessions_per_agent`) — the agent already has that many
   sessions admitted and not yet answered; counted as `sync.agent_busy.total`. Usually a slow
   indexer or scanner, not a reason to raise the cap.
4. **Pipeline admission queue** (`sync_queue_bytes`) — sessions accepted but waiting for an ingestion
   worker exceed the global byte cap; counted as `sync.pipeline.shed.total`.
5. **VD lane capacity** (`vd_scan_queue_slots`) — VD sessions only, when the scan queue is full;
   counted as `vd.capacity.503.total`.

All five are logged, throttled, with the current counts. (The two `_internal` routes are not
budget-charged; their own gate is the control class's session cap, `control_max_sessions`, counted
in `server.rejected.session_cap`.) Raise the matching option — but see the
descriptor-limit note on `max_parallel_connections`, and prefer raising `sync_workers` over
`sync_queue_bytes` when the queue sheds while CPUs sit idle: the queue is a buffer, not throughput.

### Confirming what the module is running with

Enable `wazuh_modules.debug=1` and restart: the module logs, at debug level, the value read for every
option above except `session_query_batch_size` (`0` meaning "the module default"). `getconfig wmodules` on the
modulesd socket reports the same values, except `reserved_control_connections`,
`control_max_body_bytes`, `control_max_sessions`, `max_sessions_per_agent` and
`session_query_batch_size`. Both report the value as read, not as resolved: `max_inflight_bytes`
reads `0` when the option is absent (the 256 MiB default) and `-1` when it is explicitly `0`
(unlimited).

## Related options in other daemons

The ingress side of the same pipeline is tuned in remoted: see
[`remoted.downstream_stateful_response_timeout`](../remoted/configuration.md#remoteddownstream_stateful_response_timeout)
(how long remoted waits for this module's answer to a relayed `/stateful` request — sessions are
indexed and flushed within the request, so it is deliberately longer than remoted's global
downstream default) and the `remoted.downstream_*` family it belongs to. Remoted's view of the
same requests — what the agent was actually answered, and its end-to-end latency — is in
[remoted's metrics page](../remoted/metrics.md).

## See Also

- [Architecture](architecture.md)
- [API Reference](api-reference.md)
- [Metrics](metrics.md) - The module's metric catalog, linked back to these settings
- [Schemas](flatbuffers.md)
- [Test Tools](test-tools.md)

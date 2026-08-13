# Inventory Sync Server Configuration

The Inventory Sync Server module has no XML configuration block of its own. It is registered
unconditionally and reads the `<indexer>` block for its connection to the indexer; everything else is
tuned through internal options.

## Configuration Sources

| Source | What it provides |
|---|---|
| `<indexer>` in the manager configuration | Indexer hosts and TLS material |
| `<cluster>` in the manager configuration | The cluster name stamped onto every document |
| Internal options | Every transport and connector tunable listed below |

Two values are deliberately NOT configurable:

- **The socket path** is fixed at `queue/sockets/inventory-sync.sock`, relative to the installation
  directory. Internal options can only carry integers, so there is no mechanism to set a path; remoted
  resolves the same relative path through its chroot.
- **The socket mode** is fixed at `0660`. It was an internal option and that was a trap: the value is a
  raw permission mode, but internal options are parsed as DECIMAL, so writing the documented `0660`
  produced decimal 660 -- out of range, killing the daemon -- while a value that did fit, say `440`, was
  applied as decimal 440, i.e. `0670`, silently granting the group write access on a socket the operator
  was trying to restrict.
- **The maximum header count** is fixed at 32, because it is a term of the memory ceiling the in-flight
  byte budget charges for. See `max_inflight_bytes` below.

---

## Internal Options

**Configuration file:** `/var/wazuh-manager/etc/wazuh-manager-internal-options.conf`

**Internal Options prefix:** `wazuh_modules.inventory_sync_server_*`

Internal options provide advanced tuning for the transport, admission control and the indexer
connectors.

An option present in `wazuh-manager-internal-options.conf` but out of its allowed range -- or
non-numeric -- prevents `wazuh-manager-modulesd` from starting, and is reported by
`wazuh-manager-modulesd -t`. Values are parsed as decimal; a leading zero does not mean octal.

The shipped `wazuh-manager-internal-options.conf` template lists every option below commented out
with its compiled default and range; uncomment an entry only to override it. The file is never
overwritten during upgrades.

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
- **Note:** Max simultaneous connections; over it `503` and close. Every connection and every deferred reply costs a file descriptor out of a limit shared with all of modulesd, so setting this above `wazuh_modules.rlimit_nofile` logs a warning and guarantees failures before the cap is reached.

### wazuh_modules.inventory_sync_server_max_inflight_bytes

Total in-flight request payload bytes; over it `503`.

```ini
wazuh_modules.inventory_sync_server_max_inflight_bytes=268435456
```

- **Default value:** `268435456` (256 MiB)
- **Allowed values:** `0` (unlimited) or 1 to 2147483647
- **Note:** Total in-flight request payload bytes; over it `503`. Reserved from the declared `Content-Length` at headers-complete, BEFORE the body is read, so it bounds the read-phase peak too. Raised automatically to at least one maximum-size request, so a too-small value cannot reject everything.

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
  order by the same worker. More workers spread distinct agents, not one agent's backlog.

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
  READ, this bounds bytes WAITING for a worker.

### wazuh_modules.inventory_sync_server_vd_feed_retry_after_seconds

`Retry-After` value, in seconds, answered with `503` while the vulnerability feed is not ready.

```ini
wazuh_modules.inventory_sync_server_vd_feed_retry_after_seconds=60
```

- **Default value:** `60`
- **Allowed values:** 10 to 1800
- **Note:** Only VD sessions get this header; the agent re-sends the same session after the delay.
  The minimum is 10 because a smaller value tells the whole fleet to hammer the endpoint.

### wazuh_modules.inventory_sync_server_vd_workers

Workers on the vulnerability-detection scan lane.

```ini
wazuh_modules.inventory_sync_server_vd_workers=0
```

- **Default value:** `0` (resolves to 1)
- **Allowed values:** 0 to 16
- **Note:** The scanner serializes scans internally today, so values above 1 only help once the
  scanner gains real scan parallelism.

### wazuh_modules.inventory_sync_server_vd_scan_queue_slots

Sessions allowed to wait for a VD worker.

```ini
wazuh_modules.inventory_sync_server_vd_scan_queue_slots=0
```

- **Default value:** `0` (twice `vd_workers`)
- **Allowed values:** 0 to 256
- **Note:** A VD session arriving with the queue full is answered `503` ("scan capacity exhausted") —
  scans run synchronously inside the request, so queueing more than the lane can drain only trades a
  fast `503` for a slow timeout.

---

### Indexer connectors (`indexer_sync_*` and `indexer_async_*`)

The module builds BOTH a synchronous and an asynchronous connector over one shared indexer session, and
each has its own tunables. The two families are not interchangeable: `IndexerConnectorSync` reads
`max_bulk_size` while `IndexerConnectorAsync` reads `bulk_max_bytes` for the same concept, and handing
either family the other's key is ignored silently. Keep the `indexer_sync_` / `indexer_async_` prefixes
intact.

#### Synchronous connector

#### wazuh_modules.inventory_sync_server_indexer_sync_max_bulk_size

Forwarded to the Indexer Connector as `max_bulk_size`.

```ini
wazuh_modules.inventory_sync_server_indexer_sync_max_bulk_size=10485760
```

- **Default value:** `10485760` (10 MiB)
- **Allowed values:** 4096 to 104857600
- **Note:** Forwarded to the Indexer Connector as `max_bulk_size`.

#### wazuh_modules.inventory_sync_server_indexer_sync_flush_interval_seconds

**No effect.** The value is accepted for compatibility but the module overrides the connector's
periodic flush to one hour regardless: the ingestion workers own every flush (a timer-driven flush
that fails discards the buffer silently, which would let a worker answer `200` for lost data).

```ini
wazuh_modules.inventory_sync_server_indexer_sync_flush_interval_seconds=20
```

- **Default value:** `20` (ignored)
- **Allowed values:** 1 to 3600
- **Note:** Kept only so existing configurations do not abort the daemon; slated for removal.

#### wazuh_modules.inventory_sync_server_indexer_sync_max_retry_delay_seconds

Forwarded as `max_retry_delay_seconds`.

```ini
wazuh_modules.inventory_sync_server_indexer_sync_max_retry_delay_seconds=15
```

- **Default value:** `15`
- **Allowed values:** 1 to 3600
- **Note:** Forwarded as `max_retry_delay_seconds`. The minimum is 1 because the connector rejects anything below its base retry delay.

#### Asynchronous connector

#### wazuh_modules.inventory_sync_server_indexer_async_bulk_max_bytes

Forwarded as `bulk_max_bytes`.

```ini
wazuh_modules.inventory_sync_server_indexer_async_bulk_max_bytes=4194304
```

- **Default value:** `4194304` (4 MiB)
- **Allowed values:** 4096 to 104857600
- **Note:** Forwarded as `bulk_max_bytes`. Note the different key name from the synchronous family.

#### wazuh_modules.inventory_sync_server_indexer_async_flush_interval_seconds

Forwarded as `flush_interval_seconds`.

```ini
wazuh_modules.inventory_sync_server_indexer_async_flush_interval_seconds=20
```

- **Default value:** `20`
- **Allowed values:** 1 to 3600
- **Note:** Forwarded as `flush_interval_seconds`.

#### wazuh_modules.inventory_sync_server_indexer_async_max_retry_delay_seconds

Forwarded as `max_retry_delay_seconds`.

```ini
wazuh_modules.inventory_sync_server_indexer_async_max_retry_delay_seconds=15
```

- **Default value:** `15`
- **Allowed values:** 1 to 3600
- **Note:** Forwarded as `max_retry_delay_seconds`.

#### wazuh_modules.inventory_sync_server_indexer_async_logger_queue_size

Forwarded as `logger_queue_size`.

```ini
wazuh_modules.inventory_sync_server_indexer_async_logger_queue_size=8
```

- **Default value:** `8`
- **Allowed values:** 1 to 65536
- **Note:** Forwarded as `logger_queue_size`.

#### wazuh_modules.inventory_sync_server_indexer_async_logger_threads

Forwarded as `logger_threads`.

```ini
wazuh_modules.inventory_sync_server_indexer_async_logger_threads=1
```

- **Default value:** `1`
- **Allowed values:** 1 to 64
- **Note:** Forwarded as `logger_threads`.

#### wazuh_modules.inventory_sync_server_indexer_async_max_queue_bytes

Forwarded as `max_queue_bytes`.

```ini
wazuh_modules.inventory_sync_server_indexer_async_max_queue_bytes=67108864
```

- **Default value:** `67108864` (64 MiB)
- **Allowed values:** `0` (unlimited) or 1 to 2147483647
- **Note:** Forwarded as `max_queue_bytes`. An unbounded queue is the only unbounded allocation this module can be configured to make, so the shipped default is deliberately finite.

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

### The module logs that it cannot use its socket path

The manager will not start. The path is fixed, so the fault is always its parent directory: it is
missing, is not writable, or a file that is not a socket is sitting at the path. Check
`/var/wazuh-manager/queue/sockets/`.

### `/stats` and `/config` answer 503

No configured indexer host is healthy. The module keeps serving and retries; check the `<indexer>` hosts
and that the indexer is running. This is expected while the indexer starts up after the manager.

### Requests are answered 503 under load

Four gates shed with a `503`, in the order a request meets them:

1. **Connection cap** (`max_parallel_connections`) — too many simultaneous connections.
2. **In-flight byte budget** (`max_inflight_bytes`) — too many request bytes being read at once.
3. **Pipeline admission queue** (`sync_queue_bytes`) — sessions accepted but waiting for an ingestion
   worker exceed the global byte cap; visible as `sync.pipeline.shed.total` in `GET /metrics`.
4. **VD lane capacity** (`vd_scan_queue_slots`) — VD sessions only, when the scan queue is full.

All four are logged, throttled, with the current counts. Raise the matching option — but see the
descriptor-limit note on `max_parallel_connections`, and prefer raising `sync_workers` over
`sync_queue_bytes` when the queue sheds while CPUs sit idle: the queue is a buffer, not throughput.

### Confirming what the module is running with

Enable `wazuh_modules.debug=1` and restart: the module logs every resolved tunable at startup. The values
are also reported by `getconfig wmodules` on the modulesd socket.

## Related options in other daemons

The ingress side of the same pipeline is tuned in remoted: see
[`remoted.downstream_stateful_response_timeout`](../remoted/configuration.md) (how long remoted
waits for this module's answer to a relayed `/stateful` request — sessions are indexed and flushed
within the request, so it is deliberately longer than remoted's global downstream default) and the
`remoted.downstream_*` family it belongs to.

## See Also

- [Architecture](architecture.md)
- [API Reference](api-reference.md)
- [Schemas](flatbuffers.md)
- [Test Tools](test-tools.md)

# UDS HTTP Server

The manager's shared HTTP/1.1-over-Unix-domain-socket **server transport**
(`src/shared_modules/uds_http_server/`): asynchronous end to end, with deferred
responses, an in-flight byte budget with real load shedding, and a two-phase shutdown
with named guarantees. Manager daemons use it to serve local peers over
`queue/sockets/*`.

What it deliberately is **not**: remoted's agent-facing TCP/TLS server (a protocol peer
of this library, not a layer of it), and not a general web framework — one request per
connection, exact-match routing, no TLS, no keep-alive, no chunked encoding.

## Consumers

Five servers, each on its own socket under `/var/wazuh-manager/queue/sockets/`:

| Consumer | Daemon | Socket | Routes | Transport settings |
|---|---|---|---|---|
| Inventory Sync Server | `wazuh-manager-modulesd` | `inventory-sync-http.sock` | [API reference](../../inventory-sync-server/api-reference.md) | `wazuh_modules.inventory_sync_server_*` internal options — [configuration](../../inventory-sync-server/configuration.md) |
| Task Manager | `wazuh-manager-modulesd` | `task-http.sock` | [API reference](../../task_manager/api-reference.md) | I/O threads: `wazuh_modules.manager_task_io_threads` ([threading](../../task_manager/manager-tasks.md#threading)); body cap of `POST /v1/manager-tasks`: [`max_payload_bytes`](../../task_manager/configuration.md#max_payload_bytes) + 64 KiB; the rest fixed in code |
| Vulnerability Scanner | `wazuh-manager-modulesd` | `vd-http.sock` | [Local HTTP API](../../vulnerability-scanner/api-reference.md#local-http-api-vd-httpsock) | Fixed in code: 2 I/O threads, 3600 s response backstop |
| Wazuh DB | `wazuh-manager-db` | `wdb-http.sock` | [API reference](../../wazuh_db/api-reference.md) | Fixed in code: the library defaults |
| Remoted admin socket | `wazuh-manager-remoted` | `remote-admin-http.sock` | `GET /`, `GET /metrics`, `GET /status`, `GET /tls` — [Local admin socket](../../remoted/README.md#local-admin-socket) | Fixed in code: 2 I/O threads, 64 connections, 16 reserved for control |

This library has **no configuration of its own**. Each consumer sets the transport knobs
(I/O threads, in-flight byte budget, connection caps, timeouts, reserved control
connections) in code. Inventory Sync exposes most of them as internal options; Task
Manager exposes its I/O thread count and sizes one route's body cap from
`max_payload_bytes`. The other three consumers expose none.

The library defaults, which apply wherever a consumer does not override them:

| Setting | Default |
|---|---|
| I/O threads | one per available CPU |
| Concurrent accepts | 2 |
| Connections | 1024, of which 64 reserved for Control and Liveness routes (at most a quarter of the cap) |
| In-flight byte budget | 256 MiB (Data routes only) |
| Body cap | none of its own: a request declaring more than the budget can ever admit is `413` |
| Control / Liveness body cap | 64 KiB / 4 KiB |
| Control / Liveness concurrent sessions | 256 / 64 |
| URL, header name, header value, header count | 2048 bytes, 256 bytes, 8192 bytes, 32 |
| Timeouts | head 10 s, body 30 s, response backstop 300 s, write 10 s, drain on stop 2 s |
| Socket mode | `0660`, set explicitly after `bind()` |

Every server logs the effective values once at start, at INFO, under its consumer's tag:
`<name> server bound to '<socket>' (mode 0660, <n> I/O thread(s), …; timeouts s: header=… body=…
response=… write=… drain=…).`

## What an operator sees

Fixed status semantics, with throttled per-condition diagnostics (one storm cannot
suppress another kind's first line):

| Status | Meaning | Typical cause |
|---|---|---|
| `400` | Malformed request | Broken client |
| `404` | No route for that path | Routes are `method + exact path` — no patterns |
| `405` + `Allow` | Path exists, wrong method | The `Allow` header lists what the route accepts |
| `411` | `Transfer-Encoding: chunked` | Chunked bodies are refused by design. The byte budget must know the size at headers-complete, so send `Content-Length` |
| `413` | Declared body over a cap | The server-wide cap (by default, what the byte budget could ever admit), the route class's cap, or a per-route override. The peer is wrong; raising limits is a consumer setting |
| `414` / `431` | URI / headers too large | Parser limits |
| `500` | The consumer's handler threw | Check the consumer's log (lines carry the consumer's own name) |
| `503` | Load shed | Byte budget exhausted, connection cap, per-class or per-route session cap, a dropped responder, or shutdown in progress |
| `504` | Handler never answered | The response-timer backstop fired |

Only Data routes are charged the byte budget. Control and Liveness routes (health
probes, `/metrics`, status queries) are exempt, and connection headroom is reserved for
them. They keep answering while the data plane sheds 503s. Every response closes its
connection: one request per connection.

## Log lines

Each condition has its own throttle, so a line reports how many occurrences its window
(`%d s`) covered. Every line carries the consumer's tag and name (`<name>` below is the
consumer's, for example `inventory sync`):

| Level | Line | Meaning |
|---|---|---|
| WARN | `Refused <n> connection(s) with 503 in the last <s> s: the <cap>-connection limit is reached. …` | The accept-time connection cap; some consumers append the option that raises it |
| WARN | `Rejected <n> request(s) with 503 in the last <s> s: the in-flight payload budget is exhausted (…).` | Byte budget; some consumers append the option that raises it |
| WARN | `Rejected <n> request(s) with 503 in the last <s> s: the <class>-class session limit (<cap>) is reached. …` | A class or per-route session cap |
| WARN | `Rejected <n> request(s) with 413 in the last <s> s: the declared body exceeds the <class>-class cap (…).` | Class or per-route body cap |
| WARN | `Rejected <n> request(s) in the last <s> s for exceeding a configured limit (last: <status> on '<path>').` | Parser limits: `411`, the server-wide `413`, `414`, `431` |
| WARN | `Answered <n> request(s) in the last <s> s with <404 or 405>: no route for <METHOD> '<path>'.` | A route mismatch between peer and server |
| WARN | `<n> request(s) in the last <s> s were not answered within their response backstop and were closed with 504 (…).` | A stuck handler or a lost responder |
| WARN | `<n> request(s) in the last <s> s were dropped by their handler without a response and were answered 503. This is a handler bug.` | Handler bug |
| WARN | `Closed <n> connection(s) in the last <s> s that timed out before a response was due (last phase: …).` | Slow or vanished peer while reading the request or writing the reply |
| WARN | `Failed to accept <n> <name> connection(s) in the last <s> s: <reason>. The listener is still accepting; peers will retry.` | Transient `accept()` failure, usually descriptor exhaustion |
| ERROR | `<n> request(s) failed while being dispatched in the last <s> s and were answered 500 (last: …).` | The handler threw |
| INFO | `Removing the existing socket at '<path>' (a leftover from an unclean shutdown) before binding.` | A stale socket file was replaced at start |
| WARN | `Not unlinking '<path>': another process has re-bound it since this server started.` | Two servers fought over one socket path (double start) |

A malformed request (`400`) and a peer that leaves while its reply is pending are logged
only at debug level.

## Related

- [Architecture](architecture.md) — request pipeline, threading and the accept loop,
  two-phase shutdown, route-class QoS.
- [Integration Guide](integration-guide.md) — for module developers consuming the library.
- [Metrics Library](../metrics/README.md) — Inventory Sync, Task Manager and the remoted
  admin socket publish this transport's `diagnostics()` as pull metrics; Vulnerability
  Scanner and Wazuh DB do not.

## Development

Developer documentation (requirements, design decisions, test map):
`src/shared_modules/uds_http_server/README.md` in the repository.

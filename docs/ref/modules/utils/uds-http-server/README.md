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
| Task Manager | `wazuh-manager-modulesd` | `task-http.sock` | [API reference](../../task_manager/api-reference.md) | I/O threads: `wazuh_modules.manager_task_io_threads` ([threading](../../task_manager/manager-tasks.md#threading)); the rest fixed in code |
| Vulnerability Scanner | `wazuh-manager-modulesd` | `vd-http.sock` | [Local HTTP API](../../vulnerability-scanner/api-reference.md#local-http-api-vd-httpsock) | Fixed in code: 2 I/O threads, 3600 s response backstop |
| Wazuh DB | `wazuh-manager-db` | `wdb-http.sock` | [API reference](../../wazuh_db/api-reference.md) | Fixed in code: the library defaults |
| Remoted admin socket | `wazuh-manager-remoted` | `remote-admin-http.sock` | `GET /`, `GET /metrics`, `GET /status`, `GET /tls` — [Local admin socket](../../remoted/README.md#local-admin-socket) | Fixed in code: 2 I/O threads, 64 connections, 16 reserved for control |

This library has **no configuration of its own**. Each consumer sets the transport knobs
(I/O threads, in-flight byte budget, connection caps, timeouts, reserved control
connections) in code. Inventory Sync exposes most of them as internal options, and Task
Manager exposes its I/O thread count. The other three consumers expose none.

## What an operator sees

Fixed status semantics, with throttled per-condition diagnostics (one storm cannot
suppress another kind's first line):

| Status | Meaning | Typical cause |
|---|---|---|
| `400` | Malformed request | Broken client |
| `404` | No route for that path | Routes are `method + exact path` — no patterns |
| `405` + `Allow` | Path exists, wrong method | The `Allow` header lists what the route accepts |
| `411` | `Transfer-Encoding: chunked` | Chunked bodies are refused by design. The byte budget must know the size at headers-complete, so send `Content-Length` |
| `413` | Declared body over the route-class cap | The peer is wrong; raising limits is a consumer setting |
| `414` / `431` | URI / headers too large | Parser limits |
| `500` | The consumer's handler threw | Check the consumer's log (lines carry the consumer's own name) |
| `503` | Load shed | Byte budget exhausted, connection cap, per-class session cap, a dropped responder, or shutdown in progress |
| `504` | Handler never answered | The response-timer backstop fired |

Only Data routes are charged the byte budget. Control and Liveness routes (health
probes, `/metrics`, status queries) are exempt, and connection headroom is reserved for
them. They keep answering while the data plane sheds 503s. Every response closes its
connection: one request per connection.

## Related

- [Architecture](architecture.md) — request pipeline, two-phase shutdown, route-class QoS.
- [Integration Guide](integration-guide.md) — for module developers consuming the library.
- [Metrics Library](../metrics/README.md) — consumers publish this transport's
  `diagnostics()` as pull metrics.

## Development

Developer documentation (requirements, design decisions, test map):
`src/shared_modules/uds_http_server/README.md` in the repository.

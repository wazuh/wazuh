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

| Consumer | Socket | Configuration |
|---|---|---|
| Inventory Sync Server | `queue/sockets/inventory-sync-http.sock` | [inventory-sync-server/configuration.md](../../inventory-sync-server/configuration.md) |
| Remoted module admin socket (`GET /`, `GET /metrics`) | `queue/sockets/remote-admin-http.sock` | [remoted/configuration.md](../../remoted/configuration.md) |

This library has **no standalone configuration**: each consumer exposes the transport
knobs (I/O threads, in-flight byte budget, connection caps, timeouts, reserved control
connections...) as its own settings and documents them in its own configuration page.

## What an operator sees

Fixed status semantics, with throttled per-condition diagnostics (one storm cannot
suppress another kind's first line):

| Status | Meaning | Typical cause |
|---|---|---|
| `400` | Malformed request | Broken client |
| `404` | No route for that path | Routes are `method + exact path` — no patterns |
| `405` + `Allow` | Path exists, wrong method | The `Allow` header lists what the route accepts |
| `411` | No `Content-Length` | Chunked encoding is refused by design — the byte budget must know the size at headers-complete |
| `413` | Declared body over the route-class cap | The peer is wrong; raising limits is a consumer setting |
| `414` / `431` | URI / headers too large | Parser limits |
| `500` | The consumer's handler threw | Check the consumer's log (lines carry the consumer's own name) |
| `503` | Load shed | Byte budget exhausted, connection cap, per-class session cap, a dropped responder, or shutdown in progress |
| `504` | Handler never answered | The response-timer backstop fired |

Liveness routes (probes, `/metrics`) are budget-exempt and have reserved connection
headroom — they keep answering exactly while the data plane sheds 503s.

## Related

- [Architecture](architecture.md) — request pipeline, two-phase shutdown, route-class QoS.
- [Integration Guide](integration-guide.md) — for module developers consuming the library.
- [Metrics Library](../metrics/README.md) — consumers publish this transport's
  `diagnostics()` as pull metrics.

## Development

Developer documentation (requirements, design decisions, test map):
`src/shared_modules/uds_http_server/README.md` in the repository.

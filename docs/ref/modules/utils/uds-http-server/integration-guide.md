# Integration guide

How a manager module consumes `uds_http_server` — the library's consumer contract. The
design behind each rule (requirements RF/RNF, decisions, test map) is in the developer
README, `src/shared_modules/uds_http_server/README.md`. Reference consumer:
`src/wazuh_modules/inventory_sync_server/`.

## Link

`target_link_libraries(<your_module> PRIVATE wazuh_uds_http_server)`. The library is
STATIC + PIC, never SHARED, and is archived into each consumer `.so` with its symbols
hidden. Your module must define its own `Log::GLOBAL_LOG_FUNCTION` (a missing definition
is a link error) **and** install it with `Log::assignLogFunction()` — without the call the
module still compiles and links, and the server logs nothing at all. Every copy logs
through its own module's sink. Transport dependencies (standalone asio, llhttp) stay
private behind the PImpl — no public header names them; `makeUdsHttpServer()` is the
single transport swap point.

## Identity

Fill `logTag`, `serverName` (rendered as "`<name>` server / connection(s) /
request(s)" in every diagnostic) and `serverHeader` (the `Server:` response header) —
and, if your capacity knobs are internal options, the two hint fields
(`budgetOptionHint`, `connectionCapOptionHint`) — so diagnostics name **your** module and
**your** options.

## Socket path

No default; an empty path makes `start()` throw. Use a path relative to the installation
directory, which is the working directory of every consumer daemon (all five sockets are
`queue/sockets/<name>.sock`). A path that does not fit `sun_path` (107 characters) makes
`start()` throw naming both. Pre-flight bind feasibility with `socketPathIsUsable()`
(`socketPathCheck.hpp`) for fail-fast startups. The library never creates the parent
directory, refuses to unlink a path that exists and is not a socket, replaces a stale
socket (logged at INFO), `chmod`s the socket to `socketMode` (default `0660`) after
`bind()`, and unlinks at teardown only the inode it bound.

## Handlers never block (RNF-5)

Handlers run inline on I/O threads: enqueue the real work to your own executor and
reply through the responder (from any thread, any time — `send()` is exactly-once).
The request `shared_ptr` carries the byte reservation: keep it alive exactly as long as
you need the payload, drop it before replying if you are done with the bytes. A handler
that throws is answered `500`; a responder dropped without `send()` is answered `503`
and logged as a handler bug.

## Route classes

Declare each route's class with `RouteOptions`: **Data** (budget-charged, sheddable),
**Control** (budget-exempt, own body and session caps, reserved headroom), **Liveness**
(probes, `/metrics` — budget-exempt, answered from resident state, 4 KiB body and 64
sessions). Always pass `RouteOptions`: the older `addRoute(method, path, handler, bool)`
spelling maps `true` — also the 3-argument default — to Data and `false` to Liveness,
never to Control, so a probe registered without it is shed under load and an admin POST
registered with `false` hits the Liveness caps. `RouteOptions` also carries per-route
overrides — `maxBodyBytes`, `maxSessions` (enforced in addition to the class cap) and
`responseTimeoutSec` — each `0` meaning "the class or server default"; set
`responseTimeoutSec` on a route whose peer waits longer than the server-wide backstop. A
Control route that does real work still sheds its own capacity module-side (bounded
queue → 503). Routes are exact `method + path` matches (the path before `?`; carry
identity in a header, not in the path) and must be registered before `start()`;
`addRoute()` afterwards throws `std::logic_error`.

## Shutdown order

`stopAccepting()` **first**, then tear down whatever your handlers reach, then
`stop()`. That ordering is what the S1/S2 guarantees exist for (see
[Architecture](architecture.md#two-phase-shutdown-s1s2s3)). Both are idempotent and safe
on a server that never started; the destructor calls `stop()`.

## Diagnostics as metrics

The library does not depend on `wazuh_metrics`; it exposes a `diagnostics()` snapshot
(budget available/in-flight bytes, in-flight requests, live sessions, sessions per route
class, and cumulative transport-level 503s by cause: budget exhausted, session cap,
shutdown, no response). These are relaxed atomic loads, callable at any point between
construction and destruction. The 503 counters matter because those requests never reach
a handler, so your endpoint metrics cannot see them. Publish those
fields as pull metrics through your own `wazuh::metrics::IManager`. Mind the pull
lifetime rule (pulls cannot be unregistered): capture a `weak_ptr` resolved under your
own lock, register once, and let an expired target read as zeros — reference wiring:
`registerTransportDiagnostics()` in inventory sync's facade. See the
[Metrics Library](../metrics/integration-guide.md).

## Restarting

One-shot lifecycle: `start()` throws if reused — build a fresh instance per start cycle.

## Test support

The library's own suite is `uds_http_server_utest` (ctest label `uds_http_server_utest`,
pinned to C++17 — the floor's enforcement point). Consumer tests typically drive their endpoints against a real
instance on a temp socket path; see `src/wazuh_modules/inventory_sync_server/test/unit/` for patterns.

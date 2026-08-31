# Integration guide

How a manager module consumes `uds_http_server`. This distills the **Consumer contract**
of the dev README (`src/shared_modules/uds_http_server/README.md`) — same bullet
titles; when in doubt, that file is authoritative. Reference consumer:
`src/wazuh_modules/inventory_sync_server/`.

## Link

`target_link_libraries(<your_module> PRIVATE wazuh_uds_http_server)`. The library is
STATIC + PIC and is archived into each consumer `.so`; your module must define its own
`Log::GLOBAL_LOG_FUNCTION` (every module already does), and every copy logs through its
own module's sink. Transport dependencies (standalone asio, llhttp) stay private behind
the PImpl — no public header names them; `makeUdsHttpServer()` is the single transport
swap point.

## Identity

Fill `logTag`, `serverName` (rendered as "`<name>` server / connection(s) /
request(s)" in every diagnostic) and `serverHeader` (the `Server:` response header) —
and, if your capacity knobs are internal options, the two hint fields — so diagnostics
name **your** module and **your** options.

## Socket path

No default; an empty path makes `start()` throw. Use a relative path — daemons
`chdir()`/`chroot()` into the install dir. Pre-flight bind feasibility with
`socketPathCheck.hpp` for fail-fast startups; the library refuses to unlink a
non-socket and inode-guards the unlink at teardown.

## Handlers never block (RNF-5)

Handlers run inline on I/O threads: enqueue the real work to your own executor and
reply through the responder (from any thread, any time — `send()` is exactly-once).
The request `shared_ptr` carries the byte reservation: keep it alive exactly as long as
you need the payload, drop it before replying if you are done with the bytes.

## Route classes

Declare each route's class: **Data** (budget-charged, sheddable), **Control** (reserved
session headroom), **Liveness** (probes, `/metrics` — budget-exempt). A Control route
that does real work still sheds its own capacity module-side (bounded queue → 503).

## Shutdown order

`stopAccepting()` **first**, then tear down whatever your handlers reach, then
`stop()`. That ordering is what the S1/S2 guarantees exist for (see
[Architecture](architecture.md)).

## Diagnostics as metrics

The library does not depend on `wazuh_metrics`; it exposes a `diagnostics()` snapshot
(budget available/in-flight bytes, in-flight requests, live sessions — relaxed atomic
loads, callable at any point between construction and destruction). Publish those
fields as pull metrics through your own `wazuh::metrics::IManager`. Mind the pull
lifetime rule (pulls cannot be unregistered): capture a `weak_ptr` resolved under your
own lock, register once, and let an expired target read as zeros — reference wiring:
`registerTransportDiagnostics()` in inventory sync's facade. See the
[Metrics Library](../metrics/integration-guide.md).

## Restarting

One-shot lifecycle: `start()` throws if reused — build a fresh instance per start cycle.

## Test support

The library's own suite is `uds_http_server_utest` (pinned to C++17 — the floor's
enforcement point). Consumer tests typically drive their endpoints against a real
instance on a temp socket path; see `inventory_sync_server/test/unit/` for patterns.

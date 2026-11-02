# HttpSrv Module

## Overview

The **httpsrv** module is the engine's HTTP server over Unix Domain Sockets (UDS). `httpsrv::Server` serves one
socket on the manager's shared HTTP-over-UDS transport (`src/shared_modules/uds_http_server`) and adds what the
engine needs on top of it: transport-neutral request/response types, a bounded executor that keeps handlers off
the I/O threads, a three-step shutdown with a deadline, a log bridge and metrics. The engine runs up to two
instances: the API server (management, metrics, geo, content, …) and, when event processing is enabled, the
event ingest server.

## Architecture

```
            engine-api-http.sock                        engine-ingest-http.sock
                    │                                              │
     ┌──────────────▼───────────────┐              ┌───────────────▼──────────────┐
     │ uds_http_server (I/O threads)│              │ uds_http_server (I/O threads)│
     │ parse, route, 404/405/411/   │              │ parse, route, 413 at the cap,│
     │ 413/431/503 before handlers  │              │ connection cap, byte budget  │
     └──────────────┬───────────────┘              └───────────────┬──────────────┘
                    │                                              │
     ┌──────────────▼───────────────┐              ┌───────────────▼──────────────┐
     │ httpsrv::Server "API services"│             │ httpsrv::Server "Event ingest"│
     │ inline: GET /status,         │              │ BoundedExecutor max(2,nproc/4)│
     │         POST /metrics/*      │              │ queue = max connections       │
     │ BoundedExecutor 4, queue 64  │              └───────────────┬──────────────┘
     └──────────────┬───────────────┘                              │
                    │ RouteHandler(const Request&, Response&)       │
     ┌──────────────▼───────────────┐              ┌───────────────▼──────────────┐
     │ api::adapter + api/<module>  │              │ api::event::pushEvent        │
     │ (protobuf ↔ JSON)            │              │ (NDJSON batch → router)      │
     └──────────────────────────────┘              └──────────────────────────────┘
```

## Key Concepts

### Neutral types (`interface/httpsrv/types.hpp`)

- `Method` — `GET`, `POST`, `PUT`, `DELETE` (and `ERROR_METHOD`).
- `Request` — method, raw target (query string included), lower-cased headers with `header()` and
  `headerCount()` (2 means "more than once"), and a zero-copy `body` view kept alive by `owner`.
  `Request::fromOwned()` builds one that owns its body (tests and tools).
- `Response` — `status`, `body`, `contentType`, set together with `setContent()`.
- `RouteHandler = std::function<void(const Request&, Response&)>` — synchronous; `api::adapter` re-exports it.
- `RouteOptions` — route class (`Data`, `Control`, `Liveness`), `maxBodyBytes` (0 = the class default,
  `UNLIMITED_BODY` = none), `runInline`, and an optional `payloadTooLargeBody`/`payloadTooLargeContentType`
  that replaces the transport's JSON `413` for that route's cap.

### Route registrar (`IRouteRegistrar`)

`interface/httpsrv/irouteregistrar.hpp` holds the one call an API module needs from a server:
`addRoute(method, path, RouteHandler, RouteOptions = {})`. Every `api::<module>::handlers::registerHandlers()`
takes a `std::shared_ptr<IRouteRegistrar>`, so the modules do not depend on the server class. `Server`
implements it; the API modules register through `ApiRouteRegistrar` (below).

### Server (`include/httpsrv/server.hpp`)

`httpsrv::Server` owns one transport (linked PRIVATE: no transport type appears in an httpsrv header) and one
`BoundedExecutor`.

- **I/O pool**: `ioThreads` sizes the transport pool independently of the handler executor.
  The event ingest server fixes it at two threads; zero keeps the transport default of one per available CPU.
- **Executor** (`BoundedExecutor`): except for inline routes, the transport's I/O threads never run a handler.
  Each admitted request becomes a job of a fixed pool with a bounded queue (`executorThreads`, `executorQueue`).
- **Inline routes** (`RouteOptions::runInline`): the handler runs on the transport's I/O thread instead of the
  executor, so the route answers even when every worker is busy. Only for handlers that never block; the API's
  `GET /status` and `POST /metrics/*` use it.
- **Answers the server writes itself**: executor queue full ⇒ `503 {"error":"Server busy","code":503}`;
  stopping ⇒ `503 {"error":"Server shutting down","code":503}`; handler threw ⇒ `500` `Internal server error`
  (`text/plain`). The transport adds its own `404/405/411/413/414/431/503/504` (see
  `docs/ref/modules/utils/uds-http-server/`).
- **Shutdown** (`shutdown()` for one server, `shutdownAll()` for several, default deadline 10 s). The
  deadline is the grace admitted requests get, counted from the call: steps 1 and 2 run within it (step 1
  can block while the transport answers requests not yet dispatched) and the executor keeps working
  meanwhile; there is no second window after them. Steps 4 and 5 come after the deadline, so a whole
  shutdown can take longer than it:
  1. `stopAccepting()` on every server — no new request reaches a handler, replies still go out;
  2. `closeAdmission()` on every executor — nothing new is queued, queued requests keep running;
  3. `drainUntil(deadline)` in parallel — at the deadline, unstarted requests get the shutdown `503`
     and running ones are reported as abandoned;
  4. `stop()` on every transport;
  5. `waitForHandlers()` on every server — a handler still running past the deadline is waited for (with a WARN
     naming how many), never left running; its late reply is dropped.
  `shutdown()` and `shutdownAll()` return only after step 5, so the caller can destroy what the handlers use (the
  engine shuts protobuf down right after) without a handler running into it. `shutdownAll()` logs one
  `HTTP servers stopped: …` line with the counts.
- **Stats** (`stats()`): in-flight bytes/requests and sessions from the transport, queue depth, running
  handlers, `503`/`500` counters by cause and the transport's `413`s.
- **Metrics** (`registerMetrics(weakServer, instance)`): publishes `stats()` as eleven fastmetrics pull metrics
  named `server.<instance>.<suffix>` (`metric_names.hpp`: `server_metric()` and the `SERVER_*` suffixes). They
  hold a weak reference and read 0 once the server is gone. fastmetrics keeps the first registration of a
  name, so register each instance name once per process. The ingest server registers `"ingest"`, the API server
  `"api"`; the operator catalog is in the engine book's [Metrics](../../../../docs/ref/modules/engine/README.md#metrics).
- `ServerOptions`: name and log tag, `maxConnections`, `maxInFlightBytes` (0 = transport default), `byteBudget`
  (false = no in-flight byte budget, and so no parser limit derived from it), `maxBodySize`, `ioThreads` (0 = one
  per available CPU), executor size, `expectContinue` (answer `Expect: 100-continue` once admitted), `detailedLogging` (one TRACE line per request,
  no bodies), and `budgetOptionHint` / `connectionCapOptionHint` (the settings named, as "consider raising",
  in the transport's budget and connection-limit `503` log lines; ingest sets
  `analysisd.server_enriched_events_max_inflight_bytes` and `…_max_connections`). Timeouts and the `0660`
  socket mode are the transport's.

### API server (`include/httpsrv/apiServer.hpp`)

`makeApiServer()` builds the API instance: 4 workers, queue 64, no byte budget (no API route charges it, so
the body is bounded only by the route caps), `100 Continue`, detailed TRACE, metrics `"api"`.
`ApiRouteRegistrar` is the `IRouteRegistrar` the API modules register on: a Control route without its own cap
gets `analysisd.server_api_payload_max_bytes` (0 = unlimited), a Liveness route 4 KiB
(`API_LIVENESS_BODY_CAP`), each with the documented `413` text from `payloadTooLargeText()`
(`Payload too large. Max allowed: <n> bytes (<n/1024> KiB).`).

## Server Instances

The engine creates up to two server instances in `main.cpp`:

| Instance | Name | Socket key | Body limit | Logging | Purpose |
|----------|------|------------|------------|---------|---------|
| `apiServer` | `"API services"` | `conf::key::SERVER_API_SOCKET` (`engine-api-http.sock`) | `analysisd.server_api_payload_max_bytes` per route, `0` unlimited (a negative value is logged and treated as `0`); `GET /status` and `POST /metrics/*` 4 KiB; no byte budget | Detailed | Management API, built by `makeApiServer()`; routes registered through `ApiRouteRegistrar` |
| `engineRemoteServer` | `"Event ingest"` | `conf::key::SERVER_ENRICHED_EVENTS_SOCKET` (`engine-ingest-http.sock`) | `analysisd.server_enriched_events_max_body_bytes` (64 MiB), plus a connection cap and an in-flight byte budget | Minimal | Event ingestion (`/events/enriched`), built by `api::event::makeIngestServer()`; created only when `analysisd.server_enable_event_processing` is true |

## API Route Registration

Nine API sub-modules register handlers on the API server (`api::rawevtindexer` only when the raw event
indexer exists), plus one direct route on the event server. The request/response contracts are
documented for operators in the engine's [public](../../../../docs/ref/modules/engine/public-api-reference.md)
and [private](../../../../docs/ref/modules/engine/private-api-reference.md) API references.

| Sub-module | Routes | Server |
|------------|--------|--------|
| `api::metrics` | `POST /metrics/{enable,get,list,dump}` | API (Liveness, inline) |
| `api::geo` | `POST /_internal/geo/db/{get,list}` | API |
| `api::router` | `POST /_internal/router/route/{post,delete,get,reload,patchPriority}`, `POST /_internal/router/table/get` | API |
| `api::tester` | `POST /_internal/tester/session/{post,delete,get,reload}`, `POST /_internal/tester/table/get`, `POST /_internal/tester/run/post`, `POST /logtest`, `DELETE /logtest` | API |
| `api::dumper` | `POST /_internal/event-dumper/{activate,deactivate,status}` | API |
| `api::rawevtindexer` | `POST /_internal/raweventindexer/status` | API |
| `api::cmcrud` | `POST /_internal/content/namespace/{list,create,delete,import}`, `POST /_internal/content/policy/{upsert,delete}`, `POST /_internal/content/{list,get,upsert,delete}`, `POST /content/validate/{policy,resource}` | API |
| `api::ioccrud` | `POST /content/ioc/update`, `GET /content/ioc/state` | API |
| `api::status` | `GET /status` | API (Liveness, inline) |
| `api::event` | `POST /events/enriched` | Event |

## Dependencies

| Dependency | CMake Target | Role |
|------------|-------------|------|
| `base` | `base` (via `httpsrv::ihttpsrv` and directly) | Logging, process utilities, `cpp_get_nproc()` |
| `eMessages` | `eMessages` (public) | Protobuf definitions (transitive, for the API modules) |
| `uds_http_server` | `wazuh_uds_http_server` (**private**, registered by an `if(NOT TARGET)` guard; the instrumented `wazuh_uds_http_server_tsan` under `ENGINE_ENABLE_TSAN`) | Transport |
| `fastmetrics` | `fastmetrics::fastmetrics` (**private**) | `registerMetrics()` |

`api::adapter` links only the interface target `httpsrv::ihttpsrv`; `api::event` and the engine executable link
`httpsrv` (`src/engine/CMakeLists.txt`).

## Configuration

The module reads no setting; `main.cpp` passes the socket paths and the API payload limit, and
`api::event::makeIngestServer()` sizes the ingest server from the three
`analysisd.server_enriched_events_max_*` keys (validated before the socket is bound). The keys
(`analysisd.server_api_socket`, `analysisd.server_api_payload_max_bytes`,
`analysisd.server_enriched_events_socket`, `analysisd.server_enable_event_processing`; registered in
`conf/src/conf.cpp`) and their defaults — `/var/wazuh-manager/queue/sockets/engine-api-http.sock` and
`/var/wazuh-manager/queue/sockets/engine-ingest-http.sock` on a manager — are documented for operators in
[Engine API server](../../../../docs/ref/modules/engine/configuration.md#engine-api-server).
`analysisd.server_api_timeout` is not a server timeout: `main.cpp` passes it to the router orchestrator as
the tester timeout, which bounds how long the tester API handlers wait for a test result.

## Integration in `main.cpp`

```cpp
// 1. Create the API server, the registrar that applies its body limits, and its exit hook (error paths)
apiServer = httpsrv::makeApiServer();
const auto apiRoutes = std::make_shared<httpsrv::ApiRouteRegistrar>(apiServer, serverApiPayloadMaxBytes);
exitHandler.add([apiServer]() { if (apiServer->isRunning()) apiServer->shutdown(); eMessage::ShutdownEMessageLibrary(); });

// 2. Register all API route handlers
api::metrics::handlers::registerHandlers(metricsManager, apiRoutes, "wazuh-manager-analysisd", engineUptimeISO);
api::geo::handlers::registerHandlers(geoManager, apiRoutes);
api::router::handlers::registerHandlers(orchestrator, cmStore, apiRoutes);
// ... tester, dumper, rawevtindexer (if enabled), cmcrud, ioccrud, status ...

// 3. Start the API server
apiServer->start(confManager.get<std::string>(conf::key::SERVER_API_SOCKET));

// 4. Only when analysisd.server_enable_event_processing is true: the event ingest server
//    (route /events/enriched, its executor and its server.ingest.* metrics), and its exit hook
engineRemoteServer = api::event::makeIngestServer(orchestrator, dumper, agentMetadataCache, ingestLimits);
exitHandler.add([engineRemoteServer]() { if (engineRemoteServer->isRunning()) engineRemoteServer->shutdown(); });

// 5. Start it
engineRemoteServer->start(confManager.get<std::string>(conf::key::SERVER_ENRICHED_EVENTS_SOCKET));
```

The main thread then polls `engineRemoteServer->isRunning()` every 100 ms (with event processing disabled,
the shutdown flag) and, when a shutdown signal arrives, calls `shutdownAll({ingest, api})` (or `({api})`):
both servers stop accepting first, drain together until 10 s after the call, then stop, before any dependency's exit
hook runs.

## Thread Safety

- Register every route before `start()`: the transport's route table is immutable once started, and a later
  `addRoute` throws `std::logic_error`.
- Handlers run concurrently on the executor's workers (inline ones on the transport's I/O threads) and must be
  thread-safe themselves; a response is sent exactly once.
- `shutdown()`, `shutdownAll()` and the destructor are safe from the thread that owns the server; `stats()` can
  be read from any thread at any time (the metrics do).

## File Structure

```
httpsrv/
├── CMakeLists.txt                     # Build: ihttpsrv (INTERFACE), httpsrv (STATIC), httpsrv_utest
├── interface/httpsrv/
│   ├── types.hpp                      # Method, Request/Response, RouteHandler, RouteOptions, UNLIMITED_BODY
│   └── irouteregistrar.hpp            # IRouteRegistrar
├── include/httpsrv/
│   ├── server.hpp                     # Server, ServerOptions, ServerStats, shutdownAll(), registerMetrics()
│   ├── apiServer.hpp                  # makeApiServer(), ApiRouteRegistrar, payloadTooLargeText()
│   └── boundedExecutor.hpp            # Fixed worker pool with a bounded queue
├── src/
│   ├── server.cpp
│   ├── apiServer.cpp
│   └── boundedExecutor.cpp
└── test/src/unit/
    ├── server_test.cpp                # Server over a real socket
    ├── serverMetrics_test.cpp         # registerMetrics(): names, values, server gone
    ├── apiServer_test.cpp             # API limits and documented 413 text, server.api.* metrics
    └── boundedExecutor_test.cpp       # Queue bound, admission, drain deadline, join
```

## Testing

### Unit Tests (`httpsrv_utest`)

| Test | Verifies |
|------|----------|
| `BoundedExecutorTest.*` | Every job runs once; full queue and closed admission refuse; the drain runs queued jobs, rejects the unstarted ones at the deadline and reports running ones; `join()` and the destructor wait for a job that outlived the deadline, and `join()` can be called twice |
| `ServerTest.*` | Neutral request/response round trip; a repeated header counted as 2; executor full ⇒ `503` busy; handler throw ⇒ `500` text; a running reply delivered within the deadline; unstarted requests ⇒ shutdown `503`; `shutdownAll()` stops every server; socket mode `0660`; a path that is not a socket refused (and kept); `expectContinue` reaches the wire; an inline route answers while the executor is full, and a throw there is a `500`; without a byte budget the parser has no limit; registering through `IRouteRegistrar`; the connection-limit `503` counted as a connection shed; the connection-limit and budget `503` log lines name the settings given as `connectionCapOptionHint` / `budgetOptionHint` |
| `ServerOutlivingHandlerTest.*` | Parameterized over `shutdown()` and `shutdownAll()`: each returns only after a handler that outlived the deadline (and the transport's 2 s reply drain) ended |
| `ApiServerTest.*` | The documented `413` text (`payloadTooLargeText()`), a Control route over the limit refused before its body, `0` meaning unlimited, Liveness routes capped at 4 KiB, the eleven `server.api.*` metrics |
| `ServerMetricsTest.*` | The eleven `server.<instance>.*` names registered; the values follow `stats()` (running, queue depth, executor-full `503`, `413`); every metric reads 0 once the server is destroyed |

The API's routes end to end — every handler on the real socket — are covered by the engine integration tests
(`src/engine/test/integration_tests`, `engine-it`).

Build and run:

```bash
make -C src -j TARGET=manager ENGINE_TEST=y      # from the repository root; ENGINE_TEST sticks in the cache
src/build/engine/source/httpsrv/httpsrv_utest
```

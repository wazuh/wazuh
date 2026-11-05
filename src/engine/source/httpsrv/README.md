# HttpSrv Module

## Overview

The **httpsrv** module provides an HTTP server over Unix Domain Sockets (UDS) for the Wazuh engine's internal API. Built on top of [cpp-httplib](https://github.com/yhirose/cpp-httplib), it handles route registration, request dispatching, payload size enforcement, and lifecycle management (start/stop with optional background thread). The engine runs up to two server instances: the API server (management, metrics, geo, etc.) on this cpp-httplib `Server`, and, when event processing is enabled, the event ingest server on `UdsServer` (see below), which runs on the manager's shared HTTP-over-UDS transport.

## Architecture

```
                      Unix Domain Socket
                    (AF_UNIX, .sock file)
                            │
                ┌───────────▼───────────────────────────────────────────┐
                │            httpsrv::Server                            │
                │                                                       │
                │   httplib::Server (thread pool: 2–16 workers)         │
                │                                                       │
                │   ┌───────────────────────────────────────────────┐   │
                │   │  Route Table                                   │   │
                │   │                                                │   │
                │   │  POST /events/enriched       → pushEvent        │   │
                │   │  POST /_internal/router/*    → router handlers  │   │
                │   │  POST /_internal/geo/db/*    → geo handlers     │   │
                │   │  POST /metrics/*             → metrics handlers │   │
                │   │  POST /_internal/event-dumper/* → dumper        │   │
                │   │  GET  /status                → status handler   │   │
                │   │  ...                                            │   │
                │   └───────────────────────────────────────────────┘   │
                │                                                       │
                │   Features:                                           │
                │   • Payload size limit (413 response)                 │
                │   • Exception handler (500 on uncaught exceptions)    │
                │   • Request/response logging (TRACE level)            │
                │   • Socket permission set to 0660 after bind          │
                └───────────────────────────────────────────────────────┘
                            │
                    addRoute(Method, path, handler)
                            │
                ┌───────────▼───────────────────────────────────────────┐
                │         api::adapter (separate module)                 │
                │                                                       │
                │   httplib::Request/Response ←→ Protobuf domain types   │
                │                                                       │
                │   parseRequest<Req,Res>() → deserialize proto from JSON│
                │   userResponse<Res>()     → serialize proto + 200 OK   │
                │   userErrorResponse<Res>()→ serialize error + 400      │
                │   internalErrorResponse() → serialize error + 500      │
                └───────────────────────────────────────────────────────┘
                            │
                     RouteHandler = std::function<void(
                         const httplib::Request&,
                         httplib::Response&)>
                            │
                ┌───────────▼───────────────────────────────────────────┐
                │           API Sub-modules                              │
                │                                                       │
                │   api/metrics    api/geo      api/router               │
                │   api/tester     api/dumper   api/rawevtindexer         │
                │   api/cmcrud     api/ioccrud  api/status                │
                │   api/event (event server)                              │
                └───────────────────────────────────────────────────────┘
```

## Key Concepts

### Interface (`IServer<ServerImpl>`)

CRTP interface in `interface/httpsrv/iserver.hpp`:

| Method | Description |
|--------|-------------|
| `start(socketPath, useThread)` | Bind to UDS and start listening. If `useThread=true`, runs in a background thread |
| `stop()` | Stop the server, join thread, remove socket file |
| `addRoute(method, route, handler)` | Register an HTTP handler for a method+path combination |
| `isRunning()` | Check if the server is currently listening |

### HTTP Methods

```cpp
enum class Method { GET, POST, PUT, DELETE, ERROR_METHOD };
```

Utility functions `methodToStr()` and `strToMethod()` convert between enum and string. `addRoute()` throws
`std::runtime_error` for `ERROR_METHOD`.

### Server Implementation

`Server` wraps `httplib::Server` and adds:

| Feature | Implementation |
|---------|----------------|
| **Unix Domain Socket** | `set_address_family(AF_UNIX)`, binds to file path |
| **Thread pool** | `CPPHTTPLIB_THREAD_POOL_COUNT` (unless predefined) = `cpp_get_nproc() - 1` clamped to `[2, 16]` (`include/httpsrv/server.hpp`) |
| **Payload limit** | `set_payload_max_length()` — `413` with `Payload too large. Max allowed: <n> bytes (<n/1024> KiB).` (or `Payload too large.` when unlimited); a 413 body set by a handler is kept |
| **Exception safety** | `set_exception_handler()` logs the exception at ERROR and answers `500` with `Internal server error` |
| **Logging** | Detailed mode: TRACE before the handler (method, path, body) and after it (request body truncated to 1024 chars, response status and body); minimal mode: one TRACE line per request |
| **Socket path** | `start()` throws if the path is empty, the server is running or the parent directory is missing; an existing socket file is removed first |
| **Socket permissions** | `chmod(0660)` after bind (a failure is only a WARNING) |
| **Threaded start** | Polls `is_running()` for up to 10 s; throws if bind/listen fails in that time (a slow start alone does not throw) |
| **Clean shutdown** | `stop()` is noexcept and a no-op when not running; otherwise stops, joins the thread and removes the socket file. The destructor calls it |

### Constructor Parameters

```cpp
Server(const std::string& id, size_t payloadMaxBytes = 0, bool enableDetailedLogging = true);
```

| Parameter | Description |
|-----------|-------------|
| `id` | String identifier for log messages and the server thread name (e.g., `"API services"`) |
| `payloadMaxBytes` | Maximum request body size in bytes. `0` = unlimited (`getPayloadMaxBytes()` returns it) |
| `enableDetailedLogging` | If `true`, logs full request method/path/body and response status. If `false`, logs only that a request was received |

### Route Handler Signature

All handlers must match the `httplib` callback signature:

```cpp
std::function<void(const httplib::Request&, httplib::Response&)>
```

The `api::adapter` module (separate from httpsrv) wraps this into `adapter::RouteHandler` and provides protobuf serialization/deserialization helpers.

## Server Instances

The engine creates up to two server instances in `main.cpp`:

| Instance | ID | Socket key | Payload Limit | Logging | Purpose |
|----------|-----|--------|---------------|---------|---------|
| `apiServer` (`httpsrv::Server`) | `"API services"` | `conf::key::SERVER_API_SOCKET` (`engine-api-http.sock`) | `analysisd.server_api_payload_max_bytes` (a negative value is logged and treated as `0`) | Detailed | Management API (routes, metrics, geo, content, etc.) |
| `engineRemoteServer` (`httpsrv::UdsServer`) | `"Event ingest"` | `conf::key::SERVER_ENRICHED_EVENTS_SOCKET` (`engine-ingest-http.sock`) | `analysisd.server_enriched_events_max_body_bytes` (64 MiB), plus a connection cap and an in-flight byte budget | Minimal | Event ingestion (`/events/enriched`), built by `api::event::makeIngestServer()`; created only when `analysisd.server_enable_event_processing` is true |

## API Route Registration

Nine API sub-modules register handlers on the API server (`api::rawevtindexer` only when the raw event
indexer exists), plus one direct route on the event server. The request/response contracts are
documented for operators in the engine's [public](../../../../docs/ref/modules/engine/public-api-reference.md)
and [private](../../../../docs/ref/modules/engine/private-api-reference.md) API references.

| Sub-module | Routes | Server |
|------------|--------|--------|
| `api::metrics` | `POST /metrics/{enable,get,list,dump}` | API |
| `api::geo` | `POST /_internal/geo/db/{get,list}` | API |
| `api::router` | `POST /_internal/router/route/{post,delete,get,reload,patchPriority}`, `POST /_internal/router/table/get` | API |
| `api::tester` | `POST /_internal/tester/session/{post,delete,get,reload}`, `POST /_internal/tester/table/get`, `POST /_internal/tester/run/post`, `POST /logtest`, `DELETE /logtest` | API |
| `api::dumper` | `POST /_internal/event-dumper/{activate,deactivate,status}` | API |
| `api::rawevtindexer` | `POST /_internal/raweventindexer/status` | API |
| `api::cmcrud` | `POST /_internal/content/namespace/{list,create,delete,import}`, `POST /_internal/content/policy/{upsert,delete}`, `POST /_internal/content/{list,get,upsert,delete}`, `POST /content/validate/{policy,resource}` | API |
| `api::ioccrud` | `POST /content/ioc/update`, `GET /content/ioc/state` | API |
| `api::status` | `GET /status` | API |
| `api::event` | `POST /events/enriched` | Event |

## UdsServer (shared `uds_http_server` transport)

`httpsrv::UdsServer` serves a socket on the manager's shared HTTP-over-UDS transport
(`src/shared_modules/uds_http_server`, linked PRIVATE: no transport type appears in an httpsrv
header). It coexists with the cpp-httplib `httpsrv::Server` while the engine moves its servers over.

- **Neutral types** (`interface/httpsrv/types.hpp`): `Request` (method, raw target, lower-cased
  headers, `header()`, `headerCount()` — 2 means "more than once" — and a zero-copy `body` view
  kept alive by `owner`), `Response` (status, body, content type) and the synchronous
  `RouteHandler = void(const Request&, Response&)`. `Request::fromOwned()` builds one outside a
  transport (tests).
- **Executor** (`BoundedExecutor`): the transport's I/O threads never run a handler. Each admitted
  request becomes a job of a fixed pool with a bounded queue (`executorThreads`, `executorQueue`).
- **Answers the server writes itself**: executor queue full ⇒ `503 {"error":"Server busy","code":503}`;
  stopping ⇒ `503 {"error":"Server shutting down","code":503}`; handler threw ⇒ `500` `Internal server error`
  (`text/plain`). The transport adds its own `404/405/411/413/431/503/504` (see
  `docs/ref/modules/utils/uds-http-server/`).
- **Shutdown** (`shutdown()` for one server, `shutdownAll()` for several, default deadline 10 s):
  1. `stopAccepting()` on every server — no new request reaches a handler, replies still go out;
  2. `closeAdmission()` on every executor — nothing new is queued, queued requests keep running;
  3. `drainUntil(deadline)` in parallel — at the deadline, unstarted requests get the shutdown `503`
     and running ones are reported as abandoned;
  4. `stop()` on every transport;
  5. `waitForHandlers()` on every server — a handler still running past the deadline is waited
     for (with a WARN naming how many), never left running; its late reply is dropped.
  `shutdown()` and `shutdownAll()` return only after step 5, so the caller can destroy what the
  handlers use (the engine shuts protobuf down right after) without a handler running into it.
- **Stats** (`stats()`): in-flight bytes/requests and sessions from the transport, queue depth,
  running handlers, `503`/`500` counters by cause and the transport's `413`s.
- **Metrics** (`registerMetrics(weakServer, instance)`): publishes `stats()` as eleven fastmetrics pull
  metrics named `server.<instance>.<suffix>` (`metric_names.hpp`: `server_metric()` and the
  `SERVER_*` suffixes). They hold a weak reference and read 0 once the server is gone. fastmetrics keeps
  the first registration of a name, so register each instance name once per process. The ingest
  server registers `"ingest"`; the operator catalog is in the engine book's
  [Metrics](../../../../docs/ref/modules/engine/README.md#metrics).
- `Options`: name and log tag, `maxConnections`, `maxInFlightBytes` (0 = transport default),
  `maxBodySize`, executor size, `expectContinue` (answer `Expect: 100-continue` once admitted),
  `detailedLogging` (one TRACE line per request, no bodies), and `budgetOptionHint` / `connectionCapOptionHint`
  (the settings named, as "consider raising", in the transport's budget and connection-limit `503` log lines; the
  ingest server sets `analysisd.server_enriched_events_max_inflight_bytes` and `…_max_connections`). I/O threads,
  timeouts and the `0660` socket mode are the transport's.

## Dependencies

| Dependency | CMake Target | Role |
|------------|-------------|------|
| `base` | `base` (via `httpsrv::ihttpsrv` and directly) | Logging, process utilities, `cpp_get_nproc()` |
| `httplib` | header-only (`httplib.h`), reached through the `eMessages` link | HTTP server implementation |
| `eMessages` | `eMessages` (public) | Protobuf definitions (transitive) |
| `uds_http_server` | `wazuh_uds_http_server` (**private**, registered by an `if(NOT TARGET)` guard) | Transport of `UdsServer` |
| `fastmetrics` | `fastmetrics::fastmetrics` (**private**) | `registerMetrics()` |

`api::adapter` links `httpsrv`; the engine executable links it directly (`src/engine/CMakeLists.txt`).

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
// 1. Create API server with payload limit, and its shutdown hook
apiServer = std::make_shared<httpsrv::Server>("API services", static_cast<size_t>(serverApiPayloadMaxBytes), true);
exitHandler.add([apiServer]() { apiServer->stop(); eMessage::ShutdownEMessageLibrary(); });

// 2. Register all API route handlers
api::metrics::handlers::registerHandlers(metricsManager, apiServer, "wazuh-manager-analysisd", engineUptimeISO);
api::geo::handlers::registerHandlers(geoManager, apiServer);
api::router::handlers::registerHandlers(orchestrator, cmStore, apiServer);
// ... tester, dumper, rawevtindexer (if enabled), cmcrud, ioccrud, status ...

// 3. Start API server (threaded)
apiServer->start(confManager.get<std::string>(conf::key::SERVER_API_SOCKET));

// 4. Only when analysisd.server_enable_event_processing is true: the event ingest server on the
//    shared transport (route /events/enriched, its executor and its server.ingest.* metrics),
//    and its exit hook
engineRemoteServer = api::event::makeIngestServer(orchestrator, dumper, agentMetadataCache, ingestLimits);
exitHandler.add([engineRemoteServer]() { if (engineRemoteServer->isRunning()) engineRemoteServer->shutdown(); });

// 5. Start it
engineRemoteServer->start(confManager.get<std::string>(conf::key::SERVER_ENRICHED_EVENTS_SOCKET));
```

The main thread then polls `engineRemoteServer->isRunning()` every 100 ms and, when a shutdown signal
arrives, calls `shutdown(DEFAULT_SHUTDOWN_DEADLINE)` (stop accepting, drain for up to 10 s, stop).

## Thread Safety

- Register routes (`addRoute`) **before** `start()`, as `main.cpp` does. Adding a route to a running server does not throw (`AddRouteStarted`), but `httplib::Server` does not synchronize its handler tables with in-flight dispatch.
- Registering the same method and path twice does not throw, and the **first** handler keeps serving (`ServeIgnoredOverride`).
- Request handling: `httplib` dispatches requests across its thread pool (2–16 workers); handlers run concurrently and must be thread-safe themselves.
- `stop()` is noexcept and safe to call from any thread. It signals the server, joins the background thread, and cleans up the socket file.

## File Structure

```
httpsrv/
├── CMakeLists.txt                                   # Build: ihttpsrv (INTERFACE), httpsrv (STATIC)
├── interface/httpsrv/
│   ├── iserver.hpp                                  # IServer<> CRTP interface (start, stop, addRoute, isRunning)
│   └── types.hpp                                    # Method, Request/Response, RouteHandler, RouteOptions
├── include/httpsrv/
│   ├── server.hpp                                   # Server class declaration (httplib wrapper)
│   ├── boundedExecutor.hpp                          # Fixed worker pool with a bounded queue
│   └── udsServer.hpp                                # UdsServer, shutdownAll(), registerMetrics()
├── src/
│   ├── server.cpp                                   # Server implementation (bind, listen, route dispatch, logging)
│   ├── boundedExecutor.cpp
│   └── udsServer.cpp
└── test/src/
    ├── generic_request.proto                        # Test protobuf definition
    ├── generic_request.pb.h                         # Generated protobuf header
    ├── generic_request.pb.cc                        # Generated protobuf source
    ├── unit/
    │   ├── server_test.cpp                          # Unit tests (create, start/stop, socket paths, addRoute)
    │   ├── boundedExecutor_test.cpp                 # Queue bound, admission, drain deadline, join
    │   ├── udsServer_test.cpp                       # UdsServer over a real socket
    │   └── udsServerMetrics_test.cpp                # registerMetrics(): names, values, server gone
    └── component/
        └── server_test.cpp                          # Component tests over a real UDS client (routes, payload limits)
```

## Testing

### Unit Tests (`httpsrv_utest`)

| Test | Verifies |
|------|----------|
| `Create` | Server construction succeeds |
| `StartEmptySocketPath` | Empty path throws `std::runtime_error` |
| `StartInvalidSocketPath` | Non-existent parent directory throws |
| `StartStop` | Normal start/stop lifecycle |
| `StartStopCurrentThread` | Blocking start mode (no background thread) |
| `StopNotStarted` | `stop()` on a server never started |
| `StartAlreadyStarted` | A second `start()` throws |
| `AddRoute`, `AddOverrideRoute` | Route registration, including the same route twice |
| `IsRunning` | `isRunning()` before and after start |
| `BoundedExecutorTest.*` | Every job runs once; full queue and closed admission refuse; the drain runs queued jobs, rejects the unstarted ones at the deadline and reports running ones; `join()` and the destructor wait for a job that outlived the deadline, and `join()` can be called twice |
| `UdsServerTest.*` | Neutral request/response round trip; a repeated header counted as 2; executor full ⇒ `503` busy; handler throw ⇒ `500` text; a running reply delivered within the deadline; unstarted requests ⇒ shutdown `503`; `shutdownAll()` stops every server; socket mode `0660`; a path that is not a socket refused (and kept); `expectContinue` reaches the wire; the connection-limit and budget `503` log lines name the settings given as `connectionCapOptionHint` / `budgetOptionHint` |
| `UdsServerOutlivingHandlerTest.*` | Parameterized over `shutdown()` and `shutdownAll()`: each returns only after a handler that outlived the deadline (and the transport's 2 s reply drain) ended |
| `UdsServerMetricsTest.*` | The eleven `server.<instance>.*` names registered; the values follow `stats()` (running, queue depth, executor-full `503`, `413`); every metric reads 0 once the server is destroyed |

### Component Tests (`httpsrv_ctest`)

| Test | Verifies |
|------|----------|
| `ServerStart` | Server starts and listens on UDS |
| `ServerStartTwice` | Double start throws |
| `ServerStop` | Clean shutdown |
| `RouteTest.*` (GET/POST/PUT/DELETE) | Adding routes before/after start and twice, serving, not serving when stopped, the ignored override, `500` on an uncaught handler exception |
| `BodyRouteTest.*` | Payload at the limit accepted, over the limit `413`, unlimited accepts a large body, a handler's own `413` body preserved |

Build and run:

```bash
make -C src -j TARGET=manager ENGINE_TEST=y      # from the repository root; ENGINE_TEST sticks in the cache
src/build/engine/source/httpsrv/httpsrv_utest
src/build/engine/source/httpsrv/httpsrv_ctest
```

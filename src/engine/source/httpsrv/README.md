# HttpSrv Module

## Overview

The **httpsrv** module provides an HTTP server over Unix Domain Sockets (UDS) for the Wazuh engine's internal API. Built on top of [cpp-httplib](https://github.com/yhirose/cpp-httplib), it handles route registration, request dispatching, payload size enforcement, and lifecycle management (start/stop with optional background thread). The engine runs up to two server instances: one for API services (management, metrics, geo, etc.) and, when event processing is enabled, one for event ingestion.

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
| `id` | String identifier for log messages and the server thread name (e.g., `"API services"`, `"Event services"`) |
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
| `apiServer` | `"API services"` | `conf::key::SERVER_API_SOCKET` (`engine-api-http.sock`) | `analysisd.server_api_payload_max_bytes` (a negative value is logged and treated as `0`) | Detailed | Management API (routes, metrics, geo, content, etc.) |
| `engineRemoteServer` | `"Event services"` | `conf::key::SERVER_ENRICHED_EVENTS_SOCKET` (`engine-ingest-http.sock`) | Unlimited (`0`) | Minimal | Event ingestion (`/events/enriched`); created only when `analysisd.server_enable_event_processing` is true |

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

## Dependencies

| Dependency | CMake Target | Role |
|------------|-------------|------|
| `base` | `base` (via `httpsrv::ihttpsrv` and directly) | Logging, process utilities, `cpp_get_nproc()` |
| `httplib` | header-only (`httplib.h`), reached through the `eMessages` link | HTTP server implementation |
| `eMessages` | `eMessages` (public) | Protobuf definitions (transitive) |

`api::adapter` links `httpsrv`; the engine executable links it directly (`src/engine/CMakeLists.txt`).

## Configuration

The module reads no setting; `main.cpp` passes the socket paths and the payload limit. The keys
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

// 4. Only when analysisd.server_enable_event_processing is true:
//    event server (unlimited payload, minimal logging) and its shutdown hook
engineRemoteServer = std::make_shared<httpsrv::Server>("Event services", 0, false);
exitHandler.add([engineRemoteServer]() { engineRemoteServer->stop(); });

// 5. Register event ingestion route
engineRemoteServer->addRoute(httpsrv::Method::POST,
                             "/events/enriched",
                             api::event::handlers::pushEvent(orchestrator, dumper, agentMetadataCache));

// 6. Start event server (threaded)
engineRemoteServer->start(confManager.get<std::string>(conf::key::SERVER_ENRICHED_EVENTS_SOCKET));
```

The main thread then polls `engineRemoteServer->isRunning()` every 100 ms and stops it when a shutdown
signal arrives.

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
│   └── iserver.hpp                                  # IServer<> CRTP interface (start, stop, addRoute, isRunning)
├── include/httpsrv/
│   └── server.hpp                                   # Server class declaration (httplib wrapper)
├── src/
│   └── server.cpp                                   # Server implementation (bind, listen, route dispatch, logging)
└── test/src/
    ├── generic_request.proto                        # Test protobuf definition
    ├── generic_request.pb.h                         # Generated protobuf header
    ├── generic_request.pb.cc                        # Generated protobuf source
    ├── unit/
    │   └── server_test.cpp                          # Unit tests (create, start/stop, socket paths, addRoute)
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

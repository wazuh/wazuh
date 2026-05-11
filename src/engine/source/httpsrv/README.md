# HttpSrv Module

## Overview

The **httpsrv** module provides an HTTP server over Unix Domain Sockets (UDS) for the Wazuh engine's internal API. Built on top of [cpp-httplib](https://github.com/yhirose/cpp-httplib), it handles route registration, request dispatching, payload size enforcement, and lifecycle management (start/stop with optional background thread). The engine runs two server instances: one for API services (management, metrics, geo, etc.) and one for event ingestion.

## Architecture

```
                      Unix Domain Socket
                    (AF_UNIX, .sock file)
                            │
                ┌───────────▼───────────────────────────────────────────┐
                │            httpsrv::Server                            │
                │                                                       │
                │   httplib::Server (thread pool: 8–16 workers)         │
                │                                                       │
                │   ┌───────────────────────────────────────────────┐   │
                │   │  Route Table                                   │   │
                │   │                                                │   │
                │   │  POST /events/enriched      → pushEvent        │   │
                │   │  POST /_internal/router/*    → router handlers  │   │
                │   │  POST /_internal/geo/db/*    → geo handlers     │   │
                │   │  POST /metrics/*             → metrics handlers │   │
                │   │  POST /_internal/event-*     → dumper handlers  │   │
                │   │  ...                                           │   │
                │   └───────────────────────────────────────────────┘   │
                │                                                       │
                │   Features:                                           │
                │   • Payload size limit (413 response)                 │
                │   • Exception handler (500 on uncaught exceptions)    │
                │   • Request/response logging (TRACE level)            │
                │   • Socket permission set to 660                      │
                └───────────────────────────────────────────────────────┘
                            │
                    addRoute(Method, path, handler)
                            │
                ┌───────────▼───────────────────────────────────────────┐
                │         api::adapter (separate module)                 │
                │                                                       │
                │   httplib::Request/Response ←→ Protobuf domain types   │
                │                                                       │
                │   parseRequest<Req>()     → deserialize proto from JSON│
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
                │   api/cmcrud     api/ioccrud  api/event                 │
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

Utility functions `methodToStr()` and `strToMethod()` convert between enum and string.

### Server Implementation

`Server` wraps `httplib::Server` and adds:

| Feature | Implementation |
|---------|----------------|
| **Unix Domain Socket** | `set_address_family(AF_UNIX)`, binds to file path |
| **Thread pool** | `CPPHTTPLIB_THREAD_POOL_COUNT` clamped to `[8, 16]` based on `hardware_concurrency()` |
| **Payload limit** | `set_payload_max_length()` — returns `413 Payload Too Large` when exceeded |
| **Exception safety** | `set_exception_handler()` catches all route handler exceptions → `500 Internal Server Error` |
| **Logging** | `set_logger()` logs every request/response at TRACE level (truncated to 1024 chars) |
| **Socket permissions** | `chmod(660)` after bind for group-readable access |
| **Threaded start** | Waits up to 10s for server to become ready, throws on failure |
| **Clean shutdown** | `stop()` is noexcept, removes socket file, joins thread |

### Constructor Parameters

```cpp
Server(const std::string& id, size_t payloadMaxBytes = 0, bool enableDetailedLogging = true);
```

| Parameter | Description |
|-----------|-------------|
| `id` | String identifier for log messages (e.g., `"API services"`, `"Event services"`) |
| `payloadMaxBytes` | Maximum request body size in bytes. `0` = unlimited |
| `enableDetailedLogging` | If `true`, logs full request method/path/body and response status. If `false`, logs only that a request was received |

### Route Handler Signature

All handlers must match the `httplib` callback signature:

```cpp
std::function<void(const httplib::Request&, httplib::Response&)>
```

The `api::adapter` module (separate from httpsrv) wraps this into `adapter::RouteHandler` and provides protobuf serialization/deserialization helpers.

## Server Instances

The engine creates two separate server instances in `main.cpp`:

| Instance | ID | Socket | Payload Limit | Logging | Purpose |
|----------|-----|--------|---------------|---------|---------|
| `apiServer` | `"API services"` | `SERVER_API_SOCKET` | Configurable | Detailed | Management API (routes, metrics, geo, content, etc.) |
| `engineRemoteServer` | `"Event services"` | `SERVER_ENRICHED_EVENTS_SOCKET` | Unlimited (`0`) | Minimal | Event ingestion (`/events/enriched`) |

## API Route Registration

Eight API sub-modules register handlers on the API server, plus one direct route on the event server:

| Sub-module | Routes | Server |
|------------|--------|--------|
| `api::metrics` | `/metrics/{enable,get,list,dump}` | API |
| `api::geo` | `/_internal/geo/db/{get,list}` | API |
| `api::router` | `/_internal/router/route/*`, `/_internal/router/table/get` | API |
| `api::tester` | `/_internal/tester/*` | API |
| `api::dumper` | `/_internal/event-dumper/{activate,deactivate,status}` | API |
| `api::rawevtindexer` | `/_internal/raweventindexer/status` | API |
| `api::cmcrud` | `/_internal/content/{namespace,policy,resource}/*` | API |
| `api::ioccrud` | `/content/ioc/{update,state}` | API |
| `api::event` | `POST /events/enriched` | Event |

## Dependencies

| Dependency | CMake Target | Role |
|------------|-------------|------|
| `base` | `base` | Logging, process utilities |
| `httplib` | (header-only, via `eMessages`) | HTTP server implementation |
| `eMessages` | `eMessages` | Protobuf definitions (transitive) |

## Configuration

| Key | Env Override | Default | Description |
|-----|-------------|---------|-------------|
| `analysisd.server_api_socket` | `WAZUH_SERVER_API_SOCKET` | `$WAZUH_HOME/queue/sockets/analysis` | UDS path for API server |
| `analysisd.server_api_timeout` | `WAZUH_SERVER_API_TIMEOUT` | `5000` | Server timeout (ms) |
| `analysisd.server_api_payload_max_bytes` | `WAZUH_SERVER_API_PAYLOAD_MAX_BYTES` | `0` (unlimited) | Max payload size for API server |
| `analysisd.server_enriched_events_socket` | `WAZUH_SERVER_ENRICHED_EVENTS_SOCKET` | `$WAZUH_HOME/queue/sockets/queue-http.sock` | UDS path for event server |

## Integration in `main.cpp`

```cpp
// 1. Create API server with payload limit
apiServer = std::make_shared<httpsrv::Server>(
    "API services", serverApiPayloadMaxBytes, true);

// 2. Register all API route handlers
api::metrics::handlers::registerHandlers(metricsManager, apiServer, ...);
api::geo::handlers::registerHandlers(geoManager, apiServer);
api::router::handlers::registerHandlers(orchestrator, cmStore, apiServer);
// ... 5 more sub-modules ...

// 3. Start API server (threaded)
apiServer->start(confManager.get<std::string>(conf::key::SERVER_API_SOCKET));

// 4. Create event server (unlimited payload, minimal logging)
engineRemoteServer = std::make_shared<httpsrv::Server>("Event services", 0, false);

// 5. Register event ingestion route
engineRemoteServer->addRoute(
    httpsrv::Method::POST, "/events/enriched",
    api::event::handlers::pushEvent(orchestrator, dumper));

// 6. Start event server (threaded)
engineRemoteServer->start(confManager.get<std::string>(conf::key::SERVER_ENRICHED_EVENTS_SOCKET));

// 7. Shutdown hooks
exitHandler.add([apiServer]() { apiServer->stop(); });
exitHandler.add([engineRemoteServer]() { engineRemoteServer->stop(); });
```

## Thread Safety

- Route registration (`addRoute`) must happen **before** `start()`. The underlying `httplib::Server` is not safe for concurrent route addition while running.
- Request handling is thread-safe: `httplib` dispatches requests across its thread pool (8–16 workers).
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
    │   └── server_test.cpp                          # Unit tests (create, start/stop, socket paths)
    └── component/
        └── server_test.cpp                          # Component tests (route handling, payload limits, protobuf)
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

### Component Tests (`httpsrv_ctest`)

| Test | Verifies |
|------|----------|
| `ServerStart` | Server starts and listens on UDS |
| `ServerStartTwice` | Double start throws |
| `ServerStop` | Clean shutdown |
| Route tests | GET/POST/PUT/DELETE route handling, protobuf serialization, payload limit enforcement (413) |

Build and run:

```bash
make --directory=$WAZUH_REPO/src -j TARGET=manager ENGINE_TEST=y DEBUG=yes
$ENGINE_BUILD/source/httpsrv/httpsrv_utest
$ENGINE_BUILD/source/httpsrv/httpsrv_ctest
```

# Wazuh Engine API — Developer Guide

## Overview

The Wazuh Engine exposes an internal HTTP API over a **Unix Domain Socket (UDS)**. This API is the control plane for the engine: it handles routing, testing, content management, archiving, geolocation, IOC synchronization, and more.

The API system spans five tightly-coupled locations in the repository:

| Layer | Path (relative to repo root) | Language | Role |
|-------|------|----------|------|
| **Proto definitions** | `src/engine/source/proto/src/*.proto` | Protobuf | Single source of truth for request/response schemas |
| **C++ Handlers** | `src/engine/source/api/` | C++ | HTTP handler implementations (this directory) |
| **Python transport library** | `src/engine/tools/api-communication/` | Python | Low-level client: proto→JSON over UDS |
| **Python CLI tools** | `src/engine/tools/engine-suite/` | Python | CLI commands that exercise the API |
| **OpenAPI spec** | `docs/ref/modules/engine/spec.yaml` | YAML | Public documentation (OpenAPI 3.0.3) |

### Communication Architecture

```
┌──────────────────────┐     HTTP/JSON over UDS      ┌──────────────────────┐
│  Python CLI tools    │  ─────────────────────────►  │   wazuh-engine       │
│  (engine-suite)      │  ◄─────────────────────────  │   (C++ HTTP server)  │
│                      │                               │                      │
│  Uses APIClient      │   Unix socket path            │  httplib server on   │
│  from                │   /run/wazuh-server/analysis   │  UDS, routes to     │
│  api-communication   │                               │  handler functions   │
└──────────────────────┘                               └──────────────────────┘
```

**Wire format**: All messages are serialized as **JSON** (not binary protobuf). Protobuf is used as a **schema and validation layer** on both sides:
- **C++ side**: `eMessage::eMessageFromJson` / `eMessageToJson` converts between protobuf objects and JSON strings.
- **Python side**: `google.protobuf.json_format.MessageToDict` / `ParseDict` converts between protobuf objects and Python dicts, which are then JSON-serialized via `json.dumps`.

---

## Directory Structure (this directory)

```
api/
├── CMakeLists.txt                              # INTERFACE library linking all sub-modules
├── README.md                                   # This document
│
├── adapter/                                    # Core framework (header-only)
│   ├── include/api/adapter/
│   │   ├── adapter.hpp                         # RouteHandler typedef, proto↔HTTP helpers
│   │   └── helpers.hpp                         # tryGetProperty helper
│   └── test/include/api/adapter/
│       └── baseHandler_test.hpp                # GTest base fixture for handler tests
│
├── router/                                     # Router route management handlers
│   ├── include/api/router/handlers.hpp
│   ├── src/handlers.cpp
│   └── test/src/unit/handlers_test.cpp
│
├── geo/                                        # GeoIP database query handlers
│   ├── include/api/geo/handlers.hpp
│   ├── src/handlers.cpp
│   └── test/src/unit/handlers_test.cpp
│
├── tester/                                     # Tester session & run handlers
│   ├── include/api/tester/handlers.hpp
│   ├── src/handlers.cpp
│   └── test/src/unit/handlers_test.cpp
│
├── event/                                      # Event ingestion handlers + NDJson parser
│   ├── include/api/event/
│   │   ├── handlers.hpp
│   │   └── ndJsonParser.hpp
│   ├── src/handlers.cpp
│   └── test/src/unit/
│
├── archiver/                                   # Archive enable/disable/status handlers
│   ├── include/api/archiver/handlers.hpp
│   ├── src/handlers.cpp
│   └── test/src/unit/handlers_test.cpp
│
├── rawevtindexer/                              # Raw event indexer status
│   ├── include/api/rawevtindexer/handlers.hpp
│   ├── src/handlers.cpp
│   └── test/src/unit/handlers_test.cpp
│
├── cmcrud/                                     # Content Manager: namespace, policy, resource CRUD
│   ├── include/api/cmcrud/handlers.hpp
│   ├── src/handlers.cpp
│   └── test/src/unit/handlers_test.cpp
│
└── ioccrud/                                    # IOC (Indicator of Compromise) sync handlers
    ├── include/api/ioccrud/handlers.hpp
    ├── src/handlersSync.cpp
    └── test/src/unit/handlers_test.cpp
```

---

## Core Concepts

### 1. `adapter::RouteHandler`

All handlers share a single type alias defined in `adapter/include/api/adapter/adapter.hpp`:

```cpp
using RouteHandler = std::function<void(const httplib::Request&, httplib::Response&)>;
```

This is a standard `httplib` request/response callback.

### 2. Adapter Utilities

The `adapter` module (header-only) provides template helpers for the proto↔HTTP conversion:

| Utility | Purpose |
|---------|---------|
| `parseRequest<Req, Res>(req)` | Deserialize JSON body → protobuf `Req`. Returns `ResOrErrorResp<pair<Handler, Req>>` |
| `userResponse<Res>(res)` | Serialize protobuf `Res` → 200 JSON response |
| `userErrorResponse<Res>(msg)` | 400 error with protobuf error envelope |
| `internalErrorResponse<Res>(msg)` | 500 error with protobuf error envelope |
| `getReqAndHandler<Req, Res, IHandler>(req, weakPtr)` | Combines `weak_ptr` lock + request parse (most common entry point) |
| `createRequest<Req>(req)` | Protobuf → `httplib::Request` (for testing) |
| `parseResponse<Res>(res)` | `httplib::Response` → protobuf (for testing) |

### 3. Handler Pattern (Convention-Based)

There is **no abstract base class**. Every sub-module follows the same convention:

**a) Free functions returning `RouteHandler` (factory pattern)**
```cpp
// In namespace api::<module>::handlers
adapter::RouteHandler activateArchiver(const std::shared_ptr<::archiver::IArchiver>& archiver);
```

**b) Inline `registerHandlers()` function wiring routes to the server**
```cpp
inline void registerHandlers(const std::shared_ptr<::archiver::IArchiver>& archiver,
                             const std::shared_ptr<httpsrv::Server>& server)
{
    server->addRoute(httpsrv::Method::POST, "/archiver/activate", activateArchiver(archiver));
    server->addRoute(httpsrv::Method::POST, "/archiver/deactivate", deactivateArchiver(archiver));
    server->addRoute(httpsrv::Method::POST, "/archiver/status", getArchiverStatus(archiver));
}
```

**c) Handler factory implementation (lambda capturing a `weak_ptr`)**
```cpp
adapter::RouteHandler activateArchiver(const std::shared_ptr<::archiver::IArchiver>& archiver)
{
    return [weakArchiver = std::weak_ptr(archiver)](const auto& req, auto& res)
    {
        using RequestType = eArchiver::ArchiverActivate_Request;
        using ResponseType = eEngine::GenericStatus_Response;

        // 1. Lock the weak_ptr and parse the protobuf request in one call
        auto result = adapter::getReqAndHandler<RequestType, ResponseType, ::archiver::IArchiver>(
            req, weakArchiver);
        if (adapter::isError(result)) {
            res = adapter::getErrorResp(result);
            return;
        }

        // 2. Destructure the result
        auto [archiver, protoReq] = adapter::getRes(result);

        // 3. Execute domain logic via the interface
        archiver->activate();

        // 4. Build and return the protobuf response
        ResponseType eResponse;
        eResponse.set_status(eEngine::ReturnStatus::OK);
        res = adapter::userResponse(eResponse);
    };
}
```

### 4. Build Structure

- The root `CMakeLists.txt` creates an **INTERFACE** target `api` that links all sub-modules.
- Each sub-module is a **STATIC** library (except `adapter`, which is INTERFACE/header-only).
- Each sub-module links `api::adapter` and its domain interface library (e.g., `archiver::iface`).
- Test targets link the module + `GTest::gtest_main` + `api::adapter::test` + domain mocks.

```cmake
# Example: archiver CMakeLists.txt
add_library(api_archiver STATIC ${SRC_DIR}/handlers.cpp)
target_link_libraries(api_archiver PUBLIC api::adapter archiver::iface)
add_library(api::archiver ALIAS api_archiver)
```

---

## Protobuf Definitions (`src/engine/source/proto/`)

### Proto Files

| File | Package | Domain |
|------|---------|--------|
| `engine.proto` | `com.wazuh.api.engine` | Base types: `ReturnStatus` enum, `GenericStatus_Response` |
| `router.proto` | `com.wazuh.api.engine.router` | Route CRUD, table queries, event queue |
| `tester.proto` | `com.wazuh.api.engine.tester` | Session management, test runs, logtest |
| `geo.proto` | `com.wazuh.api.engine.geo` | GeoIP database queries |
| `archiver.proto` | `com.wazuh.api.engine.archiver` | Archive activate/deactivate/status |
| `rawevtindexer.proto` | `com.wazuh.api.engine.rawevtindexer` | Raw event indexer status |
| `crud.proto` | `com.wazuh.api.engine.content` | Namespace, policy, and resource CRUD |
| `ioc.proto` | `com.wazuh.api.engine.ioc` | IOC sync: update and state |
| `metrics.proto` | `com.wazuh.api.engine.metrics` | Metrics dump/get/enable/list (internal only) |
| `request_response.proto` | `com.wazuh.api.engine.test` | Generic test request/response |

### Naming Convention

Proto messages follow a strict naming pattern:
```
{Action}{Resource}_{Request|Response}
```

Examples:
- `ArchiverActivate_Request` / `GenericStatus_Response` (shared)
- `RoutePost_Request` / `RouteGet_Response`
- `SessionPost_Request` / `SessionGet_Response`

When an endpoint returns only a status, it uses the shared `GenericStatus_Response` from `engine.proto`.

### Code Generation

Proto files are the **single source of truth**. Both C++ and Python code are generated from them.

**Generated output locations:**
- **C++**: `src/engine/source/proto/include/eMessages/*.pb.{cc,h}` (committed to the repo)
- **Python**: `src/engine/tools/api-communication/src/api_communication/proto/*_pb2.{py,pyi}` (committed to the repo)

**How to regenerate:**

```bash
cd src/engine
cmake --preset debug -DENGINE_GENERATE_PROTO=ON
cmake --build ./build --target generate_protobuf_code
```

Or via the top-level Makefile:
```bash
/usr/bin/make --directory ./src TARGET=server  # with ENGINE_GENERATE_PROTO=ON in CMake
```

**What `generateCode.sh` does:**
1. Runs `protoc` with `--cpp_out` → generates `.pb.cc` and `.pb.h` in `source/proto/include/eMessages/`
2. Runs `protoc` with `--python_out` and `--pyi_out` → generates `_pb2.py` and `.pyi` in `tools/api-communication/src/api_communication/proto/`
3. Cleans old generated files first (preserves `eMessage.h`, `readme.md`, and `__init__.py`)
4. Runs `clang-format` on `.proto` sources
5. Post-processes Python imports: rewrites `import foo_pb2 as ...` → `import api_communication.proto.foo_pb2 as ...`

> **Important**: After modifying any `.proto` file, you **must** regenerate the code. Both the C++ `.pb.h/.pb.cc` files and Python `_pb2.py/.pyi` files are committed to the repository.

---

## Python Transport Library (`src/engine/tools/api-communication/`)

### Package: `api_communication`

A thin HTTP client that uses protobuf for type-safe schema validation. The wire format is **plain JSON over HTTP on a Unix Domain Socket**.

**Installation:**
```bash
pip install -e src/engine/tools/api-communication
```

### Key Components

#### `api_communication.client.APIClient`

```python
from api_communication.client import APIClient

client = APIClient("/run/wazuh-server/analysis")  # UDS path

# Option 1: send_recv (returns raw dict)
error, response_dict = client.send_recv(proto_request_message)

# Option 2: send (validates response against a proto type)
error, response_dict = client.send(request_proto, response_proto)

# Option 3: jsend (send raw JSON, use proto only for endpoint routing)
error, response_dict = client.jsend(json_dict, request_proto, response_proto)
```

**Return convention**: All methods return `Tuple[Optional[str], dict]` — `(error_string_or_None, json_response)`.

**Transport flow:**
1. `MessageToDict(proto_message)` → Python dict
2. `get_endpoint(proto_message)` → `(error, endpoint_path, http_method)`
3. `json.dumps(dict)` → HTTP body, sent via `httpx.Client(transport=HTTPTransport(uds=...))`
4. Response JSON → `ParseDict(json, response_proto)` for validation

#### `api_communication.endpoints.get_endpoint`

A static dispatch table mapping protobuf request message types to HTTP endpoints:

```python
def get_endpoint(message: Message) -> Tuple[Optional[str], str, str]:
    """Returns (error, endpoint_path, http_method)"""
    if isinstance(message, archiver.ArchiverActivate_Request):
        endpoint = 'archiver/activate'
    # ... instanceof checks for all message types
```

---

## Python CLI Tools (`src/engine/tools/engine-suite/`)

### Package: `engine-suite`

Provides 5 CLI entry points that exercise the API via `api-communication`:

| CLI Command | Module | Domain |
|------------|--------|--------|
| `engine-router` | `engine_router` | Route CRUD, table, ingest |
| `engine-test` | `engine_test` | Tester sessions, integration test runs |
| `engine-archiver` | `engine_archiver` | Archive activate/deactivate/status |
| `engine-public` | `engine_public` | Content validation, IOC, logtest cleanup |
| `engine-private` | `engine_private` | Internal CRUD: namespaces, resources, policies, geo, rawevt |

**Installation:**
```bash
pip install -e src/engine/tools/engine-suite
```

### Command Module Pattern

Every command module follows a two-function pattern:

```python
# File: engine_archiver/cmds/activate.py

from api_communication.client import APIClient
import api_communication.proto.archiver_pb2 as archiver
import api_communication.proto.engine_pb2 as engine

def run(args):
    client = APIClient(args['api_socket'])

    request = archiver.ArchiverActivate_Request()
    error, response = client.send_recv(request)
    if error:
        sys.exit(f'Error: {error}')

    parsed = ParseDict(response, engine.GenericStatus_Response())
    if parsed.status == engine.ERROR:
        sys.exit(f'Error: {parsed.error}')

    return 0

def configure(subparsers):
    parser = subparsers.add_parser('activate', help='Activate the archiver')
    parser.set_defaults(func=run)
```

### CLI Entry Point Pattern (`__main__.py`)

```python
def parse_args():
    parser = argparse.ArgumentParser(prog='engine-archiver')
    parser.add_argument('--api-socket', type=str, default=Constants.SOCKET_PATH)
    subparsers = parser.add_subparsers(title='subcommands', required=True, dest='subcommand')

    configure_activate(subparsers)
    configure_deactivate(subparsers)
    configure_status(subparsers)

    return parser.parse_args()

def main():
    args = parse_args()
    args.func(vars(args))
```

---

## OpenAPI Specification (`docs/ref/modules/engine/spec.yaml`)

The spec documents the **public-facing** API endpoints using OpenAPI 3.0.3. It does **not** include internal (`_internal/`) endpoints or the metrics API.

### Tags (Domains)
`Router`, `Tester`, `Geo`, `Archiver`, `Raw Event Indexer`, `Content`, `Logtest`

### Schema Conventions

| Pattern | Example |
|---------|---------|
| Base response | `Response` schema: `{status: ReturnStatus, error?: string}` |
| Extended response | `allOf: [Response, {additional fields}]` — e.g., `RouteGet_Response` |
| Empty request | `EmptyRequest` schema: `{}` |
| Proto `google.protobuf.Struct` | `type: object` (free-form JSON) |
| Proto `repeated X` | `type: array, items: {$ref: X}` |
| Response codes | 200 (success or domain response), 400 (validation error), 500 (internal) |

### Proto ↔ Spec Mapping

| Protobuf | OpenAPI |
|----------|---------|
| `GenericStatus_Response` | `GenericSuccess_200` response component |
| `ReturnStatus` enum | `ReturnStatus` schema enum |
| `google.protobuf.Struct` | `type: object` |
| `optional string` | `nullable: true` / `type: string` |
| Message-specific `_Response` | `allOf` composition with `Response` base |

---

## Complete Endpoint Reference

### Public Endpoints

| Domain | Path | Method | Request Proto | Response Proto |
|--------|------|--------|---------------|----------------|
| **Content** | `/content/validate/policy` | POST | `policyValidate_Request` | `GenericStatus_Response` |
| **Content** | `/content/validate/resource` | POST | `resourceValidate_Request` | `GenericStatus_Response` |
| **Content** | `/content/ioc/update` | POST | `UpdateIoc_Request` | `GenericStatus_Response` |
| **Content** | `/content/ioc/state` | GET | `GetIocState_Request` | `GetIocState_Response` |
| **Logtest** | `/logtest` | POST | `PublicRunPost_Request` | `RunPost_Response` |
| **Logtest** | `/logtest` | DELETE | `LogtestDelete_Request` | `GenericStatus_Response` |
| **Router** | `/router/route/post` | POST | `RoutePost_Request` | `GenericStatus_Response` |
| **Router** | `/router/route/delete` | POST | `RouteDelete_Request` | `GenericStatus_Response` |
| **Router** | `/router/route/get` | POST | `RouteGet_Request` | `RouteGet_Response` |
| **Router** | `/router/route/reload` | POST | `RouteReload_Request` | `GenericStatus_Response` |
| **Router** | `/router/route/patchPriority` | POST | `RoutePatchPriority_Request` | `GenericStatus_Response` |
| **Router** | `/router/table/get` | POST | `TableGet_Request` | `TableGet_Response` |
| **Tester** | `/tester/session/post` | POST | `SessionPost_Request` | `GenericStatus_Response` |
| **Tester** | `/tester/session/delete` | POST | `SessionDelete_Request` | `GenericStatus_Response` |
| **Tester** | `/tester/session/get` | POST | `SessionGet_Request` | `SessionGet_Response` |
| **Tester** | `/tester/session/reload` | POST | `SessionReload_Request` | `GenericStatus_Response` |
| **Tester** | `/tester/run/post` | POST | `RunPost_Request` | `RunPost_Response` |
| **Tester** | `/tester/table/get` | POST | `TableGet_Request` | `TableGet_Response` |
| **Geo** | `/geo/db/get` | POST | `DbGet_Request` | `DbGet_Response` |
| **Geo** | `/geo/db/list` | POST | `DbList_Request` | `DbList_Response` |
| **Archiver** | `/archiver/activate` | POST | `ArchiverActivate_Request` | `GenericStatus_Response` |
| **Archiver** | `/archiver/deactivate` | POST | `ArchiverDeactivate_Request` | `GenericStatus_Response` |
| **Archiver** | `/archiver/status` | POST | `ArchiverStatus_Request` | `ArchiverStatus_Response` |

### Internal Endpoints (prefixed with `/_internal/`)

| Domain | Path | Method | Request Proto | Response Proto |
|--------|------|--------|---------------|----------------|
| **Raw Event Indexer** | `/_internal/raweventindexer/status` | POST | `RawEvtIndexerStatus_Request` | `RawEvtIndexerStatus_Response` |
| **Content NS** | `/_internal/content/namespace/list` | POST | `namespaceGet_Request` | `namespaceGet_Response` |
| **Content NS** | `/_internal/content/namespace/create` | POST | `namespacePost_Request` | `GenericStatus_Response` |
| **Content NS** | `/_internal/content/namespace/delete` | POST | `namespaceDelete_Request` | `GenericStatus_Response` |
| **Content NS** | `/_internal/content/namespace/import` | POST | `namespaceImport_Request` | `GenericStatus_Response` |
| **Content Policy** | `/_internal/content/policy/upsert` | POST | `policyPost_Request` | `GenericStatus_Response` |
| **Content Policy** | `/_internal/content/policy/delete` | POST | `policyDelete_Request` | `GenericStatus_Response` |
| **Content Resource** | `/_internal/content/list` | POST | `resourceList_Request` | `resourceList_Response` |
| **Content Resource** | `/_internal/content/get` | POST | `resourceGet_Request` | `resourceGet_Response` |
| **Content Resource** | `/_internal/content/upsert` | POST | `resourcePost_Request` | `GenericStatus_Response` |
| **Content Resource** | `/_internal/content/delete` | POST | `resourceDelete_Request` | `GenericStatus_Response` |

---

## Step-by-Step Guide: Adding a New Endpoint

This section provides a complete walkthrough for adding a new API endpoint with all the required artifacts.

### Step 1: Define the Protobuf Messages

Create or modify a `.proto` file in `src/engine/source/proto/src/`:

```proto
// src/engine/source/proto/src/example.proto
syntax = "proto3";
import "engine.proto";
package com.wazuh.api.engine.example;

message ExampleAction_Request {
    string name = 1;
    optional string description = 2;
}

message ExampleAction_Response {
    ReturnStatus status = 1;
    optional string error = 2;
    string result = 3;
}
```

**If the endpoint only returns a success/error status**, use `GenericStatus_Response` from `engine.proto` instead of defining a custom response.

### Step 2: Regenerate Proto Code

```bash
cd src/engine
cmake --preset debug -DENGINE_GENERATE_PROTO=ON
cmake --build ./build --target generate_protobuf_code
```

This generates:
- `source/proto/include/eMessages/example.pb.{cc,h}` (C++)
- `tools/api-communication/src/api_communication/proto/example_pb2.{py,pyi}` (Python)

### Step 3: Create the C++ Handler Module

Create a new directory `src/engine/source/api/example/` with this structure:

#### `include/api/example/handlers.hpp`

```cpp
#ifndef API_EXAMPLE_HANDLERS_HPP
#define API_EXAMPLE_HANDLERS_HPP

#include <api/adapter/adapter.hpp>
#include <example/iexample.hpp>  // Your domain interface
#include <base/baseTypes.hpp>

namespace api::example::handlers
{

adapter::RouteHandler exampleAction(const std::shared_ptr<::example::IExample>& example);

inline void registerHandlers(const std::shared_ptr<::example::IExample>& example,
                             const std::shared_ptr<httpsrv::Server>& server)
{
    server->addRoute(httpsrv::Method::POST, "/example/action", exampleAction(example));
}

} // namespace api::example::handlers

#endif // API_EXAMPLE_HANDLERS_HPP
```

#### `src/handlers.cpp`

```cpp
#include <api/example/handlers.hpp>
#include <base/logging.hpp>
#include <eMessages/example.pb.h>

namespace api::example::handlers
{
namespace eExample = adapter::eEngine::example;
namespace eEngine = adapter::eEngine;

adapter::RouteHandler exampleAction(const std::shared_ptr<::example::IExample>& example)
{
    return [lambdaName = logging::getLambdaName(__FUNCTION__, "apiHandler"),
            weakExample = std::weak_ptr(example)](const auto& req, auto& res)
    {
        using RequestType = eExample::ExampleAction_Request;
        using ResponseType = eExample::ExampleAction_Response;

        auto result = adapter::getReqAndHandler<RequestType, ResponseType, ::example::IExample>(
            req, weakExample);
        if (adapter::isError(result)) {
            res = adapter::getErrorResp(result);
            return;
        }

        auto [handler, protoReq] = adapter::getRes(result);

        // Execute domain logic
        const auto actionResult = handler->doAction(protoReq.name());

        // Build and return response
        ResponseType eResponse;
        eResponse.set_status(eEngine::ReturnStatus::OK);
        eResponse.set_result(actionResult);
        res = adapter::userResponse(eResponse);
    };
}
} // namespace api::example::handlers
```

#### `CMakeLists.txt`

```cmake
set(SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/src)
set(INC_DIR ${CMAKE_CURRENT_LIST_DIR}/include)

add_library(api_example STATIC ${SRC_DIR}/handlers.cpp)
target_include_directories(api_example PUBLIC ${INC_DIR} PRIVATE ${SRC_DIR})
target_link_libraries(api_example PUBLIC api::adapter example::iface)
add_library(api::example ALIAS api_example)

if(ENGINE_BUILD_TEST)
    set(TEST_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/test/src)
    set(UNIT_SRC_DIR ${TEST_SRC_DIR}/unit)

    add_executable(api_example_utest ${UNIT_SRC_DIR}/handlers_test.cpp)
    target_link_libraries(api_example_utest PRIVATE
        api::example GTest::gtest_main api::adapter::test example::mocks)
    gtest_discover_tests(api_example_utest)
endif()
```

#### Register in the root `api/CMakeLists.txt`

Add `add_subdirectory(${ENGINE_SOURCE_DIR}/api/example)` and link `api::example` to the `api` INTERFACE target.

### Step 4: Add the Python Endpoint Route

Edit `src/engine/tools/api-communication/src/api_communication/endpoints.py`:

```python
import api_communication.proto.example_pb2 as example

# Inside get_endpoint():
    # Example
    if isinstance(message, example.ExampleAction_Request):
        endpoint = 'example/action'
```

### Step 5: Create the Python CLI Command

Create a command module in the appropriate `engine-suite` CLI tool.

> **Which CLI tool?** Use `engine_public` for public-facing endpoints, `engine_private` for `_internal/` endpoints, `engine_router` for router-specific commands, `engine_archiver` for archiver commands, or `engine_test` for tester/session commands.

#### Output Formatting Conventions

All commands that return data should use `dict_to_str_yml()` from `shared.dumpers` for YAML output (the default). For commands where JSON output is also useful, add an `--output-format` argument with `choices=["text", "json"]`.

The `shared.dumpers` module provides:
- **`dict_to_str_yml(data)`** — Converts a dict to a YAML string using a custom `EngineDumper` (handles single-quotes → double-quotes, newlines → literal `|` block style).
- **`dict_to_str_json(data, pretty=False)`** — Converts a dict to a JSON string, optionally pretty-printed.

#### Argument Conventions

- **Positional arguments** for required identifiers (e.g., `name`, `uuid`, `route`).
- **Optional flags** with short aliases (e.g., `-d`, `--description`, `-n`, `--space`, `-c`, `--content`).
- **`choices`** for enum-like arguments (e.g., `choices=["text", "json"]` for output formats, valid type names, etc.). This enables shell autocomplete for those values.
- **`default`** values should always be explicit (e.g., `default=None`, `default="text"`, `default=False`).
- **`action='store_true'`** for boolean flags (e.g., `--json`).
- **stdin support**: For content arguments, allow reading from stdin when no value is provided (see upsert pattern below).

#### Command Module: Write-Only Example (no response data)

`src/engine/tools/engine-suite/src/engine_public/cmds/example/action.py`

```python
import sys
from google.protobuf.json_format import ParseDict

from api_communication.client import APIClient
import api_communication.proto.example_pb2 as example
import api_communication.proto.engine_pb2 as engine


def run(args):

    # Get the params
    api_socket: str = args['api_socket']

    # Create API client
    client = APIClient(api_socket)

    # Create the request
    request = example.ExampleAction_Request()
    request.name = args['name']
    if args['description']:
        request.description = args['description']

    # Send the request
    error, response = client.send_recv(request)
    if error:
        sys.exit(f'Error executing action: {error}')

    # Parse the response
    parsed_response = ParseDict(response, engine.GenericStatus_Response())
    if parsed_response.status == engine.ERROR:
        sys.exit(f'Error executing action: {parsed_response.error}')

    return 0


def configure(subparsers):
    parser = subparsers.add_parser('action', help='Execute an example action')
    parser.add_argument('name', type=str, help='Name of the example')
    parser.add_argument('-d', '--description', type=str, default=None,
                        help='Description of the action (optional)')
    parser.set_defaults(func=run)
```

#### Command Module: Read Example (returns data, YAML/JSON output)

`src/engine/tools/engine-suite/src/engine_public/cmds/example/get.py`

```python
import sys
import json
from google.protobuf.json_format import ParseDict
from shared.dumpers import dict_to_str_yml

from api_communication.client import APIClient
import api_communication.proto.example_pb2 as example
import api_communication.proto.engine_pb2 as engine


def run(args):

    # Get the params
    api_socket: str = args['api_socket']

    # Create API client
    client = APIClient(api_socket)

    # Create the request
    request = example.ExampleGet_Request()
    request.name = args['name']

    # Send the request
    error, response = client.send_recv(request)
    if error:
        sys.exit(f'Error getting example: {error}')

    # Parse the response
    parsed_response = ParseDict(response, example.ExampleGet_Response())
    if parsed_response.status == engine.ERROR:
        sys.exit(f'Error getting example: {parsed_response.error}')

    # Print the response in the requested format
    if args['output_format'] == 'json':
        print(json.dumps(response, indent=4))
    else:
        print(dict_to_str_yml(response))

    return 0


def configure(subparsers):
    parser = subparsers.add_parser('get', help='Get example details')
    parser.add_argument('name', type=str, help='Name of the example to get')
    parser.add_argument('-f', '--output-format', type=str,
                        choices=['text', 'json'], default='text',
                        help='Output format (text or json). Default: text')
    parser.set_defaults(func=run)
```

#### Command Module: Content Upsert Example (stdin support)

`src/engine/tools/engine-suite/src/engine_private/cmds/example/upsert.py`

```python
import sys

from api_communication.client import APIClient
import api_communication.proto.engine_pb2 as engine
import api_communication.proto.example_pb2 as example


def run(args):

    # Get the params
    api_socket: str = args['api_socket']

    # Create the request
    request = example.ExampleUpsert_Request()
    request.name = args['name']

    content = args['content']
    # Read all content from stdin if not provided as argument
    if not content:
        content = sys.stdin.read()
    request.ymlContent = content

    # Create the api request
    try:
        client = APIClient(api_socket)
        error, response = client.send(request, engine.GenericStatus_Response())

        if error:
            sys.exit(f'Error upserting example: {error}')

    except Exception as e:
        sys.exit(f'Error upserting example: {e}')

    return 0


def configure(subparsers):
    parser = subparsers.add_parser('upsert', help='Upsert an example resource')
    parser.add_argument('name', type=str, help='Name of the resource to upsert')
    parser.add_argument('-c', '--content', type=str, default='',
                        help='Content of the item, can be passed as argument or '
                        'redirected from a file using the "|" operator or the "<" '
                        'operator.')
    parser.set_defaults(func=run)
```

#### Register in the CLI's `__main__.py`

For a **flat CLI** (e.g., `engine-archiver`, `engine-router`) register directly on the root subparsers:

```python
from engine_public.cmds.example.action import configure as configure_example_action
from engine_public.cmds.example.get import configure as configure_example_get

# Inside parse_args(), after creating subparsers:
configure_example_action(subparsers)
configure_example_get(subparsers)
```

For a **nested CLI** (e.g., `engine-private` with `cm`, `ns`, `geo` groups) create a sub-parser group:

```python
from engine_private.cmds.example.action import configure as configure_example_action
from engine_private.cmds.example.get import configure as configure_example_get

# Inside parse_args():
example_parser = subparsers.add_parser('example', help='Example operations')
example_subparsers = example_parser.add_subparsers(
    title='example commands', required=True, dest='example_command')

configure_example_action(example_subparsers)
configure_example_get(example_subparsers)
```

> **Autocomplete**: The `__main__.py` files already include `argcomplete` support wrapped in a `try/except ImportError` block. When you define arguments with `choices` (e.g., `choices=['text', 'json']`), `argcomplete` will automatically provide tab-completion for those values. No additional code is needed in individual command modules.

### Step 6: Document in OpenAPI Spec

Add the endpoint to `docs/ref/modules/engine/spec.yaml`:

#### Path definition

```yaml
paths:
  /example/action:
    post:
      tags:
        - Example
      summary: Execute an example action
      description: Executes the example action with the given parameters.
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: "#/components/schemas/ExampleAction_Request"
      responses:
        "200":
          description: Successful operation
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/ExampleAction_Response"
        "400":
          $ref: "#/components/responses/BadRequest_400"
        "500":
          $ref: "#/components/responses/InternalServerError_500"
```

#### Schema definitions

```yaml
components:
  schemas:
    ExampleAction_Request:
      type: object
      required: [name]
      properties:
        name:
          type: string
          description: Name parameter
        description:
          type: string
          nullable: true
          description: Optional description

    ExampleAction_Response:
      allOf:
        - $ref: "#/components/schemas/Response"
        - type: object
          properties:
            result:
              type: string
              description: The action result
```

### Step 7: Write Unit Tests

Create `test/src/unit/handlers_test.cpp` using the parameterized test pattern:

```cpp
#include <gtest/gtest.h>
#include <api/adapter/baseHandler_test.hpp>
#include <api/example/handlers.hpp>
#include <example/mockExample.hpp>
#include <eMessages/example.pb.h>

using namespace api::adapter;
using namespace api::test;
using namespace api::example::handlers;
using namespace ::example::mocks;

using ExampleHandlerTest = BaseHandlerTest<::example::IExample, MockExample>;
using ExampleHandlerT = Params<::example::IExample, MockExample>;

TEST_P(ExampleHandlerTest, Handler)
{
    auto [reqGetter, handlerGetter, resGetter, mocker] = GetParam();
    handlerTest(reqGetter, handlerGetter, resGetter, m_iHandler, m_mockHandler, mocker);
}

INSTANTIATE_TEST_SUITE_P(
    Api,
    ExampleHandlerTest,
    ::testing::Values(
        // Success case
        ExampleHandlerT(
            []() {
                eEngine::example::ExampleAction_Request protoReq;
                protoReq.set_name("test");
                return createRequest(protoReq);
            },
            [](const std::shared_ptr<::example::IExample>& h) {
                return exampleAction(h);
            },
            []() {
                eEngine::example::ExampleAction_Response protoRes;
                protoRes.set_status(eEngine::ReturnStatus::OK);
                protoRes.set_result("success");
                return userResponse(protoRes);
            },
            [](auto& mock) {
                EXPECT_CALL(mock, doAction("test")).WillOnce(Return("success"));
            }
        ),
        // Bad request case
        ExampleHandlerT(
            []() {
                httplib::Request req;
                req.body = "not json";
                req.set_header("Content-Type", "text/plain");
                return req;
            },
            [](const std::shared_ptr<::example::IExample>& h) {
                return exampleAction(h);
            },
            []() {
                return userErrorResponse<eEngine::GenericStatus_Response>(
                    "Failed to parse protobuff json request: ...");
            },
            [](auto&) {}
        )
    )
);
```

---

## Checklist: New Endpoint

Use this checklist when adding or modifying an endpoint:

- [ ] **Proto**: Define/update messages in `src/engine/source/proto/src/<domain>.proto`
- [ ] **Proto regen**: Run `cmake --build ./build --target generate_protobuf_code`
- [ ] **C++ handler**: Create factory function returning `adapter::RouteHandler`
- [ ] **C++ registration**: Add route in `registerHandlers()` inline function
- [ ] **C++ CMake**: Add/update `CMakeLists.txt` for the handler module
- [ ] **C++ tests**: Add parameterized test cases using `BaseHandlerTest`
- [ ] **Python endpoints**: Add `isinstance` mapping in `api-communication/endpoints.py`
- [ ] **Python CLI**: Add `configure()` + `run()` command module in `engine-suite`
- [ ] **Python CLI registration**: Register the command in the appropriate `__main__.py`
- [ ] **OpenAPI spec**: Add path + schemas in `docs/ref/modules/engine/spec.yaml`

---

## Key Files Quick Reference

| What | Path |
|------|------|
| Proto definitions | `src/engine/source/proto/src/*.proto` |
| Proto generation script | `src/engine/source/proto/generateCode.sh` |
| C++ generated proto headers | `src/engine/source/proto/include/eMessages/*.pb.h` |
| Adapter framework | `src/engine/source/api/adapter/include/api/adapter/adapter.hpp` |
| Test base fixture | `src/engine/source/api/adapter/test/include/api/adapter/baseHandler_test.hpp` |
| Python generated proto | `src/engine/tools/api-communication/src/api_communication/proto/*_pb2.py` |
| Python endpoint routing | `src/engine/tools/api-communication/src/api_communication/endpoints.py` |
| Python API client | `src/engine/tools/api-communication/src/api_communication/client.py` |
| Default socket path | `src/engine/tools/engine-suite/src/shared/default_settings.py` |
| OpenAPI spec | `docs/ref/modules/engine/spec.yaml` |
| CMake proto option | `src/engine/CMakeLists.txt` (`ENGINE_GENERATE_PROTO`) |

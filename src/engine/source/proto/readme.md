# Proto Module (eMessages)

## Overview

The **proto** module is the schema definition layer for the Wazuh engine's internal API. It uses **Protocol Buffers (proto3)** as the single source of truth for all request/response message types, then generates both C++ and Python code from those definitions.

Despite using protobuf for schema definition and validation, the **wire format is JSON** — not binary protobuf. The proto layer provides:

- Type-safe message definitions shared between C++ handlers and Python CLI tools
- JSON ↔ protobuf serialization helpers (`eMessage.h`)
- Generated `.pb.cc`/`.pb.h` (C++) and `_pb2.py`/`.pyi` (Python) files committed to the repository

## Architecture

```
┌─────────────────────────────────────┐
│          .proto source files        │  (src/*.proto)
│          Single source of truth     │
└──────────┬──────────────┬───────────┘
           │              │
     generateCode.sh      │
     (protoc)             │
           │              │
    ┌──────▼──────┐  ┌────▼──────────────────────────┐
    │  C++ output │  │  Python output                 │
    │  .pb.cc/h   │  │  _pb2.py / .pyi               │
    │  eMessages/ │  │  api_communication/proto/      │
    └──────┬──────┘  └────┬──────────────────────────-┘
           │              │
    ┌──────▼──────┐  ┌────▼──────────────────────────┐
    │  eMessage.h │  │  Python APIClient              │
    │  JSON↔Proto │  │  json_format / ParseDict       │
    │  helpers    │  │                                 │
    └──────┬──────┘  └────┬───────────────────────────┘
           │              │
    ┌──────▼──────┐  ┌────▼──────────────────────────┐
    │  C++ API    │  │  Python CLI tools              │
    │  handlers   │  │  (engine-suite)                │
    └─────────────┘  └───────────────────────────────-┘
```

## Key Concepts

### JSON as Wire Format

Although messages are defined in protobuf, they are serialized as **JSON** on the wire (HTTP over the engine's Unix domain sockets, `/var/wazuh-manager/queue/sockets/engine-api-http.sock` for the API). Protobuf serves as a **schema and validation layer**:

- **C++ side**: `eMessage::eMessageFromJson<T>(jsonStr)` → protobuf object, `eMessage::eMessageToJson(msg)` → JSON string
- **Python side**: `google.protobuf.json_format.ParseDict(dict, msg)` and `MessageToDict(msg)` for validation and conversion

### Message Naming Convention

Most request/response messages follow the pattern:

```
{Resource}{Action}_{Request|Response}
```

Examples:
- `RoutePost_Request` / `RouteGet_Response`
- `EventDumperActivate_Request` / `EventDumperStatus_Response`
- `SessionPost_Request` / `RunPost_Response`
- `StatusGet_Request` / `StatusGet_Response`

The pattern is not enforced: `crud.proto` starts with a lowercase resource (`namespaceGet_Request`, `policyPost_Request`, `resourceList_Response`), `ioc.proto` puts the action first (`UpdateIoc_Request`, `GetIocState_Response`), `metrics.proto` omits the resource (`Enable_Request`, `Dump_Response`), and `request_response.proto` defines plain `Request`/`Response`. Follow the file you are adding to.

When an endpoint returns only a status, it reuses the shared `GenericStatus_Response` from `engine.proto`.

### Base Types (`engine.proto`)

The base proto file defines types shared across all domains:

```protobuf
enum ReturnStatus {
    UNKNOWN = 0;
    OK      = 1;
    ERROR   = 2;
}

message GenericStatus_Response {
    ReturnStatus status   = 1;
    optional string error = 2;
}
```

All domain-specific `.proto` files import `engine.proto` and build upon these base types.

## Directory Structure

```
proto/
├── readme.md                           # This document
├── CMakeLists.txt                      # Static library target for generated C++ code
├── generateCode.sh                     # Code generation script (protoc wrapper)
├── src/                                # Proto source definitions
│   ├── engine.proto                    # Base types: ReturnStatus, GenericStatus_Response
│   ├── router.proto                    # Route CRUD, table queries, event queue
│   ├── tester.proto                    # Session management, test runs, logtest
│   ├── geo.proto                       # GeoIP database queries
│   ├── event_dumper.proto             # Event dumper activate/deactivate/status
│   ├── rawevtindexer.proto             # Raw event indexer status
│   ├── crud.proto                      # Namespace, policy, and resource CRUD
│   ├── ioc.proto                       # IOC sync: update and state
│   ├── metrics.proto                   # Metrics dump/get/enable/list (internal)
│   ├── status.proto                    # Engine status (GET /status): spaces, resources
│   └── request_response.proto          # Generic test request/response
└── include/eMessages/                  # Generated output (DO NOT EDIT)
    ├── eMessage.h                      # Hand-written JSON↔Proto helpers (preserved)
    ├── readme.md                       # "Do not edit" warning (preserved)
    ├── engine.pb.cc / engine.pb.h      # Generated from engine.proto
    ├── router.pb.cc / router.pb.h      # Generated from router.proto
    ├── tester.pb.cc / tester.pb.h      # Generated from tester.proto
    ├── geo.pb.cc / geo.pb.h            # ...
    ├── event_dumper.pb.cc / event_dumper.pb.h
    ├── rawevtindexer.pb.cc / .pb.h
    ├── crud.pb.cc / crud.pb.h
    ├── ioc.pb.cc / ioc.pb.h
    ├── metrics.pb.cc / metrics.pb.h
    ├── status.pb.cc / status.pb.h
    └── request_response.pb.cc / .pb.h
```

## Proto Files

| File | Package | Domain |
|------|---------|--------|
| `engine.proto` | `com.wazuh.api.engine` | Base types: `ReturnStatus`, `GenericStatus_Response` |
| `router.proto` | `com.wazuh.api.engine.router` | Route CRUD, table queries, event queue ingestion |
| `tester.proto` | `com.wazuh.api.engine.tester` | Session management, test runs, logtest |
| `geo.proto` | `com.wazuh.api.engine.geo` | GeoIP database queries |
| `event_dumper.proto` | `com.wazuh.api.engine.event_dumper` | Event dumper activate/deactivate/status |
| `rawevtindexer.proto` | `com.wazuh.api.engine.rawevtindexer` | Raw event indexer status |
| `crud.proto` | `com.wazuh.api.engine.content` | Namespace, policy, and resource CRUD |
| `ioc.proto` | `com.wazuh.api.engine.ioc` | IOC sync: update and state |
| `metrics.proto` | `com.wazuh.api.engine.metrics` | Metrics dump/get/enable/list (internal only) |
| `status.proto` | `com.wazuh.api.engine.status` | Engine status (`StatusGet_Request`/`StatusGet_Response`) |
| `request_response.proto` | `com.wazuh.api.engine.test` | Generic test request/response |

## C++ Helpers (`eMessage.h`)

This is the only hand-written file in `include/eMessages/`. It provides template functions for JSON↔protobuf conversion:

| Function | Signature | Description |
|----------|-----------|-------------|
| `eMessageFromJson<T>` | `(const std::string& json) → std::variant<base::Error, T>` | Parse JSON string → protobuf message. Ignores unknown fields. |
| `eMessageToJson<T>` | `(const T& message, bool printPrimitiveFields = true) → std::variant<base::Error, std::string>` | Serialize protobuf message → compact JSON string. Preserves field names, prints default fields unless `printPrimitiveFields` is false. Use it for response serialization, not to rebuild request payloads in handlers. |
| `eRepeatedFieldToJson<T>` | `(const RepeatedPtrField<T>&, bool printPrimitiveFields = true) → std::variant<base::Error, std::string>` | Serialize a repeated field as a JSON array string. |
| `ShutdownEMessageLibrary` | `() → void` | Call `google::protobuf::ShutdownProtobufLibrary()` for clean exit. |

### Parse Options

- **Input** (`eMessageFromJson`): `ignore_unknown_fields = true`, `case_insensitive_enum_parsing = false`
- **Output** (`eMessageToJson`, `eRepeatedFieldToJson`): `add_whitespace = false`, `always_print_primitive_fields = printPrimitiveFields` (default `true`), `preserve_proto_field_names = true`, `always_print_enums_as_ints = false`

Every template `static_assert`s that `T` derives from `google::protobuf::Message`.

> Warning
> For request handlers, parse `req.body` into `json::Json` and extract the relevant subtree from the body when you need a `json::Json` payload. Avoid converting request payloads back out of protobuf messages.

## Code Generation

### How to Regenerate

After modifying any `.proto` file, regenerate both C++ and Python code. The engine is configured inside the manager's single build tree, src/build (see [docs/dev/build-sources.md](../../../../docs/dev/build-sources.md)); once that tree exists (after `make -C src deps` and a build), turn the option on in it and build the target:

```bash
cmake -DENGINE_GENERATE_PROTO=ON src/build
cmake --build src/build --target generate_protobuf_code
```

The option sticks in the CMake cache, and while it is `ON` every `eMessages` build regenerates the code first; reconfigure with `-DENGINE_GENERATE_PROTO=OFF` when done.

Both the C++ `.pb.h/.pb.cc` files and Python `_pb2.py/.pyi` files **must be committed** to the repository after regeneration.

### What `generateCode.sh` Does

1. **Format**: Runs `clang-format` (`clang-format-11`, `clang-format-10` or `clang-format`, whichever is found first; skipped with a warning if none) with `-style=file` on all `.proto` source files
2. **Clean**: Deletes all files in `include/eMessages/` except `eMessage.h` and `readme.md`; deletes all files in the Python output directory except `__init__.py`
3. **Generate C++**: `protoc --cpp_out` → `.pb.cc` and `.pb.h` in `include/eMessages/`
4. **Generate Python**: `protoc --python_out --pyi_out` → `_pb2.py` and `.pyi` in `tools/api-communication/src/api_communication/proto/`
5. **Fix Python imports**: Rewrites `import foo_pb2 as …` → `import api_communication.proto.foo_pb2 as _foo_pb2` for package-qualified imports

### Prerequisites

The `protoc` compiler must be built and available at `${PROTOBUF_DIR}/build/protoc`, with the protobuf includes under `${PROTOBUF_DIR}/src/google/protobuf`. `src/engine/CMakeLists.txt` sets `PROTOBUF_DIR` to `external/protobuf` under the configure source directory (`src/external/protobuf`, filled by `make -C src deps`). The `ENGINE_GENERATE_PROTO` CMake option must be explicitly set to `ON` — code generation is disabled by default.

## CMake Target

| Target | Type | Description |
|--------|------|-------------|
| `eMessages` | STATIC | Compiled protobuf C++ code (all `.pb.cc` files) |

**Dependencies:**

```
eMessages  ←── protobuf::libprotobuf, base
```

The library is automatically built from all `.cc` files found in `include/eMessages/` via a CMake `file(GLOB)` (evaluated at configure time, so a new `.proto` needs a reconfigure after generation). When `generate_protobuf_code` target exists (protoc found + `ENGINE_GENERATE_PROTO=ON`), `eMessages` depends on it to ensure code is up-to-date before compilation.

## Style Guide

- **Syntax**: Proto3
- **Formatting**: Engine project `clang-format` style (applied automatically by `generateCode.sh`)
- **Reference**: https://protobuf.dev/programming-guides/style/

## Related Documentation

- [API Developer Guide](../api/README.md) — Full details on how proto messages are used in C++ handlers, Python CLI tools, and the OpenAPI spec
- [include/eMessages/readme.md](include/eMessages/readme.md) — Warning note for the generated output directory

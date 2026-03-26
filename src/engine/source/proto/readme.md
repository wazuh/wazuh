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

Although messages are defined in protobuf, they are serialized as **JSON** on the wire (HTTP over Unix Domain Socket). Protobuf serves as a **schema and validation layer**:

- **C++ side**: `eMessage::eMessageFromJson<T>(jsonStr)` → protobuf object, `eMessage::eMessageToJson(msg)` → JSON string
- **Python side**: `google.protobuf.json_format.ParseDict(dict, msg)` and `MessageToDict(msg)` for validation and conversion

### Message Naming Convention

All proto messages follow a strict pattern:

```
{Action}{Resource}_{Request|Response}
```

Examples:
- `RoutePost_Request` / `RouteGet_Response`
- `ArchiverActivate_Request` / `ArchiverStatus_Response`
- `SessionPost_Request` / `RunPost_Response`

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
│   ├── archiver.proto                  # Archive activate/deactivate/status
│   ├── rawevtindexer.proto             # Raw event indexer status
│   ├── crud.proto                      # Namespace, policy, and resource CRUD
│   ├── ioc.proto                       # IOC sync: update and state
│   ├── metrics.proto                   # Metrics dump/get/enable/list (internal)
│   └── request_response.proto          # Generic test request/response
└── include/eMessages/                  # Generated output (DO NOT EDIT)
    ├── eMessage.h                      # Hand-written JSON↔Proto helpers (preserved)
    ├── readme.md                       # "Do not edit" warning (preserved)
    ├── engine.pb.cc / engine.pb.h      # Generated from engine.proto
    ├── router.pb.cc / router.pb.h      # Generated from router.proto
    ├── tester.pb.cc / tester.pb.h      # Generated from tester.proto
    ├── geo.pb.cc / geo.pb.h            # ...
    ├── archiver.pb.cc / archiver.pb.h
    ├── rawevtindexer.pb.cc / .pb.h
    ├── crud.pb.cc / crud.pb.h
    ├── ioc.pb.cc / ioc.pb.h
    ├── metrics.pb.cc / metrics.pb.h
    └── request_response.pb.cc / .pb.h
```

## Proto Files

| File | Package | Domain |
|------|---------|--------|
| `engine.proto` | `com.wazuh.api.engine` | Base types: `ReturnStatus`, `GenericStatus_Response` |
| `router.proto` | `com.wazuh.api.engine.router` | Route CRUD, table queries, event queue ingestion |
| `tester.proto` | `com.wazuh.api.engine.tester` | Session management, test runs, logtest |
| `geo.proto` | `com.wazuh.api.engine.geo` | GeoIP database queries |
| `archiver.proto` | `com.wazuh.api.engine.archiver` | Archive activate/deactivate/status |
| `rawevtindexer.proto` | `com.wazuh.api.engine.rawevtindexer` | Raw event indexer status |
| `crud.proto` | `com.wazuh.api.engine.content` | Namespace, policy, and resource CRUD |
| `ioc.proto` | `com.wazuh.api.engine.ioc` | IOC sync: update and state |
| `metrics.proto` | `com.wazuh.api.engine.metrics` | Metrics dump/get/enable/list (internal only) |
| `request_response.proto` | `com.wazuh.api.engine.test` | Generic test request/response |

## C++ Helpers (`eMessage.h`)

This is the only hand-written file in `include/eMessages/`. It provides template functions for JSON↔protobuf conversion:

| Function | Signature | Description |
|----------|-----------|-------------|
| `eMessageFromJson<T>` | `(const string& json) → variant<Error, T>` | Parse JSON string → protobuf message. Ignores unknown fields. |
| `eMessageToJson<T>` | `(const T& msg, bool printPrimitive = true) → variant<Error, string>` | Serialize protobuf message → JSON string. Preserves field names, prints default fields. |
| `eRepeatedFieldToJson<T>` | `(const RepeatedPtrField<T>&, ...) → variant<Error, string>` | Serialize a repeated field as a JSON array string. |
| `eStructToJson` | `(const Struct& s) → variant<Error, json::Json>` | Convert a `google.protobuf.Struct` → `json::Json` object, recursively handling nested structs, arrays, and primitives. |
| `ShutdownEMessageLibrary` | `() → void` | Call `google::protobuf::ShutdownProtobufLibrary()` for clean exit. |

### Parse Options

- **Input** (`eMessageFromJson`): `ignore_unknown_fields = true`, `case_insensitive_enum_parsing = false`
- **Output** (`eMessageToJson`): `always_print_primitive_fields = true`, `preserve_proto_field_names = true`, `always_print_enums_as_ints = false`

## Code Generation

### How to Regenerate

After modifying any `.proto` file, regenerate both C++ and Python code:

```bash
cd src/engine
cmake --preset debug -DENGINE_GENERATE_PROTO=ON
cmake --build ./build --target generate_protobuf_code
```

Both the C++ `.pb.h/.pb.cc` files and Python `_pb2.py/.pyi` files **must be committed** to the repository after regeneration.

### What `generateCode.sh` Does

1. **Format**: Runs `clang-format` on all `.proto` source files
2. **Clean**: Deletes all files in `include/eMessages/` except `eMessage.h` and `readme.md`; deletes all files in the Python output directory except `__init__.py`
3. **Generate C++**: `protoc --cpp_out` → `.pb.cc` and `.pb.h` in `include/eMessages/`
4. **Generate Python**: `protoc --python_out --pyi_out` → `_pb2.py` and `.pyi` in `tools/api-communication/src/api_communication/proto/`
5. **Fix Python imports**: Rewrites `import foo_pb2 as ...` → `import api_communication.proto.foo_pb2 as ...` for proper package-relative imports

### Prerequisites

The `protoc` compiler must be built and available at `${PROTOBUF_DIR}/build/protoc`. This path is typically provided by vcpkg during the engine build. The `ENGINE_GENERATE_PROTO` CMake option must be explicitly set to `ON` — code generation is disabled by default.

## CMake Target

| Target | Type | Description |
|--------|------|-------------|
| `eMessages` | STATIC | Compiled protobuf C++ code (all `.pb.cc` files) |

**Dependencies:**

```
eMessages  ←── protobuf::libprotobuf, base
```

The library is automatically built from all `.cc` files found in `include/eMessages/` via a CMake `file(GLOB)`. When `generate_protobuf_code` target exists (protoc found + `ENGINE_GENERATE_PROTO=ON`), `eMessages` depends on it to ensure code is up-to-date before compilation.

## Style Guide

- **Syntax**: Proto3
- **Formatting**: Engine project `clang-format` style (applied automatically by `generateCode.sh`)
- **Reference**: https://protobuf.dev/programming-guides/style/

## Related Documentation

- [API Developer Guide](../api/README.md) — Full details on how proto messages are used in C++ handlers, Python CLI tools, and the OpenAPI spec
- [include/eMessages/readme.md](include/eMessages/readme.md) — Warning note for the generated output directory

# `schemf` Module — Schema Fields

## Overview

The `schemf` module provides the **schema definition and validation system** for the Wazuh engine. It models the structure of indexed events by defining typed fields organized in a hierarchical tree, and validates operations and values against those field types at build time.

Its primary purpose is to ensure that decoders and rules only write data that is compatible with the target index mapping. The schema is aligned with the WCS (Wazuh Common Schema), which in turn maps to the underlying indexer field types (OpenSearch/Elasticsearch-compatible).

## Key Concepts

### Field

A `Field` represents a single entry in the schema. It has:
- A **type** (`schemf::Type`) — one of 40+ supported types (e.g., `KEYWORD`, `INTEGER`, `IP`, `OBJECT`, `NESTED`, etc.)
- Optional **properties** — child fields, only valid for container types (`OBJECT`, `NESTED`, `FLAT_OBJECT`)

Fields form a tree: an `OBJECT` field can contain child fields, which can themselves be objects, creating a nested structure that mirrors the JSON event layout.

### Type

Defined in `interface/schemf/type.hpp`. An enum covering all indexer-compatible field types:

| Category | Types |
|----------|-------|
| **Boolean** | `BOOLEAN` |
| **Numeric** | `BYTE`, `SHORT`, `INTEGER`, `LONG`, `FLOAT`, `HALF_FLOAT`, `SCALED_FLOAT`, `DOUBLE`, `UNSIGNED_LONG` |
| **String** | `KEYWORD`, `TEXT`, `MATCH_ONLY_TEXT`, `WILDCARD`, `CONSTANT_KEYWORD`, `COMPLETION`, `SEARCH_AS_YOU_TYPE`, `SEMANTIC` |
| **Date** | `DATE`, `DATE_NANOS` |
| **Network** | `IP` |
| **Binary** | `BINARY` |
| **Container** | `OBJECT`, `NESTED`, `FLAT_OBJECT` |
| **Geo** | `GEO_POINT` |
| **Special** | `TOKEN_COUNT`, `JOIN`, `KNN_VECTOR`, `SPARSE_VECTOR`, `RANK_FEATURE`, `RANK_FEATURES`, `PERCOLATOR`, `STAR_TREE`, `DERIVED` |
| **Range** | `INTEGER_RANGE`, `LONG_RANGE`, `FLOAT_RANGE`, `DOUBLE_RANGE`, `DATE_RANGE`, `IP_RANGE` |

Helper functions:
- `typeToStr(Type)` / `strToType(string_view)` — bidirectional conversion
- `hasProperties(Type)` — returns `true` for `OBJECT`, `NESTED`, `FLAT_OBJECT`

### Schema

The `Schema` class holds the complete field tree and implements both `ISchema` (read-only queries) and `IValidator` (build-time and runtime validation). It is the central object of the module.

### Validation

The validation system operates at **two levels**:

1. **Build-time validation**: When the builder constructs a decoder/rule, it checks that operations target valid fields and use compatible types. This catches errors early without processing any events.
2. **Runtime validation**: For cases where build-time validation is insufficient (e.g., a value comes from a dynamic reference), a `ValueValidator` function is returned that will be called at event processing time.

## Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                   Consumer (Builder module)                     │
│                                                                │
│  1. Loads the schema JSON from the store                       │
│  2. Creates a Schema object and calls schema.load(json)        │
│  3. At build time, validates operations via IValidator          │
│     - validateTargetField(name): is the target field valid?     │
│     - validate(name, token/value): is the operation compatible? │
└───────────────────────┬────────────────────────────────────────┘
                        │
                        ▼
┌────────────────────────────────────────────────────────────────┐
│                     schemf::Schema                             │
│                                                                │
│  ┌──────────────────────┐  ┌────────────────────────────────┐  │
│  │  m_fields             │  │  Validator (internal)          │  │
│  │  (field tree)         │  │  Type compatibility matrix     │  │
│  │                      │  │  Value validators per type     │  │
│  │  OBJECT              │  │                                │  │
│  │  ├─ host: KEYWORD    │  │  validate(field, JTypeToken)   │  │
│  │  ├─ port: INTEGER    │  │  validate(field, STypeToken)   │  │
│  │  └─ meta: OBJECT     │  │  validate(field, ValueToken)   │  │
│  │     └─ id: KEYWORD   │  │  validateTargetField(field)    │  │
│  └──────────────────────┘  └────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────┘
```

## Directory Structure

```
schemf/
├── CMakeLists.txt                              # Build: defines schemf::ischema, schemf, schemf::mocks
├── interface/
│   └── schemf/
│       ├── type.hpp                            # Type enum + typeToStr/strToType/hasProperties helpers
│       ├── ischema.hpp                         # ISchema interface (getType, getJsonType, hasField)
│       └── ivalidator.hpp                      # IValidator interface, validation tokens, ValidationResult
├── include/
│   └── schemf/
│       ├── field.hpp                           # Field class (type + properties tree node)
│       └── schema.hpp                          # Schema class (field tree + validation, implements IValidator)
├── src/
│   ├── field.cpp                               # Field construction and property management
│   ├── schema.cpp                              # Schema: addField, removeField, hasField, load, get
│   ├── validator.cpp                           # Validator: type compatibility matrix and validation logic
│   └── valueValidators.hpp                     # Per-type value validator factories (bool, int, string, IP, date, etc.)
└── test/
    ├── mocks/
    │   └── schemf/
    │       ├── mockSchema.hpp                  # GMock mock for IValidator
    │       ├── emptySchema.hpp                 # Test helper: schema with no fields
    │       └── straightValidator.hpp           # Test helper: configurable pass/fail validator
    └── src/
        ├── unit/
        │   └── field_test.cpp                  # Unit tests for Field
        └── component/
            ├── schema_test.cpp                 # Component tests: addField, load, remove, hasField
            └── validator_test.cpp              # Component tests: type compatibility and validation
```

## Public Interface

### `ISchema`

Read-only schema query interface. Defined in `interface/schemf/ischema.hpp`.

```cpp
class ISchema {
    // Get the schema type of a field (e.g., Type::KEYWORD)
    virtual Type getType(const DotPath& name) const = 0;

    // Get the JSON type of a field (e.g., json::Json::Type::String)
    virtual json::Json::Type getJsonType(const DotPath& name) const = 0;

    // Check if a field exists in the schema
    virtual bool hasField(const DotPath& name) const = 0;
};
```

### `IValidator`

Build-time and runtime validation interface. Extends `ISchema`. Defined in `interface/schemf/ivalidator.hpp`.

```cpp
class IValidator : public ISchema {
    // Classify a target field: SCHEMA (exists) or TEMPORARY (starts with '_')
    virtual RespOrError<TargetFieldKind> validateTargetField(const DotPath& name) const = 0;

    // Validate an operation intent (token) against a field's type
    virtual RespOrError<ValidationResult> validate(const DotPath& name, const ValidationToken& token) const = 0;

    // Validate a concrete JSON value against a field's type
    virtual RespOrError<ValidationResult> validate(const DotPath& name, const json::Json& jsonValue) const = 0;
};
```

### Validation Tokens

Tokens describe the *intent* of an operation at build time, without providing a concrete value:

| Token | Created via | Purpose |
|-------|------------|---------|
| `JTypeToken` | `JTypeToken::create(json::Json::Type)` | "This operation will produce a value of this JSON type" |
| `STypeToken` | `STypeToken::create(schemf::Type)` | "This operation will produce a value of this schema type" |
| `ValueToken` | `ValueToken::create(json::Json)` | "This operation will write this exact value" |
| `nullptr` | `runtimeValidation()` | "Cannot determine type at build time — defer to runtime" |
| `BaseToken` | `elementValidationToken()` | "Validate as array element instead of whole array" |

### `ValidationResult`

Returned by `validate()`:
- `needsRuntimeValidation()` — `true` if a runtime validator is needed
- `getValidator()` — returns the `ValueValidator` function (or `nullptr`)

### `TargetFieldKind`

Returned by `validateTargetField()`:
- `SCHEMA` — field exists in the schema
- `TEMPORARY` — field does not exist but is a valid temporary field (root starts with `_`)

## Validation Logic

### Type Compatibility Matrix

The validator maintains a compatibility matrix that defines which schema types can be assigned from which other types. For example:

- `INTEGER` field accepts: `LONG` (with runtime validation), `SHORT` (no extra validation), `BYTE` (no extra validation)
- `KEYWORD` field accepts: `TEXT`, `DATE`, `IP`, `BINARY`, etc. (all string-family types)
- `OBJECT` fields are only compatible with other objects
- Some types are incompatible with everything: `KNN_VECTOR`, `SPARSE_VECTOR`, `RANK_FEATURE`, etc.

When a compatible type requires additional validation (e.g., `LONG` → `INTEGER` may overflow), a runtime `ValueValidator` is returned.

### Target Field Classification

```
validateTargetField("host.name")
  ├── Field exists in schema? → TargetFieldKind::SCHEMA
  ├── Root is "." (root target)? → TargetFieldKind::TEMPORARY  
  ├── Root starts with '_'? → TargetFieldKind::TEMPORARY
  └── Otherwise → Error: "not defined in WCS schema and not a temporary field"
```

Temporary fields (rooted at `_`) are used for intermediate values during event processing that are not indexed.

### Value Validators

Per-type validators in `valueValidators.hpp`:

| Validator | Checks |
|-----------|--------|
| `getBoolValidator` | `json.isBool()` |
| `getShortValidator` | `json.isInt()` and value in int8 range |
| `getIntegerValidator` | `json.isInt()` |
| `getLongValidator` | `json.isInt64()` |
| `getFloatValidator` | `json.isFloat()` |
| `getDoubleValidator` | `json.isDouble()` |
| `getUnsignedLongValidator` | `json.isUint64()` |
| `getStringValidator` | `json.isString()` |
| `getDateValidator` | String matching `%Y-%m-%dT%H:%M:%SZ` format |
| `getIpValidator` | Valid IP address string |
| `getBinaryValidator` | Valid base64-encoded string |
| `getObjectValidator` | `json.isObject()` |
| `getIncompatibleValidator` | Always fails (for types that cannot be written to) |

## Schema Loading

Schemas are loaded from a JSON document:

```json
{
  "fields": {
    "host.name": { "type": "keyword" },
    "host.ip": { "type": "ip" },
    "event.created": { "type": "date" },
    "source.port": { "type": "integer" },
    "metadata": { "type": "object" }
  }
}
```

`Schema::load()` parses this format and calls `addField()` for each entry. Dot-separated field names automatically create intermediate `OBJECT` parents (e.g., `host.name` creates `host` as `OBJECT` and `name` as `KEYWORD` under it).

## Array Handling

Fields are implicitly array-capable. The `asArray()` helper wraps a `ValueValidator` to validate each element individually when the value is an array, or validate the value directly if it's not. Array index access is supported in paths (e.g., `field.0` to access index 0).

## CMake Targets

| Target | Alias | Type | Description |
|--------|-------|------|-------------|
| `schemf_ischema` | `schemf::ischema` | INTERFACE | Interfaces only (`ISchema`, `IValidator`, `Type`). Depends on `base`. |
| `schemf` | — | STATIC | Full implementation. Depends on `schemf::ischema`, `hlp`, `base`. |
| `schemf_mocks` | `schemf::mocks` | INTERFACE | GMock mocks for external testing. Depends on `schemf::ischema`. |
| `schemf_utest` | — | EXECUTABLE | Unit tests for Field. |
| `schemf_ctest` | — | EXECUTABLE | Component tests for Schema and Validator. |

## Testing

### Unit Tests (`field_test.cpp`)

Tests for the `Field` class: construction with valid/invalid parameters, property management, type constraints.

### Component Tests — Schema (`schema_test.cpp`)

- **AddField**: All type variants, nested paths, conflict detection (duplicate fields, non-object parents)
- **Get/HasField**: Type retrieval, nested path resolution, array index access
- **RemoveField**: Single and nested field removal
- **Load**: JSON schema loading for all supported types, error handling for invalid schemas

### Component Tests — Validator (`validator_test.cpp`)

- **Type compatibility**: For each schema type, tests all compatible and incompatible schema types and JSON types
- **Runtime validation**: Verifies that runtime validators are returned when needed
- **Target field classification**: Schema fields, temporary fields (`_*`), root target, invalid fields
- **Value validation**: Concrete JSON values against all supported field types

### Running Tests

```bash
# From the engine build directory:
./schemf_utest    # Unit tests
./schemf_ctest    # Component tests
```

## Related Documentation

For details on how the `builder` module integrates with the schema validation system — including how helpers register validation tokens, dynamic vs static validation, and the full build-time → runtime flow — see:

> [`src/engine/source/builder/src/builders/README.md`](../builder/src/builders/README.md) — *Helper Functions – Field Validation System*

## Relevant Design Decisions

1. **Two-phase validation**: Build-time validation catches most errors early (type mismatches, unknown fields). Runtime validation handles dynamic cases where the actual value is only known at event processing time. This split minimizes runtime overhead for statically-determined operations.

2. **Type compatibility matrix**: Rather than strict type equality, the validator allows compatible type assignments (e.g., `SHORT` → `INTEGER`) to support realistic use cases where a decoder might produce a narrower type than the target field. Some compatible assignments require runtime bounds checking.

3. **Temporary fields**: Fields rooted at `_` bypass schema validation entirely, providing a mechanism for intermediate computation values that are not indexed. This keeps the schema strict for indexed fields while allowing flexibility for processing logic.

4. **Implicit array support**: Any field can hold an array of its type. The `asArray()` wrapper transparently handles per-element validation, avoiding the need for separate array type definitions.

5. **Indexer-aligned type system**: The `Type` enum mirrors indexer field types (OpenSearch/Elasticsearch), ensuring that the engine's schema is always compatible with the target storage system. This includes specialized types like `GEO_POINT`, `KNN_VECTOR`, and range types.

6. **Schema as `IValidator`**: The `Schema` class directly implements `IValidator`, keeping the field tree and validation logic in a single object. The internal `Validator` class is a hidden implementation detail that holds the compatibility matrix.

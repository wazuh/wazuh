# Helper Functions – Field Validation System

This document describes how helper functions (operations registered via `registerOpBuilders`) validate the
fields they operate on. The validation ensures type safety between the decoder/rule logic written by users
and the underlying schema that defines the event structure.

> **See also:** [`src/engine/source/schemf/README.md`](../../../schemf/README.md) — Documentation of the schema module itself (type system, field tree, `IValidator` interface, value validators).

---

## Table of Contents

1. [Overview](#overview)
2. [Key Types](#key-types)
3. [Registration: `OpBuilderEntry`](#registration-opbuilderentry)
4. [Validation Tokens](#validation-tokens)
   - [Static Tokens](#static-tokens)
   - [Dynamic Tokens (`DynamicValToken`)](#dynamic-tokens-dynamicvaltoken)
5. [Target Field Classification](#target-field-classification)
6. [Build-Time Validation](#build-time-validation)
7. [Runtime Validation](#runtime-validation)
8. [Full Validation Flow](#full-validation-flow)
9. [Schema Types and JSON Type Mapping](#schema-types-and-json-type-mapping)
10. [Type Compatibility Matrix](#type-compatibility-matrix)
11. [Value Validators](#value-validators)
12. [Examples by Registration Pattern](#examples-by-registration-pattern)

---

## Overview

Every helper function (e.g. `int_equal`, `parse_ip`, `map`, `concat`) is registered with a
**validation intent** and an **operation builder**. The validation intent declares what type
constraints the helper imposes on the target field. When a decoder uses a helper on a specific
field, the engine validates – at **build time** if possible, otherwise at **runtime** – that
the target field's schema type is compatible with what the helper expects.

The three pillars of the system are:

| Concept | Purpose |
|---------|---------|
| **Target field classification** | Determines if the field belongs to the schema, is temporary (`_`-prefixed), or is invalid. |
| **Build-time validation** | Uses the `ValidationToken` to check type compatibility against the schema *before* the pipeline runs. |
| **Runtime validation** | Wraps a map operation with a `ValueValidator` that checks the actual JSON value *during* event processing. |

---

## Key Types

Defined in `builders.hpp`:

```cpp
using DynamicValToken = std::function<schemf::ValidationToken(const std::vector<OpArg>&, const schemf::IValidator&)>;

using ValidationInfo = std::variant<schemf::ValidationToken, DynamicValToken>;

using OpBuilderEntry = std::tuple<ValidationInfo, OpBuilder>;
```

- **`ValidationInfo`**: Either a pre-computed, static `ValidationToken` or a `DynamicValToken` factory
  that computes the token from the operation arguments at build time.
- **`OpBuilderEntry`**: The registry entry for a helper — a tuple of the validation info and the
  operation builder function.

---

## Registration: `OpBuilderEntry`

Helpers are registered in `builder/src/register.hpp` via `registerOpBuilders`. Each call follows the pattern:

```cpp
registry->template add<builders::OpBuilderEntry>("helper_name", {validationInfo, builderFunction});
```

The builder is an `OpBuilder`, a variant of `MapBuilder`, `TransformBuilder` and `FilterBuilder`
(`builders.hpp`). Which alternative it holds matters below: only a `MapBuilder` gets runtime validation.

The first element of the tuple (`validationInfo`) dictates **how** the target field is validated.

---

## Validation Tokens

Validation tokens (defined in `schemf/interface/schemf/ivalidator.hpp`) encode the **intent** of the operation — what
it expects from the target field. They form a class hierarchy rooted at `BaseToken`:

```
BaseToken                    (no type info – element-level validation / array check only)
 ├── JTypeToken              (expects a JSON type: String, Number, Boolean, Object — never Array)
 ├── STypeToken              (expects a schema type: IP, LONG, DATE, KEYWORD, …)
 └── ValueToken              (carries a concrete JSON value for immediate validation)
```

A `nullptr` token means **runtime validation only** — no build-time check is performed.

### Static Tokens

Used when the helper **always** expects the same type, regardless of its arguments. The factories in use
include:

| Factory | Token Type | Meaning |
|---------|-----------|---------|
| `schemf::runtimeValidation()` | `nullptr` | Skip build-time validation entirely; only validate at runtime. |
| `schemf::elementValidationToken()` | `BaseToken` (no type) | Array-element-level validation. Used by `array_contains`, `array_append`, etc. |
| `schemf::JTypeToken::create(json::Json::Type::Number)` | `JTypeToken` | Target field must map to JSON `Number`. |
| `schemf::JTypeToken::create(json::Json::Type::String)` | `JTypeToken` | Target field must map to JSON `String`. |
| `schemf::JTypeToken::create(json::Json::Type::Object)` | `JTypeToken` | Target field must map to JSON `Object`. |
| `schemf::STypeToken::create(schemf::Type::IP)` | `STypeToken` | Target field must be schema type `IP`. |
| `schemf::STypeToken::create(schemf::Type::DATE)` | `STypeToken` | Target field must be schema type `DATE`. |
| `schemf::STypeToken::create(schemf::Type::OBJECT)` | `STypeToken` | Target field must be schema type `OBJECT`. |

"Must" means *exactly that type or a compatible one* — see the [Type Compatibility Matrix](#type-compatibility-matrix).

### Dynamic Tokens (`DynamicValToken`)

Used when the validation depends on the **arguments** passed to the helper. The factory receives the
parsed arguments and the validator, and returns a `ValidationToken` at build time.

Example — the `map` and `filter` helpers (`opmap/map.cpp` `mapValidator()`, `opfilter/filter.cpp`
`filterValidator()`, identical bodies):

```cpp
// From opmap/map.cpp
DynamicValToken mapValidator()
{
    return [](const std::vector<OpArg>& opArgs,
              const schemf::IValidator& validator) -> schemf::ValidationToken
    {
        utils::assertSize(opArgs, 1);

        if (opArgs[0]->isValue())
        {
            // Literal value → create a ValueToken for immediate build-time validation
            return schemf::ValueToken::create(
                std::static_pointer_cast<Value>(opArgs[0])->value());
        }
        // Reference → resolve its schema type, or fall back to runtime validation
        return schemf::tokenFromReference(
            std::static_pointer_cast<Reference>(opArgs[0])->dotPath(), validator);
    };
}
```

- When the argument is a **literal value**, a `ValueToken` is created so the actual value is validated
  against the target field's schema type *during build time*.
- When the argument is a **reference** to another field, `tokenFromReference` looks up that field's
  schema type and creates an `STypeToken`. If the referenced field does not exist in the schema
  (e.g. a temporary field), it falls back to `runtimeValidation()`.

---

## Target Field Classification

Before any type validation, the system classifies the target field via
`IValidator::validateTargetField(name)`:

```
                      ┌─────────────────┐
                      │  Target Field   │
                      └────────┬────────┘
                               │
                    ┌──────────▼──────────┐
                    │ Is root path "."?   │
                    └──────────┬──────────┘
                         yes   │   no
                    ┌──────────┘   └──────────┐
                    ▼                          ▼
            TEMPORARY                ┌─────────────────┐
            (no validation)          │ Exists in schema?│
                                     └────────┬────────┘
                                        yes   │   no
                                     ┌────────┘   └────────┐
                                     ▼                      ▼
                                  SCHEMA           ┌──────────────────┐
                              (full validation)    │ Root starts '_'? │
                                                   └────────┬────────┘
                                                      yes   │   no
                                                   ┌────────┘   └────────┐
                                                   ▼                      ▼
                                              TEMPORARY                 ERROR
                                          (no validation)    "Field not in schema and
                                                              not a temporary field"
```

| Classification | Behaviour |
|---------------|-----------|
| **`SCHEMA`** | Full build-time + possible runtime validation against the schema type. |
| **`TEMPORARY`** | No validation. These are working fields (prefixed with `_`) that are never indexed. Variables/temporary fields can hold any type. |
| **Error** | Build fails. Non-schema fields that don't start with `_` are rejected with `Field '<name>' is not defined in WCS schema and is not a temporary field (root must start with '_')`. |

The root target `.` is classified as `TEMPORARY` too (e.g. merge operations into the event root).

The `_`-prefixed convention allows decoders to use intermediate fields (e.g. `_tmp.parsed_value`)
without requiring them to be defined in the schema.

---

## Build-Time Validation

Build-time validation occurs in `baseHelper.cpp → buildType()` and the dispatch in `schemf/src/validator.cpp`.
The flow is:

1. Call `validator.validate(targetField, validationToken)`; an error is thrown and fails the build.
2. The validator first classifies the target field (see above); a `TEMPORARY` field ends validation with no
   runtime validator.
3. Depending on the token type, a **dispatch** occurs:

### `JTypeToken` dispatch
Checks that the JSON type expected by the helper is one the schema field accepts (one JSON type per schema type,
except `GEO_POINT`, which accepts `Object` and `String`). For example, `int_equal` creates `JTypeToken(Number)`.
If the target field is of schema type `IP` (which maps to JSON `String`), the build **fails** with
`Operation expects a JSON type 'number', but field '<name>' does not accept it. Accepted types: [string]`.

If the JSON types match, any available `ValueValidator` for the schema type is returned for
runtime validation (e.g. for a `LONG` field, the runtime validator checks that the number fits
in int64 range).

### `STypeToken` dispatch
Checks schema type compatibility:
- If the schema type **matches exactly**, no runtime validator is needed.
- If the types are **compatible** (see compatibility matrix), the validator for the target type
  is returned for runtime validation if the compatibility requires it.
- If the types are **incompatible**, the build **fails** (`Operation expects schema type '<t>', but field '<name>'
  is of incompatible schema type '<t>'`).

### `ValueToken` dispatch
Validates the actual JSON value against the target field's value validator **immediately at
build time**. If valid, no runtime validator is needed (the value is already proven correct). A `null` value is
always accepted.

### `BaseToken` (element validation) dispatch
Used for array operations. Performs no type check beyond the target field classification. Returns the target
type's runtime validator wrapped with `asArray()`, so that each array element is validated individually at runtime.

### `nullptr` (runtime-only) dispatch
No build-time check beyond the classification. Returns the same runtime validator as `BaseToken`.

Every runtime validator is wrapped with `asArray()` except `GEO_POINT`'s, which handles arrays itself.

---

## Runtime Validation

Runtime validation occurs only for **map operations** (`MapBuilder`) when the build-time validation
determines it is needed (i.e. `ValidationResult::needsRuntimeValidation()` returns true).

The wrapping is done in `baseHelper.cpp → runType()`:

```
Original MapOp
      │
      ▼
  Execute MapOp on event
      │
      ▼
  Get result value
      │
      ▼
  Run ValueValidator on value
      │
      ├── null or Valid → return result
      └── Invalid → return failure with "<opName> -> schema validation failed: <reason>" trace
```

Each `ValueValidator` is a function `(const json::Json&) → base::OptError` that checks the concrete
JSON value. When the target field is an array, the validator is wrapped via `asArray()` which applies
the element validator to each element individually.

Filter and transform operations do **not** get runtime type wrapping: `runType()` returns any builder that is not a
`MapBuilder` unchanged, even when the `ValidationResult` carries a validator. So `int_equal` (a filter),
`parse_ip` and `array_append` (transforms) are checked only at build time.

---

## Full Validation Flow

The complete flow from helper invocation to execution:

```
                        ┌────────────────────────────────┐
                        │   baseHelperBuilder() called   │
                        └──────────────┬─────────────────┘
                                       │
                    ┌──────────────────▼────────────────────┐
                    │  1. Resolve definitions (replace $ref) │
                    └──────────────────┬────────────────────┘
                                       │
                    ┌──────────────────▼────────────────────┐
                    │  2. Look up OpBuilderEntry from       │
                    │     registry by helper name           │
                    └──────────────────┬────────────────────┘
                                       │
                    ┌──────────────────▼────────────────────┐
                    │  2b. Check the builder kind matches   │
                    │     the helper type (map / filter)    │
                    └──────────────────┬────────────────────┘
                                       │
                    ┌──────────────────▼────────────────────┐
                    │  3. Resolve ValidationToken:          │
                    │     - Static? Use directly            │
                    │     - Dynamic? Call factory with args  │
                    └──────────────────┬────────────────────┘
                                       │
                    ┌──────────────────▼────────────────────┐
                    │  4. buildType():                      │
                    │     validator.validate(field, token)  │
                    │     → classifies target field         │
                    │     → dispatches by token type        │
                    │     → returns ValidationResult        │
                    └──────────────────┬────────────────────┘
                                       │
                         ┌─────────────┴──────────────┐
                         │                            │
                   needsRuntime?                 no runtime
                    = true                       needed
                         │                            │
                    ┌────▼─────┐                 ┌────▼─────┐
                    │ runType()│                 │  Return   │
                    │ wraps    │                 │  builder  │
                    │ MapOp    │                 │  as-is    │
                    └────┬─────┘                 └──────────┘
                         │
                    ┌────▼──────────────────────────────┐
                    │  5. toTransform() + toExpression() │
                    │     → final Expression node        │
                    └───────────────────────────────────┘
```

`runType()` wraps only a `MapBuilder`; any other builder comes back unchanged. Step 1 replaces a reference argument
that names a definition of the asset by the definition's value (see
[`defs/README.md`](../../../defs/README.md)). In step 5, `toTransform()` of a `MapBuilder` also checks the asset
type's allowed fields (`Map operation '<op>' not allowed on target field '<field>'`). Any failure is rethrown as
`Failed to build operation '<name>': <reason>`.

---

## Schema Types and JSON Type Mapping

Schema types are based on **OpenSearch data types** and are defined in the enum `schemf::Type`
(`schemf/interface/schemf/type.hpp`). At startup the engine loads the field types from the store document
`schema/engine-schema/0` (`main.cpp`; a missing document only logs a warning and runs without a schema). The
installer generates `src/engine/ruleset/schemas/engine-schema.json` from the WCS flat files with `engine-schema`
and copies it there (`generateSchemaFiles` and `installEngineStore` in `src/init/inst-functions.sh`).

It defines fields like:

```json
{
  "fields": {
    "source.ip":        { "type": "ip" },
    "event.code":       { "type": "keyword" },
    "client.as.number": { "type": "long" },
    "event.duration":   { "type": "long" },
    "@timestamp":       { "type": "date" }
  }
}
```

Each schema type maps to a single JSON type via `typeToJType()`:

| Schema Type | JSON Type | Description |
|-------------|----------|-------------|
| `BOOLEAN` | `Boolean` | True/false |
| `BYTE` | `Number` | 8-bit integer |
| `SHORT` | `Number` | 16-bit integer |
| `INTEGER` | `Number` | 32-bit integer |
| `LONG` | `Number` | 64-bit integer |
| `UNSIGNED_LONG` | `Number` | 64-bit unsigned integer |
| `FLOAT` | `Number` | 32-bit float |
| `HALF_FLOAT` | `Number` | 16-bit float |
| `SCALED_FLOAT` | `Number` | Scaled float |
| `DOUBLE` | `Number` | 64-bit float |
| `TOKEN_COUNT` | `Number` | Token count |
| `KEYWORD` | `String` | Exact-match string |
| `TEXT` | `String` | Full-text string |
| `MATCH_ONLY_TEXT` | `String` | Match-only text |
| `WILDCARD` | `String` | Wildcard string |
| `CONSTANT_KEYWORD` | `String` | Constant keyword |
| `COMPLETION` | `String` | Completion suggest |
| `SEARCH_AS_YOU_TYPE` | `String` | Search-as-you-type |
| `SEMANTIC` | `String` | Semantic text |
| `DATE` | `String` | ISO 8601 date string |
| `DATE_NANOS` | `String` | Nanosecond-precision date string |
| `IP` | `String` | IPv4/IPv6 address string |
| `BINARY` | `String` | Base64-encoded binary |
| `OBJECT` | `Object` | JSON object |
| `NESTED` | `Object` | Nested object |
| `FLAT_OBJECT` | `Object` | Flat object |
| `GEO_POINT` | `Object` | Geographic point |
| `JOIN` | `Object` | Join field |

Every other `schemf::Type` (`KNN_VECTOR`, `SPARSE_VECTOR`, `RANK_FEATURE(S)`, `PERCOLATOR`, `STAR_TREE`, `DERIVED`
and the `*_RANGE` types) maps to no JSON type and gets `getIncompatibleValidator()`: no helper can write it.

> Multiple schema types share the same JSON type. For example, both `IP` and `KEYWORD` are JSON
> `String`, but `IP` has a stricter validator that checks IP address format.

---

## Type Compatibility Matrix

When a helper expects a schema type (via `STypeToken`) that differs from the target field's schema
type, the validator checks a **compatibility map**. Each schema type declares which other types are
compatible, and whether additional runtime validation is needed.

The map is `registerCompatibles()` in `schemf/src/validator.cpp`. Key compatibility rules:

| Target Field Type | Compatible Helper Types (needs runtime validation?) |
|-------------------|----------------------------------------------------|
| `LONG` | `INTEGER` (no), `SHORT` (no), `BYTE` (no) |
| `INTEGER` | `LONG` (yes), `SHORT` (no), `BYTE` (no) |
| `SHORT` | `INTEGER` (yes), `LONG` (yes), `BYTE` (no) |
| `BYTE` | `INTEGER` (yes), `LONG` (yes), `SHORT` (yes) |
| `DOUBLE` | `FLOAT` (no), `HALF_FLOAT` (no), `SCALED_FLOAT` (no) |
| `FLOAT` | `DOUBLE` (yes), `HALF_FLOAT` (no), `SCALED_FLOAT` (no) |
| `HALF_FLOAT` | `FLOAT` (yes), `DOUBLE` (yes), `SCALED_FLOAT` (yes) |
| `SCALED_FLOAT` | `FLOAT` (no), `HALF_FLOAT` (no), `DOUBLE` (yes) |
| `IP`, `BINARY` | `KEYWORD` (yes), `TEXT` (yes), `WILDCARD` (yes) |
| `DATE` | `KEYWORD` (yes), `TEXT` (yes), `WILDCARD` (yes), `DATE_NANOS` (yes) |
| `DATE_NANOS` | `KEYWORD` (yes), `TEXT` (yes), `WILDCARD` (yes), `DATE` (yes) |
| `KEYWORD`, `TEXT`, `MATCH_ONLY_TEXT`, `WILDCARD`, `CONSTANT_KEYWORD`, `COMPLETION`, `SEARCH_AS_YOU_TYPE`, `SEMANTIC` | every other string type of this row, plus `DATE`, `DATE_NANOS`, `IP`, `BINARY` (all no) |
| `BOOLEAN`, `UNSIGNED_LONG`, `TOKEN_COUNT`, object types, `GEO_POINT` | none |

The "needs runtime validation" flag means that even though the types are structurally compatible,
the value must be checked at runtime (e.g. a `KEYWORD` value stored in an `IP` field must actually
be a valid IP address).

---

## Value Validators

Defined in `schemf/src/valueValidators.hpp`, each validator checks the concrete JSON value:

| Validator | Checks |
|-----------|--------|
| `getBoolValidator()` | `value.isBool()` |
| `getByteValidator()` | Is integer, fits in int8 range (used for `BYTE`) |
| `getShortValidator()` | Is integer, fits in int16 range (used for `SHORT`) |
| `getIntegerValidator()` | `value.isInt()` |
| `getLongValidator()` | `value.isInt64()` |
| `getUnsignedLongValidator()` | `value.isUint64()` (used for `UNSIGNED_LONG` and `TOKEN_COUNT`) |
| `getFloatValidator()` | `value.isFloat()` (used for `FLOAT`, `HALF_FLOAT`, `SCALED_FLOAT`) |
| `getDoubleValidator()` | `value.isDouble()` |
| `getStringValidator()` | `value.isString()` (every string type without a stricter validator) |
| `getDateValidator()` | Is string in the exact form `YYYY-MM-DDTHH:MM:SS[.fraction]Z` (two-digit fields, 1-9 fraction digits, zone `Z` or `Zulu` and nothing after it) that is a real calendar date and time (month 1-12, valid day of month, hour < 24, minute < 60, second < 60) |
| `getDateNanosValidator()` | `getDateValidator()` plus the range a `date_nanos` mapping can store (nanoseconds since the epoch in an int64): `1970-01-01T00:00:00Z` to `2262-04-11T23:47:16.854775807Z` |
| `getIpValidator()` | Is string that `inet_pton` accepts as IPv4 or IPv6 (whole string; no embedded NUL, no zone id) |
| `getBinaryValidator()` | Is string that is entirely Base64 (padding allowed, nothing after it) |
| `getObjectValidator()` | `value.isObject()` |
| `getGeoValidator()` | `{"lat":n,"lon":n}` or GeoJSON Point object; `"lat,lon"`, WKT `POINT(lon lat)` or geohash string; `[lon, lat]` or an array of geo points |
| `getIncompatibleValidator()` | Always fails (type cannot be used in helpers) |

---

## Examples by Registration Pattern

### 1. Static `JTypeToken` — `int_equal`

```cpp
registry->template add<builders::OpBuilderEntry>(
    "int_equal",
    {schemf::JTypeToken::create(json::Json::Type::Number), builders::opfilter::opBuilderHelperIntEqual});
```

- **Build-time**: Checks that the target field's JSON type is `Number`.
- **Runtime**: None. The dispatch returns the target type's validator (e.g. `LONG` → `getLongValidator()`), but
  `int_equal` is a `FilterBuilder`, which `runType()` does not wrap. A `MapBuilder` registered with a
  `JTypeToken` (e.g. `concat`, `to_string`) would have its output validated per element (for arrays) or directly.

### 2. Static `STypeToken` — `parse_ip`

```cpp
registry->template add<builders::OpBuilderEntry>(
    "parse_ip", {schemf::STypeToken::create(schemf::Type::IP), builders::optransform::ipParseBuilder});
```

- **Build-time**: Checks that the target field's schema type is `IP`, or one whose compatibility map lists `IP`:
  the `KEYWORD`/`TEXT` row of the matrix (not flagged for runtime validation). Any other target, `DATE` included,
  fails the build.
- **Runtime**: None — `ipParseBuilder` is a transform, and the `KEYWORD` → `IP` entry carries no runtime flag
  anyway.

### 3. `runtimeValidation()` — `exists`

```cpp
registry->template add<builders::OpBuilderEntry>("exists",
                                                 {schemf::runtimeValidation(), builders::opfilter::existsBuilder});
```

- **Build-time**: No type check. The field classification still runs (must be schema or `_`-prefixed).
- **Runtime**: None. The target type's validator is returned, but `exists` is a filter; only a map helper
  registered with `runtimeValidation()` would be wrapped.

### 4. `elementValidationToken()` — `array_append`

```cpp
registry->template add<builders::OpBuilderEntry>(
    "array_append", {schemf::elementValidationToken(), builders::optransform::getArrayAppendBuilder(false, false)});
```

- **Build-time**: `BaseToken` — only the target field classification runs.
- **Runtime**: None. The dispatch returns the element validator wrapped with `asArray()`, but
  `getArrayAppendBuilder()` returns a `TransformBuilder`, which `runType()` does not wrap.

### 5. `DynamicValToken` — `map`

```cpp
registry->template add<builders::OpBuilderEntry>("map",
                                                 {builders::opmap::mapValidator(), builders::opmap::mapBuilder});
```

- At build time the `DynamicValToken` factory inspects the argument:
  - **Literal value** (e.g. `42`, `"hello"`) → `ValueToken` created → value validated immediately
    against the target field's type. No runtime validation needed if it passes.
  - **Reference** (e.g. `$source.ip`) → `tokenFromReference()` looks up the referenced field's
    schema type → `STypeToken` created → build-time compatibility check. Runtime validator added
    if the types are compatible but need value checking.
  - **Reference to non-schema field** → falls back to `runtimeValidation()`: the target type's validator checks
    the mapped value at runtime.

`map` is a `MapBuilder`, so it is the one helper in this list whose runtime validator is actually applied.

---

## Summary

```
┌──────────────────────────────────────────────────────────────────┐
│                    Helper Registration                           │
│  OpBuilderEntry = (ValidationInfo, OpBuilder)                    │
│                                                                  │
│  ValidationInfo:                                                 │
│  ├── JTypeToken     → "target must be this JSON type"            │
│  ├── STypeToken     → "target must be this schema type"          │
│  ├── nullptr        → "skip build-time, validate at runtime"     │
│  ├── BaseToken      → "validate array elements"                  │
│  └── DynamicValToken→ "compute token from args at build time"    │
│         ├── Value arg  → ValueToken (validate value now)         │
│         └── Ref arg    → STypeToken or nullptr                   │
└──────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────────┐
│                    Build-Time Check                               │
│  1. Classify target: SCHEMA / TEMPORARY / Error                  │
│  2. TEMPORARY → no validation, done                              │
│  3. SCHEMA → dispatch by token type:                             │
│     • JTypeToken  → JSON type match?                             │
│     • STypeToken  → schema type compatible?                      │
│     • ValueToken  → validate value against field validator        │
│     • BaseToken   → return runtime validator for elements         │
│     • nullptr     → return runtime validator                      │
│  4. Return ValidationResult(runtimeValidator | nullptr)           │
└──────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────────┐
│                    Runtime Check (MapBuilder only)                │
│  If ValidationResult has a validator:                             │
│    wrap MapOp → execute, then validate output value               │
│    (for arrays, validate each element via asArray())              │
└──────────────────────────────────────────────────────────────────┘
```

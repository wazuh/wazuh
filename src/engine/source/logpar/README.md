# Logpar Module

## Overview

The **logpar** module implements the **log parsing expression language** used by the Wazuh Engine to extract structured fields from raw log lines. It takes a logpar expression string (e.g., `<timestamp> <host> <message>`) and compiles it into a composed parser that, when applied to a log line, returns a JSON object with the extracted fields.

Logpar bridges the **parsec** combinator library (grammar-level parsing) with the **hlp** library (type-specific parsers like IP, date, JSON, etc.) and the **schemf** schema validator (field type resolution). It is the mechanism that turns declarative extraction patterns in decoder definitions into executable parsers.

## Architecture

```
                     logpar expression string
                    "literal<field/args>(?group)"
                              │
                    ┌─────────▼──────────┐
                    │   parsec grammar    │  pLogpar → pExpr, pField,
                    │   (parser::*)       │  pLiteral, pChoice, pGroup
                    └─────────┬──────────┘
                              │ list<ParserInfo>
                    ┌─────────▼──────────┐
                    │   Logpar::build()   │  Resolves field types via
                    │                     │  schema + overrides, selects
                    │                     │  parser builder per type
                    └─────────┬──────────┘
                              │           ┌─────────────────────┐
                              ├──────────►│  schemf::IValidator  │  Field type lookup
                              │           └─────────────────────┘
                              │           ┌─────────────────────┐
                              ├──────────►│  ParserBuilders      │  hlp::parsers::*
                              │           │  (registered)        │  Type-specific parsers
                              │           └─────────────────────┘
                    ┌─────────▼──────────┐
                    │  hlp::parser::Parser│  Composed runtime parser
                    │  (log line → JSON)  │
                    └────────────────────┘
```

## Key Concepts

| Concept | Description |
|---|---|
| **Logpar Expression** | A string pattern like `[<date>] <host> <message>` that describes how to decompose a log line into fields. |
| **ParserType** | Enum of 28+ types (numeric, string, format, encoding, other) that map to specific hlp parser builders. |
| **Field Expression** | `<fieldName/arg1/arg2>` — extracts a value into `fieldName` using the parser determined by the field's schema type or explicit args. Prefix with `?` for optional: `<?field>`. |
| **Literal** | Plain text between field expressions, matched exactly. Escaped with `\`. |
| **Choice** | `<field1>?<field2>` — tries the first parser, falls back to the second. |
| **Group** | `(?...content...)` — makes a whole subsequence optional. Supports nesting up to `maxGroupRecursion` levels. |
| **Wildcard** | `<~>` — matches and discards content (no target field). |
| **Field Parser Override** | JSON config that forces a specific parser type for a field, bypassing schema type resolution. |
| **Schema Type Mapping** | Automatic mapping from `schemf::Type` (e.g., `LONG`, `IP`, `TEXT`) to `ParserType` for schema-defined fields. |
| **End Token** | The literal delimiter that tells a field parser where to stop consuming input. Resolved from the next element in the expression. |

### Expression Grammar Syntax

| Symbol | Meaning |
|---|---|
| `<` / `>` | Field expression delimiters |
| `?` | Optional marker (before field name or after field for choice) |
| `\` | Escape character |
| `/` | Argument separator within a field expression |
| `(` / `)` | Group delimiters |
| `~` | Wildcard (discard captured value) |
| `.` | Field name segment separator |

### Parser Types

| Category | Types |
|---|---|
| **Numeric** | `long`, `double`, `float`, `half_float`, `scaled_float`, `byte`, `unsigned_long`, `integer`, `short` |
| **String** | `text`, `literal`, `quoted`, `between` |
| **Encoding** | `binary` |
| **Format** | `csv`, `dsv`, `json`, `xml`, `kv` |
| **Other** | `bool`, `date`, `ip`, `uri`, `fqdn`, `file`, `useragent`, `alphanumeric`, `ignore` |

## Directory Structure

```
logpar/
├── CMakeLists.txt
├── README.md
├── include/logpar/
│   ├── logpar.hpp           # Logpar class, ParserType enum, grammar AST types, parsec parsers
│   └── registerParsers.hpp  # registerParsers() — registers all hlp parser builders
├── src/
│   └── logpar.cpp           # Grammar parsers implementation + Logpar class implementation
└── test/
    └── src/unit/
        ├── logpar_test.hpp  # Test fixtures with mock schema
        └── logpar_test.cpp  # Unit tests (construction, parsing, building)
```

## Public Interface

### `Logpar` Class ([logpar.hpp](include/logpar/logpar.hpp))

```cpp
namespace hlp::logpar {

class Logpar {
public:
    Logpar(const json::Json& fieldParserOverrides,
           const std::shared_ptr<schemf::IValidator>& schemaValidator,
           size_t maxGroupRecursion = 1,
           size_t debugLvl = 0);

    void registerBuilder(ParserType type, const ParserBuilder& builder);

    hlp::parser::Parser build(std::string_view logpar) const;
};

}
```

| Method | Description |
|---|---|
| **Constructor** | Takes field parser override config (JSON), schema validator, max group nesting depth, and debug level. Validates config structure, loads overrides, initializes schema-type→parser-type mapping. |
| `registerBuilder(type, builder)` | Registers an hlp parser builder function for a given `ParserType`. Throws if already registered. |
| `build(expression)` | Parses a logpar expression string into an AST, resolves field types, composes parser builders, and returns a single executable `hlp::parser::Parser` that transforms log lines into JSON. |

### `registerParsers()` ([registerParsers.hpp](include/logpar/registerParsers.hpp))

```cpp
void hlp::registerParsers(std::shared_ptr<logpar::Logpar> logpar);
```

Convenience function that registers all 28 built-in hlp parser builders (numeric, string, encoding, format, and other types) with a `Logpar` instance.

### Grammar AST Types

| Type | Description |
|---|---|
| `parser::Literal` | A literal string token to match exactly |
| `parser::FieldName` | A field name identifier |
| `parser::Field` | Field name + arguments + optional flag |
| `parser::Choice` | Two alternative fields (`<a>?<b>`) |
| `parser::Group` | Optional subsequence with nested children |
| `ParserInfo` | `variant<Literal, Field, Choice, Group>` — the AST node type |

### Grammar Parsers

Low-level parsec-based parsers exposed in `hlp::logpar::parser`:

- `pLogpar()` — parses a complete logpar expression
- `pExpr()` — parses a sequence of tokens
- `pField()` / `pFieldName()` / `pArgs()` — parse field expressions
- `pLiteral()` — parses literal text
- `pChoice()` — parses choice expressions
- `pGroup()` — parses optional groups (recursive)

## Implementation Details

### Build Pipeline

1. **Parse**: `pLogpar()` parses the expression string into a `list<ParserInfo>` AST using parsec combinators.
2. **Resolve**: `buildParsers()` iterates the AST. For each `Field`, it resolves the parser type:
   - If the field is a **wildcard** (`~`), no target field is set.
   - If the field is **not in schema** (custom/temporary), uses the explicit type arg or defaults to `text`.
   - If the field is **in schema**, checks field parser overrides first, then maps the schema type to a parser type.
3. **Compose**: Each resolved type looks up its registered `ParserBuilder`, which creates an `hlp::parser::Parser`. End tokens are computed from the next literal/group in the expression to tell the parser where to stop.
4. **Combine**: All parsers are combined with `hlp::parser::combinator::all()` and an EOF parser is appended.

### End Token Resolution

Fields need to know where their value ends. The algorithm:
- If followed by a **literal**: use that literal as the end token.
- If followed by a **group**: recursively resolve the group's first literal as end token, plus the token after the group.
- If at **end of expression**: use empty string (EOF).
- Otherwise: no end token (empty list).

### Group Recursion

Groups `(?...content...)` make their content optional. They can be nested, but nesting depth is limited by `maxGroupRecursion` (default: 1). Groups that follow a field create a choice: the field+group vs. the field alone with the token after the group as delimiter.

### Schema Type Mapping

The constructor populates a mapping from all `schemf::Type` values to `ParserType`. Supported types map to their natural parser (e.g., `LONG` → `P_LONG`, `IP` → `P_IP`, `TEXT`/`KEYWORD` → `P_TEXT`). Unsupported types (e.g., `GEO_POINT`, `NESTED`, range types) map to `ERROR_TYPE` and will throw at build time if used.

## CMake Targets

| Target | Type | Description |
|---|---|---|
| `logpar` | STATIC | The logpar library |
| `logpar_utest` | Executable | Unit tests |

**Key dependencies**: `hlp`, `base`, `schemf::ischema`, `parsec`

## Testing

Unit tests cover:

- **Construction**: Valid config, missing name/fields, non-string overrides, null schema
- **Expression parsing** (parameterized): 20+ expression patterns testing literals, fields, wildcards, optionals, choices, groups, escape sequences, and invalid patterns
- **End-to-end parsing**: Logpar expressions applied to sample log lines, verifying extracted JSON matches expected output
- **Schema integration**: Field type resolution via mock schema, override application
- **Error cases**: Unknown parser types, unsupported schema types, max recursion, unregistered builders

## Consumers

| Consumer | Usage |
|---|---|
| **`builder`** | The `Builder` class holds a `shared_ptr<Logpar>` and uses it to compile `parse\|` operations in decoder definitions into runtime parsers |
| **`main.cpp`** | Engine entry point — creates `Logpar` instance with schema and overrides config, calls `registerParsers()`, passes to builder |

# Logpar Module

## Overview

The **logpar** module implements the **log parsing expression language** used by the Wazuh Engine to extract structured fields from raw log lines. It takes a logpar expression string (e.g., `<timestamp> <host> <message>`) and compiles it into a composed parser that, when applied to a log line, returns a JSON object with the extracted fields.

Logpar bridges the **parsec** combinator library (grammar-level parsing) with the **hlp** library (type-specific parsers like IP, date, JSON, etc.) and the **schemf** schema validator (field type resolution). It is the mechanism that turns the declarative extraction patterns of a decoder's `parse` stage into executable parsers. The operator-facing syntax and parser reference is [ref-parser.md](../../../../docs/ref/modules/engine/ref-parser.md).

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
| **ParserType** | Enum (namespace `hlp`) of 28 parser types (numeric, string, format, encoding, other) plus `ERROR_TYPE`; each maps to an hlp parser builder. `strToParserType()`/`parserTypeToStr()` convert to and from the names below. |
| **Field Expression** | `<fieldName/arg1/arg2>` — extracts a value into `fieldName` using the parser determined by the field's schema type or explicit args. Prefix with `?` for optional: `<?field>`. |
| **Literal** | Plain text between field expressions, matched exactly. Escaped with `\`. |
| **Choice** | `<field1>?<field2>` — tries the first parser, falls back to the second. Neither side may be optional. |
| **Group** | `(?...content...)` — makes a whole subsequence optional. Supports nesting up to `maxGroupRecursion` levels. |
| **Wildcard** | `<~>` — matches and discards content (no target field). |
| **Field Parser Override** | JSON config (`{"name": …, "fields": {"<schema field>": "<parser type>"}}`) that forces a specific parser type for a schema field, bypassing schema type resolution. `main.cpp` reads it from the internal store document `schema/wazuh-logpar-overrides/0`. |
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

Field names are alphanumeric plus `_`, `@`, `#` (`~` is also accepted as the first character), per `syntax::EXPR_FIELD_EXTENDED_CHARS[_FIRST]`.

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
| **Constructor** | Takes field parser override config (JSON), schema validator, max group nesting depth, and debug level. Throws if `maxGroupRecursion` exceeds `parser::MAX_GROUP_NESTING` (64), the schema is null, the config is not an object with a string `/name` and an object `/fields`, or an override names a field absent from the schema or a value that is not a known parser type string. Then initializes the schema-type→parser-type mapping. `main.cpp` uses the defaults for depth (1) and debug level (0). |
| `registerBuilder(type, builder)` | Registers an hlp parser builder function for a given `ParserType`. Throws if already registered. |
| `build(expression)` | Parses a logpar expression string into an AST, resolves field types, composes parser builders, and returns a single executable `hlp::parser::Parser` that transforms log lines into JSON. A syntax error throws `std::runtime_error` with the formatted parsec trace. |

### `registerParsers()` ([registerParsers.hpp](include/logpar/registerParsers.hpp))

```cpp
void hlp::registerParsers(std::shared_ptr<logpar::Logpar> logpar);
```

Inline function that registers all 28 built-in hlp parser builders (numeric, string, encoding, format, and other types) with a `Logpar` instance; `main.cpp` calls it right after construction.

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

- `pLogpar(maxGroupDepth = MAX_GROUP_NESTING)` — parses a complete logpar expression (requires end of input)
- `pExpr()` — parses a sequence of tokens
- `pField()` / `pFieldName()` / `pArgs()` — parse field expressions
- `pLiteral()` — parses literal text
- `pChoice()` — parses choice expressions
- `pGroup(maxDepth = MAX_GROUP_NESTING)` — parses optional groups (recursive, depth-limited)
- `pEof<T>()`, `pChar()`, `pNotChar()`, `pEscapedChar()`, `pRawLiteral()`, `pRawLiteral1()`, `pCharAlphaNum()` — character-level helpers

## Implementation Details

### Build Pipeline

1. **Parse**: `pLogpar(m_maxGroupRecursion)` parses the expression string into a `list<ParserInfo>` AST using parsec combinators.
2. **Resolve**: `buildParsers()` iterates the AST. For each `Field`, it resolves the parser type:
   - Unless the field is the **wildcard** (`~`), its name is checked with `schemf::IValidator::validateTargetField()`; an invalid target throws.
   - If the field is the wildcard or **not a schema field** (custom/temporary), uses the explicit type arg (first argument, removed from the parser options; unknown name throws) or defaults to `text`.
   - If the field is **in schema**, checks field parser overrides first, then maps the schema type to a parser type.
   - The wildcard gets no target field: its value is discarded.
3. **Compose**: Each resolved type looks up its registered `ParserBuilder`, which creates an `hlp::parser::Parser`. End tokens are computed from the next literal/group in the expression to tell the parser where to stop.
4. **Combine**: All parsers are combined with `hlp::parser::combinator::all()` and an EOF parser (`hlp::parsers::getEofParser`) is appended, so the whole line must be consumed.

### End Token Resolution

Fields need to know where their value ends. The algorithm:
- If followed by a **literal**: use that literal as the end token.
- If followed by a **group**: recursively resolve the group's first literal as end token, plus the token after the group. A group must start with a literal (or a run of groups followed by a literal); otherwise the build throws.
- If at **end of expression**: use empty string (EOF).
- Otherwise: no end token (empty list).

### Group Recursion

Groups `(?...content...)` make their content optional. They can be nested, but nesting depth is limited by `maxGroupRecursion` (default: 1). The limit is enforced while the expression is parsed, before a nested group is descended into, so the recursive group parser's stack use is bounded by the limit rather than by the expression length; the constructor refuses a `maxGroupRecursion` above `parser::MAX_GROUP_NESTING` (64). `build()` also throws `Max group recursion level reached` when more consecutive groups appear than `maxGroupRecursion`. Groups that follow a field create a choice: the field+group vs. the field alone with the token after the group as delimiter.

### Schema Type Mapping

The constructor populates a mapping from all `schemf::Type` values to `ParserType`. Supported types map to their natural parser (e.g., `LONG` → `P_LONG`, `IP` → `P_IP`, `DATE`/`DATE_NANOS` → `P_DATE`; `TEXT`, `KEYWORD`, `WILDCARD` and the other string-like types → `P_TEXT`; `TOKEN_COUNT` → `P_UNSIGNED_LONG`). Unsupported types (e.g., `OBJECT`, `NESTED`, `GEO_POINT`, `FLAT_OBJECT`, vector and range types) map to `ERROR_TYPE` and throw at build time if a parsed field has them.

## CMake Targets

| Target | Type | Description |
|---|---|---|
| `logpar` | STATIC | The logpar library |
| `logpar_utest` | Executable | Unit tests (`ENGINE_BUILD_TEST` only; links `schemf::mocks`) |

**Key dependencies**: `hlp`, `base`, `schemf::ischema`, `parsec`

## Testing

Unit tests cover:

- **Construction**: valid config, `maxGroupRecursion` over the limit, non-object config, missing name/fields, non-string overrides
- **Grammar parsers** (parameterized): field, literal, choice, expression, group and full-logpar parsers over valid and invalid patterns (wildcards, optionals, escapes), group depth limits including deep nesting that must fail without exhausting the stack
- **End-to-end parsing**: logpar expressions built and applied to sample log lines, verifying the extracted JSON
- **Schema integration**: additional schema types mapped to parsers, and incompatible schema types mapped to `ERROR_TYPE`

## Consumers

| Consumer | Usage |
|---|---|
| **`builder`** | `BuilderDeps::logpar` (`shared_ptr<hlp::logpar::Logpar>`) is handed to `getParseBuilder()`, which compiles the `parse` stage's `parse\|<field>` expressions in decoder definitions into runtime parsers |
| **`main.cpp`** | Engine entry point — reads the overrides document `schema/wazuh-logpar-overrides/0` from the store (startup fails without it), creates the `Logpar` with the schema validator, calls `registerParsers()`, passes it to the builder |

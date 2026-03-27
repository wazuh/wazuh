# HLP — High-Level Parsers

## Overview

`hlp` is a library of **type-specific parsers** for the Wazuh Engine's log parsing pipeline. Each parser is a self-contained function that can recognize, validate, and extract a particular data type (IP addresses, dates, JSON, CSV, URIs, etc.) from a raw text input, optionally mapping the result into a JSON event.

Parsers are composed from two layers:

- **Syntax parsers** — lightweight, character-level combinators that consume input without semantic validation.
- **Semantic parsers** — validation and mapping functions that run after syntax recognition, converting the matched text into typed JSON fields.

The `logpar` module compiles log format expressions into parser chains by selecting the appropriate HLP builder function for each field type.

## Architecture

```
              Log format expression (logpar)
                        │
                        ▼
              ┌───────────────────┐
              │  ParserBuilder    │   hlp::Params → hlp::parser::Parser
              │  (factory fn)     │
              └────────┬──────────┘
                       │
          ┌────────────┼─────────────┐
          ▼            ▼             ▼
     getIPParser  getDateParser  getTextParser  ...
          │            │             │
          ▼            ▼             ▼
    ┌──────────────────────────────────────┐
    │       Three-Phase Execution          │
    │                                      │
    │  1. Syntax parsing                   │
    │     syntax::Parser(input)            │
    │     → Result<string_view>            │
    │                                      │
    │  2. Semantic parsing                 │
    │     SemParser(parsed_text)           │
    │     → Mapper | Error                 │
    │                                      │
    │  3. Mapping                          │
    │     Mapper(json::Json& event)        │
    │     → sets typed field in event      │
    └──────────────────────────────────────┘
```

### Three-Phase Pipeline

The `parser::run()` function orchestrates the three phases:

| Phase | Input | Output | Purpose |
|-------|-------|--------|---------|
| **Syntax** | `string_view` text | `Result<SemToken>` with remaining | Character-level pattern matching (what to consume) |
| **Semantic** | Matched `string_view` | `Mapper` or `Error` | Type validation (is it a valid IP? valid date?) |
| **Mapping** | `json::Json& event` | Modified event | Write the typed value into the target field |

This separation allows syntax to be fast and reusable, while semantic validation and mapping vary per data type.

## Key Concepts

### Parser Type

```cpp
namespace hlp::parser {
    using Mapper    = std::function<void(json::Json&)>;
    using SemParser = std::function<std::variant<Mapper, base::Error>(std::string_view)>;
    struct SemToken { std::string_view parsed; SemParser semParser; };
    using Parser    = abs::Parser<SemToken>;  // function<Result<SemToken>(string_view)>
}
```

### Params — Builder Input

Every parser builder receives the same `Params` struct:

```cpp
struct Params {
    std::string name;         // Parser name (used in error traces)
    std::string targetField;  // JSON path to set in the event (empty = no mapping)
    Stop stop;                // End-token strings that delimit the parser's input
    Options options;          // Parser-specific extra arguments
};
```

### ParserBuilder

```cpp
using ParserBuilder = std::function<parser::Parser(const Params&)>;
```

The `logpar` module maintains a registry of `ParserBuilder` functions, one per type name (e.g., `"ip"` → `getIPParser`).

### Syntax Combinators

The `syntax.hpp` header provides low-level combinators that build syntax parsers:

| Combinator | Operator | Description |
|------------|----------|-------------|
| Sequence | `lhs & rhs` | Succeeds if both parsers succeed in order |
| Choice | `lhs \| rhs` | Succeeds if either parser succeeds |
| Optional | `opt(p)` | Always succeeds |
| Repeat | `times(p, min, max)` | Matches min–max times (0 = unbounded) |
| Many | `many(p)` | Zero or more |
| Many1 | `many1(p)` | One or more |
| Repeat exact | `repeat(p, n)` | Exactly n times |

Basic syntax parsers: `any()`, `char_(c)`, `digit()`, `hex()`, `alnum()`, `literal(str)`, `toEnd(token)`, `toEnd()`.

### Abstract Result

`abs::Result<T>` is a generic parse result that supports nesting:

- `success()` / `failure()` — outcome
- `remaining()` — unconsumed input
- `value()` — extracted value of type `T`
- `nested()` — child results from sub-parsers
- `trace()` — parser name for error reporting

Factory helpers: `makeSuccess(...)`, `makeFailure(...)`.

## Directory Structure

```
hlp/
├── CMakeLists.txt
├── include/hlp/                      # Public headers
│   ├── hlp.hpp                       # All parser builder declarations + Params/ParserBuilder types
│   ├── parser.hpp                    # Parser, SemToken, Mapper, SemParser, run(), combinators
│   └── abstractParser.hpp            # Result<T>, Parser<T>, makeSuccess/makeFailure
├── src/
│   ├── syntax.hpp                    # Syntax-level parser type, combinators, basic parsers
│   └── parsers/                      # One .cpp per parser type
│       ├── text.cpp                  # getTextParser — match until stop token
│       ├── literal.cpp               # getLiteralParser — exact string match
│       ├── number.cpp                # getByte/Short/Integer/Long/Float/Double/... parsers
│       ├── number.hpp                # Number parsing helpers (tryStrToNumber)
│       ├── bool.cpp                  # getBoolParser — "true"/"false"
│       ├── ip.cpp                    # getIPParser — IPv4/IPv6 via inet_pton
│       ├── date.cpp                  # getDateParser — chrono-based date parsing + TZDB
│       ├── json.cpp                  # getJSONParser — rapidJSON streaming parser
│       ├── xml.cpp                   # getXMLParser — pugixml parser
│       ├── web.cpp                   # getUriParser, getUAParser, getFQDNParser
│       ├── dsv_csv.cpp              # getDSVParser, getCSVParser — delimiter/comma separated
│       ├── kvmap.cpp                 # getKVParser — key-value map parsing
│       ├── quoted.cpp                # getQuotedParser — quoted string extraction
│       ├── between.cpp              # getBetweenParser — match between delimiters
│       ├── alphanumeric.cpp         # getAlphanumericParser
│       ├── encodings.cpp            # getBinaryParser — base64 decoding
│       ├── file.cpp                  # getFilePathParser — Windows/Unix paths
│       ├── ignore.cpp                # getIgnoreParser — skip repeated prefix
│       ├── eof.cpp                   # getEofParser — match end of input
│       ├── parse_field.hpp          # Field class + getField/unescape/updateDoc helpers
│       └── parse_field.cpp          # Field parsing implementation (for DSV/KV)
└── test/src/unit/
    ├── hlp_test.hpp                  # Test harness and helpers
    ├── hlp_test.cpp                  # General integration tests
    ├── text_test.cpp
    ├── literal_test.cpp
    ├── numeric_test.cpp
    ├── eof_test.cpp
    ├── alnum_test.cpp
    ├── bool_test.cpp
    ├── between_test.cpp
    ├── date_test.cpp
    ├── binary_test.cpp
    ├── json_test.cpp
    ├── ip_test.cpp
    ├── ignore_test.cpp
    ├── xml_test.cpp
    ├── quoted_test.cpp
    ├── file_test.cpp
    ├── web_test.cpp
    ├── kvmap_test.cpp
    └── dsv_csv_test.cpp
```

## Public Interface

### Parser Builders (hlp.hpp)

All builders follow the signature `Parser fn(const Params&)`. Each validates its `params`, constructs a syntax parser from combinators, wires up a semantic parser, and returns a composed `Parser`.

| Builder | Type Parsed | Stop | Options |
|---------|-------------|------|---------|
| `getTextParser` | Any text until stop | Required | — |
| `getLiteralParser` | Exact string | — | `[literal]` |
| `getEofParser` | End of input | — | — |
| `getBoolParser` | `true` / `false` | Optional | — |
| `getByteParser` | 8-bit integer | Optional | — |
| `getShortParser` | 16-bit integer | Optional | — |
| `getIntegerParser` | 32-bit integer | Optional | — |
| `getLongParser` | 64-bit integer | Optional | — |
| `getUnsignedLongParser` | Unsigned 64-bit | Optional | — |
| `getHalfFloatParser` | 16-bit float | Optional | — |
| `getFloatParser` | 32-bit float | Optional | — |
| `getDoubleParser` | 64-bit float | Optional | — |
| `getScaledFloatParser` | Scaled float | Optional | — |
| `getBinaryParser` | Base64 string | Optional | — |
| `getDateParser` | Date/time | Optional | `[format, locale]` or `[sample, locale]` |
| `getIPParser` | IPv4 / IPv6 | — | — |
| `getUriParser` | URI (ECS url) | Optional | — |
| `getUAParser` | User-Agent | Optional | — |
| `getFQDNParser` | Domain name | Optional | — |
| `getFilePathParser` | File path | Optional | — |
| `getJSONParser` | JSON value | — | — |
| `getXMLParser` | XML document | — | — |
| `getDSVParser` | Delimiter-separated | Required | `[delimiter, quote, escape, fields...]` |
| `getCSVParser` | Comma-separated | Required | `[fields...]` |
| `getKVParser` | Key-value map | Optional | `[separator, delimiter]` |
| `getQuotedParser` | Quoted string | — | `[quote_char, escape_char]` |
| `getBetweenParser` | Between delimiters | — | `[start, end]` |
| `getAlphanumericParser` | Alphanumeric chars | — | — |
| `getIgnoreParser` | Skip prefix | — | `[string_to_ignore]` |

### Execution (parser.hpp)

```cpp
// Run syntax → semantic → mapping pipeline
std::optional<base::Error> parser::run(const Parser& parser, std::string_view text, json::Json& event);
```

### HLP-Level Combinators (parser.hpp)

```cpp
namespace hlp::parser::combinator {
    Parser choice(const Parser& lhs, const Parser& rhs);  // try left, then right
    Parser sequence(...);  // run parsers in order, nest results
}
```

### TZDB Initialization

```cpp
void hlp::initTZDB(const std::string& path, bool autoUpdate, const std::string& forceVersion = "");
```

Initializes the timezone database used by the date parser.

## Implementation Details

### Parser Pattern

Each parser builder in `src/parsers/` follows the same structure:

1. **Validate `params`** — check required options, stop tokens
2. **Build syntax parser** — compose `syntax::Parser` from combinators
3. **Build semantic parser** — create a `SemParser` lambda that validates the matched text and returns a `Mapper`
4. **Return composed parser** — a lambda that runs syntax, wraps the result in `SemToken{parsed, semP}`

Example flow for `getIPParser`:
- Syntax: `ipv4 | mixed | ipv6` using digit/hex combinators
- Semantic: validates via `inet_pton(AF_INET)` and `inet_pton(AF_INET6)`
- Mapper: `event.setString(parsed, targetField)`

### Field Parsing (parse_field.hpp/cpp)

Used by DSV/CSV and KV parsers to split delimited fields while respecting quoting and escaping:
- `getField()` — parses a single field from input with configurable delimiter, quote, and escape characters
- `unescape()` — removes escape characters from parsed values
- `updateDoc()` — adds key-value to JSON, auto-detecting numeric types for unquoted values

### External Libraries

| Library | Used By | Purpose |
|---------|---------|---------|
| `FastFloat` | Number parsers | Fast string-to-number conversion |
| `date::date-tz` | Date parser | Chrono-based date/time parsing with timezone support |
| `CURL::libcurl` | URI parser | URL parsing |
| `pugixml` | XML parser | XML document parsing |
| `rapidjson` | JSON parser | Streaming JSON parsing |

## CMake Targets

| Target | Type | Description |
|--------|------|-------------|
| `hlp` | STATIC | All parser implementations (links FastFloat, date-tz, curl, pugixml) |
| `hlp_utest` | Executable | Unit tests (one test file per parser type) |

## Testing

Each parser has a dedicated test file (`*_test.cpp`) testing:
- Valid inputs → successful parse and correct JSON mapping
- Invalid inputs → parse failure with appropriate error traces
- Edge cases: empty input, missing stop tokens, partial matches

## Consumers

| Consumer | Dependency | Usage |
|----------|------------|-------|
| **logpar** | `hlp` | Registers parser builders, compiles log format expressions into parser chains using HLP builders |
| **schemf** | `hlp` | Uses HLP for value validation against schema types |
| **builder** | `hlp` (via `logpar`) | HLP transform operation wrappers for event processing |

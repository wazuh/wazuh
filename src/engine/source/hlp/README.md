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
    using SemParser = std::function<std::variant<Mapper, base::Error>(std::string_view, bool)>;
    struct SemToken { std::string_view parsed; SemParser semParser; };
    using Parser    = abs::Parser<SemToken>;  // function<Result<SemToken>(string_view)>
}
```

The semantic parser receives the matched text plus an `enableTrace` flag. When `enableTrace` is `false`, parsers may
skip building detailed error strings and return an empty `base::Error` instead.

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

Basic syntax parsers (namespace `syntax::parsers`): `any()`, `char_(c)`, `digit()`, `hex()`, `alnum(additional = "")`,
`literal(str, caseSensitive = true)`, `toEnd(char)`, `toEnd(string)`, `toEnd(vector<string>)`, `toEnd()`.
The combinators live in `syntax::combinators`.

### Abstract Result

`abs::Result<T>` is a generic parse result that supports nesting:

- `success()` / `failure()` — outcome
- `remaining()` — unconsumed input
- `hasValue()` / `value()` — whether a value was extracted, and the value of type `T`
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
│       ├── json.cpp                  # getJSONParser — rapidjson Document over a StringStream, depth-bounded
│       ├── xml.cpp                   # getXMLParser — pugixml parser
│       ├── web.cpp                   # getUriParser, getUAParser, getFQDNParser
│       ├── dsv_csv.cpp               # getDSVParser, getCSVParser — delimiter/comma separated
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
    ├── address_space_cap.hpp         # Runs a check in a child with a capped address space (KV numeric keys)
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
    ├── dsv_csv_test.cpp
    └── parse_field_test.cpp          # getField quoting/escaping edge cases
```

## Public Interface

### Parser Builders (hlp.hpp)

All builders follow the signature `Parser fn(const Params&)`. Each validates its `params`, constructs a syntax parser from combinators, wires up a semantic parser, and returns a composed `Parser`.

`Stop` says whether the builder throws `std::runtime_error` when `params.stop` is empty ("Required") or
does not read it at all ("—"). `Options` lists what each builder accepts; any other count or shape
throws at build time. Builders declared in `hlp.hpp` live in namespace `hlp::parsers`.

| Builder | Type Parsed | Stop | Options |
|---------|-------------|------|---------|
| `getTextParser` | Any text until stop | Required | none |
| `getLiteralParser` | Exact string | — | exactly `[literal]` |
| `getEofParser` | End of input | — | none |
| `getBoolParser` | `true` / `false` | — | none |
| `getByteParser` | 8-bit integer | — | none |
| `getShortParser` | 16-bit integer | — | none |
| `getIntegerParser` | 32-bit integer | — | none |
| `getLongParser` | 64-bit integer | — | none |
| `getUnsignedLongParser` | Unsigned 64-bit | — | none |
| `getHalfFloatParser` | 16-bit float | — | none |
| `getFloatParser` | 32-bit float | — | none |
| `getDoubleParser` | 64-bit float | — | none |
| `getScaledFloatParser` | Scaled float | — | none |
| `getBinaryParser` | Base64 string | — | none |
| `getDateParser` | Date/time | — | `[format]` or `[sample]`, optionally followed by a locale (default: the C/POSIX locale) |
| `getIPParser` | IPv4 / IPv6 | — | none |
| `getUriParser` | URI (ECS url) | Required | none |
| `getUAParser` | User-Agent | Required | none |
| `getFQDNParser` | Domain name | — | none |
| `getFilePathParser` | File path | Required | none |
| `getJSONParser` | JSON value | — | none |
| `getXMLParser` | XML document | Required | none, or `[module]`: `default` or `windows` |
| `getDSVParser` | Delimiter-separated | Required | `[delimiter, quote, escape, header1, header2, ...]` (at least 5; the three characters single) |
| `getCSVParser` | Comma-separated | Required | `[header1, header2, ...]` (at least 2; delimiter `,`, quote and escape `"`) |
| `getKVParser` | Key-value map | — | exactly `[separator, delimiter, quote, escape]` (separator ≠ delimiter, both non-empty; quote and escape single characters) |
| `getQuotedParser` | Quoted string | — | 0–2: `[quote, escape]`, single characters, defaults `"` and `\` |
| `getBetweenParser` | Between delimiters | — | exactly `[start, end]`, not both empty |
| `getAlphanumericParser` | Alphanumeric chars | — | 0 or 1: `[additional_chars]` also accepted |
| `getIgnoreParser` | Skip prefix | — | exactly `[string_to_ignore]` (non-empty); a `targetField` is rejected |

### Execution (parser.hpp)

```cpp
// Run syntax → semantic → mapping pipeline
std::optional<base::Error>
parser::run(const Parser& parser, std::string_view text, json::Json& event, bool enableTrace = true);
```

`parser::run` returns an empty optional on success. On failure it returns a `base::Error`; when `enableTrace` is
`false`, the error is still present but its `message` may be empty.

### HLP-Level Combinators (parser.hpp)

```cpp
namespace hlp::parser::combinator {
    Parser choice(const Parser& lhs, const Parser& rhs);      // try left, then right
    Parser opt(const Parser& parser);                         // parser becomes optional
    Parser all(const std::vector<Parser>& parsers);           // run parsers in order, nest results
}
```

### TZDB Initialization

```cpp
void hlp::initTZDB(const std::string& path, bool autoUpdate, const std::string& forceVersion = "");
```

Initializes the timezone database used by the date parser. `main.cpp` calls it with
`<analysisd.tzdb_path>/iana`, `analysisd.tzdb_auto_update` and `analysisd.tzdb_force_version_update`
(defaults in `conf/src/conf.cpp`; operator reference in the engine book's
[Time-zone database](../../../../docs/ref/modules/engine/configuration.md#time-zone-database)). A forced version turns auto-update
on and downloads that version unless it is already the loaded one; with no database present and auto-update
disabled it throws.

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

### Nesting depth cap

The JSON, XML and KV parsers (`getJSONParser`, `getXMLParser`, `getKVParser`) build JSON structure from event text, so they share one nesting cap: `json::Json::MAX_DEPTH = 256`, declared in `src/engine/source/base/include/base/json.hpp` next to `json::Json::parseBounded`, which the `json::Json` constructors from text use as well. It is a compile-time constant: it is not configurable, and it is not a size limit (the size of the input is capped by remoted, before the engine).

Input nested deeper than 256 levels (json::Json::MAX_DEPTH) is rejected: the parser fails as on invalid input, the field is not set and nothing is logged; the nesting depth exceeds the limit (256) message names the cap in test traces.

The root container is level 1: 256 nested containers (objects and arrays) parse, the 257th fails. What is counted and what each parser returns:

| Parser | Depth unit | Fails at | Returns |
|--------|------------|----------|---------|
| `getJSONParser` | open JSON containers (objects and arrays), counted by `json::Json::parseBounded` | the 257th nested container | Syntax-phase failure (`makeFailure`) whose trace names the limit; no document is built |
| `getXMLParser` | nested XML elements, counted by `xmlToJson` (in `windows` mode the root `Event`, omitted from the output, is level 1) | the 257th nested element | Semantic-phase `base::Error`, the same contract as `Invalid XML` |
| `getKVParser` | tokens of the destination path of a key, with or without a value: one level per `.` plus one | a key with 256 dots (a key with 255 dots maps) | Semantic-phase `base::Error` |

`parser::run()` turns either failure into a `base::Error` that carries the message only when tracing is enabled (test mode) and is empty otherwise, exactly as for any other parse failure.

XML text and CDATA are leaves (`#text`) and do not add a level. A CDATA child is a leaf and does not produce a member of its own: `<a><![CDATA[x]]></a>` maps to `{"a":{"#text":"x"}}`.

**Invariant**: building the document and walking it afterwards (parse, copy, serialization, merge) costs one recursion per level, and the cap is sized so that this recursion fits the default 8 MiB process stack. The stack requirement is part of the operator contract and lives in [Process limits](../../../../docs/ref/modules/engine/configuration.md#process-limits); the per-parser behavior is in the [parser reference](../../../../docs/ref/modules/engine/ref-parser.md). Neither is repeated here.

### Field Parsing (parse_field.hpp/cpp)

Used by DSV/CSV and KV parsers to split delimited fields while respecting quoting and escaping:
- `getField()` — parses a single field from input with configurable delimiter, quote, and escape characters
- `unescape()` — removes escape characters from parsed values
- `updateDoc()` — adds a key-value to the JSON (`setNullAsMembers` for an empty value, `setStringAsMembers` otherwise); the dots of the key nest the value in both cases (`a.b=` maps to `{"a":{"b":null}}`); rejects destination paths deeper than the nesting cap. Every token of the key is written as an object member, never as an array index: `123=v` maps to `{"123":"v"}` and `a.5=v` to `{"a":{"5":"v"}}`, and the cost does not depend on the value of a numeric key
- `hasInvalidPointerEscape()` — true when a key has a `~` not followed by `0` or `1` (or a trailing `~`): such a key is not a valid JSON Pointer token and `updateDoc()` would throw on it. `kvmap` fails the parse on it; `dsv_csv` rejects such an output name when the parser is built

### External Libraries

| Library | Used By | Purpose |
|---------|---------|---------|
| `FastFloat` | Number parsers | Fast string-to-number conversion |
| `date::date-tz` | Date parser | Chrono-based date/time parsing with timezone support |
| `CURL::libcurl` | URI parser | URL parsing |
| `pugixml` | XML parser | XML document parsing |
| `rapidjson` | JSON parser | Streaming JSON parsing, bounded by `json::Json::parseBounded` |

## CMake Targets

| Target | Type | Description |
|--------|------|-------------|
| `hlp` | STATIC | All parser implementations (`base` public; FastFloat, date-tz, pthread, curl, pugixml private) |
| `hlp_utest` | Executable | Unit tests (`ENGINE_BUILD_TEST`; one test file per parser type plus `parse_field_test.cpp`); `HLP_TEST_TZDB_PATH` is `${CMAKE_SOURCE_DIR}/external/tzdata`, the top-level tree's downloaded tzdata |

## Testing

Each parser has a dedicated test file (`*_test.cpp`) testing:
- Valid inputs → successful parse and correct JSON mapping
- Invalid inputs → parse failure with appropriate error traces
- Edge cases: empty input, missing stop tokens, partial matches
- Depth boundary cases (256/257) and a stack probe (`*Depth*`, `*StackProbe`)

## Consumers

| Consumer | Dependency | Usage |
|----------|------------|-------|
| **logpar** | `hlp` (public) | `hlp::registerParsers()` registers the builders; compiles log format expressions into parser chains |
| **schemf** | `hlp` (private) | Uses HLP for value validation against schema types |
| **builder** | `hlp` (via `logpar`) | HLP transform operations (`builders/optransform/hlp.cpp`) and the parse stage |
| **main.cpp** | `hlp` (via `logpar`) | `hlp::initTZDB()` before building `Logpar` |

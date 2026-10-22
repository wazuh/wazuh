# Parsec Module

## Overview

The **parsec** module is a header-only parser combinator library for the Wazuh engine. It provides a set of composable, type-safe building blocks for constructing text parsers from small, reusable units.

A parser is a function that takes a `string_view` and a position index, and returns a typed `Result<T>` — either a parsed value on success or an error message on failure. Parsers are combined using operators and higher-order functions (combinators) to build complex grammars without separate lexer/parser phases.

The module provides **only the combinator framework** — it does not include concrete character-level parsers. Those are built by consumer modules (logpar, logicexpr, builder) on top of this foundation.

## Architecture

```
┌───────────────────────────────────────────────────┐
│              Consumer Modules                      │
│                                                    │
│  logpar         logicexpr         builder           │
│  (logpar        (boolean expr    (helper function   │
│   grammar)       tokenization)    arg parsing)      │
│                                                    │
│  Define concrete parsers:                          │
│  pChar(), pNotChar(), pLiteral(), getHelper*()...  │
└──────────────────────┬─────────────────────────────┘
                       │  use
              ┌────────▼─────────────────────┐
              │         parsec               │
              │   (combinator framework)     │
              │                              │
              │  Types: Parser<T>, Result<T> │
              │         Trace, Values<T>     │
              │                              │
              │  Combinators:                │
              │  opt, many, many1, fmap      │
              │  >>, <<, |, &, >>=           │
              │  negativeLook, positiveLook  │
              │  tag, replace                │
              └──────────────────────────────┘
```

## Key Concepts

### Parser Type

```cpp
template<typename T>
using Parser = std::function<Result<T>(std::string_view, size_t)>;
```

A parser is a function that:
- Takes the **full input text** (`string_view`) and the **current position** (`size_t index`)
- Returns a `Result<T>` containing either a parsed value + new index, or an error + position

Parsers are **pure functions** — they don't modify external state. The position index is advanced by the parser and returned in the result, allowing the next parser in a chain to continue from where the previous one left off.

### Result\<T\>

The return type of every parser. Wraps an optional value and a `Trace`:

| Method | Description |
|--------|-------------|
| `success()` / `failure()` | Check outcome |
| `value()` | Get the parsed value (const reference, or rvalue on a non-const `Result`). Precondition: `success()` — the header comment promises `std::bad_optional_access`, but the code dereferences the optional unchecked |
| `error()` | Get the trace message. Precondition: `failure()`; a success result throws `std::bad_optional_access` only when it carries no message |
| `index()` | Position after parsing (next unconsumed character) |
| `trace()` | Full `Trace` object for debugging |

Factory functions:

```cpp
// Success: value + new index (+ optional trace message and inner traces)
template<typename T>
Result<T> makeSuccess(T&& value, size_t index,
                      Trace::messageT&& trace = std::nullopt,
                      Trace::nestedTracesT&& innerTrace = std::nullopt);

// Failure: error message + position where failure occurred
template<typename T>
Result<T> makeError(std::string&& error, size_t index,
                    Trace::nestedTracesT&& innerTrace = std::nullopt);
```

### Trace

A tree-structured diagnostic that captures the success/failure history of combined parsers:

| Field | Type | Description |
|-------|------|-------------|
| `success()` | `bool` | Whether this parse step succeeded |
| `index()` | `size_t` | Position in the input |
| `message()` | `optional<string>` | Diagnostic message (error description or combinator label) |
| `innerTraces()` | `optional<vector<Trace>>` | Nested traces from sub-parsers |

Trace utilities:

| Function | Description |
|----------|-------------|
| `firstError(trace)` | Follow the first failed inner trace at each level down to the deepest one (returns `trace` itself if no inner trace failed) |
| `getLeafErrors(trace)` | Collect all leaf-level error traces |
| `detailedTrace(trace, last, prefix = "")` | Build a tree-formatted trace string for debugging |
| `formatTrace(text, trace, debugLvl)` | Human-readable error report with position markers: the main (first) error, the list of leaf errors, and with `debugLvl > 0` the detailed trace |

Example output from `formatTrace` (`debugLvl` 0; the string starts with a newline):

```
Main error: Expected digit at 3
hello world
---^

List of errors:
Expected digit at 3
hello world
---^
Expected letter at 3
hello world
---^
```

## Combinators Reference

### Sequencing

| Combinator | Syntax | Description |
|------------|--------|-------------|
| **Left shift** | `L << R` | Run L then R sequentially; return **L's result**, discard R's |
| **Right shift** | `L >> R` | Run L then R sequentially; return **R's result**, discard L's |
| **And** | `L & R` | Run L then R; return `tuple<L, R>` with both results |

All sequencing combinators fail if **either** parser fails.

### Choice

| Combinator | Syntax | Description |
|------------|--------|-------------|
| **Or** | `L \| R` | Try L first; if L fails, try R from the **same position** |

Succeeds if at least one parser succeeds. Both fail → combined failure.

### Repetition

| Combinator | Syntax | Description |
|------------|--------|-------------|
| **many** | `many(P)` | Run P zero or more times; **always succeeds** (returns empty list on first failure) |
| **many1** | `many1(P)` | Run P one or more times; fails if P doesn't succeed at least once |

Both return `Parser<Values<T>>` where `Values<T>` is `std::list<T>`.

### Lookahead

| Combinator | Syntax | Description |
|------------|--------|-------------|
| **positiveLook** | `positiveLook(P)` | Succeeds if P succeeds, but **consumes no input** |
| **negativeLook** | `negativeLook(P)` | Succeeds if P **fails**, consumes no input |

### Transformation

| Combinator | Syntax | Description |
|------------|--------|-------------|
| **opt** | `opt(P)` | Makes P optional; returns default `T{}` if P fails |
| **fmap** | `fmap<Tx, T>(f, P)` | Transform P's result through function `f: T → Tx` |
| **bind** | `P >>= M` | Monadic bind: run P, pass result to factory `M: T → Parser<Tx>`, run the new parser |
| **tag** | `tag(P, t)` | Pair P's result with a constant tag: returns `tuple<T, Tag>` |
| **replace** | `replace(P, t)` | Discard P's result, return constant tag value |

### Type Traits

```cpp
parsec::traits::is_parser<X>::value       // true if X is a Parser<T>
parsec::traits::is_parser_ret<X, R>::value // true if X is a Parser<T> where T derives from R
```

## Directory Structure

```
parsec/
├── CMakeLists.txt
├── interface/parsec/
│   └── parsec.hpp              # Full library (header-only)
└── test/src/
    └── parsec_test.cpp         # Unit tests
```

## CMake Target

| Target | Type | Description |
|--------|------|-------------|
| `parsec` | INTERFACE | Header-only library |
| `parsec_test` | EXECUTABLE | Unit tests |

**Dependencies:**

```
parsec  ←── base (INTERFACE)
```

## Testing

### Unit Tests (parsec_test.cpp)

Comprehensive coverage of all types and combinators:

| Category | Tests |
|----------|-------|
| **Trace** | Construction, copy/move, equality, field accessors (success, index, message, innerTraces) |
| **Result** | Construction, copy/move, equality, success/failure, value/error access, makeSuccess/makeError |
| **opt** | Success passthrough, failure → default value |
| **<<** | L ok / R ok, L fail, R fail |
| **>>** | L ok / R ok, L fail, R fail |
| **\|** | L ok, L fail / R ok, both fail |
| **&** | Both ok, L fail, R fail — verifies tuple construction |
| **fmap** | Success transformation, failure passthrough |
| **>>=** | Success chain, P fail, M fail |
| **many** | Multiple matches, first-failure (empty list), trace structure |
| **many1** | Multiple matches, first-failure (error) |
| **tag** | Success tagging, failure passthrough |
| **replace** | Success replacement, failure passthrough |

Tests use helper parsers: `getSuccessParser()`, `getErrorParser()`, and `getAnyParser()` (consumes one character per call).

## Consumers

| Module | Usage |
|--------|-------|
| **logpar** | Parses the logpar expression grammar (`hlp::logpar::parser::pLogpar()` and friends) into an AST. Defines low-level character parsers (`pChar`, `pNotChar`, `pEscapedChar`, `pRawLiteral`) on top of parsec combinators. The format parsers themselves (CSV, JSON, KV, …) live in `hlp`, which does not use parsec. |
| **logicexpr** | Tokenizes boolean logic expressions (AND, OR, NOT, parentheses). The template `Tokenizer<TermP>` requires `TermP` to be a `parsec::Parser` and tries it before matching operators; precedence is handled afterwards by the Shunting-Yard step. |
| **builder** | Parses helper function call arguments (`builder/src/builders/helperParser.hpp`): `getHelperQuotedArgParser()`, `getHelperRefArgParser()`, `getHelperJsonArgParser()`, `getHelperRawArgParser()` each return a `parsec::Parser<builders::OpArg>`. |

## Usage Example

Building a parser that matches "hello" followed by a space, then a single digit:

```cpp
#include <parsec/parsec.hpp>

// Primitive: match exact character
parsec::Parser<char> pChar(char c) {
    return [c](std::string_view s, size_t i) -> parsec::Result<char> {
        if (i < s.size() && s[i] == c)
            return parsec::makeSuccess<char>(char {c}, i + 1);
        return parsec::makeError<char>(
            fmt::format("Expected '{}' at {}", c, i), i);
    };
}

// Primitive: match a digit, return its integer value
parsec::Parser<int> pDigit() {
    return [](std::string_view s, size_t i) -> parsec::Result<int> {
        if (i < s.size() && std::isdigit(s[i]))
            return parsec::makeSuccess(int(s[i] - '0'), i + 1);
        return parsec::makeError<int>("Expected digit", i);
    };
}

// Combine: "hello" followed by a space, return the digit after
auto parser = pChar('h') >> pChar('e') >> pChar('l') >> pChar('l')
            >> pChar('o') >> pChar(' ') >> pDigit();

auto result = parser("hello 7", 0);
// result.success() == true
// result.value() == 7
// result.index() == 7
```

## Design Decisions

- **Header-only**: No compilation unit — the entire library is in a single header, keeping the combinator templates fully inlineable and avoiding link-time overhead.
- **Value semantics**: `Result<T>` and `Trace` are value types with full copy/move support. They are not allocation-free: a `Trace` owns an optional message string and an optional vector of inner traces, and `std::function` may allocate for large captures.
- **Trace tree**: Every combinator wraps its sub-parser traces into a tree, enabling recursive error reporting. This adds overhead but provides excellent diagnostics for complex grammars.
- **No built-in character parsers**: The module deliberately provides only the combinator framework. Concrete parsers (character matching, string literals) are defined by each consumer module to suit their specific needs.
- **`std::list` for Values**: `many`/`many1` use `std::list<T>` instead of `std::vector<T>` to enable efficient `splice` when composing `many1` on top of `many`.

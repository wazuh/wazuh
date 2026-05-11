# `defs` Module — Definition Variables

## Overview

The `defs` module provides a **variable definition and substitution system** for the Wazuh engine. It manages a set of named definitions (key-value pairs stored as JSON) and performs variable replacement in strings using the `$variable` syntax.

Its primary purpose is to allow policies and assets to declare reusable values (constants, paths, URLs, etc.) that are resolved at build time. Definitions can reference other definitions, forming dependency chains that are automatically resolved with cycle detection.

## Key Concepts

### Definition

A definition is a named value stored within a JSON object. Each key in the JSON object is a definition name, and its value can be any valid JSON type (string, number, boolean, null, array, or object).

```json
{
  "protocol": "https",
  "host": "api.example.com",
  "port": "8080",
  "base_url": "$protocol://$host:$port"
}
```

### Variable Reference

A variable reference uses the `$name` syntax within a string. When `replace()` is called, every `$name` pattern is substituted with the corresponding definition value.

- `$varname` — replaced with the value of `varname`
- `\$varname` — escaped, produces the literal `$varname`
- `$nonexistent` — left as-is if the definition doesn't exist

### Dependency Resolution

Definitions can reference other definitions. Dependencies are resolved at construction time using a **DFS (Depth-First Search) algorithm** that:

1. Traverses definition dependencies recursively
2. Resolves leaf definitions first, then works back up
3. Caches resolved values to avoid recomputation
4. **Detects circular references** and throws an error if found

```json
{
  "base": "/api",
  "version": "v1",
  "endpoint": "$base/$version"
}
```

After resolution, `$endpoint` expands to `/api/v1`.

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                   Consumer (Builder module)                   │
│                                                              │
│  1. Reads definition JSON from the store                     │
│  2. Builds a Definitions object via IDefinitionsBuilder      │
│  3. Uses IDefinitions to resolve $variables in asset configs │
└────────────────────────┬─────────────────────────────────────┘
                         │ json::Json
                         ▼
┌──────────────────────────────────────────────────────────────┐
│              defs::IDefinitionsBuilder (Factory)              │
│              Creates IDefinitions from a JSON object          │
└────────────────────────┬─────────────────────────────────────┘
                         │
                         ▼
┌──────────────────────────────────────────────────────────────┐
│                   defs::Definitions                           │
│                                                              │
│  ┌─────────────────┐  ┌──────────────────────────────────┐  │
│  │  m_definitions   │  │  m_resolvedDefinitions           │  │
│  │  (raw JSON)      │  │  (pre-resolved string cache)     │  │
│  └─────────────────┘  └──────────────────────────────────┘  │
│                                                              │
│  • get(name)      → returns raw JSON value                   │
│  • contains(name) → checks existence                         │
│  • replace(input) → substitutes $variables in a string       │
└──────────────────────────────────────────────────────────────┘
```

## Directory Structure

```
defs/
├── CMakeLists.txt                          # Build: defines targets defs, defs::idefinitions, defs::mocks
├── interface/
│   └── defs/
│       └── idefinitions.hpp                # Public interface: IDefinitions, IDefinitionsBuilder
├── include/
│   └── defs/
│       └── defs.hpp                        # Concrete implementation: Definitions, DefinitionsBuilder
├── src/
│   └── defs.cpp                            # Implementation of Definitions
└── test/
    ├── mocks/
    │   └── defs/
    │       ├── mockDefinitions.hpp          # GMock mock for IDefinitions and IDefinitionsBuilder
    │       ├── singleDef.hpp               # Test helper: single definition with fixed value
    │       └── failDef.hpp                 # Test helper: always-failing IDefinitions
    └── src/
        └── unit/
            └── defs_test.cpp               # Unit tests
```

## Public Interface

### `IDefinitions`

Main contract for accessing and using definitions. Defined in `interface/defs/idefinitions.hpp`.

```cpp
class IDefinitions {
    // Get the JSON value of a definition by its dot-path name (e.g., "/key" or "/nested/key")
    virtual json::Json get(std::string_view name) const = 0;

    // Check if a definition exists at the given dot-path
    virtual bool contains(std::string_view name) const = 0;

    // Replace all $variable references in the input string with their resolved values
    virtual std::string replace(std::string_view input) const = 0;
};
```

### `IDefinitionsBuilder`

Factory that creates `IDefinitions` instances from a JSON object:

```cpp
class IDefinitionsBuilder {
    virtual std::shared_ptr<IDefinitions> build(const json::Json& value) const = 0;
};
```

## Implementation Details

### Construction (`Definitions(const json::Json&)`)

1. **Validates** the input is a JSON object (throws otherwise)
2. **Rejects** any key starting with `$` (reserved for variable references)
3. Stores raw definitions in `m_definitions`
4. Calls `preResolveDefinitions()` to compute `m_resolvedDefinitions`

### Pre-resolution (`preResolveDefinitions`)

At construction time, all definitions with string values containing `$` references are resolved into their final form. This is a one-time cost that makes subsequent `replace()` calls fast.

The algorithm uses `resolveDefinitionDFS()`:
- Maintains a **visited set** and a **recursion stack** for cycle detection
- If a definition references another, it recursively resolves the dependency first
- Resolved values are cached in `m_resolvedDefinitions`
- Circular references (`a → b → a`) throw `std::runtime_error`

### Variable Replacement (`replace`)

When `replace()` is called:
1. Definitions are sorted by name length (longest first) to prevent prefix conflicts (e.g., `$ab` replacing inside `$abc`)
2. Each `$variable` pattern is matched with proper boundary checking — a match is only valid if the next character is not alphanumeric or underscore
3. Escaped variables (`\$var`) produce the literal `$var` with the backslash removed

### `get` and `contains`

These operate on the raw `m_definitions` JSON using dot-path navigation:
- `/key` — top-level key
- `/nested/key` — nested object access
- `/array/0` — array index access

## Variable Replacement Rules

| Input | Definitions | Output | Rule |
|-------|------------|--------|------|
| `$host` | `{"host": "localhost"}` | `localhost` | Basic substitution |
| `$host:$port` | `{"host": "localhost", "port": "8080"}` | `localhost:8080` | Multiple variables |
| `\$host` | `{"host": "localhost"}` | `$host` | Escaped — literal output |
| `$missing` | `{"host": "localhost"}` | `$missing` | Undefined — left as-is |
| `$url` | `{"host": "h", "url": "http://$host"}` | `http://h` | Dependency chain resolved |
| `$ab` | `{"ab": "X", "abc": "Y"}` | `X` | Longest-first matching prevents prefix conflict |
| `$abc` | `{"ab": "X", "abc": "Y"}` | `Y` | Boundary check ensures correct match |

## Usage from the Builder

The `builder` module is the primary consumer. The typical flow is:

```cpp
// 1. At engine startup, a DefinitionsBuilder is created
auto defsBuilder = std::make_shared<defs::DefinitionsBuilder>();

// 2. The Builder receives it as a dependency
Builder builder(..., defsBuilder, ...);

// 3. When building a policy, the builder reads the definitions JSON from the store
//    and calls defsBuilder->build(definitionsJson) to create an IDefinitions instance

// 4. During asset construction, $variables in check/parse expressions are resolved:
std::string resolved = definitions.replace("field == $expected_value");
```

## CMake Targets

| Target | Alias | Type | Description |
|--------|-------|------|-------------|
| `defs_idefinitions` | `defs::idefinitions` | INTERFACE | Interface only (`IDefinitions`, `IDefinitionsBuilder`). Depends on `base`. |
| `defs` | — | STATIC | Concrete implementation. Depends on `defs::idefinitions` and `base`. |
| `defs_mocks` | `defs::mocks` | INTERFACE | GMock mocks for external testing. Depends on `defs::idefinitions`. |
| `defs_utest` | — | EXECUTABLE | Unit tests. |

## Testing

Tests are in `test/src/unit/defs_test.cpp` and cover:

- **Construction**: Valid/invalid JSON inputs, rejection of `$`-prefixed keys
- **Get**: Basic keys, nested keys, array index access, missing keys
- **Contains**: Existence checks for flat, nested, and array paths
- **Replace**: Basic substitution, multiple variables, escaped variables, nested definitions, complex dependency chains, prefix conflict handling, special characters, edge cases (`$` at end of string, `$` followed by non-alpha)
- **Circular references**: Detection of direct cycles (`a→b→a`), transitive cycles (`a→b→c→a`), self-references (`a→a`)
- **Error messages**: Validates that exceptions contain useful diagnostic information
- **Performance**: Handles 1000+ definitions without issues
- **Special JSON values**: Numbers, booleans, null, unicode, empty strings
- **Builder**: Verifies `DefinitionsBuilder` creates valid instances and propagates errors

### Running Tests

```bash
# From the engine build directory:
./defs_utest
```

## Relevant Design Decisions

1. **Pre-resolution at construction time**: All inter-definition dependencies are resolved once during construction. This makes `replace()` calls fast (simple string substitution with no recursive lookups), at the cost of slightly more expensive construction.

2. **Longest-first replacement**: Variables are replaced in order of decreasing name length. This ensures that `$prefix` doesn't incorrectly match inside `$prefix_extended`, solving prefix conflicts without requiring special delimiters.

3. **Boundary-aware matching**: A `$variable` match is only valid if the character after the variable name is not alphanumeric or underscore. This prevents partial matches within longer identifiers.

4. **Escape mechanism**: `\$var` produces the literal `$var`, allowing users to include dollar-sign patterns that should not be treated as variable references.

5. **Fail-fast on cycles**: Circular references are detected at construction time with a clear error message, preventing infinite loops during resolution.

6. **Interface segregation**: `IDefinitions` and `IDefinitionsBuilder` are separated from the implementation, allowing the `builder` module to depend only on the interface and enabling easy mocking for tests.

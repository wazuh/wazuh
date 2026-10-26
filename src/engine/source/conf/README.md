# Conf Module

## Overview

The **conf** module provides the unified configuration system for the Wazuh engine. It loads, validates, and resolves configuration values from three sources with a strict priority order:

1. **Environment variables** (highest priority)
2. **Configuration file** (`wazuh-manager-internal-options.conf`)
3. **Default values** (lowest priority — hardcoded in C++)

Each configuration option is declared as a typed **unit** (`UConf<T>`) tied to a key, an environment variable name, and a default value. At runtime, `Conf::get<T>(key)` resolves the final value by checking the three sources in priority order.

The only consumer is [main.cpp](../main.cpp): it builds one `conf::Conf` over `/etc/wazuh-manager/wazuh-manager-internal-options.conf`, reads each setting with `confManager.get<T>(conf::key::…)` and passes the values to the module constructors. The operator-facing list of settings (keys, environment variables, defaults, ranges) is [configuration.md](../../../../docs/ref/modules/engine/configuration.md); the units themselves are registered in the `Conf` constructor in [src/conf.cpp](src/conf.cpp).

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│                  Consumer (main.cpp)                      │
│        confManager.get<T>(conf::key::<NAME>)              │
└──────────────────────┬───────────────────────────────────┘
                       │
              ┌────────▼────────┐
              │      Conf        │
              │                  │
              │  1. ENV var?     │──→ std::getenv(envName)
              │  2. File value?  │──→ m_fileConfig[key]
              │  3. Default      │──→ unit->defaultValue
              └────────┬─────────┘
                       │ load()
              ┌────────▼────────┐
              │   IFileLoader    │  (interface)
              └────────┬─────────┘
                       │
              ┌────────▼────────┐
              │   FileLoader     │  (concrete)
              │                  │
              │  Parses .conf    │
              │  file: key=val   │
              └──────────────────┘
```

## Key Concepts

### Configuration Units (`UConf<T>`)

Every configuration option is internally represented as a `UConf<T>` object (wrapped in `BaseUnitConf` for type-erased storage). Each unit holds:

- **Environment variable name** — the OS env var to check first
- **Default value** — fallback if neither env var nor file provides a value
- **Type tag** (`UnitConfType`) — used during file validation

Supported types:

| `UnitConfType` | C++ Types | Example |
|---|---|---|
| `INTEGER` | `int`, `int64_t`, `size_t` | `120` |
| `STRING` | `std::string` | `"/var/wazuh-manager/data/store"` |
| `STRING_LIST` | `std::vector<std::string>` | `"host1,host2,host3"` |
| `BOOL` | `bool` | `"true"` / `"false"` |

### Resolution Priority

When `Conf::get<T>(key)` is called:

1. **Environment variable**: If set, parse and return the value. If parsing fails, log a warning and fall through.
2. **File value**: If present in the loaded `OptionMap`, parse and return. If parsing fails, log a warning and fall through.
3. **Default value**: Always succeeds — returns the hardcoded default.

This means invalid environment variables or file values are gracefully degraded to the next source rather than causing errors at `get()` time.

### File Format

The configuration file (`wazuh-manager-internal-options.conf`) uses a simple `section.key=value` format:

```ini
# Comment
analysisd.debug=0
analysisd.store_path=/var/wazuh-manager/data/store
analysisd.cm_sync_interval=120
analysisd.dumper_enabled=false  # inline comment
analysisd.<key>=value\#with-hash   # escaped '#' in value (placeholder key)
```

`analysisd.<key>` is a placeholder for the escaping rule, not a registered key.

Parsing rules:
- Only keys under the `analysisd` section are loaded
- Lines starting with `#` are comments; inline `#` after values are stripped (use `\#` to escape)
- Surrounding quotes (`"..."` or `'...'`) are stripped from values
- String lists use comma-separated values (bracket notation `[...]` is rejected)
- Whitespace around keys and values is trimmed
- Duplicate keys: last value wins
- A line with no `=`, or with no `.` before the `=`, is logged as `Invalid configuration line ignored` and skipped
- A missing or unreadable file is only a warning (`Failed to load configuration: …`); the engine starts on environment variables and defaults
- An `analysisd.*` key that matches no registered unit is kept in the map but never validated nor read, so a misspelled key is silently ignored

### Standalone Mode

If the engine is running in standalone mode (`WAZUH_ENGINE_STANDALONE=true`, case-insensitive; any other value or unset means manager mode), the file loader is **skipped entirely** — only environment variables and default values are used. This simplifies testing and development scenarios.

The indexer host and TLS units (`analysisd.indexer_hosts`, `analysisd.indexer_ssl_*`) are read only in standalone mode, hence only from their environment variables: in manager mode `main.cpp` takes the indexer settings from the `indexer` section of `wazuh-manager.conf` (`base::managerConfig::sectionJson("indexer")`).

### Registration Phase

All configuration units must be registered via `addUnit<T>()` **before** `load()` is called. Attempting to add units after loading throws `std::logic_error`. This ensures the schema is fully declared before validation runs.

## Directory Structure

```
conf/
├── CMakeLists.txt
├── include/conf/
│   ├── conf.hpp            # Conf class (main API)
│   ├── fileLoader.hpp      # IFileLoader interface + FileLoader
│   ├── keys.hpp            # Configuration key constants
│   └── unitconf.hpp        # BaseUnitConf / UConf<T> template
├── src/
│   ├── conf.cpp            # Unit registration, load(), validate()
│   └── fileLoader.cpp      # File parsing implementation
└── test/
    └── src/
        ├── unit/
        │   ├── conf_test.cpp       # Conf unit tests (priority, validation)
        │   ├── unitconf_test.cpp   # UConf<T> unit tests (env parsing)
        │   ├── mockFileLoader.hpp  # GMock for IFileLoader
        │   └── utils.hpp           # Test helpers (setEnv/unsetEnv)
        └── component/
            └── fileLoader_test.cpp # FileLoader component tests (22 cases)
```

## Public Interface

### `Conf` (include/conf/conf.hpp)

| Method | Description |
|--------|-------------|
| `Conf(shared_ptr<IFileLoader>)` | Construct and register all default configuration units |
| `addUnit<T>(key, envName, default)` | Register a new typed configuration option (before `load()`) |
| `load()` | Load file configuration and validate types; can only be called once |
| `get<T>(key)` | Resolve the configuration value with env → file → default priority |

### `IFileLoader` / `FileLoader` (include/conf/fileLoader.hpp)

| Element | Description |
|---------|-------------|
| `IFileLoader` | Interface with a protected `load()` method and a public `operator()()` |
| `FileLoader` | Parses `analysisd.*` keys from a `.conf` file (default: `/etc/wazuh-manager/wazuh-manager-internal-options.conf`; standalone mode never reads it) |
| `OptionMap` | `std::unordered_map<std::string, std::string>` — flat key→value map |

### Configuration Keys (include/conf/keys.hpp)

All keys are `constexpr std::string_view` constants under the `conf::key` namespace, following the pattern `"analysisd.<option_name>"`. They are grouped by module (logging, store, geo, indexer, streamlog, etc.) and may change as the engine evolves.

Agent metadata retention uses `size_t` keys `AGENT_METADATA_CACHE_MAX_ENTRIES` (default 50000)
and `AGENT_METADATA_CACHE_MAX_BYTES` (default 134217728). Each zero limit independently means
unlimited. The cache validates upper bounds; startup also validates TTL and cleanup intervals.
See the [engine settings](../../../../docs/ref/modules/engine/configuration.md#agent-metadata-cache).

## Implementation Details

### Validation

On `load()`, the file-loaded `OptionMap` is validated against the declared units. For each key present in the file:

- **INTEGER**: parsed with `std::stoll`, checked for trailing characters. Unsigned (`size_t`) units refuse a leading
  `-` (after whitespace) and are parsed with `std::stoull`, so a negative file value stops start-up instead of wrapping
- **STRING**: always valid
- **STRING_LIST**: bracket notation `[...]` is rejected
- **BOOL**: must be `"true"` or `"false"` (case-insensitive)

Invalid values cause `load()` to throw `std::runtime_error`, preventing the engine from starting with a misconfigured file.

### Environment Variable Parsing

`UConf<T>::getEnvValue()` handles per-type parsing:

- **Integers**: Unsigned values reject negative environment inputs before conversion. Uses `std::stoll`/`std::stoull` with strict validation (no whitespace, no trailing chars, range checks)
- **Strings**: Direct passthrough
- **String lists**: Comma-separated with backslash escaping (`\,` for literal commas); bracket notation rejected
- **Booleans**: Case-insensitive `"true"`/`"false"`

### Error Handling

| Scenario | Behavior |
|----------|----------|
| Null `IFileLoader` | Constructor throws `std::invalid_argument` |
| Empty key or env name | `addUnit` throws `std::invalid_argument` |
| Duplicate key or env name | `addUnit` throws `std::invalid_argument` |
| `addUnit` after `load()` | Throws `std::logic_error` |
| Double `load()` call | Throws `std::logic_error` |
| Invalid file value type | `load()` throws `std::runtime_error` (`main.cpp` logs `Error loading configuration: …` and exits with failure) |
| Missing or unreadable file | `FileLoader` logs a warning and returns an empty map |
| Invalid env var at `get()` time | Warning logged, falls through to next source |
| Invalid file value at `get()` time | Warning logged, falls through to default |
| Unknown key at `get()` time | Throws `std::runtime_error` |

## CMake Targets

| Target | Type | Description |
|--------|------|-------------|
| `conf` | STATIC | Main library (Conf + FileLoader) |
| `conf_utest` | EXECUTABLE | Unit tests (configuration + unit conf) |
| `conf_ctest` | EXECUTABLE | Component tests (file loader parsing) |

**Dependencies:**

```
conf ──► base (PUBLIC), urlrequest (PRIVATE)
```

## Testing

### Unit Tests (conf_test.cpp, unitconf_test.cpp)

- **conf_test.cpp**: Tests `Conf` lifecycle (build, addUnit, load, get) with priority resolution.  Parameterized tests cover all type combinations × all three sources × valid/invalid values.
- **unitconf_test.cpp**: Tests `UConf<T>` environment variable parsing for all supported types, including `size_t` boundaries, negative-to-unsigned rejection, overflow, whitespace and invalid formats.

Configuration tests also pin cache defaults, ENV/file/default precedence, independent zero limits
and fallback after invalid unsigned environment values. `Conf` tests use `MockFileLoader` to
isolate from the filesystem. New environment regressions restore the caller's original values.

### Component Tests (fileLoader_test.cpp)

22 parameterized cases testing `FileLoader` with real temporary files:

- Valid multi-key files, duplicate keys (last wins), inline comments, escaped `#`, quoted values
- Invalid lines, non-`analysisd` sections, empty files, whitespace-only lines
- Special characters, very long values, missing newlines at EOF

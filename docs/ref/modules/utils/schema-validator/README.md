# Schema Validator

## Introduction

The **Schema Validator** is a shared module that validates JSON messages against Wazuh-indexer index template mappings. It ensures that data sent to the Wazuh indexer conforms to the expected schema, preventing indexing errors and maintaining data integrity across Wazuh components.

The validator supports Wazuh-indexer mapping syntax, including nested objects and strict validation mode. It provides detailed error messages for debugging and integrates seamlessly with multiple Wazuh modules (FIM, SCA, Syscollector on the agent; Vulnerability Scanner on the manager).

## Key Features

- **Wazuh-indexer Mapping Support**: Validates against Wazuh-indexer index template mappings
- **Type Validation**: Checks string, integer, number, boolean, date, IP and object types; other types (such as `float`) pass unchecked. See [API Reference](api-reference.md)
- **Nested Object Validation**: Recursively validates nested object structures
- **Embedded Schemas**: Schemas are embedded at compile-time for zero-configuration deployment
- **Detailed Error Messages**: Provides specific field paths and validation failures
- **Thread-Safe Singleton**: Factory can be safely accessed from multiple threads
- **Dependency Injection**: Supports custom validators for testing purposes

## Architecture Overview

The module follows a factory pattern with three main components:

```
┌─────────────────────────────────────┐
│   SchemaValidatorFactory            │
│   (Singleton)                       │
│                                     │
│  + getInstance()                    │
│  + initialize()                     │
│  + getValidator(indexPattern)       │
│  + isInitialized()                  │
└─────────────┬───────────────────────┘
              │
              │ manages
              ▼
┌─────────────────────────────────────┐
│   ISchemaValidatorEngine            │
│   (Interface)                       │
│                                     │
│  + validate(message)                │
│  + getSchemaName()                  │
└─────────────┬───────────────────────┘
              │
              │ implements
              ▼
┌─────────────────────────────────────┐
│   SchemaValidatorEngine             │
│   (Concrete Implementation)         │
│                                     │
│  + loadSchemaFromString()           │
│  + validate(message)                │
│  + getSchemaName()                  │
└─────────────────────────────────────┘
```

### Module Integration

Each Wazuh module integrates with the Schema Validator independently:

```
┌────────────┐  ┌────────────┐  ┌──────────────┐  ┌───────────────┐
│    FIM     │  │    SCA     │  │ Syscollector │  │ Vulnerability │
│            │  │            │  │              │  │    Scanner    │
└─────┬──────┘  └─────┬──────┘  └──────┬───────┘  └───────┬───────┘
      │               │                │                  │
      └───────────────┴────────────────┴──────────────────┘
                      │
          ┌───────────▼────────────┐
          │  SchemaValidatorFactory│
          │     (Singleton)        │
          └───────────┬────────────┘
                      │
          ┌───────────▼───────────┐
          │  Embedded Schemas     │
          │  - wazuh-states-*     │
          └───────────────────────┘
```

## Supported Indices

The validator embeds every template in `src/external/indexer-plugins` except `metrics-*.json`. `make deps` downloads them from `wazuh-indexer-plugins` (`INDEXER_TEMPLATES_BASE` in `src/Makefile`); a manager build adds `vulnerabilities.json` (`INDEXER_TEMPLATES_SERVER_STATES`):

- `wazuh-states-inventory-hardware`
- `wazuh-states-inventory-system`
- `wazuh-states-inventory-networks`
- `wazuh-states-inventory-packages`
- `wazuh-states-inventory-hotfixes`
- `wazuh-states-inventory-ports`
- `wazuh-states-inventory-processes`
- `wazuh-states-inventory-protocols`
- `wazuh-states-inventory-interfaces`
- `wazuh-states-inventory-users`
- `wazuh-states-inventory-groups`
- `wazuh-states-inventory-services`
- `wazuh-states-inventory-browser-extensions`
- `wazuh-states-sca`
- `wazuh-states-fim-files`
- `wazuh-states-fim-registry-keys`
- `wazuh-states-fim-registry-values`
- `wazuh-states-vulnerabilities` (manager only)

The lookup is an exact match on the name above: `wazuh-states-fim-file` finds no validator.

## Documentation Structure

- [API Reference](api-reference.md) - Complete API documentation with function signatures and examples
- [Integration Guide](integration-guide.md) - Step-by-step integration examples for different modules

## Quick Start

### C++ Integration

```cpp
#include "schemaValidator.hpp"

// 1. Initialize the factory (once during module startup)
auto& validatorFactory = SchemaValidator::SchemaValidatorFactory::getInstance();

if (validatorFactory.initialize())
{
    m_logFunction(LOG_DEBUG, "Schema validator initialized successfully from embedded resources");
}

// 2. Get a validator for a specific index
auto validator = validatorFactory.getValidator("wazuh-states-inventory-packages");

if (validator)
{
    // 3. Validate a JSON message
    std::string jsonMessage = R"({
        "wazuh": {"agent": {"id": "001"}},
        "package": {"name": "nginx", "version": "1.18.0"}
    })";

    auto result = validator->validate(jsonMessage);

    if (result.isValid)
    {
        // Message is valid, proceed with indexing
        sendToIndexer(jsonMessage);
    }
    else
    {
        // Validation failed, log errors
        for (const auto& error : result.errors)
        {
            m_logFunction(LOG_ERROR, "Validation error: " + error);
        }

        // Delete from local DB to prevent integrity loops
        deleteFromLocalDatabase(data);
    }
}
```

### C Integration (FIM)

```c
#include "schemaValidator_c.h"

// 1. Initialize the factory
if (schema_validator_initialize())
{
    mdebug1("Schema validator initialized successfully from embedded resources");
}

// 2. Validate a message
char* errorMessage = NULL;
const char* index = "wazuh-states-fim-files";
const char* message = "{\"file\":{\"path\":\"/etc/passwd\"}}";

if (schema_validator_validate(index, message, &errorMessage))
{
    // Message is valid
    send_to_indexer(message);
}
else
{
    // Validation failed
    if (errorMessage)
    {
        merror("Validation failed: %s", errorMessage);
        free(errorMessage);
    }

    delete_from_database(data);
}
```

## Integration Best Practices

1. **Initialize Once**: Call `initialize()` once during module startup
2. **Check Initialization**: Always check `isInitialized()` before getting validators
3. **Cache Validators**: Get validators once and reuse them (they're thread-safe)
4. **Handle a Missing Schema**: If the factory is not initialized, skip validation; if it is initialized but has no schema for the index, discard the message: the C API rejects it with `No schema validator found for index` (FIM then logs that at ERROR), and SCA and Syscollector log `No schema validator found for index: <index>. Discarding message.` at WARNING
5. **Delete Invalid Data**: Remove data that fails validation from local databases to prevent integrity sync loops

## Error Handling

The module gracefully handles initialization and validation failures:

### Initialization Failure
- `isInitialized()` returns `false`
- `getValidator()` returns `nullptr`
- Modules should disable validation when factory is not initialized

### Validation Failure
- `ValidationResult.isValid` is `false`
- `ValidationResult.errors` contains detailed error messages
- Modules should log errors and prevent invalid data from being sent to the indexer

## Module Integration Status

| Module | Integration Status | Documentation |
|--------|-------------------|---------------|
| Syscollector | Integrated | [Architecture](../../syscollector/architecture.md#schema-validation-integration) |
| SCA | Integrated | [Architecture](../../sca/architecture.md#schema-validation-integration) |
| FIM | Integrated | [Architecture](../../fim/architecture.md#schema-validation-integration) |
| Vulnerability Scanner (manager) | Integrated | — |

The Vulnerability Scanner validates each upserted detection against `wazuh-states-vulnerabilities`; a failure is logged at WARNING and the detection is not indexed. Unlike FIM, SCA and Syscollector, it also indexes without validation when the factory is initialized but has no `wazuh-states-vulnerabilities` schema.

## Building

The Schema Validator is built as part of the Wazuh build system:

```bash
make TARGET=server|agent <DEBUG=1>
```

Schema resources are automatically embedded during the build process using CMake.

## Testing

Run unit tests with:

```bash
cd src/build
ctest -L schema_validator -V
```

## References

- [OpenSearch Field Types](https://docs.opensearch.org/latest/field-types/)
- [Wazuh Indexer Templates](https://documentation.wazuh.com/current/user-manual/wazuh-indexer/index.html)

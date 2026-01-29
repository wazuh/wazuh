# Schema Validator

## Introduction

The **Schema Validator** is a shared module that validates JSON messages against Wazuh-indexer index template mappings. It ensures that data sent to the Wazuh indexer conforms to the expected schema, preventing indexing errors and maintaining data integrity across Wazuh components.

The validator supports Wazuh-indexer mapping syntax including all data types, nested objects, and strict validation mode. It provides detailed error messages for debugging and integrates seamlessly with multiple Wazuh modules (FIM, SCA, Syscollector).

## Key Features

- **Wazuh-indexer Mapping Support**: Validates against Wazuh-indexer index template mappings
- **Type Validation**: Supports all Wazuh-indexer data types (text, keyword, long, integer, float, boolean, date, object, etc.)
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
┌────────────┐  ┌────────────┐  ┌──────────────┐
│    FIM     │  │    SCA     │  │ Syscollector │
└─────┬──────┘  └─────┬──────┘  └──────┬───────┘
      │               │                │
      └───────────────┴────────────────┘
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

The validator supports schemas for all Wazuh state indices:

- `wazuh-states-inventory-hardware`
- `wazuh-states-inventory-system`
- `wazuh-states-inventory-network`
- `wazuh-states-inventory-packages`
- `wazuh-states-inventory-hotfixes`
- `wazuh-states-inventory-ports`
- `wazuh-states-inventory-processes`
- `wazuh-states-sca`
- `wazuh-states-fim-file`
- `wazuh-states-fim-registry`

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
    m_logFunction(LOG_INFO, "Schema validator initialized successfully");
}

// 2. Get a validator for a specific index
auto validator = validatorFactory.getValidator("wazuh-states-inventory-packages");

if (validator)
{
    // 3. Validate a JSON message
    std::string jsonMessage = R"({
        "agent": {"id": "001"},
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
    minfo("Schema validator initialized successfully");
}

// 2. Validate a message
char* errorMessage = NULL;
const char* index = "wazuh-states-fim-file";
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
4. **Handle Gracefully**: If validator is not available, log a warning and skip validation
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
| Syscollector | Integrated | [Architecture](../../modules/syscollector/architecture.md#schema-validation-integration) |
| SCA | Integrated | [Architecture](../../modules/sca/architecture.md#schema-validation-integration) |
| FIM | Integrated | [Architecture](../../modules/fim/architecture.md#schema-validation-integration) |

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

- [Wazuh-indexer Mapping Documentation](https://www.elastic.co/guide/en/Wazuh-indexer/reference/current/mapping.html)
- [Wazuh Indexer Templates](https://documentation.wazuh.com/current/user-manual/wazuh-indexer/index.html)
- [JSON Schema Validation](https://json-schema.org/)

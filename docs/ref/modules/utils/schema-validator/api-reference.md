# API Reference

This document provides complete API documentation for the Schema Validator module.

---

## C++ API

### SchemaValidatorFactory

Singleton factory for managing schema validator instances.

#### `getInstance()`

Get the singleton factory instance.

```cpp
static SchemaValidatorFactory& getInstance();
```

**Returns:** Reference to the singleton instance

**Example:**
```cpp
auto& factory = SchemaValidator::SchemaValidatorFactory::getInstance();
```

---

#### `initialize()`

Initialize the factory with embedded schema resources or custom validators.

```cpp
bool initialize(
    std::map<std::string, std::shared_ptr<ISchemaValidatorEngine>> customValidators = {}
);
```

**Parameters:**
- `customValidators` - Optional map of index pattern → validator instances for testing

**Returns:** `true` if initialization succeeded, `false` otherwise

**Example:**
```cpp
auto& factory = SchemaValidator::SchemaValidatorFactory::getInstance();

if (factory.initialize())
{
    m_logFunction(LOG_INFO, "Schema validator initialized");
}
else
{
    m_logFunction(LOG_ERROR, "Failed to initialize schema validator");
}
```

---

#### `getValidator()`

Get a validator for a specific index pattern.

```cpp
std::shared_ptr<ISchemaValidatorEngine> getValidator(const std::string& indexPattern);
```

**Parameters:**
- `indexPattern` - Index pattern (e.g., `"wazuh-states-inventory-packages"`)

**Returns:** Validator instance or `nullptr` if not found

**Example:**
```cpp
auto validator = factory.getValidator("wazuh-states-inventory-packages");

if (validator)
{
    // Use validator
}
```

---

#### `isInitialized()`

Check if the factory is initialized.

```cpp
bool isInitialized() const;
```

**Returns:** `true` if initialized, `false` otherwise

**Example:**
```cpp
if (factory.isInitialized())
{
    // Factory ready to use
}
```

---

#### `reset()`

Reset the singleton instance (for testing purposes).

```cpp
void reset();
```

**Example:**
```cpp
// For unit tests
factory.reset();
factory.initialize(mockValidators);
```

---

### ISchemaValidatorEngine

Abstract interface for schema validators.

#### `validate()` (string)

Validate a JSON message against the loaded schema.

```cpp
virtual ValidationResult validate(const std::string& message) = 0;
```

**Parameters:**
- `message` - JSON message as string

**Returns:** `ValidationResult` with validation status and errors

**Example:**
```cpp
std::string json = R"({"agent": {"id": "001"}})";
auto result = validator->validate(json);

if (result.isValid)
{
    // Valid
}
else
{
    for (const auto& error : result.errors)
    {
        m_logFunction(LOG_ERROR, error);
    }
}
```

---

#### `validate()` (json object)

Validate a JSON object against the loaded schema.

```cpp
virtual ValidationResult validate(const nlohmann::json& message) = 0;
```

**Parameters:**
- `message` - JSON object

**Returns:** `ValidationResult` with validation status and errors

**Example:**
```cpp
nlohmann::json json = {{"agent", {{"id", "001"}}}};
auto result = validator->validate(json);
```

---

#### `getSchemaName()`

Get the schema name.

```cpp
virtual std::string getSchemaName() const = 0;
```

**Returns:** Schema name (derived from index pattern)

**Example:**
```cpp
std::string name = validator->getSchemaName();
// Returns: "wazuh-states-inventory-packages"
```

---

### ValidationResult

Result of a schema validation operation.

```cpp
struct ValidationResult
{
    bool isValid;                      // True if validation passed
    std::vector<std::string> errors;   // List of validation errors (empty if valid)
};
```

**Example:**
```cpp
auto result = validator->validate(message);

if (!result.isValid)
{
    std::cerr << "Validation failed with " << result.errors.size() << " errors:" << std::endl;
    for (const auto& error : result.errors)
    {
        std::cerr << "  - " << error << std::endl;
    }
}
```

---

## C API (for FIM and C modules)

### Initialization Functions

#### `schema_validator_initialize()`

Initialize the schema validator factory.

```c
bool schema_validator_initialize(void);
```

**Returns:** `true` if initialization succeeded, `false` otherwise

**Example:**
```c
if (schema_validator_initialize())
{
    minfo("Schema validator initialized successfully");
}
else
{
    mwarn("Failed to initialize schema validator");
}
```

---

#### `schema_validator_is_initialized()`

Check if the schema validator factory is initialized.

```c
bool schema_validator_is_initialized(void);
```

**Returns:** `true` if initialized, `false` otherwise

**Example:**
```c
if (schema_validator_is_initialized())
{
    // Proceed with validation
}
```

---

### Validation Functions

#### `schema_validator_validate()`

Validate a JSON message against a schema.

```c
bool schema_validator_validate(
    const char* index,
    const char* message,
    char** errorMessage
);
```

**Parameters:**
- `index` - Index name for schema lookup (e.g., `"wazuh-states-fim-file"`)
- `message` - JSON string to validate
- `errorMessage` - Output parameter for error message (caller must free)

**Returns:** `true` if validation passed, `false` if validation failed

**Example:**
```c
char* errorMessage = NULL;
const char* index = "wazuh-states-fim-file";
const char* message = "{\"file\":{\"path\":\"/etc/passwd\",\"size\":1024}}";

if (!schema_validator_validate(index, message, &errorMessage))
{
    // Validation failed
    if (errorMessage)
    {
        merror("Schema validation failed: %s", errorMessage);
        mdebug2("Raw event that failed: %s", message);
        free(errorMessage);
    }

    // Delete from database to prevent integrity loops
    delete_from_database(data);
}
else
{
    // Validation passed
    send_to_sync_protocol(message);
}
```

---

## Common Validation Patterns

### Pattern 1: Validate and Queue (Syscollector/SCA)

```cpp
bool validateAndQueue(const std::string& data, const std::string& index)
{
    auto& factory = SchemaValidator::SchemaValidatorFactory::getInstance();

    // Check if factory is initialized
    if (!factory.isInitialized())
    {
        return true; // Skip validation if not available
    }

    // Get validator for index
    auto validator = factory.getValidator(index);
    if (!validator)
    {
        return true; // No validator for this index
    }

    // Validate
    auto result = validator->validate(data);
    if (!result.isValid)
    {
        // Log errors
        std::string errorMsg = "Validation failed for index: " + index + ". Errors:";
        for (const auto& error : result.errors)
        {
            errorMsg += "\n  - " + error;
        }
        m_logFunction(LOG_ERROR, errorMsg);
        m_logFunction(LOG_ERROR, "Raw event: " + data);

        return false;
    }

    return true;
}
```

### Pattern 2: Validate with Deferred Deletion (SCA)

```cpp
// Vector to accumulate failed items
std::vector<nlohmann::json> failedChecks;

// Process events
for (const auto& event : events)
{
    bool validationPassed = ValidateAndHandleStatefulMessage(
        event, context, checkData, &failedChecks);

    if (validationPassed)
    {
        PushStateful(event, operation, version);
    }
}

// Batch delete failed items
DeleteFailedChecksFromDB(failedChecks);
```

### Pattern 3: Validate in C (FIM)

```c
bool validate_and_persist(const char* index, const char* data, void* item_data)
{
    if (!schema_validator_is_initialized())
    {
        return true; // Skip validation
    }

    char* errorMessage = NULL;

    if (!schema_validator_validate(index, data, &errorMessage))
    {
        // Validation failed
        if (errorMessage)
        {
            mdebug2("Validation failed: %s", errorMessage);
            mdebug2("Raw event: %s", data);
            free(errorMessage);
        }

        // Mark for deferred deletion
        if (failed_list && item_data)
        {
            OSList_AddData(failed_list, item_data);
        }

        return false;
    }

    return true;
}
```

---

## Error Messages

Validation errors follow this format:

```
Field '<field_path>' expected type '<expected_type>', got '<actual_type>'
Required field '<field_path>' is missing
Field '<field_path>' is not defined in schema (strict mode)
```

**Examples:**

```
Field 'package.version' expected type 'keyword', got 'object'
Required field 'package.name' is missing
Field 'package.unknown_field' is not defined in schema (strict mode)
Field 'file.size' expected type 'long', got 'string'
```

---

## Supported Elasticsearch Types

The validator supports all Elasticsearch data types:

| Type | Description | Example |
|------|-------------|---------|
| `text` | Full-text searchable string | `"description": "A long text..."` |
| `keyword` | Exact-value string | `"status": "active"` |
| `long` | 64-bit signed integer | `"size": 1024` |
| `integer` | 32-bit signed integer | `"count": 42` |
| `short` | 16-bit signed integer | `"priority": 5` |
| `byte` | 8-bit signed integer | `"level": 3` |
| `double` | 64-bit floating point | `"score": 98.5` |
| `float` | 32-bit floating point | `"ratio": 0.75` |
| `boolean` | Boolean value | `"enabled": true` |
| `date` | Date/timestamp | `"timestamp": "2024-01-13T10:00:00Z"` |
| `object` | Nested object | `"agent": {"id": "001"}` |
| `ip` | IPv4/IPv6 address | `"ip": "192.168.1.1"` |

---

## Thread Safety

- `SchemaValidatorFactory` is thread-safe (singleton pattern)
- Validator instances are immutable and thread-safe
- Multiple threads can safely call validation methods concurrently
- C API functions are thread-safe

---

## Testing Support

### Dependency Injection

For unit testing, inject custom validators:

```cpp
// Create mock validator
auto mockValidator = std::make_shared<MockSchemaValidator>();

// Inject into factory
std::map<std::string, std::shared_ptr<ISchemaValidatorEngine>> mocks;
mocks["test-index"] = mockValidator;

auto& factory = SchemaValidator::SchemaValidatorFactory::getInstance();
factory.reset();
factory.initialize(mocks);

// Now getValidator() returns your mock
```

### Reset Factory

```cpp
// Reset factory state between tests
SchemaValidator::SchemaValidatorFactory::getInstance().reset();
```

---

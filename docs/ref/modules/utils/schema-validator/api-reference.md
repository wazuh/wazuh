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
    m_logFunction(LOG_DEBUG, "Schema validator initialized successfully from embedded resources");
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
std::string json = R"({"wazuh": {"agent": {"id": "001"}}})";
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
nlohmann::json json = {{"wazuh", {{"agent", {{"id", "001"}}}}}};
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
    mdebug1("Schema validator initialized successfully from embedded resources");
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
- `index` - Index name for schema lookup, matched exactly (e.g., `"wazuh-states-fim-files"`)
- `message` - JSON string to validate
- `errorMessage` - Output parameter for error message, errors joined by newlines (caller must free)

**Returns:** `true` if validation passed, `false` if validation failed

A `NULL` `index` or `message` returns `false` without touching `errorMessage`, so initialise it to `NULL`; an internal error returns `false` with no error message. If the factory is not initialized, every message passes (`true`). If it is initialized but has no schema for `index`, every message fails with `No schema validator found for index`; the C++ `getValidator()` returns `nullptr` instead and leaves the decision to the caller.

**Example:**
```c
char* errorMessage = NULL;
const char* index = "wazuh-states-fim-files";
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
        // No schema for this index: discard, as SCA and Syscollector do
        m_logFunction(LOG_WARNING, "No schema validator found for index: " + index + ". Discarding message.");
        return false;
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

Each error is prefixed with the dotted field path; array elements add `[<i>]`, and a message that is not an object at the top level has an empty path (`: Expected object, got array with value: []`):

```
<path>: Expected <string|integer|number|boolean|object|IP address string>, got <json type> with value: <value>
<path>: Expected date (number or ISO8601 string), got <json type> with value: <value>
<path>: Invalid date format. Expected ISO8601, got: <value>
<path>: Invalid IP address format: <value>
<path>: Field not allowed in strict mode
JSON parse error: <parser message>
```

Every field is optional: there is no missing-field error. `null` passes for any field, and in strict mode an undefined field passes if its value is `null`.

**Examples** (`wazuh-states-fim-files`):

```
file.size: Expected integer, got string with value: "1024"
file.unknown_field: Field not allowed in strict mode
file.mtime: Invalid date format. Expected ISO8601, got: yesterday
file.size: Expected integer, got number with value: 1.5
wazuh.agent.host.ip: Invalid IP address format: 999.1.1.1
file: Expected object, got string with value: "x"
file.path[1]: Expected string, got number with value: 2
```

---

## Validated Mapping Types

Only these mapping types are checked. An array in a typed field is checked element by element; a field with `properties` must be a single object, and an array there fails with `Expected object, got array`.

| Type | Accepts |
|------|---------|
| `keyword`, `text`, `match_only_text` | JSON string |
| `long`, `integer`, `short`, `unsigned_long` | JSON integer: a number written with a decimal point or exponent (`1024.0`, `1e3`) or outside the 64-bit integer range (below `-9223372036854775808` or above `18446744073709551615`) fails; within it the range is not checked |
| `scaled_float` | Any JSON number |
| `boolean` | JSON `true`/`false` |
| `date` | A number (epoch) or a string `YYYY-MM-DD[THH:MM:SS[.fraction][Z\|±HH:MM]]`, with a fraction of 1 to 9 digits; only the digit layout is checked, so `2024-13-45` passes |
| `ip` | A string holding an IPv4 or IPv6 address |
| `object` | JSON object |
| Field with `properties` | JSON object, validated recursively |

Any other type, including `byte`, `float`, `double`, `half_float` and `geo_point`, is not checked: any value passes. `wazuh-states-vulnerabilities` maps `vulnerability.score.base`, `.environmental` and `.temporal` as `float`, so a non-numeric score passes validation and is only rejected by the indexer.

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

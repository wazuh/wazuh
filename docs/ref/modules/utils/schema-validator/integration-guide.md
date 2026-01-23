# Integration Guide

This guide provides step-by-step instructions for integrating the Schema Validator into Wazuh modules.

---

## Table of Contents

- [C++ Module Integration (Syscollector, SCA)](#c-module-integration-syscollector-sca)
- [C Module Integration (FIM)](#c-module-integration-fim)
- [Helper Function Patterns](#helper-function-patterns)
- [Deferred Deletion Pattern](#deferred-deletion-pattern)
- [Error Handling](#error-handling)
- [Testing Integration](#testing-integration)

---

## C++ Module Integration (Syscollector, SCA)

### Step 1: Include Headers

Add the schema validator header to your module:

```cpp
#include "schemaValidator.hpp"
```

### Step 2: Initialize During Module Startup

Initialize the factory once during module initialization:

```cpp
void YourModule::initialize()
{
    // Initialize schema validator from embedded resources
    auto& validatorFactory = SchemaValidator::SchemaValidatorFactory::getInstance();

    if (!validatorFactory.isInitialized())
    {
        if (validatorFactory.initialize())
        {
            m_logFunction(LOG_INFO, "Schema validator initialized successfully from embedded resources");
        }
        else
        {
            m_logFunction(LOG_WARNING, "Failed to initialize schema validator. Schema validation will be disabled.");
        }
    }
}
```

### Step 3: Create Helper Function for Validation

Create a helper function to encapsulate validation logic:

```cpp
bool YourModule::validateSchemaAndLog(const std::string& data,
                                      const std::string& index,
                                      const std::string& context) const
{
    auto& validatorFactory = SchemaValidator::SchemaValidatorFactory::getInstance();

    if (!validatorFactory.isInitialized())
    {
        return true; // Validation disabled
    }

    auto validator = validatorFactory.getValidator(index);

    if (!validator)
    {
        return true; // No validator for this index
    }

    auto validationResult = validator->validate(data);

    if (validationResult.isValid)
    {
        return true;
    }

    // Validation failed - log errors
    std::string errorMsg = "Schema validation failed for message (" + context +
                           ", index: " + index + "). Errors: ";

    for (const auto& error : validationResult.errors)
    {
        errorMsg += "  - " + error;
    }

    if (m_logFunction)
    {
        m_logFunction(LOG_ERROR, errorMsg);
        m_logFunction(LOG_ERROR, "Raw event that failed validation: " + data);
    }

    return false;
}
```

### Step 4: Validate Before Sending Data

Use the helper function before sending data to the sync protocol:

```cpp
void YourModule::processEvent(const std::string& data, const std::string& index)
{
    // Validate data
    std::string context = "event processing";
    bool validationPassed = validateSchemaAndLog(data, index, context);

    if (!validationPassed)
    {
        // Discard invalid data
        if (m_logFunction)
        {
            m_logFunction(LOG_ERROR, "Discarding invalid message");
        }

        // Mark for deletion from database
        markForDeletion(data);
        return;
    }

    // Send valid data to sync protocol
    m_spSyncProtocol->persistDifference(id, operation, index, data, version);
}
```

### Step 5: Implement Batch Deletion

Create a helper function for batch deletion of invalid items:

```cpp
void YourModule::deleteFailedItemsFromDB(
    const std::vector<std::pair<std::string, nlohmann::json>>& failedItems) const
{
    if (failedItems.empty() || !m_spDBSync)
    {
        return;
    }

    try
    {
        // Create a transaction
        DBSyncTxn deleteTxn(m_spDBSync->handle(),
                            nlohmann::json::array(),
                            0, 1,
        [](ReturnTypeCallback, const nlohmann::json&) {});

        // Delete all failed items
        for (const auto& [tableName, data] : failedItems)
        {
            if (m_logFunction)
            {
                m_logFunction(LOG_DEBUG, "Deleting entry from table " + tableName +
                             " due to validation failure");
            }

            try
            {
                auto deleteQuery = DeleteQuery::builder()
                                   .table(tableName)
                                   .data(data)
                                   .rowFilter("")
                                   .build();

                m_spDBSync->deleteRows(deleteQuery.query());
            }
            catch (const std::exception& e)
            {
                if (m_logFunction)
                {
                    m_logFunction(LOG_ERROR, "Failed to delete from DBSync: " +
                                 std::string(e.what()));
                }
            }
        }

        // Finalize transaction
        deleteTxn.getDeletedRows([](ReturnTypeCallback, const nlohmann::json&) {});

        if (m_logFunction)
        {
            m_logFunction(LOG_DEBUG, "Deleted " + std::to_string(failedItems.size()) +
                         " item(s) from DBSync due to validation failure");
        }
    }
    catch (const std::exception& e)
    {
        if (m_logFunction)
        {
            m_logFunction(LOG_ERROR, "Failed to create DBSync transaction for deletion: " +
                         std::string(e.what()));
        }
    }
}
```

---

## C Module Integration (FIM)

### Step 1: Include Headers

Add the C wrapper header to your module:

```c
#include "schemaValidator_c.h"
```

### Step 2: Initialize During Module Startup

```c
void fim_initialize(void)
{
    // Initialize schema validator from embedded resources
    if (!schema_validator_is_initialized())
    {
        if (schema_validator_initialize())
        {
            minfo("Schema validator initialized successfully from embedded resources");
        }
        else
        {
            mwarn("Failed to initialize schema validator. Schema validation will be disabled.");
        }
    }
}
```

### Step 3: Validate Before Sending Data

```c
bool fim_validate_and_queue(const char* index, const char* data, void* item_data, OSList* failed_list)
{
    bool validation_passed = true;

    // Only validate if synchronization is enabled and schema validator is initialized
    if (syscheck.enable_synchronization && schema_validator_is_initialized())
    {
        char* errorMessage = NULL;

        if (!schema_validator_validate(index, data, &errorMessage))
        {
            // Validation failed - log errors
            if (errorMessage)
            {
                mdebug2("Schema validation failed for FIM message (index: %s). Error: %s",
                       index, errorMessage);
                mdebug2("Raw event that failed validation: %s", data);
                free(errorMessage);
            }

            // Mark for deferred deletion from database
            if (failed_list && item_data)
            {
                mdebug1("Marking FIM entry for deferred deletion due to validation failure");
                OSList_AddData(failed_list, item_data);
            }

            validation_passed = false;
        }
    }

    return validation_passed;
}
```

### Step 4: Implement Batch Deletion

```c
void fim_delete_failed_items(OSList* failed_list)
{
    if (!failed_list || OSList_GetSize(failed_list) == 0)
    {
        return;
    }

    mdebug1("Deleting %d FIM item(s) from database due to validation failure",
           OSList_GetSize(failed_list));

    OSListNode* node;
    OSList_foreach(node, failed_list)
    {
        void* item_data = node->data;

        // Delete item from database
        fim_db_remove_path(syscheck.database, item_data);
    }
}
```

---

## Helper Function Patterns

### Pattern 1: Validation with Context Logging (Syscollector)

```cpp
bool Syscollector::validateSchemaAndLog(const std::string& data,
                                        const std::string& index,
                                        const std::string& context) const
{
    auto& validatorFactory = SchemaValidator::SchemaValidatorFactory::getInstance();

    if (!validatorFactory.isInitialized())
    {
        return true;
    }

    auto validator = validatorFactory.getValidator(index);

    if (!validator)
    {
        return true;
    }

    auto validationResult = validator->validate(data);

    if (validationResult.isValid)
    {
        return true;
    }

    // Validation failed - log errors
    std::string errorMsg = "Schema validation failed for Syscollector message (" + context +
                           ", index: " + index + "). Errors: ";

    for (const auto& error : validationResult.errors)
    {
        errorMsg += "  - " + error;
    }

    if (m_logFunction)
    {
        m_logFunction(LOG_ERROR, errorMsg);
        m_logFunction(LOG_ERROR, "Raw event that failed validation: " + data);
    }

    return false;
}
```

**Usage:**
```cpp
bool validationPassed = validateSchemaAndLog(statefulToSend, index, "table: " + tableName);

if (!validationPassed)
{
    // Discard and mark for deletion
}
```

### Pattern 2: Validation with Deferred Deletion (SCA)

```cpp
bool SCAEventHandler::ValidateAndHandleStatefulMessage(
    const nlohmann::json& statefulEvent,
    const std::string& context,
    const nlohmann::json& checkData,
    std::vector<nlohmann::json>* failedChecks) const
{
    if (statefulEvent.empty())
    {
        return true;
    }

    auto& validatorFactory = SchemaValidator::SchemaValidatorFactory::getInstance();

    if (!validatorFactory.isInitialized())
    {
        return true;
    }

    auto validator = validatorFactory.getValidator(SCA_SYNC_INDEX);

    if (!validator)
    {
        return true;
    }

    std::string statefulData = statefulEvent.dump();
    auto validationResult = validator->validate(statefulData);

    if (validationResult.isValid)
    {
        return true;
    }

    // Validation failed - log errors
    std::string errorMsg = "Schema validation failed for SCA message (" + context +
                           ", index: " + std::string(SCA_SYNC_INDEX) + "). Errors: ";

    for (const auto& error : validationResult.errors)
    {
        errorMsg += "  - " + error;
    }

    LoggingHelper::getInstance().log(LOG_ERROR, errorMsg);
    LoggingHelper::getInstance().log(LOG_ERROR, "Raw event that failed validation: " + statefulData);

    // Handle deletion from DBSync to prevent integrity sync loops
    if (!checkData.empty() && failedChecks)
    {
        // Deferred deletion: accumulate for batch deletion with transaction
        LoggingHelper::getInstance().log(LOG_DEBUG, "Marking SCA check for deferred deletion due to validation failure");
        failedChecks->push_back(checkData);
    }

    return false;
}
```

**Usage:**
```cpp
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

// Batch delete
DeleteFailedChecksFromDB(failedChecks);
```

---

## Deferred Deletion Pattern

The deferred deletion pattern prevents nested transactions and improves performance.

### Why Deferred Deletion?

**Problem:** During DBSync callbacks, we cannot immediately delete items (would cause nested transactions)

**Solution:** Accumulate failed items and delete them in a single batch transaction after processing

### Implementation Steps

**Step 1: Create accumulator**
```cpp
std::vector<std::pair<std::string, nlohmann::json>> failedItems;
m_failedItems = &failedItems; // Make accessible to callbacks
```

**Step 2: Accumulate during processing**
```cpp
if (!validationPassed)
{
    if (m_failedItems)
    {
        m_failedItems->push_back({tableName, data});
    }
}
```

**Step 3: Clean up pointer**
```cpp
m_failedItems = nullptr;
```

**Step 4: Batch delete**
```cpp
deleteFailedItemsFromDB(failedItems);
```

### Complete Example (Syscollector)

```cpp
void Syscollector::scan()
{
    // Vector to accumulate items that fail validation
    std::vector<std::pair<std::string, nlohmann::json>> failedItems;
    m_failedItems = &failedItems;

    // Run scans
    scanHardware();
    scanOs();
    scanPackages();
    // ... etc

    // Clean up after all scans
    m_failedItems = nullptr;

    // Delete all items that failed schema validation
    deleteFailedItemsFromDB(failedItems);
}
```

---

## Error Handling

### Graceful Degradation

Always handle the case where validation is unavailable:

```cpp
auto& factory = SchemaValidator::SchemaValidatorFactory::getInstance();

// Check if initialized
if (!factory.isInitialized())
{
    // Log warning once during startup
    m_logFunction(LOG_WARNING, "Schema validator not initialized. Validation disabled.");
    return true; // Continue without validation
}

// Check if validator exists for index
auto validator = factory.getValidator(index);
if (!validator)
{
    // No validator for this index - continue without validation
    return true;
}

// Proceed with validation
auto result = validator->validate(data);
```

### Logging Strategy

**Initialization:**
```cpp
// During startup
LOG_INFO: "Schema validator initialized successfully"
LOG_WARNING: "Schema validator not initialized. Validation disabled."
```

**Validation Errors:**
```cpp
// When validation fails
LOG_ERROR: "Schema validation failed for <module> message (<context>, index: <index>). Errors: <details>"
LOG_ERROR: "Raw event that failed validation: <json>"
LOG_DEBUG: "Marking entry for deferred deletion due to validation failure"
```

**Deletion:**
```cpp
// After batch deletion
LOG_DEBUG: "Deleted N item(s) from database due to validation failure"
LOG_ERROR: "Failed to delete from database: <error>" // If deletion fails
```

---

## Testing Integration

### Unit Test Structure

```cpp
#include <gtest/gtest.h>
#include "schemaValidator.hpp"

class SchemaValidatorTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        // Reset factory for clean state
        auto& factory = SchemaValidator::SchemaValidatorFactory::getInstance();
        factory.reset();
    }

    void TearDown() override
    {
        // Clean up
        auto& factory = SchemaValidator::SchemaValidatorFactory::getInstance();
        factory.reset();
    }
};

TEST_F(SchemaValidatorTest, ValidMessage)
{
    auto& factory = SchemaValidator::SchemaValidatorFactory::getInstance();
    ASSERT_TRUE(factory.initialize());

    auto validator = factory.getValidator("wazuh-states-inventory-packages");
    ASSERT_NE(validator, nullptr);

    std::string validJson = R"({
        "agent": {"id": "001"},
        "package": {"name": "nginx", "version": "1.18.0"}
    })";

    auto result = validator->validate(validJson);
    EXPECT_TRUE(result.isValid);
    EXPECT_TRUE(result.errors.empty());
}

TEST_F(SchemaValidatorTest, InvalidMessage)
{
    auto& factory = SchemaValidator::SchemaValidatorFactory::getInstance();
    ASSERT_TRUE(factory.initialize());

    auto validator = factory.getValidator("wazuh-states-inventory-packages");
    ASSERT_NE(validator, nullptr);

    std::string invalidJson = R"({
        "agent": {"id": "001"},
        "package": {"name": 123}
    })";

    auto result = validator->validate(invalidJson);
    EXPECT_FALSE(result.isValid);
    EXPECT_FALSE(result.errors.empty());
}
```

### Mock Validator for Testing

```cpp
class MockSchemaValidator : public SchemaValidator::ISchemaValidatorEngine
{
public:
    MOCK_METHOD(ValidationResult, validate, (const std::string&), (override));
    MOCK_METHOD(ValidationResult, validate, (const nlohmann::json&), (override));
    MOCK_METHOD(std::string, getSchemaName, (), (const, override));
};

TEST_F(YourModuleTest, ValidationFailureHandling)
{
    // Create mock validator that always fails
    auto mockValidator = std::make_shared<MockSchemaValidator>();
    ON_CALL(*mockValidator, validate(testing::_))
        .WillByDefault(testing::Return(ValidationResult{false, {"Test error"}}));

    // Inject mock
    std::map<std::string, std::shared_ptr<SchemaValidator::ISchemaValidatorEngine>> mocks;
    mocks["test-index"] = mockValidator;

    auto& factory = SchemaValidator::SchemaValidatorFactory::getInstance();
    factory.reset();
    factory.initialize(mocks);

    // Test your module's handling of validation failure
    bool result = yourModule->processData(testData, "test-index");
    EXPECT_FALSE(result); // Should handle validation failure correctly
}
```

---

## CMakeLists.txt Integration

Add the schema validator library to your module's CMakeLists.txt:

```cmake
target_link_libraries(your_module
    PRIVATE
        schema_validator
)
```

---

## Troubleshooting

### Issue: Factory returns nullptr

**Cause:** Factory not initialized or index pattern not found

**Solution:**
```cpp
if (!factory.isInitialized())
{
    factory.initialize();
}

auto validator = factory.getValidator(index);
if (!validator)
{
    m_logFunction(LOG_WARNING, "No validator found for index: " + index);
    // Continue without validation
}
```

### Issue: Validation always fails

**Cause:** Data doesn't match schema structure

**Solution:**
1. Check the raw event logged in errors
2. Compare against the schema file for that index
3. Verify field names and types match exactly
4. Check for missing required fields

### Issue: Performance degradation

**Cause:** Getting validator repeatedly instead of caching

**Solution:**
```cpp
// Cache validator
auto validator = factory.getValidator(index);

// Reuse in loop
for (const auto& item : items)
{
    validator->validate(item); // Fast
}
```

---

## Next Steps

1. Review [API Reference](api-reference.md) for complete API documentation
2. Check module-specific integration in:
   - [Syscollector Architecture](../../modules/syscollector/architecture.md#schema-validation-integration)
   - [SCA Architecture](../../modules/sca/architecture.md#schema-validation-integration)
   - [FIM Architecture](../../modules/fim/architecture.md#schema-validation-integration)

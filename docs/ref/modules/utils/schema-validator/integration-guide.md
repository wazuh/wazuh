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
            m_logFunction(LOG_DEBUG, "Schema validator initialized successfully from embedded resources");
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
            mdebug1("Schema validator initialized successfully from embedded resources");
        }
        else
        {
            mwarn("Failed to initialize schema validator. Schema validation will be disabled.");
        }
    }
}
```

### Step 3: Validate Before Sending Data

FIM validates each stateful event in `validate_and_persist_fim_event()` (`run_check.c`) and persists it only if it passes. A failure seen while FIM is shutting down is ignored, because `exit()` may already have torn down the validator's state; anything else is logged at ERROR and the entry is marked for deletion:

```c
bool validate_and_persist_fim_event(
    const cJSON* stateful_event,
    const char* id,
    Operation_t operation,
    const char* index,
    uint64_t document_version,
    const char* item_description,
    bool mark_for_deletion,
    OSList* failed_list,
    void* failed_item_data,
    int sync_flag
) {
    bool validation_passed = true;

    // Only validate if synchronization is enabled and schema validator is initialized
    if (syscheck.enable_synchronization && schema_validator_is_initialized()) {
        char* msg = cJSON_PrintUnformatted(stateful_event);
        char* errorMessage = NULL;

        if (!schema_validator_validate(index, msg, &errorMessage)) {
            // A schema-validation failure observed while the agent is shutting down is not
            // trustworthy: HandleSIG() calls exit(), which tears down the schema validator's
            // process-static state (e.g. the ISO8601 regex) while this scan thread may still be
            // validating events, so a perfectly valid event can be reported as invalid. Do not
            // surface it as an error and do not act on the untrustworthy result (no deletion, no
            // persistence): the agent is stopping and the event is re-evaluated on the next start.
            if (fim_shutdown_process_on()) {
                mdebug1("Ignoring schema validation failure for %s during shutdown%s%s",
                        item_description,
                        (errorMessage && errorMessage[0]) ? ": " : "",
                        (errorMessage && errorMessage[0]) ? errorMessage : "");
                os_free(errorMessage);
                os_free(msg);
                return true;
            }

            // Validation failed - log errors
            if (errorMessage) {
                merror("Schema validation failed for %s (index: %s). Errors: %s",
                       item_description, index, errorMessage);
                os_free(errorMessage);
            }

            merror("Raw event that failed validation: %s", msg);
            mdebug1("Skipping persistence of invalid event for %s", item_description);
            validation_passed = false;

            // Mark for deletion from DBSync if requested and this is an INSERT or MODIFY operation
            if (mark_for_deletion && failed_list && failed_item_data) {
                mdebug1("Marking %s for deletion from DBSync due to validation failure", item_description);
                OSList_AddData(failed_list, failed_item_data);
            }
        }

        os_free(msg);
    }

    // Persist stateful event only if validation passed (or validation is disabled) AND sync_flag is 1
    if (validation_passed && sync_flag == 1) {
        persist_syscheck_msg(id, operation, index, stateful_event, document_version);
    }

    return validation_passed;
}
```

### Step 4: Delete Invalid Entries After the Transaction

FIM deletes each entry that failed validation once the database transaction has finished (`run_check.c`); registry keys and values use `cleanup_failed_registry_keys()` and `cleanup_failed_registry_values()`:

```c
void cleanup_failed_fim_files(OSList* failed_paths) {
    if (!failed_paths) {
        return;
    }

    OSListNode* node;
    OSList_foreach(node, failed_paths) {
        const char* failed_path = (const char*)node->data;
        mdebug1("Deleting %s from DBSync due to validation failure", failed_path);
        fim_db_file_delete(failed_path);
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
    // initialize() failed at startup, which already logged:
    // LOG_WARNING "Failed to initialize schema validator. Schema validation will be disabled."
    return true; // Continue without validation
}

// Check if validator exists for index
auto validator = factory.getValidator(index);
if (!validator)
{
    // No schema for this index - discard instead of sending it unvalidated
    m_logFunction(LOG_WARNING, "No schema validator found for index: " + index + ". Discarding message.");
    return false;
}

// Proceed with validation
auto result = validator->validate(data);
```

### Logging Strategy

**Initialization:**
```cpp
// During startup
LOG_DEBUG: "Schema validator initialized successfully from embedded resources"
LOG_WARNING: "Failed to initialize schema validator. Schema validation will be disabled."
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
LOG_DEBUG: "Deleting <item> from DBSync due to validation failure"          // FIM, one per item
LOG_DEBUG: "Deleting entry from table <table> due to validation failure"    // Syscollector, one per item
LOG_DEBUG: "Deleted N item(s) from DBSync due to validation failure"        // Syscollector; SCA logs "N SCA check(s)"
LOG_ERROR: "Failed to delete from DBSync: <error>"                          // SCA (whole batch) or Syscollector (per row), if deletion fails
LOG_ERROR: "Failed to create DBSync transaction for deletion: <error>"      // Syscollector, if the transaction cannot be created
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
        "wazuh": {"agent": {"id": "001"}},
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
        "wazuh": {"agent": {"id": "001"}},
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
   - [Syscollector Architecture](../../syscollector/architecture.md#schema-validation-integration)
   - [SCA Architecture](../../sca/architecture.md#schema-validation-integration)
   - [FIM Architecture](../../fim/architecture.md#schema-validation-integration)

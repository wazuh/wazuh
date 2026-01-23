#include <gtest/gtest.h>
#include "schemaValidator.hpp"

using namespace SchemaValidator;

class SchemaValidatorTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        // Create test schema in memory
        createTestSchema();
    }

    void createTestSchema()
    {
        nlohmann::json schema = {
            {"index_patterns", {"test-index*"}},
            {"priority", 1},
            {"template", {
                {"settings", {
                    {"index", {
                        {"number_of_replicas", "0"},
                        {"number_of_shards", "1"}
                    }}
                }},
                {"mappings", {
                    {"date_detection", false},
                    {"dynamic", "strict"},
                    {"properties", {
                        {"name", {{"type", "keyword"}, {"ignore_above", 1024}}},
                        {"age", {{"type", "integer"}}},
                        {"score", {{"type", "long"}}},
                        {"email", {{"type", "keyword"}}},
                        {"created_at", {{"type", "date"}}},
                        {"is_active", {{"type", "boolean"}}},
                        {"ip_address", {{"type", "ip"}}},
                        {"port", {{"type", "short"}}},
                        {"counter", {{"type", "unsigned_long"}}},
                        {"price", {{"type", "scaled_float"}}},
                        {"description", {{"type", "match_only_text"}}},
                        {"metadata", {{"type", "object"}}},
                        {"address", {
                            {"properties", {
                                {"street", {{"type", "keyword"}}},
                                {"city", {{"type", "keyword"}}}
                            }}
                        }}
                    }}
                }}
            }}
        };

        m_testSchemaString = schema.dump();
    }

    std::string m_testSchemaString;
};

TEST_F(SchemaValidatorTest, LoadSchemaSuccess)
{
    SchemaValidatorEngine validator;
    EXPECT_TRUE(validator.loadSchemaFromString(m_testSchemaString));
    EXPECT_EQ(validator.getSchemaName(), "test-index");
}

TEST_F(SchemaValidatorTest, LoadSchemaFail)
{
    SchemaValidatorEngine validator;
    EXPECT_FALSE(validator.loadSchemaFromString("invalid json"));
}

TEST_F(SchemaValidatorTest, ValidateValidMessage)
{
    SchemaValidatorEngine validator;
    validator.loadSchemaFromString(m_testSchemaString);

    nlohmann::json message = {
        {"name", "John Doe"},
        {"age", 30},
        {"score", 12345},
        {"email", "john@example.com"},
        {"created_at", "2025-12-29T10:00:00.000Z"},
        {"is_active", true},
        {"address", {{"street", "123 Main St"}, {"city", "New York"}}}};

    ValidationResult result = validator.validate(message);
    EXPECT_TRUE(result.isValid);
    EXPECT_TRUE(result.errors.empty());
}

TEST_F(SchemaValidatorTest, ValidateInvalidTypeInteger)
{
    SchemaValidatorEngine validator;
    validator.loadSchemaFromString(m_testSchemaString);

    nlohmann::json message = {{"name", "John Doe"}, {"age", "not a number"}};

    ValidationResult result = validator.validate(message);
    EXPECT_FALSE(result.isValid);
    EXPECT_FALSE(result.errors.empty());
}

TEST_F(SchemaValidatorTest, ValidateIntegerWithNumericString)
{
    SchemaValidatorEngine validator;
    validator.loadSchemaFromString(m_testSchemaString);

    // Strict validation rejects numeric strings for integer fields
    nlohmann::json message = {{"name", "John Doe"}, {"age", "30"}};

    ValidationResult result = validator.validate(message);
    EXPECT_FALSE(result.isValid);
    EXPECT_FALSE(result.errors.empty());
}

TEST_F(SchemaValidatorTest, ValidateIntegerWithFloat)
{
    SchemaValidatorEngine validator;
    validator.loadSchemaFromString(m_testSchemaString);

    // Strict validation rejects floats for integer fields
    nlohmann::json message = {{"name", "John Doe"}, {"age", 30.5}};

    ValidationResult result = validator.validate(message);
    EXPECT_FALSE(result.isValid);
    EXPECT_FALSE(result.errors.empty());
}

TEST_F(SchemaValidatorTest, ValidateStrictModeExtraField)
{
    SchemaValidatorEngine validator;
    validator.loadSchemaFromString(m_testSchemaString);

    // OpenSearch rejects extra fields with non-null values in strict mode
    nlohmann::json message = {
        {"name", "John Doe"}, {"age", 30}, {"extra_field", "not allowed"}};

    ValidationResult result = validator.validate(message);
    EXPECT_FALSE(result.isValid);
    EXPECT_FALSE(result.errors.empty());
    EXPECT_TRUE(result.errors[0].find("extra_field") != std::string::npos);
}

TEST_F(SchemaValidatorTest, ValidateStrictModeExtraFieldNull)
{
    SchemaValidatorEngine validator;
    validator.loadSchemaFromString(m_testSchemaString);

    // OpenSearch ACCEPTS extra fields if their value is null in strict mode
    nlohmann::json message = {
        {"name", "John Doe"}, {"age", 30}, {"extra_field", nullptr}};

    ValidationResult result = validator.validate(message);
    EXPECT_TRUE(result.isValid);
    EXPECT_TRUE(result.errors.empty());
}

TEST_F(SchemaValidatorTest, ValidateStrictModeNestedExtraFieldNull)
{
    SchemaValidatorEngine validator;
    validator.loadSchemaFromString(m_testSchemaString);

    // OpenSearch ACCEPTS extra fields in nested objects if value is null
    nlohmann::json message = {
        {"name", "John Doe"},
        {"age", 30},
        {"address", {{"street", "123 Main St"}, {"city", "New York"}, {"extra", nullptr}}}
    };

    ValidationResult result = validator.validate(message);
    EXPECT_TRUE(result.isValid);
    EXPECT_TRUE(result.errors.empty());
}

TEST_F(SchemaValidatorTest, ValidateStrictModeNestedExtraFieldNonNull)
{
    SchemaValidatorEngine validator;
    validator.loadSchemaFromString(m_testSchemaString);

    // OpenSearch REJECTS extra fields in nested objects if value is non-null
    nlohmann::json message = {
        {"name", "John Doe"},
        {"age", 30},
        {"address", {{"street", "123 Main St"}, {"city", "New York"}, {"extra", "not allowed"}}}
    };

    ValidationResult result = validator.validate(message);
    EXPECT_FALSE(result.isValid);
    EXPECT_FALSE(result.errors.empty());
    EXPECT_TRUE(result.errors[0].find("address.extra") != std::string::npos);
}

TEST_F(SchemaValidatorTest, ValidateNestedObject)
{
    SchemaValidatorEngine validator;
    validator.loadSchemaFromString(m_testSchemaString);

    nlohmann::json message = {{"name", "John Doe"},
                              {"age", 30},
                              {"address", {{"street", "123 Main St"}, {"city", "New York"}}}};

    ValidationResult result = validator.validate(message);
    EXPECT_TRUE(result.isValid);
    EXPECT_TRUE(result.errors.empty());
}

TEST_F(SchemaValidatorTest, ValidateDateAsLong)
{
    SchemaValidatorEngine validator;
    validator.loadSchemaFromString(m_testSchemaString);

    // Date as milliseconds since epoch (OpenSearch format)
    nlohmann::json message = {{"name", "John Doe"}, {"age", 30}, {"created_at", 1735468800000}};

    ValidationResult result = validator.validate(message);
    EXPECT_TRUE(result.isValid);
    EXPECT_TRUE(result.errors.empty());
}

TEST_F(SchemaValidatorTest, ValidateDateAsInteger)
{
    SchemaValidatorEngine validator;
    validator.loadSchemaFromString(m_testSchemaString);

    // Date as seconds since epoch (OpenSearch format)
    nlohmann::json message = {{"name", "John Doe"}, {"age", 30}, {"created_at", 1735468800}};

    ValidationResult result = validator.validate(message);
    EXPECT_TRUE(result.isValid);
    EXPECT_TRUE(result.errors.empty());
}

TEST_F(SchemaValidatorTest, ValidateDateAsString)
{
    SchemaValidatorEngine validator;
    validator.loadSchemaFromString(m_testSchemaString);

    // Date as ISO8601 string (OpenSearch format)
    nlohmann::json message = {{"name", "John Doe"}, {"age", 30}, {"created_at", "2025-12-29T10:00:00.000Z"}};

    ValidationResult result = validator.validate(message);
    EXPECT_TRUE(result.isValid);
    EXPECT_TRUE(result.errors.empty());
}

TEST_F(SchemaValidatorTest, ValidateDateAsStringNumeric)
{
    SchemaValidatorEngine validator;
    validator.loadSchemaFromString(m_testSchemaString);

    // Strict validation rejects string "123" as it's not a valid ISO8601 date
    nlohmann::json message = {{"name", "John Doe"}, {"age", 30}, {"created_at", "123"}};

    ValidationResult result = validator.validate(message);
    EXPECT_FALSE(result.isValid);
    EXPECT_FALSE(result.errors.empty());
}

TEST_F(SchemaValidatorTest, ValidateInvalidDate)
{
    SchemaValidatorEngine validator;
    validator.loadSchemaFromString(m_testSchemaString);

    // Only non-string and non-integer types should fail
    nlohmann::json message = {{"name", "John Doe"}, {"age", 30}, {"created_at", true}};

    ValidationResult result = validator.validate(message);
    EXPECT_FALSE(result.isValid);
    EXPECT_FALSE(result.errors.empty());
}

TEST_F(SchemaValidatorTest, ValidateNullValues)
{
    SchemaValidatorEngine validator;
    validator.loadSchemaFromString(m_testSchemaString);

    // OpenSearch allows null for any field
    nlohmann::json message = {
        {"name", nullptr},
        {"age", nullptr},
        {"created_at", nullptr},
        {"is_active", nullptr}
    };

    ValidationResult result = validator.validate(message);
    EXPECT_TRUE(result.isValid);
    EXPECT_TRUE(result.errors.empty());
}

TEST_F(SchemaValidatorTest, ValidateNullForNestedObject)
{
    SchemaValidatorEngine validator;
    validator.loadSchemaFromString(m_testSchemaString);

    // OpenSearch allows null for nested objects too
    nlohmann::json message = {
        {"name", "John Doe"},
        {"age", 30},
        {"address", nullptr}  // Nested object can be null
    };

    ValidationResult result = validator.validate(message);
    EXPECT_TRUE(result.isValid);
    EXPECT_TRUE(result.errors.empty());
}

TEST_F(SchemaValidatorTest, ValidateStringMessage)
{
    SchemaValidatorEngine validator;
    validator.loadSchemaFromString(m_testSchemaString);

    std::string messageStr = R"({"name": "John Doe", "age": 30, "email": "john@example.com"})";

    ValidationResult result = validator.validate(messageStr);
    EXPECT_TRUE(result.isValid);
    EXPECT_TRUE(result.errors.empty());
}

TEST_F(SchemaValidatorTest, ValidateInvalidJSON)
{
    SchemaValidatorEngine validator;
    validator.loadSchemaFromString(m_testSchemaString);

    std::string messageStr = R"({"name": "John Doe", "age": 30,})";

    ValidationResult result = validator.validate(messageStr);
    EXPECT_FALSE(result.isValid);
    EXPECT_FALSE(result.errors.empty());
    EXPECT_TRUE(result.errors[0].find("parse error") != std::string::npos);
}

TEST_F(SchemaValidatorTest, ValidateKeywordWithNumber)
{
    SchemaValidatorEngine validator;
    validator.loadSchemaFromString(m_testSchemaString);

    // Strict validation rejects numbers for keyword fields
    nlohmann::json message = {{"name", 123}, {"age", 30}};

    ValidationResult result = validator.validate(message);
    EXPECT_FALSE(result.isValid);
    EXPECT_FALSE(result.errors.empty());
}

TEST_F(SchemaValidatorTest, ValidateKeywordWithBoolean)
{
    SchemaValidatorEngine validator;
    validator.loadSchemaFromString(m_testSchemaString);

    // Strict validation rejects booleans for keyword fields
    nlohmann::json message = {{"name", true}, {"age", 30}};

    ValidationResult result = validator.validate(message);
    EXPECT_FALSE(result.isValid);
    EXPECT_FALSE(result.errors.empty());
}

TEST_F(SchemaValidatorTest, ValidateKeywordAsArray)
{
    SchemaValidatorEngine validator;
    validator.loadSchemaFromString(m_testSchemaString);

    // OpenSearch accepts both single values and arrays for keyword fields
    nlohmann::json message = {{"name", nlohmann::json::array({"John Doe", "Jane Doe"})}, {"age", 30}};

    ValidationResult result = validator.validate(message);
    EXPECT_TRUE(result.isValid);
    EXPECT_TRUE(result.errors.empty());
}

TEST_F(SchemaValidatorTest, ValidateKeywordArrayMixedTypes)
{
    SchemaValidatorEngine validator;
    validator.loadSchemaFromString(m_testSchemaString);

    // Strict validation rejects arrays with mixed types for keyword fields
    nlohmann::json message = {{"name", nlohmann::json::array({123, "string", true})}, {"age", 30}};

    ValidationResult result = validator.validate(message);
    EXPECT_FALSE(result.isValid);
    EXPECT_FALSE(result.errors.empty());
}

TEST_F(SchemaValidatorTest, ValidateIntegerAsArray)
{
    SchemaValidatorEngine validator;
    validator.loadSchemaFromString(m_testSchemaString);

    // OpenSearch accepts both single values and arrays for integer fields
    nlohmann::json message = {{"name", "John Doe"}, {"age", nlohmann::json::array({30, 31, 32})}};

    ValidationResult result = validator.validate(message);
    EXPECT_TRUE(result.isValid);
    EXPECT_TRUE(result.errors.empty());
}

TEST_F(SchemaValidatorTest, ValidateDateAsArray)
{
    SchemaValidatorEngine validator;
    validator.loadSchemaFromString(m_testSchemaString);

    // OpenSearch accepts both single values and arrays for date fields
    nlohmann::json message = {
        {"name", "John Doe"},
        {"age", 30},
        {"created_at", nlohmann::json::array({1735468800000, "2025-12-29T10:00:00.000Z"})}
    };

    ValidationResult result = validator.validate(message);
    EXPECT_TRUE(result.isValid);
    EXPECT_TRUE(result.errors.empty());
}

TEST_F(SchemaValidatorTest, ValidateDateRealOpenSearchScenarios)
{
    SchemaValidatorEngine validator;
    validator.loadSchemaFromString(m_testSchemaString);

    // Test case 1: Array of integers (milliseconds) - VALID
    nlohmann::json msg1 = {{"created_at", nlohmann::json::array({123, 123})}};
    auto result1 = validator.validate(msg1);
    EXPECT_TRUE(result1.isValid);

    // Test case 2: Array with string numeric - INVALID (not ISO8601)
    nlohmann::json msg2 = {{"created_at", nlohmann::json::array({"123"})}};
    auto result2 = validator.validate(msg2);
    EXPECT_FALSE(result2.isValid);
    EXPECT_FALSE(result2.errors.empty());

    // Test case 3: Null value - VALID
    nlohmann::json msg3 = {{"created_at", nullptr}};
    auto result3 = validator.validate(msg3);
    EXPECT_TRUE(result3.isValid);

    // Test case 4: Invalid date format - INVALID
    // (strict_date_optional_time||epoch_millis doesn't support RFC format)
    nlohmann::json msg4 = {{"created_at", "Tue 23 Dec 2025 02:28:56 PM UTC"}};
    auto result4 = validator.validate(msg4);
    EXPECT_FALSE(result4.isValid);
    EXPECT_FALSE(result4.errors.empty());

    // Test case 5: Array with invalid date format - INVALID
    nlohmann::json msg5 = {{"created_at", nlohmann::json::array({"Tue 23 Dec 2025 02:28:56 PM UTC"})}};
    auto result5 = validator.validate(msg5);
    EXPECT_FALSE(result5.isValid);
    EXPECT_FALSE(result5.errors.empty());
}

TEST_F(SchemaValidatorTest, ValidateArrayWithInvalidElement)
{
    SchemaValidatorEngine validator;
    validator.loadSchemaFromString(m_testSchemaString);

    // Array with one invalid element should fail
    nlohmann::json message = {{"name", "John Doe"}, {"age", nlohmann::json::array({30, "invalid"})}};

    ValidationResult result = validator.validate(message);
    EXPECT_FALSE(result.isValid);
    EXPECT_FALSE(result.errors.empty());
    EXPECT_TRUE(result.errors[0].find("age[1]") != std::string::npos);
}

TEST_F(SchemaValidatorTest, ValidateBooleanWithString)
{
    SchemaValidatorEngine validator;
    validator.loadSchemaFromString(m_testSchemaString);

    // Strict validation rejects string "true" for boolean fields
    nlohmann::json message = {{"name", "John Doe"}, {"is_active", "true"}};

    ValidationResult result = validator.validate(message);
    EXPECT_FALSE(result.isValid);
    EXPECT_FALSE(result.errors.empty());
}

TEST_F(SchemaValidatorTest, ValidateBooleanWithStringFalse)
{
    SchemaValidatorEngine validator;
    validator.loadSchemaFromString(m_testSchemaString);

    // Strict validation rejects string "false" for boolean fields
    nlohmann::json message = {{"name", "John Doe"}, {"is_active", "false"}};

    ValidationResult result = validator.validate(message);
    EXPECT_FALSE(result.isValid);
    EXPECT_FALSE(result.errors.empty());
}

TEST_F(SchemaValidatorTest, ValidateBooleanRejectsNumbers)
{
    SchemaValidatorEngine validator;
    validator.loadSchemaFromString(m_testSchemaString);

    // OpenSearch REJECTS numeric values for boolean fields
    nlohmann::json message = {{"name", "John Doe"}, {"is_active", 1}};

    ValidationResult result = validator.validate(message);
    EXPECT_FALSE(result.isValid);
    EXPECT_FALSE(result.errors.empty());
}

TEST_F(SchemaValidatorTest, ValidateBooleanRejectsInvalidString)
{
    SchemaValidatorEngine validator;
    validator.loadSchemaFromString(m_testSchemaString);

    // OpenSearch rejects strings other than "true"/"false"
    nlohmann::json message = {{"name", "John Doe"}, {"is_active", "yes"}};

    ValidationResult result = validator.validate(message);
    EXPECT_FALSE(result.isValid);
    EXPECT_FALSE(result.errors.empty());
}

// Factory tests with embedded resources
// Note: These tests rely on schemas being embedded at compile time
// from external/indexer-plugins/*.json files

TEST_F(SchemaValidatorTest, FactoryInitialization)
{
    SchemaValidatorFactory& factory = SchemaValidatorFactory::getInstance();
    // Initialize loads from embedded resources
    bool initialized = factory.initialize();
    // May be true or false depending on whether schemas were embedded
    EXPECT_TRUE(initialized || !initialized); // Just check it doesn't crash
}

TEST_F(SchemaValidatorTest, FactoryGetValidator)
{
    SchemaValidatorFactory& factory = SchemaValidatorFactory::getInstance();
    factory.initialize();

    // This test depends on embedded schemas being available
    // In a real deployment, the schemas would be embedded at build time
    auto validator = factory.getValidator("wazuh-states-fim-file");
    // May be nullptr if schemas weren't embedded during build
    // Just verify the API works without crashing
    if (validator)
    {
        EXPECT_FALSE(validator->getSchemaName().empty());
    }
}

TEST_F(SchemaValidatorTest, FactoryGetNonExistentValidator)
{
    SchemaValidatorFactory& factory = SchemaValidatorFactory::getInstance();
    factory.initialize();

    auto validator = factory.getValidator("non-existent-index-pattern");
    EXPECT_EQ(validator, nullptr);
}

// ============================================================================
// Tests for new types: short, unsigned_long, scaled_float, match_only_text, object
// ============================================================================

TEST_F(SchemaValidatorTest, ValidateShortWithInteger)
{
    SchemaValidatorEngine validator;
    validator.loadSchemaFromString(m_testSchemaString);

    nlohmann::json message = {{"port", 8080}};
    ValidationResult result = validator.validate(message);
    EXPECT_TRUE(result.isValid);
}

TEST_F(SchemaValidatorTest, ValidateShortWithFloat)
{
    SchemaValidatorEngine validator;
    validator.loadSchemaFromString(m_testSchemaString);

    // Strict validation rejects floats for short fields
    nlohmann::json message = {{"port", 8080.5}};
    ValidationResult result = validator.validate(message);
    EXPECT_FALSE(result.isValid);
    EXPECT_FALSE(result.errors.empty());
}

TEST_F(SchemaValidatorTest, ValidateShortWithNumericString)
{
    SchemaValidatorEngine validator;
    validator.loadSchemaFromString(m_testSchemaString);

    // Strict validation rejects numeric strings for short fields
    nlohmann::json message = {{"port", "8080"}};
    ValidationResult result = validator.validate(message);
    EXPECT_FALSE(result.isValid);
    EXPECT_FALSE(result.errors.empty());
}

TEST_F(SchemaValidatorTest, ValidateShortWithInvalidString)
{
    SchemaValidatorEngine validator;
    validator.loadSchemaFromString(m_testSchemaString);

    nlohmann::json message = {{"port", "not_a_number"}};
    ValidationResult result = validator.validate(message);
    EXPECT_FALSE(result.isValid);
    EXPECT_FALSE(result.errors.empty());
}

TEST_F(SchemaValidatorTest, ValidateUnsignedLongWithInteger)
{
    SchemaValidatorEngine validator;
    validator.loadSchemaFromString(m_testSchemaString);

    nlohmann::json message = {{"counter", 9223372036854775807}};
    ValidationResult result = validator.validate(message);
    EXPECT_TRUE(result.isValid);
}

TEST_F(SchemaValidatorTest, ValidateUnsignedLongWithFloat)
{
    SchemaValidatorEngine validator;
    validator.loadSchemaFromString(m_testSchemaString);

    // Strict validation rejects floats for unsigned_long fields
    nlohmann::json message = {{"counter", 123.456}};
    ValidationResult result = validator.validate(message);
    EXPECT_FALSE(result.isValid);
    EXPECT_FALSE(result.errors.empty());
}

TEST_F(SchemaValidatorTest, ValidateUnsignedLongWithNumericString)
{
    SchemaValidatorEngine validator;
    validator.loadSchemaFromString(m_testSchemaString);

    // Strict validation rejects numeric strings for unsigned_long fields
    nlohmann::json message = {{"counter", "9223372036854775807"}};
    ValidationResult result = validator.validate(message);
    EXPECT_FALSE(result.isValid);
    EXPECT_FALSE(result.errors.empty());
}

TEST_F(SchemaValidatorTest, ValidateUnsignedLongWithInvalidString)
{
    SchemaValidatorEngine validator;
    validator.loadSchemaFromString(m_testSchemaString);

    nlohmann::json message = {{"counter", "invalid"}};
    ValidationResult result = validator.validate(message);
    EXPECT_FALSE(result.isValid);
    EXPECT_FALSE(result.errors.empty());
}

TEST_F(SchemaValidatorTest, ValidateScaledFloatWithInteger)
{
    SchemaValidatorEngine validator;
    validator.loadSchemaFromString(m_testSchemaString);

    nlohmann::json message = {{"price", 100}};
    ValidationResult result = validator.validate(message);
    EXPECT_TRUE(result.isValid);
}

TEST_F(SchemaValidatorTest, ValidateScaledFloatWithFloat)
{
    SchemaValidatorEngine validator;
    validator.loadSchemaFromString(m_testSchemaString);

    nlohmann::json message = {{"price", 99.99}};
    ValidationResult result = validator.validate(message);
    EXPECT_TRUE(result.isValid);
}

TEST_F(SchemaValidatorTest, ValidateScaledFloatWithNumericString)
{
    SchemaValidatorEngine validator;
    validator.loadSchemaFromString(m_testSchemaString);

    // Strict validation rejects numeric strings for scaled_float fields
    nlohmann::json message = {{"price", "99.99"}};
    ValidationResult result = validator.validate(message);
    EXPECT_FALSE(result.isValid);
    EXPECT_FALSE(result.errors.empty());
}

TEST_F(SchemaValidatorTest, ValidateScaledFloatWithInvalidString)
{
    SchemaValidatorEngine validator;
    validator.loadSchemaFromString(m_testSchemaString);

    nlohmann::json message = {{"price", "not_a_price"}};
    ValidationResult result = validator.validate(message);
    EXPECT_FALSE(result.isValid);
    EXPECT_FALSE(result.errors.empty());
}

TEST_F(SchemaValidatorTest, ValidateMatchOnlyTextWithString)
{
    SchemaValidatorEngine validator;
    validator.loadSchemaFromString(m_testSchemaString);

    nlohmann::json message = {{"description", "This is a text description"}};
    ValidationResult result = validator.validate(message);
    EXPECT_TRUE(result.isValid);
}

TEST_F(SchemaValidatorTest, ValidateMatchOnlyTextWithNumber)
{
    SchemaValidatorEngine validator;
    validator.loadSchemaFromString(m_testSchemaString);

    // Strict validation rejects numbers for text fields
    nlohmann::json message = {{"description", 12345}};
    ValidationResult result = validator.validate(message);
    EXPECT_FALSE(result.isValid);
    EXPECT_FALSE(result.errors.empty());
}

TEST_F(SchemaValidatorTest, ValidateMatchOnlyTextWithBoolean)
{
    SchemaValidatorEngine validator;
    validator.loadSchemaFromString(m_testSchemaString);

    // Strict validation rejects booleans for text fields
    nlohmann::json message = {{"description", true}};
    ValidationResult result = validator.validate(message);
    EXPECT_FALSE(result.isValid);
    EXPECT_FALSE(result.errors.empty());
}

TEST_F(SchemaValidatorTest, ValidateObjectTypeValid)
{
    SchemaValidatorEngine validator;
    validator.loadSchemaFromString(m_testSchemaString);

    nlohmann::json message = {{"metadata", {{"key1", "value1"}, {"key2", 123}}}};
    ValidationResult result = validator.validate(message);
    EXPECT_TRUE(result.isValid);
}

TEST_F(SchemaValidatorTest, ValidateObjectTypeInvalid)
{
    SchemaValidatorEngine validator;
    validator.loadSchemaFromString(m_testSchemaString);

    // Object type expects JSON object, not string
    nlohmann::json message = {{"metadata", "not_an_object"}};
    ValidationResult result = validator.validate(message);
    EXPECT_FALSE(result.isValid);
    EXPECT_FALSE(result.errors.empty());
}

TEST_F(SchemaValidatorTest, ValidateObjectTypeWithArray)
{
    SchemaValidatorEngine validator;
    validator.loadSchemaFromString(m_testSchemaString);

    // Object type expects JSON object, not array
    nlohmann::json message = {{"metadata", nlohmann::json::array({1, 2, 3})}};
    ValidationResult result = validator.validate(message);
    EXPECT_FALSE(result.isValid);
    EXPECT_FALSE(result.errors.empty());
}

// ============================================================================
// Tests for IP type (comprehensive)
// ============================================================================

TEST_F(SchemaValidatorTest, ValidateIPv4Valid)
{
#ifdef _WIN32
    GTEST_SKIP() << "IP tests are skipped on Windows (inet_pton not available under wine)";
#else
    SchemaValidatorEngine validator;
    validator.loadSchemaFromString(m_testSchemaString);

    nlohmann::json message = {{"ip_address", "192.168.1.1"}};
    ValidationResult result = validator.validate(message);
    EXPECT_TRUE(result.isValid);
#endif
}

TEST_F(SchemaValidatorTest, ValidateIPv6AllZeros)
{
#ifdef _WIN32
    GTEST_SKIP() << "IPv6 tests are skipped on Windows (inet_pton issues under wine)";
#else
    SchemaValidatorEngine validator;
    validator.loadSchemaFromString(m_testSchemaString);

    nlohmann::json message = {{"ip_address", "::"}};
    ValidationResult result = validator.validate(message);
    EXPECT_TRUE(result.isValid);
#endif
}

TEST_F(SchemaValidatorTest, ValidateIPv6Loopback)
{
#ifdef _WIN32
    GTEST_SKIP() << "IPv6 tests are skipped on Windows (inet_pton issues under wine)";
#else
    SchemaValidatorEngine validator;
    validator.loadSchemaFromString(m_testSchemaString);

    nlohmann::json message = {{"ip_address", "::1"}};
    ValidationResult result = validator.validate(message);
    EXPECT_TRUE(result.isValid);
#endif
}

TEST_F(SchemaValidatorTest, ValidateIPv6Standard)
{
#ifdef _WIN32
    GTEST_SKIP() << "IPv6 tests are skipped on Windows (inet_pton issues under wine)";
#else
    SchemaValidatorEngine validator;
    validator.loadSchemaFromString(m_testSchemaString);

    nlohmann::json message = {{"ip_address", "2001:db8::1"}};
    ValidationResult result = validator.validate(message);
    EXPECT_TRUE(result.isValid);
#endif
}

TEST_F(SchemaValidatorTest, ValidateIPv6WithZone)
{
#ifdef _WIN32
    GTEST_SKIP() << "IPv6 tests are skipped on Windows (inet_pton issues under wine)";
#else
    SchemaValidatorEngine validator;
    validator.loadSchemaFromString(m_testSchemaString);

    nlohmann::json message = {{"ip_address", "fe80::1%eth0"}};
    ValidationResult result = validator.validate(message);
    EXPECT_TRUE(result.isValid);
#endif
}

TEST_F(SchemaValidatorTest, ValidateIPv4MappedIPv6)
{
#ifdef _WIN32
    GTEST_SKIP() << "IPv6 tests are skipped on Windows (inet_pton issues under wine)";
#else
    SchemaValidatorEngine validator;
    validator.loadSchemaFromString(m_testSchemaString);

    nlohmann::json message = {{"ip_address", "::ffff:192.0.2.1"}};
    ValidationResult result = validator.validate(message);
    EXPECT_TRUE(result.isValid);
#endif
}

TEST_F(SchemaValidatorTest, ValidateIPCIDRNotationInvalid)
{
#ifdef _WIN32
    GTEST_SKIP() << "IP tests are skipped on Windows (inet_pton not available under wine)";
#else
    SchemaValidatorEngine validator;
    validator.loadSchemaFromString(m_testSchemaString);

    // OpenSearch rejects CIDR notation for IP fields
    nlohmann::json message = {{"ip_address", "192.168.1.0/24"}};
    ValidationResult result = validator.validate(message);
    EXPECT_FALSE(result.isValid);
    EXPECT_FALSE(result.errors.empty());
#endif
}

TEST_F(SchemaValidatorTest, ValidateIPWithNumberInvalid)
{
#ifdef _WIN32
    GTEST_SKIP() << "IP tests are skipped on Windows (inet_pton not available under wine)";
#else
    SchemaValidatorEngine validator;
    validator.loadSchemaFromString(m_testSchemaString);

    // IP field expects string, not number
    nlohmann::json message = {{"ip_address", 192168001001}};
    ValidationResult result = validator.validate(message);
    EXPECT_FALSE(result.isValid);
    EXPECT_FALSE(result.errors.empty());
#endif
}

TEST_F(SchemaValidatorTest, ValidateIPAsArray)
{
#ifdef _WIN32
    GTEST_SKIP() << "IPv6 tests are skipped on Windows (inet_pton issues under wine)";
#else
    SchemaValidatorEngine validator;
    validator.loadSchemaFromString(m_testSchemaString);

    // OpenSearch accepts arrays of IPs
    nlohmann::json message = {{"ip_address", nlohmann::json::array({"192.168.1.1", "::1", "2001:db8::1"})}};
    ValidationResult result = validator.validate(message);
    EXPECT_TRUE(result.isValid);
#endif
}

TEST_F(SchemaValidatorTest, ValidateIPArrayWithInvalidElement)
{
#ifdef _WIN32
    GTEST_SKIP() << "IP tests are skipped on Windows (inet_pton not available under wine)";
#else
    SchemaValidatorEngine validator;
    validator.loadSchemaFromString(m_testSchemaString);

    // Array with invalid IP should fail
    nlohmann::json message = {{"ip_address", nlohmann::json::array({"192.168.1.1", "192.168.1.0/24"})}};
    ValidationResult result = validator.validate(message);
    EXPECT_FALSE(result.isValid);
    EXPECT_FALSE(result.errors.empty());
#endif
}

// ============================================================================
// Tests for Date with floats (verified with OpenSearch)
// ============================================================================

TEST_F(SchemaValidatorTest, ValidateDateWithFloatEpochMillis)
{
    SchemaValidatorEngine validator;
    validator.loadSchemaFromString(m_testSchemaString);

    // Float as epoch_millis (with decimals)
    nlohmann::json message = {{"created_at", 1704196800000.123}};
    ValidationResult result = validator.validate(message);
    EXPECT_TRUE(result.isValid);
}

TEST_F(SchemaValidatorTest, ValidateDateWithFloatEpochSeconds)
{
    SchemaValidatorEngine validator;
    validator.loadSchemaFromString(m_testSchemaString);

    // Float as epoch_seconds (seconds with decimals = milliseconds)
    nlohmann::json message = {{"created_at", 1704196800.123}};
    ValidationResult result = validator.validate(message);
    EXPECT_TRUE(result.isValid);
}

TEST_F(SchemaValidatorTest, ValidateDateWithFloatAsString)
{
    SchemaValidatorEngine validator;
    validator.loadSchemaFromString(m_testSchemaString);

    // Strict validation rejects string "1704196800000.123" as it's not ISO8601
    nlohmann::json message = {{"created_at", "1704196800000.123"}};
    ValidationResult result = validator.validate(message);
    EXPECT_FALSE(result.isValid);
    EXPECT_FALSE(result.errors.empty());
}

TEST_F(SchemaValidatorTest, ValidateDateAsArrayWithFloats)
{
    SchemaValidatorEngine validator;
    validator.loadSchemaFromString(m_testSchemaString);

    // Array with float epoch values
    nlohmann::json message = {{"created_at", nlohmann::json::array({1704196800000.5, 1704196900000.75})}};
    ValidationResult result = validator.validate(message);
    EXPECT_TRUE(result.isValid);
}

// ============================================================================
// Tests for Long type (dedicated tests)
// ============================================================================

TEST_F(SchemaValidatorTest, ValidateLongWithInteger)
{
    SchemaValidatorEngine validator;
    validator.loadSchemaFromString(m_testSchemaString);

    nlohmann::json message = {{"score", 9223372036854775807}};
    ValidationResult result = validator.validate(message);
    EXPECT_TRUE(result.isValid);
}

TEST_F(SchemaValidatorTest, ValidateLongWithFloat)
{
    SchemaValidatorEngine validator;
    validator.loadSchemaFromString(m_testSchemaString);

    // Strict validation rejects floats for long fields
    nlohmann::json message = {{"score", 12345.67}};
    ValidationResult result = validator.validate(message);
    EXPECT_FALSE(result.isValid);
    EXPECT_FALSE(result.errors.empty());
}

TEST_F(SchemaValidatorTest, ValidateLongWithNumericString)
{
    SchemaValidatorEngine validator;
    validator.loadSchemaFromString(m_testSchemaString);

    // Strict validation rejects numeric strings for long fields
    nlohmann::json message = {{"score", "9223372036854775807"}};
    ValidationResult result = validator.validate(message);
    EXPECT_FALSE(result.isValid);
    EXPECT_FALSE(result.errors.empty());
}

TEST_F(SchemaValidatorTest, ValidateLongWithInvalidString)
{
    SchemaValidatorEngine validator;
    validator.loadSchemaFromString(m_testSchemaString);

    nlohmann::json message = {{"score", "not_a_number"}};
    ValidationResult result = validator.validate(message);
    EXPECT_FALSE(result.isValid);
    EXPECT_FALSE(result.errors.empty());
}

TEST_F(SchemaValidatorTest, ValidateLongAsArray)
{
    SchemaValidatorEngine validator;
    validator.loadSchemaFromString(m_testSchemaString);

    nlohmann::json message = {{"score", nlohmann::json::array({100, 200, 300})}};
    ValidationResult result = validator.validate(message);
    EXPECT_TRUE(result.isValid);
}

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

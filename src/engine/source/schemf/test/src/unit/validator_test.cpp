#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "validator.hpp"
#include <base/json.hpp>
#include <schemf/schema.hpp>

using namespace schemf;
using namespace testing;

// ---------------------------------------------------------------------------
// Assertion helpers
// ---------------------------------------------------------------------------

#define EXPECT_OK(res) ASSERT_FALSE(base::isError(res)) << "Unexpected error: " << base::getError(res).message

#define EXPECT_ERR(res, substr)                                                                                        \
    do                                                                                                                 \
    {                                                                                                                  \
        ASSERT_TRUE(base::isError(res));                                                                               \
        EXPECT_THAT(base::getError(res).message, HasSubstr(substr));                                                   \
    } while (0)

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

class ValidatorTest : public ::testing::Test
{
protected:
    std::unique_ptr<Schema> m_schema;
    std::unique_ptr<Schema::Validator> m_validator;

    void SetUp() override
    {
        m_schema = std::make_unique<Schema>();
        m_schema->addField("source.ip", Field::Parameters {.type = Type::IP});
        m_schema->addField("source.port", Field::Parameters {.type = Type::INTEGER});
        m_schema->addField("event.kind", Field::Parameters {.type = Type::KEYWORD});
        m_schema->addField("event.duration", Field::Parameters {.type = Type::LONG});
        m_schema->addField("host.name", Field::Parameters {.type = Type::TEXT});
        m_schema->addField("@timestamp", Field::Parameters {.type = Type::DATE});
        m_schema->addField("event.tags", Field::Parameters {.type = Type::KEYWORD});
        m_schema->addField("rank.feature", Field::Parameters {.type = Type::RANK_FEATURE});
        m_schema->addField("geo.location", Field::Parameters {.type = Type::GEO_POINT});
        m_validator = std::make_unique<Schema::Validator>(*m_schema);
    }
};

class ValidatorEmptySchemaTest : public ::testing::Test
{
protected:
    std::unique_ptr<Schema> m_schema;
    std::unique_ptr<Schema::Validator> m_validator;

    void SetUp() override
    {
        m_schema = std::make_unique<Schema>();
        m_validator = std::make_unique<Schema::Validator>(*m_schema);
    }
};

// ---------------------------------------------------------------------------
// validateTargetField
// ---------------------------------------------------------------------------

TEST_F(ValidatorTest, ValidateTargetField_RootIsTemporary)
{
    auto res = m_validator->validateTargetField(DotPath {});
    EXPECT_OK(res);
    EXPECT_EQ(base::getResponse(res), TargetFieldKind::TEMPORARY);
}

TEST_F(ValidatorTest, ValidateTargetField_UnderscoreRootIsTemporary)
{
    auto res = m_validator->validateTargetField(DotPath {"_tmp.foo"});
    EXPECT_OK(res);
    EXPECT_EQ(base::getResponse(res), TargetFieldKind::TEMPORARY);
}

TEST_F(ValidatorTest, ValidateTargetField_SchemaField)
{
    auto res = m_validator->validateTargetField(DotPath {"source.ip"});
    EXPECT_OK(res);
    EXPECT_EQ(base::getResponse(res), TargetFieldKind::SCHEMA);
}

TEST_F(ValidatorTest, ValidateTargetField_NotInSchemaErrors)
{
    auto res = m_validator->validateTargetField(DotPath {"not.a.field"});
    EXPECT_ERR(res, "not defined in WCS schema");
}

TEST_F(ValidatorTest, ValidateTargetField_IncompatibleTypeStillSchema)
{
    auto res = m_validator->validateTargetField(DotPath {"rank.feature"});
    EXPECT_OK(res);
    EXPECT_EQ(base::getResponse(res), TargetFieldKind::SCHEMA);
}

// ---------------------------------------------------------------------------
// ValueToken
// ---------------------------------------------------------------------------

TEST_F(ValidatorTest, ValidateValue_MatchingType)
{
    auto token = ValueToken::create(json::Json {"42"});
    auto res = m_validator->validate(DotPath {"source.port"}, token);
    EXPECT_OK(res);
}

TEST_F(ValidatorTest, ValidateValue_TypeMismatch)
{
    auto token = ValueToken::create(json::Json {"\"abc\""});
    auto res = m_validator->validate(DotPath {"source.port"}, token);
    EXPECT_ERR(res, "value validation failed");
    EXPECT_THAT(base::getError(res).message, HasSubstr("integer"));
}

TEST_F(ValidatorTest, ValidateValue_RightJsonTypeButValidatorFails)
{
    auto token = ValueToken::create(json::Json {"\"not-an-ip\""});
    auto res = m_validator->validate(DotPath {"source.ip"}, token);
    EXPECT_ERR(res, "value validation failed");
}

// ---------------------------------------------------------------------------
// STypeToken
// ---------------------------------------------------------------------------

TEST_F(ValidatorTest, ValidateSType_ExactMatch)
{
    auto token = STypeToken::create(Type::IP);
    auto res = m_validator->validate(DotPath {"source.ip"}, token);
    EXPECT_OK(res);
    EXPECT_FALSE(base::getResponse(res).needsRuntimeValidation());
}

TEST_F(ValidatorTest, ValidateSType_CompatibleSafe)
{
    // DATE field ← KEYWORD token: compatible with runtime validation (true)
    auto token = STypeToken::create(Type::KEYWORD);
    auto res = m_validator->validate(DotPath {"@timestamp"}, token);
    EXPECT_OK(res);
    EXPECT_TRUE(base::getResponse(res).needsRuntimeValidation());
}

TEST_F(ValidatorTest, ValidateSType_CompatibleUnsafe)
{
    // KEYWORD field ← TEXT token: compatible, no runtime validation (false)
    auto token = STypeToken::create(Type::TEXT);
    auto res = m_validator->validate(DotPath {"event.kind"}, token);
    EXPECT_OK(res);
    EXPECT_FALSE(base::getResponse(res).needsRuntimeValidation());
}

TEST_F(ValidatorTest, ValidateSType_NotCompatible)
{
    // IP field ← INTEGER token: incompatible
    auto token = STypeToken::create(Type::INTEGER);
    auto res = m_validator->validate(DotPath {"source.ip"}, token);
    EXPECT_ERR(res, "incompatible schema type");
}

// ---------------------------------------------------------------------------
// JTypeToken
// ---------------------------------------------------------------------------

TEST_F(ValidatorTest, ValidateJType_Match)
{
    // KEYWORD field expects JSON String → match
    auto token = JTypeToken::create(json::Json::Type::String);
    auto res = m_validator->validate(DotPath {"event.kind"}, token);
    EXPECT_OK(res);
    EXPECT_TRUE(base::getResponse(res).needsRuntimeValidation());
}

TEST_F(ValidatorTest, ValidateJType_Mismatch)
{
    // INTEGER field expects JSON Number, not String
    auto token = JTypeToken::create(json::Json::Type::String);
    auto res = m_validator->validate(DotPath {"source.port"}, token);
    EXPECT_ERR(res, "JSON type");
}

// ---------------------------------------------------------------------------
// Array wrapper (asArray)
// ---------------------------------------------------------------------------

TEST_F(ValidatorTest, ValidateValue_ArrayAllItemsValid)
{
    auto token = ValueToken::create(json::Json {R"(["a","b"])"});
    auto res = m_validator->validate(DotPath {"event.tags"}, token);
    EXPECT_OK(res);
}

TEST_F(ValidatorTest, ValidateValue_ArrayOneItemInvalid)
{
    auto token = ValueToken::create(json::Json {R"([1, "bad", 3])"});
    auto res = m_validator->validate(DotPath {"source.port"}, token);
    EXPECT_ERR(res, "value validation failed");
}

TEST_F(ValidatorTest, ValidateValue_ArrayWrapperRejectsScalar)
{
    // event.tags is KEYWORD (string), passing numeric scalar should fail
    auto token = ValueToken::create(json::Json {"123"});
    auto res = m_validator->validate(DotPath {"event.tags"}, token);
    EXPECT_ERR(res, "value validation failed");
}

// ---------------------------------------------------------------------------
// Dispatcher edge cases
// ---------------------------------------------------------------------------

TEST_F(ValidatorEmptySchemaTest, Validate_FieldNotInSchema_Errors)
{
    auto token = JTypeToken::create(json::Json::Type::String);
    auto res = m_validator->validate(DotPath {"foo.bar"}, token);
    EXPECT_ERR(res, "not defined in WCS schema");
}

TEST_F(ValidatorTest, Validate_TemporaryShortCircuits)
{
    auto token = JTypeToken::create(json::Json::Type::String);
    auto res = m_validator->validate(DotPath {"_x.y"}, token);
    EXPECT_OK(res);
    EXPECT_FALSE(base::getResponse(res).needsRuntimeValidation());
}

TEST_F(ValidatorTest, Validate_NullToken_RuntimeOnly)
{
    auto res = m_validator->validate(DotPath {"source.ip"}, runtimeValidation());
    EXPECT_OK(res);
    EXPECT_TRUE(base::getResponse(res).needsRuntimeValidation());
}

TEST_F(ValidatorTest, Validate_BaseTokenDispatchReturnsRuntimeValidator)
{
    // BaseToken is not JType/SType/Value — falls through to the last branch
    // which returns a runtime validator for schema fields
    auto token = elementValidationToken();
    auto res = m_validator->validate(DotPath {"source.ip"}, token);
    EXPECT_OK(res);
    EXPECT_TRUE(base::getResponse(res).needsRuntimeValidation());
}

TEST_F(ValidatorTest, ValidateJType_IncompatibleField_Fails)
{
    // RANK_FEATURE maps to Unknown JSON type — no JTypeToken can match
    auto token = JTypeToken::create(json::Json::Type::String);
    auto res = m_validator->validate(DotPath {"rank.feature"}, token);
    EXPECT_ERR(res, "JSON type");
}

// ---------------------------------------------------------------------------
// GEO_POINT — JTypeToken dispatch
// ---------------------------------------------------------------------------

TEST_F(ValidatorTest, GeoPoint_JType_AcceptsObject)
{
    auto token = JTypeToken::create(json::Json::Type::Object);
    auto res = m_validator->validate(DotPath {"geo.location"}, token);
    EXPECT_OK(res);
    EXPECT_TRUE(base::getResponse(res).needsRuntimeValidation());
}

TEST_F(ValidatorTest, GeoPoint_JType_AcceptsString)
{
    auto token = JTypeToken::create(json::Json::Type::String);
    auto res = m_validator->validate(DotPath {"geo.location"}, token);
    EXPECT_OK(res);
    EXPECT_TRUE(base::getResponse(res).needsRuntimeValidation());
}

TEST_F(ValidatorTest, GeoPoint_JType_RejectsNumber)
{
    auto token = JTypeToken::create(json::Json::Type::Number);
    auto res = m_validator->validate(DotPath {"geo.location"}, token);
    EXPECT_ERR(res, "JSON type");
    EXPECT_THAT(base::getError(res).message, HasSubstr("object"));
    EXPECT_THAT(base::getError(res).message, HasSubstr("string"));
}

TEST_F(ValidatorTest, GeoPoint_Regression_IntegerRejectsString)
{
    auto token = JTypeToken::create(json::Json::Type::String);
    auto res = m_validator->validate(DotPath {"source.port"}, token);
    EXPECT_ERR(res, "JSON type");
}

// ---------------------------------------------------------------------------
// GEO_POINT — ValueToken build-time validation
// ---------------------------------------------------------------------------

TEST_F(ValidatorTest, GeoPoint_Value_ValidObject)
{
    auto token = ValueToken::create(json::Json {R"({"lat":40.71,"lon":-74.00})"});
    auto res = m_validator->validate(DotPath {"geo.location"}, token);
    EXPECT_OK(res);
}

TEST_F(ValidatorTest, GeoPoint_Value_ValidString)
{
    auto token = ValueToken::create(json::Json {"\"40.71,-74.00\""});
    auto res = m_validator->validate(DotPath {"geo.location"}, token);
    EXPECT_OK(res);
}

TEST_F(ValidatorTest, GeoPoint_Value_ValidArray)
{
    auto token = ValueToken::create(json::Json {"[-74.00,40.71]"});
    auto res = m_validator->validate(DotPath {"geo.location"}, token);
    EXPECT_OK(res);
}

TEST_F(ValidatorTest, GeoPoint_Value_InvalidString)
{
    auto token = ValueToken::create(json::Json {"\"not_geo\""});
    auto res = m_validator->validate(DotPath {"geo.location"}, token);
    EXPECT_ERR(res, "value validation failed");
}

// ---------------------------------------------------------------------------
// GEO_POINT — getJsonTypes
// ---------------------------------------------------------------------------

TEST_F(ValidatorTest, GeoPoint_GetJsonTypes_ContainsObjectAndString)
{
    auto types = m_validator->getJsonTypes(DotPath {"geo.location"});
    EXPECT_TRUE(types.count(json::Json::Type::Object));
    EXPECT_TRUE(types.count(json::Json::Type::String));
    EXPECT_FALSE(types.count(json::Json::Type::Number));
}

// ---------------------------------------------------------------------------
// GEO_POINT — JTypeToken: Array token construction, and runtime validator
//             behaviour when the actual value is an array
// ---------------------------------------------------------------------------

// JtypeObject with [lon, lat]
// The geo validator (skipArrayWrap=true) must accept it via isGeoArray().
TEST_F(ValidatorTest, GeoPoint_JType_Object_RuntimeValidator_AcceptsLonLatArray)
{
    auto token = JTypeToken::create(json::Json::Type::Object);
    auto res = m_validator->validate(DotPath {"geo.location"}, token);
    EXPECT_OK(res);
    EXPECT_TRUE(base::getResponse(res).needsRuntimeValidation());

    auto validator = base::getResponse(res).getValidator();
    json::Json arrValue {"[-74.00,40.71]"};
    EXPECT_FALSE(base::isError(validator(arrValue)));
}

// String with [lon, lat]
TEST_F(ValidatorTest, GeoPoint_JType_String_RuntimeValidator_AcceptsLonLatArray)
{
    auto token = JTypeToken::create(json::Json::Type::String);
    auto res = m_validator->validate(DotPath {"geo.location"}, token);
    EXPECT_OK(res);
    EXPECT_TRUE(base::getResponse(res).needsRuntimeValidation());

    auto validator = base::getResponse(res).getValidator();
    json::Json arrValue {"[-74.00,40.71]"};
    EXPECT_FALSE(base::isError(validator(arrValue)));
}

// Ojects with "array of geo_points".
TEST_F(ValidatorTest, GeoPoint_JType_Object_RuntimeValidator_AcceptsArrayOfGeoObjects)
{
    auto token = JTypeToken::create(json::Json::Type::Object);
    auto res = m_validator->validate(DotPath {"geo.location"}, token);
    EXPECT_OK(res);

    auto validator = base::getResponse(res).getValidator();
    json::Json arrValue {R"([{"lat":40.71,"lon":-74.00},{"lat":51.50,"lon":-0.12}])"};
    EXPECT_FALSE(base::isError(validator(arrValue)));
}

// Array whose elements are geo_point strings — accepted.
TEST_F(ValidatorTest, GeoPoint_JType_Object_RuntimeValidator_AcceptsArrayOfGeoStrings)
{
    auto token = JTypeToken::create(json::Json::Type::Object);
    auto res = m_validator->validate(DotPath {"geo.location"}, token);
    EXPECT_OK(res);

    auto validator = base::getResponse(res).getValidator();
    json::Json arrValue {R"(["40.71,-74.00","51.50,-0.12"])"};
    EXPECT_FALSE(base::isError(validator(arrValue)));
}

// Array that is neither a valid [lon,lat] pair nor an array of valid, rejected.
TEST_F(ValidatorTest, GeoPoint_JType_Object_RuntimeValidator_RejectsInvalidArray)
{
    auto token = JTypeToken::create(json::Json::Type::Object);
    auto res = m_validator->validate(DotPath {"geo.location"}, token);
    EXPECT_OK(res);

    auto validator = base::getResponse(res).getValidator();
    json::Json arrValue {R"(["not_geo","also_not_geo"])"};
    EXPECT_TRUE(base::isError(validator(arrValue)));
}

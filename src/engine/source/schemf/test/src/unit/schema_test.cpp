#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <base/json.hpp>
#include <schemf/schema.hpp>

using namespace schemf;
using namespace testing;

// ---------------------------------------------------------------------------
// addField — error paths not covered by component tests
// ---------------------------------------------------------------------------

TEST(SchemaUnitTest, AddField_EmptyPathThrows)
{
    Schema s;
    EXPECT_THROW(s.addField(DotPath {}, Field::Parameters {.type = Type::TEXT}), std::invalid_argument);
}

// ---------------------------------------------------------------------------
// removeField — error paths not covered by component tests
// ---------------------------------------------------------------------------

TEST(SchemaUnitTest, RemoveField_EmptyPathThrows)
{
    Schema s;
    EXPECT_THROW(s.removeField(DotPath {}), std::runtime_error);
}

TEST(SchemaUnitTest, RemoveField_NonExistentFieldThrows)
{
    Schema s;
    EXPECT_THROW(s.removeField("no.such.field"), std::runtime_error);
}

// ---------------------------------------------------------------------------
// hasField — edge cases not covered by component tests
// ---------------------------------------------------------------------------

TEST(SchemaUnitTest, HasField_RootReturnsFalse)
{
    Schema s;
    EXPECT_FALSE(s.hasField(DotPath {}));
}

// ---------------------------------------------------------------------------
// getType — error path not covered by component tests
// ---------------------------------------------------------------------------

TEST(SchemaUnitTest, GetType_MissingFieldThrows)
{
    Schema s;
    EXPECT_THROW(s.getType("no.field"), std::runtime_error);
}

TEST(SchemaUnitTest, GetJsonType_MissingFieldThrows)
{
    Schema s;
    EXPECT_THROW(s.getJsonType("no.field"), std::runtime_error);
}

// ---------------------------------------------------------------------------
// load — paths not exercised by component tests
// (component test always wraps fields in {"fields": ...}, never tests bare failures)
// ---------------------------------------------------------------------------

TEST(SchemaUnitTest, Load_NonObjectJsonThrows)
{
    Schema s;
    EXPECT_THROW(s.load(json::Json {"[]"}), std::runtime_error);
}

TEST(SchemaUnitTest, Load_MissingFieldsKeyThrows)
{
    Schema s;
    EXPECT_THROW(s.load(json::Json {"{}"}), std::runtime_error);
}

TEST(SchemaUnitTest, Load_FieldEntryMissingTypeKeyThrows)
{
    // entryToField requires a "/type" key; missing it throws
    Schema s;
    json::Json j {R"({"fields":{"f":{"nottype":"keyword"}}})"};
    EXPECT_THROW(s.load(j), std::runtime_error);
}

TEST(SchemaUnitTest, Load_FieldEntryNotObjectThrows)
{
    // entryToField rejects non-object entries
    Schema s;
    json::Json j {R"({"fields":{"f":"keyword"}})"};
    EXPECT_THROW(s.load(j), std::runtime_error);
}

// ---------------------------------------------------------------------------
// validate / validateTargetField — wrappers not tested in component tests
// ---------------------------------------------------------------------------

TEST(SchemaUnitTest, ValidateTargetField_DelegatesCorrectly)
{
    Schema s;
    s.addField("src.ip", Field::Parameters {.type = Type::IP});

    auto res = s.validateTargetField(DotPath {"src.ip"});
    ASSERT_FALSE(base::isError(res));
    EXPECT_EQ(base::getResponse(res), TargetFieldKind::SCHEMA);
}

TEST(SchemaUnitTest, Validate_WithTokenDelegatesCorrectly)
{
    Schema s;
    s.addField("src.ip", Field::Parameters {.type = Type::IP});

    auto token = STypeToken::create(Type::IP);
    auto res = s.validate(DotPath {"src.ip"}, token);
    ASSERT_FALSE(base::isError(res));
    EXPECT_FALSE(base::getResponse(res).needsRuntimeValidation());
}

TEST(SchemaUnitTest, Validate_WithJsonValueDelegatesCorrectly)
{
    Schema s;
    s.addField("src.ip", Field::Parameters {.type = Type::IP});

    auto res = s.validate(DotPath {"src.ip"}, json::Json {"\"192.168.0.1\""});
    EXPECT_FALSE(base::isError(res));
}

TEST(SchemaUnitTest, Validate_WithJsonValueInvalidFails)
{
    Schema s;
    s.addField("src.ip", Field::Parameters {.type = Type::IP});

    auto res = s.validate(DotPath {"src.ip"}, json::Json {"\"not-an-ip\""});
    EXPECT_TRUE(base::isError(res));
}

#include <gtest/gtest.h>

#include <fmt/format.h>

#include <schemf/mockSchema.hpp>
#include <schemf/schema.hpp>

using namespace schemf;

using ParamsTuple = std::tuple<std::vector<std::tuple<std::string, Field::Parameters>>, bool>;
class Params : public ::testing::TestWithParam<ParamsTuple>
{
};

TEST_P(Params, AddField)
{
    auto [inputs, shouldPass] = GetParam();
    Schema schema;
    if (shouldPass)
    {
        for (auto [name, field] : inputs)
        {
            ASSERT_NO_THROW(schema.addField(name, field));
        }
    }
    else
    {
        try
        {
            for (auto [name, field] : inputs)
            {
                schema.addField(name, field);
            }
        }
        catch (const std::exception& e)
        {
            SUCCEED();
            return;
        }
        FAIL() << "Expected exception";
    }
}

TEST_P(Params, Get)
{
    auto [inputs, shouldPass] = GetParam();
    if (shouldPass)
    {
        Schema schema;
        for (auto [name, field] : inputs)
        {
            schema.addField(name, field);
            ASSERT_TRUE(schema.hasField(name));
            ASSERT_EQ(schema.getType(name), Field(field).type());
        }
    }
}

TEST_P(Params, Remove)
{
    auto [inputs, shouldPass] = GetParam();
    if (shouldPass)
    {
        Schema schema;
        for (auto [name, field] : inputs)
        {
            schema.addField(name, field);
        }

        // One at a time
        for (auto it = inputs.rbegin(); it != inputs.rend(); ++it)
        {
            auto [name, field] = *it;
            ASSERT_NO_THROW(schema.removeField(name));
            try
            {
                ASSERT_FALSE(schema.hasField(name));
            }
            catch (const std::exception& e)
            {
                SUCCEED();
            }
        }
    }
}

INSTANTIATE_TEST_SUITE_P(SchemaTest,
                         Params,
                         ::testing::Values(
                                           // Basic types
                                           ParamsTuple({{"a", {Type::TEXT}}}, true),
                                           ParamsTuple({{"a", {Type::WILDCARD}}}, true),
                                           ParamsTuple({{"a", {Type::INTEGER}}}, true),
                                           ParamsTuple({{"a", {Type::ERROR}}}, false),
                                           ParamsTuple({{"a", {Type::OBJECT}}}, true),
                                           ParamsTuple({{"a", {Type::BOOLEAN}}}, true),
                                           // Numeric types
                                           ParamsTuple({{"a", {Type::BYTE}}}, true),
                                           ParamsTuple({{"a", {Type::SHORT}}}, true),
                                           ParamsTuple({{"a", {Type::LONG}}}, true),
                                           ParamsTuple({{"a", {Type::FLOAT}}}, true),
                                           ParamsTuple({{"a", {Type::HALF_FLOAT}}}, true),
                                           ParamsTuple({{"a", {Type::SCALED_FLOAT}}}, true),
                                           ParamsTuple({{"a", {Type::DOUBLE}}}, true),
                                           ParamsTuple({{"a", {Type::UNSIGNED_LONG}}}, true),
                                           // String types
                                           ParamsTuple({{"a", {Type::KEYWORD}}}, true),
                                           ParamsTuple({{"a", {Type::MATCH_ONLY_TEXT}}}, true),
                                           ParamsTuple({{"a", {Type::CONSTANT_KEYWORD}}}, true),
                                           // Date types
                                           ParamsTuple({{"a", {Type::DATE}}}, true),
                                           ParamsTuple({{"a", {Type::DATE_NANOS}}}, true),
                                           // Special types
                                           ParamsTuple({{"a", {Type::IP}}}, true),
                                           ParamsTuple({{"a", {Type::BINARY}}}, true),
                                           ParamsTuple({{"a", {Type::GEO_POINT}}}, true),
                                           ParamsTuple({{"a", {Type::COMPLETION}}}, true),
                                           ParamsTuple({{"a", {Type::SEARCH_AS_YOU_TYPE}}}, true),
                                           ParamsTuple({{"a", {Type::TOKEN_COUNT}}}, true),
                                           ParamsTuple({{"a", {Type::SEMANTIC}}}, true),
                                           // Object-like types
                                           ParamsTuple({{"a", {Type::NESTED}}}, true),
                                           ParamsTuple({{"a", {Type::FLAT_OBJECT}}}, true),
                                           // Conflict detection tests
                                           ParamsTuple({{"a", {Type::OBJECT}}, {"a", {Type::BOOLEAN}}}, false),
                                           ParamsTuple({{"a", {Type::TEXT}}, {"a.b", {Type::TEXT}}}, false),
                                           ParamsTuple({{"a", {Type::WILDCARD}}, {"a.b", {Type::WILDCARD}}}, false),
                                           ParamsTuple({{"a", {Type::OBJECT}}, {"a.b", {Type::TEXT}}}, true),
                                           // Nested path tests
                                           ParamsTuple({{"a.b.c.d", {Type::BOOLEAN}}}, true),
                                           ParamsTuple({{"a.b.c.d", {Type::INTEGER}}, {"a.b", {Type::TEXT}}}, false),
                                           ParamsTuple({{"a.b.c.d", {Type::INTEGER}}, {"a.b.a", {Type::TEXT}}}, true),
                                           // Mixed type tests
                                           ParamsTuple({{"a", {Type::NESTED}}, {"a.b", {Type::KEYWORD}}}, true),
                                           ParamsTuple({{"a", {Type::FLAT_OBJECT}}, {"a.b", {Type::LONG}}}, true),
                                           ParamsTuple({{"num", {Type::BYTE}}, {"str", {Type::KEYWORD}}, {"obj", {Type::OBJECT}}}, true),
                                           ParamsTuple({{"date", {Type::DATE}}, {"ip", {Type::IP}}, {"geo", {Type::GEO_POINT}}}, true)));

using LoadTuple = std::tuple<std::string, bool>;
class LoadJson : public ::testing::TestWithParam<LoadTuple>
{
};

TEST_P(LoadJson, Loads)
{
    const auto& [jsonStr, shouldPass] = GetParam();
    json::Json json(fmt::format(R"({{"fields":{}}})", jsonStr).c_str());
    Schema schema {};

    if (shouldPass)
    {
        ASSERT_NO_THROW(schema.load(json));
        auto jsonObj = json.getObject("/fields").value();
        for (const auto& [key, value] : jsonObj)
        {
            ASSERT_TRUE(schema.hasField(key));
            ASSERT_EQ(schema.getType(key), strToType(value.getString("/type").value().c_str()));
        }
    }
    else
    {
        ASSERT_THROW(schema.load(json), std::runtime_error);
    }
}

INSTANTIATE_TEST_SUITE_P(SchemaTest,
                         LoadJson,
                         ::testing::Values(
                                           // Basic string types
                                           LoadTuple(R"({"a": {"type": "text"}})", true),
                                           LoadTuple(R"({"a": {"type": "wildcard"}})", true),
                                           LoadTuple(R"({"a": {"type": "keyword"}})", true),
                                           LoadTuple(R"({"a": {"type": "match_only_text"}})", true),
                                           LoadTuple(R"({"a": {"type": "constant_keyword"}})", true),
                                           // Numeric types
                                           LoadTuple(R"({"a": {"type": "integer"}})", true),
                                           LoadTuple(R"({"a": {"type": "byte"}})", true),
                                           LoadTuple(R"({"a": {"type": "short"}})", true),
                                           LoadTuple(R"({"a": {"type": "long"}})", true),
                                           LoadTuple(R"({"a": {"type": "float"}})", true),
                                           LoadTuple(R"({"a": {"type": "half_float"}})", true),
                                           LoadTuple(R"({"a": {"type": "scaled_float"}})", true),
                                           LoadTuple(R"({"a": {"type": "double"}})", true),
                                           LoadTuple(R"({"a": {"type": "unsigned_long"}})", true),
                                           // Date types
                                           LoadTuple(R"({"a": {"type": "date"}})", true),
                                           LoadTuple(R"({"a": {"type": "date_nanos"}})", true),
                                           // Special types
                                           LoadTuple(R"({"a": {"type": "ip"}})", true),
                                           LoadTuple(R"({"a": {"type": "binary"}})", true),
                                           LoadTuple(R"({"a": {"type": "geo_point"}})", true),
                                           LoadTuple(R"({"a": {"type": "completion"}})", true),
                                           LoadTuple(R"({"a": {"type": "search_as_you_type"}})", true),
                                           LoadTuple(R"({"a": {"type": "token_count"}})", true),
                                           LoadTuple(R"({"a": {"type": "semantic"}})", true),
                                           // Object types
                                           LoadTuple(R"({"a": {"type": "object"}})", true),
                                           LoadTuple(R"({"a": {"type": "nested"}})", true),
                                           LoadTuple(R"({"a": {"type": "flat_object"}})", true),
                                           LoadTuple(R"({"a": {"type": "boolean"}})", true),
                                           // Invalid types
                                           LoadTuple(R"({"a": {"type": "null"}})", false),
                                           LoadTuple(R"({"a": {"type": "array"}})", false),
                                           // Conflict tests
                                           LoadTuple(R"({"a": {"type": "keyword"}, "a.b": {"type": "keyword"}})", false),
                                           // Array tests
                                           LoadTuple(R"({"a": {"type": "text", "array": true}})", true),
                                           LoadTuple(R"({"a": {"type": "keyword", "array": true}})", true),
                                           LoadTuple(R"({"a": {"type": "long", "array": true}})", true),
                                           LoadTuple(R"({"a": {"type": "object", "array": true}})", true),
                                           LoadTuple(R"({"a": {"type": "boolean", "array": true}})", true),
                                           LoadTuple(R"({"a": {"type": "array", "array": true}})", false),
                                           LoadTuple(R"({"a": {"type": "byte", "array": true}})", true),
                                           LoadTuple(R"({"a": {"type": "short", "array": true}})", true),
                                           LoadTuple(R"({"a": {"type": "float", "array": true}})", true),
                                           LoadTuple(R"({"a": {"type": "double", "array": true}})", true),
                                           LoadTuple(R"({"a": {"type": "date", "array": true}})", true),
                                           LoadTuple(R"({"a": {"type": "ip", "array": true}})", true),
                                           LoadTuple(R"({"a": {"type": "geo_point", "array": true}})", true),
                                           LoadTuple(R"({"a": {"type": "nested", "array": true}})", true),
                                           // Invalid format tests
                                           LoadTuple(R"({"a.": {"type": "keyword"}})", false),
                                           LoadTuple(R"({"a": {}})", false),
                                           LoadTuple(R"({"a": [{"type": "text"}]})", false),
                                           LoadTuple(R"([{"a": {"type": "keyword"}}])", false)));

TEST(SchemaTest, ArrayItem)
{
    Schema schema;
    schema.addField("a", {Type::INTEGER});
    ASSERT_TRUE(schema.hasField("a.0"));
    ASSERT_EQ(schema.getJsonType("a.0"), json::Json::Type::Number);
    ASSERT_FALSE(schema.hasField("a.n"));
    auto itemType = schema.getType("a.0");
    ASSERT_EQ(itemType, Type::INTEGER);
    ASSERT_THROW(schema.getType("a.n"), std::runtime_error);
    ASSERT_THROW(schema.getJsonType("a.n"), std::runtime_error);
}

TEST(SchemaTest, ArrayItem_NumericTypes)
{
    std::vector<Type> numericTypes = {Type::BYTE, Type::SHORT, Type::INTEGER, Type::LONG,
                                       Type::FLOAT, Type::HALF_FLOAT, Type::SCALED_FLOAT,
                                       Type::DOUBLE, Type::UNSIGNED_LONG};

    for (auto type : numericTypes)
    {
        Schema schema;
        schema.addField("num", {type});
        ASSERT_TRUE(schema.hasField("num.0"));
        ASSERT_EQ(schema.getJsonType("num.0"), json::Json::Type::Number);
        ASSERT_EQ(schema.getType("num.0"), type);
    }
}

TEST(SchemaTest, ArrayItem_StringTypes)
{
    std::vector<Type> stringTypes = {Type::KEYWORD, Type::TEXT, Type::MATCH_ONLY_TEXT,
                                      Type::WILDCARD, Type::CONSTANT_KEYWORD, Type::DATE,
                                      Type::DATE_NANOS, Type::IP, Type::BINARY, Type::COMPLETION,
                                      Type::SEARCH_AS_YOU_TYPE, Type::SEMANTIC};

    for (auto type : stringTypes)
    {
        Schema schema;
        schema.addField("str", {type});
        ASSERT_TRUE(schema.hasField("str.0"));
        ASSERT_EQ(schema.getJsonType("str.0"), json::Json::Type::String);
        ASSERT_EQ(schema.getType("str.0"), type);
    }
}

TEST(SchemaTest, ArrayItem_ObjectTypes)
{
    std::vector<Type> objectTypes = {Type::OBJECT, Type::NESTED, Type::FLAT_OBJECT, Type::GEO_POINT};

    for (auto type : objectTypes)
    {
        Schema schema;
        schema.addField("obj", {type});
        ASSERT_TRUE(schema.hasField("obj.0"));
        ASSERT_EQ(schema.getJsonType("obj.0"), json::Json::Type::Object);
        ASSERT_EQ(schema.getType("obj.0"), type);
    }
}

TEST(SchemaTest, ArrayItem_Boolean)
{
    Schema schema;
    schema.addField("flags", {Type::BOOLEAN});
    ASSERT_TRUE(schema.hasField("flags.0"));
    ASSERT_EQ(schema.getJsonType("flags.0"), json::Json::Type::Boolean);
    ASSERT_EQ(schema.getType("flags.0"), Type::BOOLEAN);
}

TEST(SchemaTest, HasField_UnknownLeafUnderKnownContainer_ReturnsFalse)
{
    Schema schema;
    schema.addField("dns", {Type::OBJECT});

    ASSERT_NO_THROW({
        bool exists = schema.hasField("dns.test");
        ASSERT_FALSE(exists);
    });
}

TEST(SchemaTest, HasField_KnownECSLeaf_ReturnsTrue)
{
    Schema schema;
    schema.addField("dns", {Type::OBJECT});
    schema.addField("dns.answers", {Type::OBJECT});        // plain object field
    schema.addField("dns.answers.class", {Type::KEYWORD}); // leaf field

    ASSERT_TRUE(schema.hasField("dns.answers.class"));
}

TEST(SchemaTest, HasField_UnknownTopLevel_ReturnsFalse)
{
    Schema schema;

    ASSERT_NO_THROW({
        bool exists = schema.hasField("qwer.test");
        ASSERT_FALSE(exists);
    });
}

TEST(SchemaTest, HasField_UnknownUnderScalar_ReturnsFalse)
{
    Schema schema;
    schema.addField("event.code", {Type::KEYWORD}); // scalar
    ASSERT_NO_THROW({ EXPECT_FALSE(schema.hasField("event.code.foo")); });
}

TEST(SchemaTest, HasField_UnknownChildUnderArrayItem_ReturnsFalse)
{
    Schema schema;
    schema.addField("dns", {Type::OBJECT});
    schema.addField("dns.answers", {Type::OBJECT});
    ASSERT_TRUE(schema.hasField("dns.answers.0"));
    ASSERT_NO_THROW({ EXPECT_FALSE(schema.hasField("dns.answers.0.foo")); });
}

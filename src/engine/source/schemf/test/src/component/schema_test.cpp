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
                         ::testing::Values(ParamsTuple({{"a", {Type::TEXT}}}, true),
                                           ParamsTuple({{"a", {Type::WILDCARD}}}, true),
                                           ParamsTuple({{"a", {Type::INTEGER}}}, true),
                                           ParamsTuple({{"a", {Type::ERROR}}}, false),
                                           ParamsTuple({{"a", {Type::OBJECT}}}, true),
                                           ParamsTuple({{"a", {.isArray = true}}}, false),
                                           ParamsTuple({{"a", {Type::INTEGER, true}}}, true),
                                           ParamsTuple({{"a", {Type::BOOLEAN}}}, true),
                                           ParamsTuple({{"a", {Type::OBJECT}}, {"a", {Type::BOOLEAN}}}, false),
                                           ParamsTuple({{"a", {Type::TEXT}}, {"a.b", {Type::TEXT}}}, false),
                                           ParamsTuple({{"a", {Type::WILDCARD}}, {"a.b", {Type::WILDCARD}}}, false),
                                           ParamsTuple({{"a", {Type::OBJECT}}, {"a.b", {Type::TEXT}}}, true),
                                           ParamsTuple({{"a.b.c.d", {Type::BOOLEAN}}}, true),
                                           ParamsTuple({{"a.b.c.d", {Type::INTEGER}}, {"a.b", {Type::TEXT}}}, false),
                                           ParamsTuple({{"a.b.c.d", {Type::INTEGER}}, {"a.b.a", {Type::TEXT}}}, true),
                                           ParamsTuple({{"a", {Type::INTEGER, true}}, {"a.b", {Type::INTEGER}}}, false),
                                           ParamsTuple({{"a", {Type::OBJECT, true}}, {"a.b", {Type::INTEGER}}}, true)));

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
            ASSERT_EQ(value.getBool("/array").value_or(false), schema.isArray(key));
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
                         ::testing::Values(LoadTuple(R"({"a": {"type": "text"}})", true),
                                           LoadTuple(R"({"a": {"type": "wildcard"}})", true),
                                           LoadTuple(R"({"a": {"type": "integer"}})", true),
                                           LoadTuple(R"({"a": {"type": "null"}})", false),
                                           LoadTuple(R"({"a": {"type": "object"}})", true),
                                           LoadTuple(R"({"a": {"type": "array"}})", false),
                                           LoadTuple(R"({"a": {"type": "boolean"}})", true),
                                           LoadTuple(R"({"a": {"type": "keyword"}, "a.b": {"type": "keyword"}})",
                                                     false),
                                           LoadTuple(R"({"a": {"type": "text", "array": true}})", true),
                                           LoadTuple(R"({"a": {"type": "keyword", "array": true}})", true),
                                           LoadTuple(R"({"a": {"type": "long", "array": true}})", true),
                                           LoadTuple(R"({"a": {"type": "object", "array": true}})", true),
                                           LoadTuple(R"({"a": {"type": "boolean", "array": true}})", true),
                                           LoadTuple(R"({"a": {"type": "array", "array": true}})", false),
                                           LoadTuple(R"({"a.": {"type": "keyword"}})", false),
                                           LoadTuple(R"({"a": {}})", false),
                                           LoadTuple(R"({"a": [{"type": "text"}]})", false),
                                           LoadTuple(R"([{"a": {"type": "keyword"}}])", false)));

TEST(SchemaTest, ArrayItem)
{
    Schema schema;
    schema.addField("a", {Type::INTEGER, true});
    ASSERT_TRUE(schema.isArray("a"));
    ASSERT_TRUE(schema.hasField("a.0"));
    ASSERT_EQ(schema.getJsonType("a.0"), json::Json::Type::Number);
    ASSERT_FALSE(schema.hasField("a.n"));
    ASSERT_FALSE(schema.isArray("a.0"));
    auto itemType = schema.getType("a.0");
    ASSERT_EQ(itemType, Type::INTEGER);
    ASSERT_THROW(schema.getType("a.n"), std::runtime_error);
    ASSERT_THROW(schema.getJsonType("a.n"), std::runtime_error);
}

#include <gtest/gtest.h>

#include <schemf/schema.hpp>

using namespace schemf;
using JType = json::Json::Type;

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
            ASSERT_FALSE(schema.hasField(name));
        }
    }
}

INSTANTIATE_TEST_SUITE_P(SchemaTest,
                         Params,
                         ::testing::Values(ParamsTuple({{"a", {JType::String}}}, true),
                                           ParamsTuple({{"a", {JType::Number}}}, true),
                                           ParamsTuple({{"a", {JType::Null}}}, false),
                                           ParamsTuple({{"a", {JType::Object}}}, true),
                                           ParamsTuple({{"a", {JType::Array}}}, false),
                                           ParamsTuple({{"a", {JType::Array, JType::Number}}}, true),
                                           ParamsTuple({{"a", {JType::Boolean}}}, true),
                                           ParamsTuple({{"a", {JType::Object}}, {"a", {JType::Boolean}}}, false),
                                           ParamsTuple({{"a", {JType::String}}, {"a.b", {JType::String}}}, false),
                                           ParamsTuple({{"a", {JType::Object}}, {"a.b", {JType::String}}}, true),
                                           ParamsTuple({{"a.b.c.d", {JType::Boolean}}}, true),
                                           ParamsTuple({{"a.b.c.d", {JType::Number}}, {"a.b", {JType::String}}}, false),
                                           ParamsTuple({{"a.b.c.d", {JType::Number}}, {"a.b.a", {JType::String}}},
                                                       true),
                                           ParamsTuple({{"a", {JType::Array, JType::Number}}, {"a.b", {JType::Number}}}, false),
                                           ParamsTuple({{"a", {JType::Array, JType::Object}}, {"a.b", {JType::Number}}}, true)
                                                       ));

#include <gtest/gtest.h>

#include <schemf/field.hpp>

using namespace schemf;
using JType = json::Json::Type;

TEST(FieldTest, BuildsDefault)
{
    ASSERT_NO_THROW(Field());
    Field field;
    ASSERT_EQ(field.type(), JType::Null);
    ASSERT_THROW(field.itemsType(), std::runtime_error);
    ASSERT_THROW(field.itemsType(), std::runtime_error);
}

TEST(FieldTest, Type)
{
    Field field({.type = JType::String});
    ASSERT_EQ(field.type(), JType::String);
}

using PropertiesParamsTuple =
    std::tuple<Field::Parameters, std::vector<std::tuple<std::string, Field::Parameters>>, bool>;
class PropertiesParams : public ::testing::TestWithParam<PropertiesParamsTuple>
{
};

TEST_P(PropertiesParams, Properties)
{
    auto [params, properties, shouldPass] = GetParam();
    Field field(params);
    if (shouldPass)
    {
        for (auto [name, property] : properties)
        {
            ASSERT_NO_THROW(field.addProperty(name, property));
        }
        ASSERT_EQ(field.properties().size(), properties.size());
        for (auto [name, property] : properties)
        {
            ASSERT_EQ(field.properties().at(name), Field(property));
        }
    }
    else
    {
        if (field.type() == JType::Object || (field.type() == JType::Array && field.itemsType() == JType::Object))
        {
            try
            {
                for (auto [name, property] : properties)
                {
                    field.addProperty(name, property);
                }
            }
            catch (const std::exception& e)
            {
                SUCCEED();
                return;
            }
            FAIL() << "Expected failure when adding property to object or array of objects";
        }
        else
        {
            ASSERT_THROW(field.addProperty("a", {.type = JType::String}), std::runtime_error);
            ASSERT_THROW(field.properties(), std::runtime_error);
        }
    }
}

INSTANTIATE_TEST_SUITE_P(
    FieldTest,
    PropertiesParams,
    ::testing::Values(
        PropertiesParamsTuple({JType::Object}, {{"a", {JType::String}}}, true),
        PropertiesParamsTuple({JType::Object}, {{"a", {JType::Number}}}, true),
        PropertiesParamsTuple({JType::Object}, {{"a", {JType::Object}}}, true),
        PropertiesParamsTuple({JType::Object}, {{"a", {JType::Array, JType::Number}}}, true),
        PropertiesParamsTuple({JType::Object}, {{"a", {JType::Boolean}}}, true),
        PropertiesParamsTuple({JType::Object}, {{"a", {JType::String}}, {"a", {JType::String}}}, false),
        PropertiesParamsTuple({JType::String}, {{"a", {JType::String}}}, false),
        PropertiesParamsTuple({JType::Number}, {{"a", {JType::String}}}, false),
        PropertiesParamsTuple({JType::Boolean}, {{"a", {JType::String}}}, false),
        PropertiesParamsTuple({JType::Array, JType::Object}, {{"a", {JType::String}}}, true),
        PropertiesParamsTuple({JType::Array, JType::Object}, {{"a", {JType::Number}}}, true),
        PropertiesParamsTuple({JType::Array, JType::Object}, {{"a", {JType::Object}}}, true),
        PropertiesParamsTuple({JType::Array, JType::Object}, {{"a", {JType::Array, JType::Number}}}, true),
        PropertiesParamsTuple({JType::Array, JType::Object}, {{"a", {JType::Boolean}}}, true),
        PropertiesParamsTuple({JType::Array, JType::Object}, {{"a", {JType::String}}, {"a", {JType::String}}}, false),
        PropertiesParamsTuple({JType::Object}, {{"a", {JType::String}}, {"b", {JType::String}}}, true)));

using EqualsTuple = std::tuple<Field::Parameters, Field::Parameters, bool>;
class Equals : public ::testing::TestWithParam<EqualsTuple>
{
};

TEST_P(Equals, Equals)
{
    auto [lhsParams, rhsParams, expected] = GetParam();
    Field lhs(lhsParams);
    Field rhs(rhsParams);
    if (expected)
    {
        ASSERT_EQ(lhs, rhs);
    }
    else
    {
        ASSERT_NE(lhs, rhs);
    }
}

INSTANTIATE_TEST_SUITE_P(
    FieldTest,
    Equals,
    ::testing::Values(
        EqualsTuple({JType::String}, {JType::String}, true),
        EqualsTuple({JType::Number}, {JType::String}, false),
        EqualsTuple({.type = JType::Object, .properties = {{"a", Field({JType::String})}}},
                    {.type = JType::Object, .properties = {{"a", Field({JType::String})}}},
                    true),
        EqualsTuple({.type = JType::Object, .properties = {{"a", Field({JType::String})}}}, {JType::Object}, false),
        EqualsTuple({.type = JType::Array, .itemsType = JType::Object, .properties = {{"a", Field({JType::String})}}},
                    {.type = JType::Object, .properties = {{"a", Field({JType::String})}}},
                    false)));

using BuildsParamsTuple = std::tuple<Field::Parameters, bool>;
class BuildsParams : public ::testing::TestWithParam<BuildsParamsTuple>
{
};

TEST_P(BuildsParams, Builds)
{
    auto [parameters, shouldPass] = GetParam();
    Field field;
    if (shouldPass)
    {
        ASSERT_NO_THROW(field = Field {parameters});
    }
    else
    {
        ASSERT_THROW(field = Field {parameters}, std::runtime_error);
    }
}

TEST_P(BuildsParams, Copies)
{
    auto [parameters, shouldPass] = GetParam();
    if (shouldPass)
    {
        Field field(parameters);
        Field cpyConstructor(field);
        Field cpyAssignment;
        cpyAssignment = field;

        ASSERT_EQ(cpyConstructor, field);
        ASSERT_EQ(cpyAssignment, field);
    }
}

TEST_P(BuildsParams, Moves)
{
    auto [parameters, shouldPass] = GetParam();
    if (shouldPass)
    {

        Field expected(parameters);
        Field field(parameters);
        Field mvConstructor(std::move(field));
        Field mvAssignment;
        field = Field(parameters);
        mvAssignment = std::move(field);

        ASSERT_EQ(mvConstructor, expected);
        ASSERT_EQ(mvAssignment, expected);
    }
}

INSTANTIATE_TEST_SUITE_P(FieldTest,
                         BuildsParams,
                         ::testing::Values(BuildsParamsTuple({JType::String}, true),
                                           BuildsParamsTuple({JType::Number}, true),
                                           BuildsParamsTuple({JType::Null}, false),
                                           BuildsParamsTuple({JType::Object}, true),
                                           BuildsParamsTuple({JType::Array}, false),
                                           BuildsParamsTuple({JType::Array, JType::String}, true),
                                           BuildsParamsTuple({JType::Array, JType::Number}, true),
                                           BuildsParamsTuple({JType::Array, JType::Null}, false),
                                           BuildsParamsTuple({JType::Array, JType::Object}, true),
                                           BuildsParamsTuple({JType::Array, JType::Array}, true),
                                           BuildsParamsTuple({JType::String, JType::String}, false),
                                           BuildsParamsTuple({.type = JType::Number, .properties = {{}}}, false),
                                           BuildsParamsTuple({.type = JType::Object, .properties = {{}}}, true),
                                           BuildsParamsTuple({JType::Array, JType::Object, {{}}}, true),
                                           BuildsParamsTuple({JType::Array, JType::Boolean, {{}}}, false)));

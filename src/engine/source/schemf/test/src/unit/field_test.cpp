#include <gtest/gtest.h>

#include <schemf/field.hpp>

using namespace schemf;

TEST(FieldTest, BuildsDefault)
{
    ASSERT_NO_THROW(Field());
    Field field;
    ASSERT_EQ(field.type(), Type::ERROR);
}

TEST(FieldTest, Type)
{
    Field field({.type = Type::TEXT});
    ASSERT_EQ(field.type(), Type::TEXT);
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
        if (hasProperties(field.type()))
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
            ASSERT_THROW(field.addProperty("a", {.type = Type::TEXT}), std::runtime_error);
            ASSERT_THROW(field.properties(), std::runtime_error);
        }
    }
}

INSTANTIATE_TEST_SUITE_P(
    FieldTest,
    PropertiesParams,
    ::testing::Values(PropertiesParamsTuple({Type::OBJECT}, {{"a", {Type::TEXT}}}, true),
                      PropertiesParamsTuple({Type::OBJECT}, {{"a", {Type::INTEGER}}}, true),
                      PropertiesParamsTuple({Type::OBJECT}, {{"a", {Type::OBJECT}}}, true),
                      PropertiesParamsTuple({Type::OBJECT}, {{"a", {Type::INTEGER, true}}}, true),
                      PropertiesParamsTuple({Type::OBJECT}, {{"a", {Type::BOOLEAN}}}, true),
                      PropertiesParamsTuple({Type::OBJECT}, {{"a", {Type::TEXT}}, {"a", {Type::TEXT}}}, false),
                      PropertiesParamsTuple({Type::TEXT}, {{"a", {Type::TEXT}}}, false),
                      PropertiesParamsTuple({Type::INTEGER}, {{"a", {Type::TEXT}}}, false),
                      PropertiesParamsTuple({Type::BOOLEAN}, {{"a", {Type::TEXT}}}, false),
                      PropertiesParamsTuple({Type::OBJECT, true}, {{"a", {Type::TEXT}}}, true),
                      PropertiesParamsTuple({Type::OBJECT, true}, {{"a", {Type::INTEGER}}}, true),
                      PropertiesParamsTuple({Type::OBJECT, true}, {{"a", {Type::OBJECT}}}, true),
                      PropertiesParamsTuple({Type::OBJECT, true}, {{"a", {Type::INTEGER, true}}}, true),
                      PropertiesParamsTuple({Type::OBJECT, true}, {{"a", {Type::BOOLEAN}}}, true),
                      PropertiesParamsTuple({Type::OBJECT, true}, {{"a", {Type::TEXT}}, {"a", {Type::TEXT}}}, false),
                      PropertiesParamsTuple({Type::OBJECT}, {{"a", {Type::TEXT}}, {"b", {Type::TEXT}}}, true)));

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
        EqualsTuple({Type::TEXT}, {Type::TEXT}, true),
        EqualsTuple({Type::INTEGER}, {Type::TEXT}, false),
        EqualsTuple({.type = Type::OBJECT, .properties = {{"a", Field({Type::TEXT})}}},
                    {.type = Type::OBJECT, .properties = {{"a", Field({Type::TEXT})}}},
                    true),
        EqualsTuple({.type = Type::OBJECT, .properties = {{"a", Field({Type::TEXT})}}}, {Type::OBJECT}, false),
        EqualsTuple({.type = Type::OBJECT, .isArray = true, .properties = {{"a", Field({Type::TEXT})}}},
                    {.type = Type::OBJECT, .properties = {{"a", Field({Type::TEXT})}}},
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
                         ::testing::Values(BuildsParamsTuple({Type::TEXT}, true),
                                           BuildsParamsTuple({Type::INTEGER}, true),
                                           BuildsParamsTuple({Type::ERROR}, false),
                                           BuildsParamsTuple({Type::OBJECT}, true),
                                           BuildsParamsTuple({.isArray = false}, false),
                                           BuildsParamsTuple({Type::TEXT, true}, true),
                                           BuildsParamsTuple({Type::INTEGER, true}, true),
                                           BuildsParamsTuple({Type::ERROR, true}, false),
                                           BuildsParamsTuple({Type::OBJECT, true}, true),
                                           BuildsParamsTuple({.type = Type::INTEGER, .properties = {{}}}, false),
                                           BuildsParamsTuple({.type = Type::OBJECT, .properties = {{}}}, true),
                                           BuildsParamsTuple({Type::OBJECT, true, {{}}}, true),
                                           BuildsParamsTuple({Type::BOOLEAN, true, {{}}}, false)));

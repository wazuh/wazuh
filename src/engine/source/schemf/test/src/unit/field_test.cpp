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
    ::testing::Values(
        // OBJECT type can have properties
        PropertiesParamsTuple({Type::OBJECT}, {{"a", {Type::TEXT}}}, true),
        PropertiesParamsTuple({Type::OBJECT}, {{"a", {Type::INTEGER}}}, true),
        PropertiesParamsTuple({Type::OBJECT}, {{"a", {Type::OBJECT}}}, true),
        PropertiesParamsTuple({Type::OBJECT}, {{"a", {Type::BOOLEAN}}}, true),
        PropertiesParamsTuple({Type::OBJECT}, {{"a", {Type::TEXT}}, {"a", {Type::TEXT}}}, false), // duplicate
        PropertiesParamsTuple({Type::OBJECT}, {{"a", {Type::TEXT}}, {"b", {Type::TEXT}}}, true),
        // NESTED type can have properties
        PropertiesParamsTuple({Type::NESTED}, {{"a", {Type::KEYWORD}}}, true),
        PropertiesParamsTuple({Type::NESTED}, {{"a", {Type::LONG}}}, true),
        PropertiesParamsTuple({Type::NESTED}, {{"a", {Type::DATE}}}, true),
        // All numeric types cannot have properties
        PropertiesParamsTuple({Type::BYTE}, {{"a", {Type::TEXT}}}, false),
        PropertiesParamsTuple({Type::SHORT}, {{"a", {Type::TEXT}}}, false),
        PropertiesParamsTuple({Type::INTEGER}, {{"a", {Type::TEXT}}}, false),
        PropertiesParamsTuple({Type::LONG}, {{"a", {Type::TEXT}}}, false),
        PropertiesParamsTuple({Type::FLOAT}, {{"a", {Type::TEXT}}}, false),
        PropertiesParamsTuple({Type::HALF_FLOAT}, {{"a", {Type::TEXT}}}, false),
        PropertiesParamsTuple({Type::SCALED_FLOAT}, {{"a", {Type::TEXT}}}, false),
        PropertiesParamsTuple({Type::DOUBLE}, {{"a", {Type::TEXT}}}, false),
        PropertiesParamsTuple({Type::UNSIGNED_LONG}, {{"a", {Type::TEXT}}}, false),
        // All string types cannot have properties
        PropertiesParamsTuple({Type::TEXT}, {{"a", {Type::TEXT}}}, false),
        PropertiesParamsTuple({Type::KEYWORD}, {{"a", {Type::TEXT}}}, false),
        PropertiesParamsTuple({Type::MATCH_ONLY_TEXT}, {{"a", {Type::TEXT}}}, false),
        PropertiesParamsTuple({Type::WILDCARD}, {{"a", {Type::TEXT}}}, false),
        PropertiesParamsTuple({Type::CONSTANT_KEYWORD}, {{"a", {Type::TEXT}}}, false),
        // Date types cannot have properties
        PropertiesParamsTuple({Type::DATE}, {{"a", {Type::TEXT}}}, false),
        PropertiesParamsTuple({Type::DATE_NANOS}, {{"a", {Type::TEXT}}}, false),
        // Special types cannot have properties
        PropertiesParamsTuple({Type::IP}, {{"a", {Type::TEXT}}}, false),
        PropertiesParamsTuple({Type::BINARY}, {{"a", {Type::TEXT}}}, false),
        PropertiesParamsTuple({Type::GEO_POINT}, {{"a", {Type::TEXT}}}, false),
        PropertiesParamsTuple({Type::COMPLETION}, {{"a", {Type::TEXT}}}, false),
        PropertiesParamsTuple({Type::SEARCH_AS_YOU_TYPE}, {{"a", {Type::TEXT}}}, false),
        PropertiesParamsTuple({Type::TOKEN_COUNT}, {{"a", {Type::TEXT}}}, false),
        PropertiesParamsTuple({Type::SEMANTIC}, {{"a", {Type::TEXT}}}, false),
        // BOOLEAN cannot have properties
        PropertiesParamsTuple({Type::BOOLEAN}, {{"a", {Type::TEXT}}}, false)));

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
        // Same types are equal
        EqualsTuple({Type::TEXT}, {Type::TEXT}, true),
        EqualsTuple({Type::KEYWORD}, {Type::KEYWORD}, true),
        EqualsTuple({Type::INTEGER}, {Type::INTEGER}, true),
        EqualsTuple({Type::LONG}, {Type::LONG}, true),
        EqualsTuple({Type::BOOLEAN}, {Type::BOOLEAN}, true),
        // Different types are not equal
        EqualsTuple({Type::INTEGER}, {Type::TEXT}, false),
        EqualsTuple({Type::KEYWORD}, {Type::TEXT}, false),
        EqualsTuple({Type::BYTE}, {Type::SHORT}, false),
        EqualsTuple({Type::LONG}, {Type::INTEGER}, false),
        EqualsTuple({Type::FLOAT}, {Type::DOUBLE}, false),
        EqualsTuple({Type::DATE}, {Type::DATE_NANOS}, false),
        EqualsTuple({Type::OBJECT}, {Type::NESTED}, false),
        EqualsTuple({Type::NESTED}, {Type::FLAT_OBJECT}, false),
        // Numeric types
        EqualsTuple({Type::BYTE}, {Type::BYTE}, true),
        EqualsTuple({Type::SHORT}, {Type::SHORT}, true),
        EqualsTuple({Type::FLOAT}, {Type::FLOAT}, true),
        EqualsTuple({Type::DOUBLE}, {Type::DOUBLE}, true),
        EqualsTuple({Type::HALF_FLOAT}, {Type::HALF_FLOAT}, true),
        EqualsTuple({Type::SCALED_FLOAT}, {Type::SCALED_FLOAT}, true),
        EqualsTuple({Type::UNSIGNED_LONG}, {Type::UNSIGNED_LONG}, true),
        // String types
        EqualsTuple({Type::MATCH_ONLY_TEXT}, {Type::MATCH_ONLY_TEXT}, true),
        EqualsTuple({Type::WILDCARD}, {Type::WILDCARD}, true),
        EqualsTuple({Type::CONSTANT_KEYWORD}, {Type::CONSTANT_KEYWORD}, true),
        // Date types
        EqualsTuple({Type::DATE}, {Type::DATE}, true),
        EqualsTuple({Type::DATE_NANOS}, {Type::DATE_NANOS}, true),
        // Special types
        EqualsTuple({Type::IP}, {Type::IP}, true),
        EqualsTuple({Type::BINARY}, {Type::BINARY}, true),
        EqualsTuple({Type::GEO_POINT}, {Type::GEO_POINT}, true),
        EqualsTuple({Type::COMPLETION}, {Type::COMPLETION}, true),
        EqualsTuple({Type::SEARCH_AS_YOU_TYPE}, {Type::SEARCH_AS_YOU_TYPE}, true),
        EqualsTuple({Type::TOKEN_COUNT}, {Type::TOKEN_COUNT}, true),
        EqualsTuple({Type::SEMANTIC}, {Type::SEMANTIC}, true),
        // Object types
        EqualsTuple({Type::OBJECT}, {Type::OBJECT}, true),
        EqualsTuple({Type::NESTED}, {Type::NESTED}, true),
        EqualsTuple({Type::FLAT_OBJECT}, {Type::FLAT_OBJECT}, true),
        // Object with properties
        EqualsTuple({.type = Type::OBJECT, .properties = {{"a", Field({Type::TEXT})}}},
                    {.type = Type::OBJECT, .properties = {{"a", Field({Type::TEXT})}}},
                    true),
        EqualsTuple({.type = Type::OBJECT, .properties = {{"a", Field({Type::TEXT})}}},
                    {Type::OBJECT},
                    false),
        EqualsTuple({.type = Type::NESTED, .properties = {{"a", Field({Type::KEYWORD})}}},
                    {.type = Type::NESTED, .properties = {{"a", Field({Type::KEYWORD})}}},
                    true)));

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
                         ::testing::Values(
                             // Valid types
                             BuildsParamsTuple({Type::TEXT}, true),
                             BuildsParamsTuple({Type::KEYWORD}, true),
                             BuildsParamsTuple({Type::INTEGER}, true),
                             BuildsParamsTuple({Type::LONG}, true),
                             BuildsParamsTuple({Type::BOOLEAN}, true),
                             BuildsParamsTuple({Type::OBJECT}, true),
                             // Invalid type
                             BuildsParamsTuple({Type::ERROR}, false),
                             // All numeric types
                             BuildsParamsTuple({Type::BYTE}, true),
                             BuildsParamsTuple({Type::SHORT}, true),
                             BuildsParamsTuple({Type::FLOAT}, true),
                             BuildsParamsTuple({Type::DOUBLE}, true),
                             BuildsParamsTuple({Type::HALF_FLOAT}, true),
                             BuildsParamsTuple({Type::SCALED_FLOAT}, true),
                             BuildsParamsTuple({Type::UNSIGNED_LONG}, true),
                             // All string types
                             BuildsParamsTuple({Type::MATCH_ONLY_TEXT}, true),
                             BuildsParamsTuple({Type::WILDCARD}, true),
                             BuildsParamsTuple({Type::CONSTANT_KEYWORD}, true),
                             // Date types
                             BuildsParamsTuple({Type::DATE}, true),
                             BuildsParamsTuple({Type::DATE_NANOS}, true),
                             // Special types
                             BuildsParamsTuple({Type::IP}, true),
                             BuildsParamsTuple({Type::BINARY}, true),
                             BuildsParamsTuple({Type::GEO_POINT}, true),
                             BuildsParamsTuple({Type::COMPLETION}, true),
                             BuildsParamsTuple({Type::SEARCH_AS_YOU_TYPE}, true),
                             BuildsParamsTuple({Type::TOKEN_COUNT}, true),
                             BuildsParamsTuple({Type::SEMANTIC}, true),
                             // Object types
                             BuildsParamsTuple({Type::NESTED}, true),
                             BuildsParamsTuple({Type::FLAT_OBJECT}, true),
                             // Properties tests
                             BuildsParamsTuple({.type = Type::INTEGER, .properties = {{}}}, false),
                             BuildsParamsTuple({.type = Type::OBJECT, .properties = {{}}}, true),
                             BuildsParamsTuple({.type = Type::NESTED, .properties = {{}}}, true),
                             BuildsParamsTuple({.type = Type::FLAT_OBJECT, .properties = {{}}}, true),
                             BuildsParamsTuple({.type = Type::TEXT, .properties = {{}}}, false),
                             BuildsParamsTuple({.type = Type::KEYWORD, .properties = {{}}}, false)))
;

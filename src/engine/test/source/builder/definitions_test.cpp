#include <gtest/gtest.h>

#include "baseTypes.hpp"
#include "definitions.hpp"

using namespace builder::internals;
using namespace json;
using namespace base;

TEST(DefinitionsTest, SubstituteDefinitions)
{
    Json asset {
        R"({
            "definitions": {
                "foo": "bar",
                "foo2": "bar2"
            },
            "check": "$foo AND $foo2"
        })"};
    auto expected = R"({"check":"bar AND bar2"})";

    ASSERT_NO_THROW(substituteDefinitions(asset));
    ASSERT_EQ(asset.str(), expected);
}

TEST(DefinitionsTest, EmptyDefinition)
{
    Json asset {
        R"({
            "definitions": {},
            "check": "$foo"
        })"};

    ASSERT_NO_THROW(substituteDefinitions(asset));
    ASSERT_EQ(asset.str(), R"({"check":"$foo"})");
}

TEST(DefinitionsTest, NoDefinition)
{
    Json asset {
        R"({
            "check": "$foo"
        })"};

    ASSERT_NO_THROW(substituteDefinitions(asset));
    ASSERT_EQ(asset.str(), R"({"check":"$foo"})");
}

TEST(DefinitionsTest, NotObject)
{
    Json asset {
        R"({
            "definitions": "foo"
        })"};

    ASSERT_THROW(substituteDefinitions(asset), std::runtime_error);
}

TEST(DefinitionsTest, EmptyDefinitionVariableThrow)
{
    Json asset {
        R"({
            "definitions": {
                "foo": null
            },
            "check": "$foo AND $bar"
        })"};

    ASSERT_THROW(substituteDefinitions(asset), std::runtime_error);
}

TEST(DefinitionsTest, ScapedReference)
{
    // TODO: escaped dollar sign needs to be contemplated
    GTEST_SKIP();
}

TEST(DefinitionsTest, DefinitionReservedName)
{
    // TODO: A definition can't have the same name as a field, could be handled
    // in the schema
    GTEST_SKIP();
}

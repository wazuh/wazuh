#include "testUtils.hpp"
#include <gtest/gtest.h>

#include "definitions.hpp"

TEST(DefinitionsTest, SubstituteDefinitions)
{
    base::Document asset {
        R"({
            "definitions": {
                "foo": "bar",
                "foo2": "bar2"
            },
            "check": "$foo AND $foo2"
        })"};
    auto expected = R"({"check":"bar AND bar2"})";

    ASSERT_NO_THROW(builder::internals::substituteDefinitions(asset));
    ASSERT_EQ(asset.str(), expected);
}

TEST(DefinitionsTest, EmptyDefinitionsDoesNothing)
{
    base::Document asset {
        R"({
            "definitions": {},
            "check": "$foo"
        })"};

    ASSERT_NO_THROW(builder::internals::substituteDefinitions(asset));
    ASSERT_EQ(asset.str(), R"({"check":"$foo"})");
}

TEST(DefinitionsTest, EmptyDefinitionVariableThrow)
{
    base::Document asset {
        R"({
            "definitions": {
                "foo": null
            },
            "check": "$foo AND $bar"
        })"};

    ASSERT_THROW(builder::internals::substituteDefinitions(asset),
                 std::runtime_error);
}

TEST(DefinitionsTest, NoDefinitionsDoesNothing)
{
    base::Document asset {
        R"({
            "check": "$foo"
        })"};
    auto expected = R"({"check":"$foo"})";

    ASSERT_NO_THROW(builder::internals::substituteDefinitions(asset));
    ASSERT_EQ(asset.str(), expected);
}

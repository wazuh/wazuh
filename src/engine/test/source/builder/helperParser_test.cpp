#include <gtest/gtest.h>

#include <re2/re2.h>

#include "helperParser.hpp"

using HelperParserT = std::tuple<bool, std::string, builder::internals::HelperToken>;
class HelperParserTest : public ::testing::TestWithParam<HelperParserT>
{
};

TEST_P(HelperParserTest, parse)
{
    auto &[shouldPass, input, expected] = GetParam();

    auto result = builder::internals::parseHelper(input);

    if (shouldPass)
    {
        ASSERT_TRUE(std::holds_alternative<builder::internals::HelperToken>(result));
        ASSERT_EQ(std::get<builder::internals::HelperToken>(result).name, expected.name);
        ASSERT_EQ(std::get<builder::internals::HelperToken>(result).args, expected.args);
    }
    else
    {
        ASSERT_TRUE(std::holds_alternative<base::Error>(result));
    }
}

INSTANTIATE_TEST_SUITE_P(
    Builder,
    HelperParserTest,
    ::testing::Values(
        HelperParserT(false, "anything", {}),
        HelperParserT(true, "name()", {.name = "name"}),
        HelperParserT(true, "test(arg1)", {.name = "test", .args = {"arg1"}}),
        HelperParserT(true, "test(arg1,arg2)", {.name = "test", .args = {"arg1", "arg2"}}),
        HelperParserT(true, "test(arg1, arg2, arg3)", {.name = "test", .args = {"arg1", "arg2", "arg3"}}),
        HelperParserT(true, "test(arg1, arg2\\,arg3)", {.name = "test", .args = {"arg1", "arg2,arg3"}}),  // Testing escaped comma
        HelperParserT(true, "test(arg1,\\ arg2)", {.name = "test", .args = {"arg1", " arg2"}}),  // Testing escaped space
        HelperParserT(false, "test(arg1", {}),  // Missing closing parenthesis
        HelperParserT(false, "test arg1)", {}),  // Missing opening parenthesis
        HelperParserT(false, "", {}),  // Empty string
        HelperParserT(false, "()", {.name = ""}),  // No function name
        HelperParserT(true, "test(,)", {.name = "test", .args {"", ""}}),
         HelperParserT(true, "test(,,)", {.name = "test", .args {"", "", ""}}),
        HelperParserT(true, "test(, ,)", {.name = "test", .args {"", "", ""}}),
        HelperParserT(true, "test(arg1,)", {.name = "test", .args {"arg1", ""}}),
        HelperParserT(true, "test(arg1, )", {.name = "test", .args {"arg1", ""}}),
        HelperParserT(true, "test(arg1,\\ )", {.name = "test", .args {"arg1", " "}}),
        HelperParserT(true, "test(arg1,  )", {.name = "test", .args {"arg1", " "}})

));

#include "logpar_test.hpp"

#include <memory>
#include <numeric>
#include <stdexcept>

#include <fmt/format.h>

#include <schemf/mockSchema.hpp>

using namespace hlp;
using namespace schemf::mocks;
namespace logp
{
using namespace logpar::parser;
}

class LogparTest : public ::testing::Test
{
protected:
    std::shared_ptr<MockSchema> schema;

    void SetUp() override { schema = std::make_shared<MockSchema>(); }
};

TEST_F(LogparTest, Builds)
{
    auto config = logpar_test::getConfig();
    EXPECT_CALL(*schema, hasField(testing::StrEq(logpar_test::TEXT_FIELD_OVERRIDE))).WillOnce(::testing::Return(true));
    EXPECT_CALL(*schema, hasField(testing::StrEq(logpar_test::LONG_FIELD_OVERRIDE))).WillOnce(::testing::Return(true));
    ASSERT_NO_THROW(logpar::Logpar logpar(config, schema));
}

TEST_F(LogparTest, BuildsNotObjectConfig)
{
    json::Json config {"\"config\""};
    ASSERT_THROW(logpar::Logpar logpar(config, schema), std::runtime_error);
}

TEST_F(LogparTest, BuildsNoNameConfig)
{
    json::Json config {"{}"};
    ASSERT_THROW(logpar::Logpar logpar(config, schema), std::runtime_error);
}

TEST_F(LogparTest, BuildsNoFieldsConfig)
{
    json::Json config {R"({"name":"name"})"};
    ASSERT_THROW(logpar::Logpar logpar(config, schema), std::runtime_error);
}

TEST_F(LogparTest, BuildsNotStringOverride)
{
    json::Json config {R"({"name":"name","fields":{"text":1}})"};
    ASSERT_THROW(logpar::Logpar logpar(config, schema), std::runtime_error);
}

using ParseExprT = std::tuple<std::string, bool>;
class LogparParseExprTest
    : public ::testing::TestWithParam<ParseExprT>
    , public logpar_test::LogparPBase
{
protected:
    void SetUp() override { init(); }
};

TEST_P(LogparParseExprTest, Parses)
{
    auto [expression, shouldPass] = GetParam();

    if (shouldPass)
    {
        ASSERT_NO_THROW(logpar->build(expression));
    }
    else
    {
        ASSERT_THROW(logpar->build(expression), std::runtime_error);
    }
}

INSTANTIATE_TEST_SUITE_P(Parses,
                         LogparParseExprTest,
                         ::testing::Values(ParseExprT("(?literal<text>:)<~custom/long><~>", true),
                                           ParseExprT("literal", true),
                                           ParseExprT("<~>", true),
                                           ParseExprT("<~>?<~>", false),
                                           ParseExprT("<~custom/long>?<~>", true),
                                           ParseExprT("(?literal)", true),
                                           ParseExprT("(?literal) (?literal) (?literal)", true),
                                           ParseExprT("[date] <~host> <text>(?|<~opt/text>|):<~>", true),
                                           ParseExprT("literal<text>:<~custom/long><~", false),
                                           ParseExprT("", false),
                                           ParseExprT("?()", false),
                                           ParseExprT("lit<~>(?<~>:)|", false),
                                           ParseExprT("lit(?lit)(?lit)", false), // Must build if limit >= 2
                                           ParseExprT("lit(?(?lit)lit)", false), // Must build if limit >= 2
                                           ParseExprT("<~opt>?lit", false),
                                           ParseExprT("lit(?lit", false),
                                           ParseExprT("literal<text><~custom/long><~>", false),
                                           ParseExprT("literal<text>:<~custom/long/error_arg><~>", false),
                                           ParseExprT("literal<array>", false)));

using BuildParseT = std::tuple<bool, std::string, std::string, json::Json>;
class LogparBuildParseTest
    : public ::testing::TestWithParam<BuildParseT>
    , public logpar_test::LogparPBase
{
protected:
    void SetUp() override { init(); }
};

TEST_P(LogparBuildParseTest, BuildParse)
{
    auto [shouldPass, expression, text, expected] = GetParam();
    auto parser = logpar->build(expression);

    json::Json event;
    auto error = hlp::parser::run(parser, text, event);

    if (shouldPass)
    {
        ASSERT_FALSE(error) << error.value().message;
        ASSERT_EQ(event, expected);
    }
    else
    {
        ASSERT_TRUE(error);
    }
}

INSTANTIATE_TEST_SUITE_P(
    BuildParse,
    LogparBuildParseTest,
    ::testing::Values(
        BuildParseT(true, "literal", "literal", {}),
        BuildParseT(false, "literal", "literalleftover", {}),
        BuildParseT(false, "literal", "lieral", {}),
        BuildParseT(true, "<text>", "some text", logpar_test::J(R"({"text":"some text"})")),
        BuildParseT(true, "<text>end", "some textend", logpar_test::J(R"({"text":"some text"})")),
        BuildParseT(true, "lit<text>:<~a/long>", "literal:1", logpar_test::J(R"({"text":"eral","~a":1})")),
        BuildParseT(true, "lit<text>:<~a/long><~>", "literal:1ignored", logpar_test::J(R"({"text":"eral","~a":1})")),
        BuildParseT(true,
                    "lit<text>:<~a/long><~>:(?<~opt/text>)",
                    "literal:1ignored:",
                    logpar_test::J(R"({"text":"eral","~a":1})")),
        BuildParseT(true,
                    "lit<text>:<~a/long><~>:(?<~opt/text>)",
                    "literal:1ignored:optional",
                    logpar_test::J(R"({"text":"eral","~a":1,"~opt":"optional"})")),
        BuildParseT(true, "<long>?<~/literal/->", "15", logpar_test::J(R"({"long":15})")),
        BuildParseT(true, "<long>?<~/literal/->", "-", {}),
        BuildParseT(true,
                    "[date] <~host> <text>(?|<~opt/text>|):<~>",
                    "[date] host text:left over",
                    logpar_test::J(R"({"~host":"host","text":"text"})")),
        BuildParseT(false, "[date] <~host> <text>(?|<~opt/text>|):<~>", "[date] host text|left over", {}),
        BuildParseT(true,
                    "[date] <~host> <text>(?|<~opt/text>|):<~>",
                    "[date] host text|opt|:left over",
                    logpar_test::J(R"({"~host":"host","text":"text","~opt":"opt"})")),
        BuildParseT(false, "[date] <~host> <text>(?|<~opt/text>|):<~>", "[date] host text|opt|:", {}),
        BuildParseT(false, "[date] <~host> <text>(?|<~opt/text>|):<~>", "[date] host text|opt|left over", {})));

using FieldParserT = std::tuple<bool, std::string, std::string, bool, std::list<std::string>, bool, size_t>;
class LogparFieldParserTest : public ::testing::TestWithParam<FieldParserT>
{
};

TEST_P(LogparFieldParserTest, Parses)
{
    auto [success, text, name, isCustom, args, isOptional, index] = GetParam();
    auto res = logp::pField()(text, 0);
    if (success)
    {
        ASSERT_TRUE(res.success());
        ASSERT_EQ(name, res.value().name.value);
        ASSERT_EQ(args, res.value().args);
        ASSERT_EQ(isOptional, res.value().optional);
    }
    else
    {
        ASSERT_FALSE(res.success());
    }
    ASSERT_EQ(index, res.index());
}

INSTANTIATE_TEST_SUITE_P(
    Parses,
    LogparFieldParserTest,
    ::testing::Values(
        FieldParserT(true, "<ecs_.name>", "ecs_.name", false, {}, false, 11),
        FieldParserT(true, "<~ecs_.name>", "~ecs_.name", true, {}, false, 12),
        FieldParserT(true, "<ecs_.name/0/1/2>", "ecs_.name", false, {"0", "1", "2"}, false, 17),
        FieldParserT(true, "<~ecs_.name/0/1/2>", "~ecs_.name", true, {"0", "1", "2"}, false, 18),
        FieldParserT(true, "<ecs_.name//1//3//>leftover", "ecs_.name", false, {"", "1", "", "3", "", ""}, false, 19),
        FieldParserT(true, "<~ecs_.name//1//3//>leftover", "~ecs_.name", true, {"", "1", "", "3", "", ""}, false, 20),
        FieldParserT(true, "<~>", "~", true, {}, false, 3),
        FieldParserT(true, "<~//1//3//>", "~", true, {"", "1", "", "3", "", ""}, false, 11),
        FieldParserT(true, "<_name>", "_name", true, {}, false, 7),
        FieldParserT(true, "<~_name>", "~_name", true, {}, false, 8),
        FieldParserT(false, "<n'me>", {}, {}, {}, {}, 2),
        FieldParserT(false, "<~n'me>", {}, {}, {}, {}, 3),
        FieldParserT(true, R"(<name//1/\/2/\\3/4\>>)", "name", false, {"", "1", "/2", "\\3", "4>"}, false, 21),
        FieldParserT(true, "<?name>", "name", false, {}, true, 7),
        FieldParserT(true, "<?~name>", "~name", true, {}, true, 8),
        FieldParserT(true, "<?name//1//2//>", "name", false, {"", "1", "", "2", "", ""}, true, 15),
        FieldParserT(true, "<?~name//1//2//>", "~name", true, {"", "1", "", "2", "", ""}, true, 16),
        FieldParserT(true, "<@name>", "@name", false, {}, false, 7),
        FieldParserT(true, "<~@name>", "~@name", true, {}, false, 8),
        FieldParserT(true, "<?@name>", "@name", false, {}, true, 8),
        FieldParserT(true, "<?~@name>", "~@name", true, {}, true, 9)));

using LiteralParserT = std::tuple<bool, std::string, std::string, size_t>;
class LogparLiteralParserTest : public ::testing::TestWithParam<LiteralParserT>
{
};

TEST_P(LogparLiteralParserTest, Parses)
{
    auto [success, text, literal, index] = GetParam();
    auto res = logp::pLiteral()(text, 0);
    if (success)
    {
        ASSERT_TRUE(res.success());
        ASSERT_EQ(literal, res.value().value);
    }
    else
    {
        ASSERT_FALSE(res.success());
    }
    ASSERT_EQ(index, res.index());
}

INSTANTIATE_TEST_SUITE_P(Parses,
                         LogparLiteralParserTest,
                         ::testing::Values(LiteralParserT(true, "literal", "literal", 7),
                                           LiteralParserT(true, "lit<eral", "lit", 3),
                                           LiteralParserT(true, R"(lit\<eral)", "lit<eral", 9),
                                           LiteralParserT(true, R"(lit\<eral>)", "lit<eral>", 10),
                                           LiteralParserT(true, R"(lit\<eral\>)", "lit<eral", 9),
                                           LiteralParserT(true, R"(\<field>\>)", "<field>", 8),
                                           LiteralParserT(true, R"(\<field>>)", "<field>>", 9),
                                           LiteralParserT(true, "lit>eral", "lit>eral", 8),
                                           LiteralParserT(true, R"(lit\>eral)", "lit", 3),
                                           LiteralParserT(true, R"(lit\\eral)", R"(lit\eral)", 9),
                                           LiteralParserT(true, "lit(?eral)", "lit", 3),
                                           LiteralParserT(true, R"(lit\(\?eral\))", "lit(?eral)", 13),
                                           LiteralParserT(false, "", {}, 0),
                                           LiteralParserT(false, "<asdf", {}, 0),
                                           LiteralParserT(false, "?asdf", {}, 0)));

using ChoiceParserT = std::tuple<bool, std::string, logp::Choice, size_t>;
class LogparChoiceParserTest : public ::testing::TestWithParam<ChoiceParserT>
{
};

TEST_P(LogparChoiceParserTest, Parses)
{
    auto [success, text, choice, index] = GetParam();
    auto res = logp::pChoice()(text, 0);
    if (success)
    {
        ASSERT_TRUE(res.success());
        ASSERT_EQ(choice, res.value());
    }
    else
    {
        ASSERT_FALSE(res.success());
    }
    ASSERT_EQ(index, res.index());
}

INSTANTIATE_TEST_SUITE_P(
    Parses,
    LogparChoiceParserTest,
    ::testing::Values(
        ChoiceParserT(true, "<choice1>?<choice2>", {{{"choice1"}, {}, false}, {{"choice2"}, {}, false}}, 19),
        ChoiceParserT(false, "<?choice1>?<choice2>", {}, 0),
        ChoiceParserT(false, "<choice1>?<?choice2>", {}, 0),
        ChoiceParserT(false, "<?choice1>?<?choice2>", {}, 0),
        ChoiceParserT(true, "<choice1>?<choice2>?<choice3>", {{{"choice1"}, {}, false}, {{"choice2"}, {}, false}}, 19),
        ChoiceParserT(false, R"(<choice1>\?<choice2>)", {}, 0)));

using ExpressionParserT = std::tuple<bool, std::string, parsec::Values<logp::ParserInfo>, size_t>;
class LogparExpressionParserTest : public ::testing::TestWithParam<ExpressionParserT>
{
};

TEST_P(LogparExpressionParserTest, Parses)
{
    auto [success, text, values, index] = GetParam();
    auto res = logp::pExpr()(text, 0);

    if (success)
    {
        ASSERT_TRUE(res.success());
        ASSERT_EQ(values, res.value());
    }
    else
    {
        ASSERT_FALSE(res.success());
    }
    ASSERT_EQ(index, res.index());
}

INSTANTIATE_TEST_SUITE_P(
    Parses,
    LogparExpressionParserTest,
    ::testing::Values(ExpressionParserT(true, "literal", {logp::Literal {"literal"}}, 7),
                      ExpressionParserT(true,
                                        R"(literal\<literal><field>)",
                                        {logp::Literal {"literal<literal>"},
                                         logp::Field {logp::FieldName {"field"}, {}, false}},
                                        24),
                      ExpressionParserT(true, "<field>", {logp::Field {logp::FieldName {"field"}, {}, false}}, 7),
                      ExpressionParserT(true,
                                        "literal<field>literal",
                                        {logp::Literal {"literal"},
                                         logp::Field {logp::FieldName {"field"}, {}, false},
                                         logp::Literal {"literal"}},
                                        21),
                      ExpressionParserT(true,
                                        "literal<field>)leftover",
                                        {logp::Literal {"literal"}, logp::Field {logp::FieldName {"field"}, {}, false}},
                                        14),
                      ExpressionParserT(true,
                                        "literal<field>literal<choice1>?<choice2>",
                                        {logp::Literal {"literal"},
                                         logp::Field {logp::FieldName {"field"}, {}, false},
                                         logp::Literal {"literal"},
                                         logp::Choice {{{"choice1"}, {}, false}, {{"choice2"}, {}, false}}},
                                        40),
                      ExpressionParserT(true,
                                        "<choice1>?<choice2><field>literal",
                                        {logp::Choice {{{"choice1"}, {}, false}, {{"choice2"}, {}, false}},
                                         logp::Field {logp::FieldName {"field"}, {}, false},
                                         logp::Literal {"literal"}},
                                        33)));

using GroupParserT = std::tuple<bool, std::string, logp::Group, size_t>;
class LogparGroupParserTest : public ::testing::TestWithParam<GroupParserT>
{
};

TEST_P(LogparGroupParserTest, Parses)
{
    auto [success, text, group, index] = GetParam();
    auto res = logp::pGroup()(text, 0);

    if (success)
    {
        ASSERT_TRUE(res.success());
        ASSERT_EQ(group, res.value());
    }
    else
    {
        ASSERT_FALSE(res.success());
    }
    ASSERT_EQ(index, res.index());
}

INSTANTIATE_TEST_SUITE_P(
    Parses,
    LogparGroupParserTest,
    ::testing::Values(
        GroupParserT(true, "(?literal)", {{logp::Literal {"literal"}}}, 10),
        GroupParserT(true, "(?<field>)", {{logp::Field {logp::FieldName {"field"}, {}, false}}}, 10),
        GroupParserT(
            true, "(?<choice1>?<choice2>)", {{logp::Choice {{{"choice1"}, {}, false}, {{"choice2"}, {}, false}}}}, 22),
        GroupParserT(true,
                     "(?<field>literal<choice1>?<choice2>)",
                     {{logp::Field {logp::FieldName {"field"}, {}, false},
                       logp::Literal {"literal"},
                       logp::Choice {{{"choice1"}, {}, false}, {{"choice2"}, {}, false}}}},
                     36),
        GroupParserT(true, "(?literal)leftover", {{logp::Literal {"literal"}}}, 10),
        GroupParserT(
            true, "(?literal(?literal))", {{logp::Literal {"literal"}, logp::Group {{logp::Literal {"literal"}}}}}, 20),
        GroupParserT(true,
                     "(?literal<field><choice1>?<choice2>(?literal<field><choice1>?<choice2>))",
                     {{logp::Literal {"literal"},
                       logp::Field {logp::FieldName {"field"}, {}, false},
                       logp::Choice {{{"choice1"}, {}, false}, {{"choice2"}, {}, false}},
                       logp::Group {{logp::Literal {"literal"},
                                     logp::Field {logp::FieldName {"field"}, {}, false},
                                     logp::Choice {{{"choice1"}, {}, false}, {{"choice2"}, {}, false}}}}}},
                     72),
        GroupParserT(true,
                     "(?(?(?(?literal))))",
                     {{logp::Group {{logp::Group {{logp::Group {{logp::Literal {"literal"}}}}}}}}},
                     19),
        GroupParserT(true,
                     "(?literal(?literal)(?literal)(?literal))",
                     {{logp::Literal {"literal"},
                       logp::Group {{logp::Literal {"literal"}}},
                       logp::Group {{logp::Literal {"literal"}}},
                       logp::Group {{logp::Literal {"literal"}}}}},
                     40),
        GroupParserT(false, "(?literal", {}, 0),
        GroupParserT(false, "literal", {}, 0),
        GroupParserT(false, "(?literal(?literal)", {}, 0),
        GroupParserT(false, "(?literal(?literal)(?literal)(?literal)", {}, 0),
        GroupParserT(false, "(?)", {}, 0),
        GroupParserT(true,
                     "(?<?~opt/text> (?<long>?<~/literal/->))",
                     {{logp::Field {logp::FieldName {"~opt"}, {"text"}, true},
                       logp::Literal {" "},
                       logp::Group {{logp::Choice {{{"long"}, {}, false}, {{"~"}, {"literal", "-"}, false}}}}}},
                     39)));

using LogparParserT = std::tuple<bool, std::string, std::list<logp::ParserInfo>, size_t>;
class LogparLogparParserTest : public ::testing::TestWithParam<LogparParserT>
{
};

TEST_P(LogparLogparParserTest, Parses)
{
    auto [success, text, parserInfos, index] = GetParam();
    auto res = logp::pLogpar()(text, 0);

    if (success)
    {
        ASSERT_TRUE(res.success());
        ASSERT_EQ(parserInfos, res.value());
    }
    else
    {
        ASSERT_FALSE(res.success());
    }
    ASSERT_EQ(index, res.index());
}

INSTANTIATE_TEST_SUITE_P(
    Parses,
    LogparLogparParserTest,
    ::testing::Values(
        LogparParserT(true, "literal", {logp::Literal {"literal"}}, 7),
        LogparParserT(true, "<field>", {logp::Field {logp::FieldName {"field"}, {}, false}}, 7),
        LogparParserT(
            true, "<choice1>?<choice2>", {logp::Choice {{{"choice1"}, {}, false}, {{"choice2"}, {}, false}}}, 19),
        LogparParserT(true, "(?literal)", {logp::Group {{logp::Literal {"literal"}}}}, 10),
        LogparParserT(true,
                      "literal<field><choice1>?<choice2>(?literal)",
                      {logp::Literal {"literal"},
                       logp::Field {logp::FieldName {"field"}, {}, false},
                       logp::Choice {{{"choice1"}, {}, false}, {{"choice2"}, {}, false}},
                       logp::Group {{logp::Literal {"literal"}}}},
                      43),
        LogparParserT(false, "literal?leftover", {}, 7),
        LogparParserT(true,
                      "[date] <~host> <text>(?<~opt/text>|):<~>",
                      {logp::Literal {"[date] "},
                       logp::Field {logp::FieldName {"~host"}, {}, false},
                       logp::Literal {" "},
                       logp::Field {logp::FieldName {"text"}, {}, false},
                       logp::Group {{logp::Field {logp::FieldName {"~opt"}, {"text"}, false}, logp::Literal {"|"}}},
                       logp::Literal {":"},
                       logp::Field {logp::FieldName {"~"}, {}, false}},
                      40)));

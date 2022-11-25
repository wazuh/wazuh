#include "logpar_test.hpp"

#include <numeric>
#include <stdexcept>

#include <fmt/format.h>

using namespace hlp;

TEST(LogparTest, Builds)
{
    auto config = logpar_test::getConfig();
    ASSERT_NO_THROW(logpar::Logpar logpar(config));
}

TEST(LogparTest, BuildsNotObjectConfig)
{
    json::Json config {"\"config\""};
    ASSERT_THROW(logpar::Logpar logpar(config), std::runtime_error);
}

TEST(LogparTest, BuildsEmptyConfig)
{
    json::Json config {"{}"};
    ASSERT_THROW(logpar::Logpar logpar(config), std::runtime_error);
}

TEST(LogparTest, BuildLogparExpression)
{
    auto logpar = logpar_test::getLogpar();
    auto text = "(?literal<text>:)<~custom/long><~>";
    ASSERT_NO_THROW(logpar.build(text));
}

TEST(LogparTest, BuildLogparMalformedExpression)
{
    auto logpar = logpar_test::getLogpar();
    auto text = "literal<text>:<~custom/long><~";
    ASSERT_THROW(logpar.build(text), std::runtime_error);
}

TEST(LogparTest, BuildLogparMissingEndToken)
{
    auto logpar = logpar_test::getLogpar();
    auto text = "literal<text><~custom/long><~>";
    ASSERT_THROW(logpar.build(text), std::runtime_error);
}

TEST(LogparTest, BuildLogparIncorrectParserArgs)
{
    auto logpar = logpar_test::getLogpar();
    auto text = "literal<text>:<~custom/long/error_arg><~>";
    ASSERT_THROW(logpar.build(text), std::runtime_error);
}

TEST(LogparTest, BuildLogparAndParse)
{
    // Use cases
    auto logpar = logpar_test::getLogpar();
    std::list<std::tuple<unsigned, bool, std::string, std::string, json::Json>> useCases {
        {1, true, "literal", "literal", {}},
        {2, false, "literal", "literalleftover", {}},
        {3, false, "literal", "lieral", {}},
        {4, true, "<text>", "some text", logpar_test::J(R"({"text":"some text"})")},
        {5, true, "<text>end", "some textend", logpar_test::J(R"({"text":"some text"})")},
        {6,
         true,
         "lit<text>:<~a/long>",
         "literal:1",
         logpar_test::J(R"({"text":"eral","~a":1})")},
        {7,
         true,
         "lit<text>:<~a/long><~>",
         "literal:1ignored",
         logpar_test::J(R"({"text":"eral","~a":1})")},
        {8,
         true,
         "lit<text>:<~a/long><~>:(?<~opt/text>)",
         "literal:1ignored:",
         logpar_test::J(R"({"text":"eral","~a":1})")},
        {9,
         true,
         "lit<text>:<~a/long><~>:(?<~opt/text>)",
         "literal:1ignored:optional",
         logpar_test::J(R"({"text":"eral","~a":1,"~opt":"optional"})")},
        {10, true, "<long>?<~/literal/->", "15", logpar_test::J(R"({"long":15})")},
        {11, true, "<long>?<~/literal/->", "-", {}},
        {12,
         true,
         "[date] <~host> <text>:(?<~opt/text> (?<long>?<~/literal/->))",
         "[date] host text:",
         logpar_test::J(R"({"~host":"host","text":"text"})")},
        {13,
         true,
         "[date] <~host> <text>:(?<?~opt/text> (?<long>?<~/literal/->))",
         "[date] host text: ",
         logpar_test::J(R"({"~host":"host","text":"text"})")},
        {14,
         true,
         "[date] <~host> <text>:(?<?~opt/text> (?<long>?<~/literal/->))",
         "[date] host text:opt ",
         logpar_test::J(R"({"~host":"host","text":"text", "~opt":"opt"})")},
        {15,
         false,
         "[date] <~host> <text>:(?<?~opt/text> (?<long>?<~/literal/->))",
         "[date] host text:opt",
         {}},
        {16,
         true,
         "[date] <~host> <text>:(?<?~opt/text> (?<long>?<~/literal/->))",
         "[date] host text:opt 1",
         logpar_test::J(R"({"~host":"host","text":"text","~opt":"opt","long":1})")},
        {17,
         true,
         "[date] <~host> <text>:(?<?~opt/text> (?<long>?<~/literal/->))",
         "[date] host text:opt -",
         logpar_test::J(R"({"~host":"host","text":"text","~opt":"opt"})")},
    };

    // TEST
    for (auto& [n, success, expr, input, expected] : useCases)
    {
        auto parser = logpar.build(expr);
        auto parseResult = parser(input, 0);
        if (success)
        {
            ASSERT_TRUE(parseResult);
            ASSERT_EQ(parseResult.value(), expected);
        }
        else
        {
            ASSERT_FALSE(parseResult);
        }
    }
}

TEST(LogparParserTest, Field)
{
    // Use cases
    using caseT = logpar::parser::Field;
    using resultT = parsec::Result<caseT>;
    std::list<std::tuple<bool,
                         std::string,
                         std::string,
                         bool,
                         std::list<std::string>,
                         bool,
                         size_t>>
        useCases {};
    std::string name {};
    std::string nameCustom;
    std::string argsStr {};
    std::list<std::string> args {};
    std::string text {};

    // Case 1 <ecs_.name>
    name = fmt::format("ecs{}{}name",
                       logpar::syntax::EXPR_FIELD_EXTENDED_CHARS,
                       logpar::syntax::EXPR_FIELD_SEP);
    argsStr = "";
    args = {};
    text = fmt::format(
        "{}{}{}{}", logpar::syntax::EXPR_BEGIN, name, argsStr, logpar::syntax::EXPR_END);
    useCases.push_back({true, text, name, false, args, false, text.size()});

    // Case 2 <~ecs_.name>
    nameCustom = name;
    nameCustom.insert(0, 1, logpar::syntax::EXPR_CUSTOM_FIELD);
    text = fmt::format("{}{}{}{}",
                       logpar::syntax::EXPR_BEGIN,
                       nameCustom,
                       argsStr,
                       logpar::syntax::EXPR_END);
    useCases.push_back({true, text, nameCustom, true, args, false, text.size()});

    // Case 3 <ecs_.name/0/1/2>
    argsStr = fmt::format("{}0{}1{}2",
                          logpar::syntax::EXPR_ARG_SEP,
                          logpar::syntax::EXPR_ARG_SEP,
                          logpar::syntax::EXPR_ARG_SEP);
    args = {"0", "1", "2"};
    text = fmt::format(
        "{}{}{}{}", logpar::syntax::EXPR_BEGIN, name, argsStr, logpar::syntax::EXPR_END);
    useCases.push_back({true, text, name, false, args, false, text.size()});

    // Case 4 <~ecs_.name/0/1/2>
    nameCustom = name;
    nameCustom.insert(0, 1, logpar::syntax::EXPR_CUSTOM_FIELD);
    text = fmt::format("{}{}{}{}",
                       logpar::syntax::EXPR_BEGIN,
                       nameCustom,
                       argsStr,
                       logpar::syntax::EXPR_END);
    useCases.push_back({true, text, nameCustom, true, args, false, text.size()});

    // Case 5 <ecs_.name//1//3//>leftover
    argsStr = fmt::format("{}{}1{}{}3{}{}",
                          logpar::syntax::EXPR_ARG_SEP,
                          logpar::syntax::EXPR_ARG_SEP,
                          logpar::syntax::EXPR_ARG_SEP,
                          logpar::syntax::EXPR_ARG_SEP,
                          logpar::syntax::EXPR_ARG_SEP,
                          logpar::syntax::EXPR_ARG_SEP);
    args = {"", "1", "", "3", "", ""};
    text = fmt::format(
        "{}{}{}{}", logpar::syntax::EXPR_BEGIN, name, argsStr, logpar::syntax::EXPR_END);
    auto size = text.size();
    text += "leftover";
    useCases.push_back({true, text, name, false, args, false, size});

    // Case 6 <~ecs_.name//1//3//>leftover
    nameCustom = name;
    nameCustom.insert(0, 1, logpar::syntax::EXPR_CUSTOM_FIELD);
    text = fmt::format("{}{}{}{}",
                       logpar::syntax::EXPR_BEGIN,
                       nameCustom,
                       argsStr,
                       logpar::syntax::EXPR_END);
    size = text.size();
    text += "leftover";
    useCases.push_back({true, text, nameCustom, true, args, false, size});

    // Case 7 <~>
    nameCustom = "";
    nameCustom.insert(0, 1, logpar::syntax::EXPR_CUSTOM_FIELD);
    text = fmt::format("{}{}{}{}",
                       logpar::syntax::EXPR_BEGIN,
                       nameCustom,
                       argsStr,
                       logpar::syntax::EXPR_END);
    useCases.push_back({true, text, nameCustom, true, args, false, text.size()});

    // Case 8 <~//1//3//>
    text = fmt::format("{}{}{}{}",
                       logpar::syntax::EXPR_BEGIN,
                       nameCustom,
                       argsStr,
                       logpar::syntax::EXPR_END);
    useCases.push_back({true, text, nameCustom, true, args, false, text.size()});

    // Case 9 <_name>
    name = fmt::format("{}name", logpar::syntax::EXPR_FIELD_EXTENDED_CHARS);
    argsStr = "";
    args = {};
    text = fmt::format(
        "{}{}{}{}", logpar::syntax::EXPR_BEGIN, name, argsStr, logpar::syntax::EXPR_END);
    useCases.push_back({false, text, name, false, args, false, 1});

    // Case 10 <~_name>
    nameCustom = name;
    nameCustom.insert(0, 1, logpar::syntax::EXPR_CUSTOM_FIELD);
    text = fmt::format("{}{}{}{}",
                       logpar::syntax::EXPR_BEGIN,
                       nameCustom,
                       argsStr,
                       logpar::syntax::EXPR_END);
    useCases.push_back({false, text, nameCustom, true, args, false, 2});

    // Case 11 <n@me>
    name = "n@me";
    text = fmt::format(
        "{}{}{}{}", logpar::syntax::EXPR_BEGIN, name, argsStr, logpar::syntax::EXPR_END);
    useCases.push_back({false, text, name, false, args, false, 2});

    // Case 12 <~n@me>
    nameCustom = name;
    nameCustom.insert(0, 1, logpar::syntax::EXPR_CUSTOM_FIELD);
    text = fmt::format("{}{}{}{}",
                       logpar::syntax::EXPR_BEGIN,
                       nameCustom,
                       argsStr,
                       logpar::syntax::EXPR_END);
    useCases.push_back({false, text, nameCustom, true, args, false, 3});

    // Case 13 <name//1/\/2/\\3/4\>>
    name = "name";
    argsStr = fmt::format("{}{}1{}{}{}2{}{}{}3{}4{}>",
                          logpar::syntax::EXPR_ARG_SEP,
                          logpar::syntax::EXPR_ARG_SEP,
                          logpar::syntax::EXPR_ARG_SEP,
                          logpar::syntax::EXPR_ESCAPE,
                          logpar::syntax::EXPR_ARG_SEP,
                          logpar::syntax::EXPR_ARG_SEP,
                          logpar::syntax::EXPR_ESCAPE,
                          logpar::syntax::EXPR_ESCAPE,
                          logpar::syntax::EXPR_ARG_SEP,
                          logpar::syntax::EXPR_ESCAPE);
    args = {"", "1", "/2", "\\3", "4>"};
    text = fmt::format(
        "{}{}{}{}", logpar::syntax::EXPR_BEGIN, name, argsStr, logpar::syntax::EXPR_END);
    useCases.push_back({true, text, name, false, args, false, text.size()});

    // Case 14 <?name>
    name = "name";
    args = {};
    text = "<?name>";
    useCases.push_back({true, text, name, false, args, true, text.size()});

    // Case 15 <?~name>
    name = "~name";
    args = {};
    text = "<?~name>";
    useCases.push_back({true, text, name, true, args, true, text.size()});

    // Case 16 <?name//1//2//>
    name = "name";
    args = {"", "1", "", "2", "", ""};
    text = "<?name//1//2//>";
    useCases.push_back({true, text, name, false, args, true, text.size()});

    // Case 17 <?~name//1//2//>
    name = "~name";
    args = {"", "1", "", "2", "", ""};
    text = "<?~name//1//2//>";
    useCases.push_back({true, text, name, true, args, true, text.size()});

    // Test
    int caseN = 1;
    for (auto [success, t, n, c, a, o, i] : useCases)
    {
        auto res = logpar::parser::pField()(t, 0);
        if (success)
        {
            ASSERT_TRUE(res.success());
            ASSERT_EQ(n, res.value().name.value);
            ASSERT_EQ(c, res.value().name.custom);
            ASSERT_EQ(a, res.value().args);
            ASSERT_EQ(o, res.value().optional);
        }
        else
        {
            ASSERT_FALSE(res.success());
        }
        ASSERT_EQ(i, res.index);
        ASSERT_EQ(t, res.text);
        caseN++;
    }
}

TEST(LogparParserTest, Literal)
{
    // Use cases
    using caseT = logpar::parser::Literal;
    using resultT = parsec::Result<caseT>;
    std::list<std::tuple<bool, std::string, std::string, size_t>> useCases {};
    std::string literal {};
    std::string text {};

    // Case 1 literal
    literal = "literal";
    text = literal;
    useCases.push_back({true, text, literal, text.size()});

    // Case 2 lit<eral
    literal = "lit";
    text = fmt::format("{}{}eral", literal, logpar::syntax::EXPR_BEGIN);
    useCases.push_back({true, text, literal, 3});

    // Case 3 lit\<eral
    literal = fmt::format("lit{}eral", logpar::syntax::EXPR_BEGIN);
    text = fmt::format(
        "lit{}{}eral", logpar::syntax::EXPR_ESCAPE, logpar::syntax::EXPR_BEGIN);
    useCases.push_back({true, text, literal, text.size()});

    // Case 4 lit\\eral
    literal = fmt::format("lit{}eral", logpar::syntax::EXPR_ESCAPE);
    text = fmt::format(
        "lit{}{}eral", logpar::syntax::EXPR_ESCAPE, logpar::syntax::EXPR_ESCAPE);
    useCases.push_back({true, text, literal, text.size()});

    // Case 5 lit(?eral)
    literal = "lit";
    text = fmt::format("{}{}{}eral{}",
                       literal,
                       logpar::syntax::EXPR_GROUP_BEGIN,
                       logpar::syntax::EXPR_OPT,
                       logpar::syntax::EXPR_GROUP_END);
    useCases.push_back({true, text, literal, 3});

    // Case 6 lit\(\?eral)
    literal = fmt::format(
        "lit{}{}eral", logpar::syntax::EXPR_GROUP_BEGIN, logpar::syntax::EXPR_OPT);
    text = fmt::format("lit{}{}{}{}eral{}",
                       logpar::syntax::EXPR_ESCAPE,
                       logpar::syntax::EXPR_GROUP_BEGIN,
                       logpar::syntax::EXPR_ESCAPE,
                       logpar::syntax::EXPR_OPT,
                       logpar::syntax::EXPR_GROUP_END);
    useCases.push_back({true, text, literal, text.size() - 1});

    // Case 7
    text = "";
    useCases.push_back({false, text, "", 0});

    // Case 8 <asdf
    text = fmt::format("{}asdf", logpar::syntax::EXPR_BEGIN);
    useCases.push_back({false, text, "", 0});

    // Case 9 ?asdf
    text = fmt::format("{}asdf", logpar::syntax::EXPR_OPT);
    useCases.push_back({false, text, "", 0});

    // Test
    int caseN = 1;
    for (auto [success, t, l, i] : useCases)
    {
        auto res = logpar::parser::pLiteral()(t, 0);
        if (success)
        {
            ASSERT_TRUE(res.success());
            ASSERT_EQ(l, res.value().value);
        }
        else
        {
            ASSERT_FALSE(res.success());
        }
        ASSERT_EQ(i, res.index);
        ASSERT_EQ(t, res.text);
        caseN++;
    }
}

TEST(LogparParserTest, Choice)
{
    // Use cases
    using caseT = logpar::parser::Choice;
    using resultT = parsec::Result<caseT>;
    std::list<std::tuple<bool, std::string, logpar::parser::Choice, size_t>> useCases {};
    std::string text {};
    logpar::parser::Choice choice {};

    // Case 1 <choice1>?<choice2>
    text = fmt::format("{}choice1{}{}{}choice2{}",
                       logpar::syntax::EXPR_BEGIN,
                       logpar::syntax::EXPR_END,
                       logpar::syntax::EXPR_OPT,
                       logpar::syntax::EXPR_BEGIN,
                       logpar::syntax::EXPR_END);
    choice = {{{"choice1", false}, {}, false}, {{"choice2", false}, {}, false}};
    useCases.push_back({true, text, choice, text.size()});

    // Case 2 <?choice1>?<choice2>
    text = fmt::format("{}{}choice1{}{}{}choice2{}",
                       logpar::syntax::EXPR_BEGIN,
                       logpar::syntax::EXPR_OPT,
                       logpar::syntax::EXPR_END,
                       logpar::syntax::EXPR_OPT,
                       logpar::syntax::EXPR_BEGIN,
                       logpar::syntax::EXPR_END);
    useCases.push_back({false, text, {}, 0});

    // Case 3 <choice1>?<?choice2>
    text = fmt::format("{}choice1{}{}{}{}choice2{}",
                       logpar::syntax::EXPR_BEGIN,
                       logpar::syntax::EXPR_END,
                       logpar::syntax::EXPR_OPT,
                       logpar::syntax::EXPR_BEGIN,
                       logpar::syntax::EXPR_OPT,
                       logpar::syntax::EXPR_END);
    useCases.push_back({false, text, {}, 0});

    // Case 4 <?choice1>?<?choice2>
    text = fmt::format("{}{}choice1{}{}{}{}choice2{}",
                       logpar::syntax::EXPR_BEGIN,
                       logpar::syntax::EXPR_OPT,
                       logpar::syntax::EXPR_END,
                       logpar::syntax::EXPR_OPT,
                       logpar::syntax::EXPR_BEGIN,
                       logpar::syntax::EXPR_OPT,
                       logpar::syntax::EXPR_END);
    useCases.push_back({false, text, {}, 0});

    // Case 5 <choice1>?<choice2>?<choice3>
    text = fmt::format("{}choice1{}{}{}choice2{}",
                       logpar::syntax::EXPR_BEGIN,
                       logpar::syntax::EXPR_END,
                       logpar::syntax::EXPR_OPT,
                       logpar::syntax::EXPR_BEGIN,
                       logpar::syntax::EXPR_END);
    auto size = text.size();
    text += fmt::format("{}{}choice3{}",
                        logpar::syntax::EXPR_OPT,
                        logpar::syntax::EXPR_BEGIN,
                        logpar::syntax::EXPR_END);
    choice = {{{"choice1", false}, {}, false}, {{"choice2", false}, {}, false}};
    useCases.push_back({true, text, choice, size});

    // Case 6 <choice1>\?<choice2>
    text = fmt::format("{}choice1{}{}{}{}choice2{}",
                       logpar::syntax::EXPR_BEGIN,
                       logpar::syntax::EXPR_END,
                       logpar::syntax::EXPR_ESCAPE,
                       logpar::syntax::EXPR_OPT,
                       logpar::syntax::EXPR_BEGIN,
                       logpar::syntax::EXPR_END);
    useCases.push_back({false, text, {}, 0});

    // Test
    int caseN = 1;
    for (auto [success, t, c, i] : useCases)
    {
        auto res = logpar::parser::pChoice()(t, 0);
        if (success)
        {
            ASSERT_TRUE(res.success());
            ASSERT_EQ(c, res.value());
        }
        else
        {
            ASSERT_FALSE(res.success());
        }
        ASSERT_EQ(i, res.index);
        ASSERT_EQ(t, res.text);
        caseN++;
    }
}

TEST(LogparParserTest, Expression)
{
    // Use cases
    using caseT = logpar::parser::ParserInfo;
    using resultT = parsec::Result<parsec::Values<caseT>>;
    std::list<std::tuple<bool, std::string, parsec::Values<caseT>, size_t>> useCases {};
    std::string text {};
    parsec::Values<caseT> values {};

    // Case 1 literal
    text = "literal";
    values.push_back(logpar::parser::Literal {text});
    useCases.push_back({true, text, values, text.size()});

    // Case 2 <field>
    text = fmt::format("{}field{}", logpar::syntax::EXPR_BEGIN, logpar::syntax::EXPR_END);
    values.clear();
    values.push_back(
        logpar::parser::Field {logpar::parser::FieldName {"field", false}, {}, false});
    useCases.push_back({true, text, values, text.size()});

    // Case 3 literal<field>literal
    text = fmt::format(
        "literal{}field{}literal", logpar::syntax::EXPR_BEGIN, logpar::syntax::EXPR_END);
    values.clear();
    values.push_back(logpar::parser::Literal {"literal"});
    values.push_back(
        logpar::parser::Field {logpar::parser::FieldName {"field", false}, {}, false});
    values.push_back(logpar::parser::Literal {"literal"});
    useCases.push_back({true, text, values, text.size()});

    // Case 4 literal<field>)leftover
    text = fmt::format("literal{}field{}{}",
                       logpar::syntax::EXPR_BEGIN,
                       logpar::syntax::EXPR_END,
                       logpar::syntax::EXPR_GROUP_END);
    auto size = text.size() - 1;
    text += "leftover";
    useCases.push_back({true, text, {}, size});

    // Case 5 literal<field>literal<choice1>?<choice2>
    text = fmt::format("literal{}field{}literal{}choice1{}{}{}choice2{}",
                       logpar::syntax::EXPR_BEGIN,
                       logpar::syntax::EXPR_END,
                       logpar::syntax::EXPR_BEGIN,
                       logpar::syntax::EXPR_END,
                       logpar::syntax::EXPR_OPT,
                       logpar::syntax::EXPR_BEGIN,
                       logpar::syntax::EXPR_END);
    values.clear();
    values.push_back(logpar::parser::Literal {"literal"});
    values.push_back(
        logpar::parser::Field {logpar::parser::FieldName {"field", false}, {}, false});
    values.push_back(logpar::parser::Literal {"literal"});
    values.push_back(logpar::parser::Choice {{{"choice1", false}, {}, false},
                                             {{"choice2", false}, {}, false}});
    useCases.push_back({true, text, values, text.size()});

    // Case 6 <choice1>?<choice2><field>literal
    text = fmt::format("{}choice1{}{}{}choice2{}{}field{}literal",
                       logpar::syntax::EXPR_BEGIN,
                       logpar::syntax::EXPR_END,
                       logpar::syntax::EXPR_OPT,
                       logpar::syntax::EXPR_BEGIN,
                       logpar::syntax::EXPR_END,
                       logpar::syntax::EXPR_BEGIN,
                       logpar::syntax::EXPR_END);
    values.clear();
    values.push_back(logpar::parser::Choice {{{"choice1", false}, {}, false},
                                             {{"choice2", false}, {}, false}});
    values.push_back(
        logpar::parser::Field {logpar::parser::FieldName {"field", false}, {}, false});
    values.push_back(logpar::parser::Literal {"literal"});
    useCases.push_back({true, text, values, text.size()});

    // Test
    int caseN = 1;
    for (auto [success, t, v, i] : useCases)
    {
        auto res = logpar::parser::pExpr()(t, 0);
        if (success)
        {
            ASSERT_TRUE(res.success());
        }
        else
        {
            ASSERT_FALSE(res.success());
        }
        ASSERT_EQ(i, res.index);
        ASSERT_EQ(t, res.text);
        caseN++;
    }
}

TEST(LogparParserTest, Group)
{
    // Use cases
    using caseT = logpar::parser::Group;
    using resultT = parsec::Result<caseT>;
    std::list<std::tuple<bool, std::string, caseT, size_t>> useCases {};
    std::string text {};
    caseT group {};

    // Case 1 (?literal)
    text = fmt::format("{}{}literal{}",
                       logpar::syntax::EXPR_GROUP_BEGIN,
                       logpar::syntax::EXPR_OPT,
                       logpar::syntax::EXPR_GROUP_END);
    group = caseT {{logpar::parser::Literal {"literal"}}};
    useCases.push_back({true, text, group, text.size()});

    // Case 2 (?<field>)
    text = fmt::format("{}{}{}field{}{}",
                       logpar::syntax::EXPR_GROUP_BEGIN,
                       logpar::syntax::EXPR_OPT,
                       logpar::syntax::EXPR_BEGIN,
                       logpar::syntax::EXPR_END,
                       logpar::syntax::EXPR_GROUP_END);
    group = caseT {
        {logpar::parser::Field {logpar::parser::FieldName {"field", false}, {}, false}}};
    useCases.push_back({true, text, group, text.size()});

    // Case 3 (?<choice1>?<choice2>)
    text = fmt::format("{}{}{}choice1{}{}{}choice2{}{}",
                       logpar::syntax::EXPR_GROUP_BEGIN,
                       logpar::syntax::EXPR_OPT,
                       logpar::syntax::EXPR_BEGIN,
                       logpar::syntax::EXPR_END,
                       logpar::syntax::EXPR_OPT,
                       logpar::syntax::EXPR_BEGIN,
                       logpar::syntax::EXPR_END,
                       logpar::syntax::EXPR_GROUP_END);
    group = caseT {{logpar::parser::Choice {{{"choice1", false}, {}, false},
                                            {{"choice2", false}, {}, false}}}};
    useCases.push_back({true, text, group, text.size()});

    // Case 4 (?<field>literal<choice1>?<choice2>)
    text = fmt::format("{}{}{}field{}literal{}choice1{}{}{}choice2{}{}",
                       logpar::syntax::EXPR_GROUP_BEGIN,
                       logpar::syntax::EXPR_OPT,
                       logpar::syntax::EXPR_BEGIN,
                       logpar::syntax::EXPR_END,
                       logpar::syntax::EXPR_BEGIN,
                       logpar::syntax::EXPR_END,
                       logpar::syntax::EXPR_OPT,
                       logpar::syntax::EXPR_BEGIN,
                       logpar::syntax::EXPR_END,
                       logpar::syntax::EXPR_GROUP_END);
    group = caseT {
        {logpar::parser::Field {logpar::parser::FieldName {"field", false}, {}, false},
         logpar::parser::Literal {"literal"},
         logpar::parser::Choice {{{"choice1", false}, {}, false},
                                 {{"choice2", false}, {}, false}}}};
    useCases.push_back({true, text, group, text.size()});

    // Case 5 (?literal)leftover
    text = fmt::format("{}{}literal{}",
                       logpar::syntax::EXPR_GROUP_BEGIN,
                       logpar::syntax::EXPR_OPT,
                       logpar::syntax::EXPR_GROUP_END);
    auto size = text.size();
    text += "leftover";
    group = caseT {{logpar::parser::Literal {"literal"}}};
    useCases.push_back({true, text, group, size});

    // Case 6 (?literal(?literal))
    text = fmt::format("{}{}literal{}{}literal{}{}",
                       logpar::syntax::EXPR_GROUP_BEGIN,
                       logpar::syntax::EXPR_OPT,
                       logpar::syntax::EXPR_GROUP_BEGIN,
                       logpar::syntax::EXPR_OPT,
                       logpar::syntax::EXPR_GROUP_END,
                       logpar::syntax::EXPR_GROUP_END);
    group = caseT {{logpar::parser::Literal {"literal"},
                    caseT {{logpar::parser::Literal {"literal"}}}}};
    useCases.push_back({true, text, group, text.size()});

    // Case 7 (?literal<field><choice1>?<choice2>(?literal<field><choice1>?<choice2>))
    text = fmt::format("{}{}{}field{}literal{}choice1{}{}{}choice2{}{}{}{}field{}literal{"
                       "}choice1{}{}{}choice2{}{}{}",
                       logpar::syntax::EXPR_GROUP_BEGIN,
                       logpar::syntax::EXPR_OPT,
                       logpar::syntax::EXPR_BEGIN,
                       logpar::syntax::EXPR_END,
                       logpar::syntax::EXPR_BEGIN,
                       logpar::syntax::EXPR_END,
                       logpar::syntax::EXPR_OPT,
                       logpar::syntax::EXPR_BEGIN,
                       logpar::syntax::EXPR_END,
                       logpar::syntax::EXPR_GROUP_BEGIN,
                       logpar::syntax::EXPR_OPT,
                       logpar::syntax::EXPR_BEGIN,
                       logpar::syntax::EXPR_END,
                       logpar::syntax::EXPR_BEGIN,
                       logpar::syntax::EXPR_END,
                       logpar::syntax::EXPR_OPT,
                       logpar::syntax::EXPR_BEGIN,
                       logpar::syntax::EXPR_END,
                       logpar::syntax::EXPR_GROUP_END,
                       logpar::syntax::EXPR_GROUP_END);

    group = caseT {
        {logpar::parser::Field {logpar::parser::FieldName {"field", false}, {}, false},
         logpar::parser::Literal {"literal"},
         logpar::parser::Choice {{{"choice1", false}, {}, false},
                                 {{"choice2", false}, {}, false}},
         caseT {{logpar::parser::Field {
                     logpar::parser::FieldName {"field", false}, {}, false},
                 logpar::parser::Literal {"literal"},
                 logpar::parser::Choice {{{"choice1", false}, {}, false},
                                         {{"choice2", false}, {}, false}}}}}};

    useCases.push_back({true, text, group, text.size()});

    // Case 8 (?(?(?(?literal))))
    text = fmt::format("{}{}{}{}{}{}{}{}literal{}{}{}{}",
                       logpar::syntax::EXPR_GROUP_BEGIN,
                       logpar::syntax::EXPR_OPT,
                       logpar::syntax::EXPR_GROUP_BEGIN,
                       logpar::syntax::EXPR_OPT,
                       logpar::syntax::EXPR_GROUP_BEGIN,
                       logpar::syntax::EXPR_OPT,
                       logpar::syntax::EXPR_GROUP_BEGIN,
                       logpar::syntax::EXPR_OPT,
                       logpar::syntax::EXPR_GROUP_END,
                       logpar::syntax::EXPR_GROUP_END,
                       logpar::syntax::EXPR_GROUP_END,
                       logpar::syntax::EXPR_GROUP_END);
    group = caseT {{caseT {{caseT {{caseT {{logpar::parser::Literal {"literal"}}}}}}}}};
    useCases.push_back({true, text, group, text.size()});

    // Case 9 (?literal(?literal)(?literal)(?literal))
    text = fmt::format("{}{}literal{}{}literal{}{}{}literal{}{}{}literal{}{}",
                       logpar::syntax::EXPR_GROUP_BEGIN,
                       logpar::syntax::EXPR_OPT,
                       logpar::syntax::EXPR_GROUP_BEGIN,
                       logpar::syntax::EXPR_OPT,
                       logpar::syntax::EXPR_GROUP_END,
                       logpar::syntax::EXPR_GROUP_BEGIN,
                       logpar::syntax::EXPR_OPT,
                       logpar::syntax::EXPR_GROUP_END,
                       logpar::syntax::EXPR_GROUP_BEGIN,
                       logpar::syntax::EXPR_OPT,
                       logpar::syntax::EXPR_GROUP_END,
                       logpar::syntax::EXPR_GROUP_END);
    group = caseT {{logpar::parser::Literal {"literal"},
                    caseT {{logpar::parser::Literal {"literal"}}},
                    caseT {{logpar::parser::Literal {"literal"}}},
                    caseT {{logpar::parser::Literal {"literal"}}}}};
    useCases.push_back({true, text, group, text.size()});

    // Case 10 (?literal
    text = fmt::format(
        "{}{}literal", logpar::syntax::EXPR_GROUP_BEGIN, logpar::syntax::EXPR_OPT);
    useCases.push_back({false, text, {}, 0});

    // Case 11 literal
    text = "literal";
    useCases.push_back({false, text, {}, 0});

    // Case 12 (?literal(?literal)
    text = fmt::format("{}{}literal{}{}literal{}",
                       logpar::syntax::EXPR_GROUP_BEGIN,
                       logpar::syntax::EXPR_OPT,
                       logpar::syntax::EXPR_GROUP_BEGIN,
                       logpar::syntax::EXPR_OPT,
                       logpar::syntax::EXPR_GROUP_END);
    useCases.push_back({false, text, {}, 0});

    // Case 13 (?literal(?literal)(?literal)(?literal)
    text = fmt::format("{}{}literal{}{}literal{}{}{}literal{}{}{}literal{}",
                       logpar::syntax::EXPR_GROUP_BEGIN,
                       logpar::syntax::EXPR_OPT,
                       logpar::syntax::EXPR_GROUP_BEGIN,
                       logpar::syntax::EXPR_OPT,
                       logpar::syntax::EXPR_GROUP_END,
                       logpar::syntax::EXPR_GROUP_BEGIN,
                       logpar::syntax::EXPR_OPT,
                       logpar::syntax::EXPR_GROUP_END,
                       logpar::syntax::EXPR_GROUP_BEGIN,
                       logpar::syntax::EXPR_OPT,
                       logpar::syntax::EXPR_GROUP_END);
    useCases.push_back({false, text, {}, 0});

    // Case 14 (?)
    text = fmt::format("{}{}{}",
                       logpar::syntax::EXPR_GROUP_BEGIN,
                       logpar::syntax::EXPR_OPT,
                       logpar::syntax::EXPR_GROUP_END);
    useCases.push_back({false, text, {}, 0});

    // Case 15 (?<?~opt/text> (?<long>?<~/literal/->))
    text = "(?<?~opt/text> (?<long>?<~/literal/->))";
    group = caseT {
        {logpar::parser::Field {logpar::parser::FieldName {"~opt", true}, {"text"}, true},
         logpar::parser::Literal {" "},
         caseT {{logpar::parser::Choice {{{"long", false}, {}, false},
                                         {{"~", true}, {"literal", "-"}, false}}}}}};
    useCases.push_back({true, text, group, text.size()});

    // Test
    int caseN = 1;
    for (auto [success, t, g, i] : useCases)
    {
        auto res = logpar::parser::pGroup()(t, 0);
        if (success)
        {
            ASSERT_TRUE(res.success());
            auto resVal = res.value();
            ASSERT_EQ(g, res.value());
        }
        else
        {
            ASSERT_FALSE(res.success());
        }
        ASSERT_EQ(i, res.index);
        ASSERT_EQ(t, res.text);
        caseN++;
    }
}

TEST(LogparParserTest, Logpar)
{
    // Use cases
    using caseT = std::list<logpar::parser::ParserInfo>;
    using resultT = parsec::Result<caseT>;
    std::list<std::tuple<bool, std::string, caseT, size_t>> useCases {};
    std::string text {};
    caseT parserInfos {};

    // Case 1 literal
    text = "literal";
    parserInfos = {logpar::parser::Literal {"literal"}};
    useCases.push_back({true, text, parserInfos, text.size()});

    // Case 2 <field>
    text = fmt::format("{}field{}", logpar::syntax::EXPR_BEGIN, logpar::syntax::EXPR_END);
    parserInfos = {
        logpar::parser::Field {logpar::parser::FieldName {"field", false}, {}, false}};
    useCases.push_back({true, text, parserInfos, text.size()});

    // Case 3 <choice1>?<choice2>
    text = fmt::format("{}choice1{}{}{}choice2{}",
                       logpar::syntax::EXPR_BEGIN,
                       logpar::syntax::EXPR_END,
                       logpar::syntax::EXPR_OPT,
                       logpar::syntax::EXPR_BEGIN,
                       logpar::syntax::EXPR_END);
    parserInfos = {logpar::parser::Choice {
        logpar::parser::Field {logpar::parser::FieldName {"choice1", false}, {}, false},
        logpar::parser::Field {logpar::parser::FieldName {"choice2", false}, {}, false}}};
    useCases.push_back({true, text, parserInfos, text.size()});

    // Case 4 (?literal)
    text = fmt::format("{}{}literal{}",
                       logpar::syntax::EXPR_GROUP_BEGIN,
                       logpar::syntax::EXPR_OPT,
                       logpar::syntax::EXPR_GROUP_END);
    parserInfos = {logpar::parser::Group {{logpar::parser::Literal {"literal"}}}};
    useCases.push_back({true, text, parserInfos, text.size()});

    // Case 5 literal<field><choice1>?<choice2>(?literal)
    text = fmt::format("literal{}field{}{}choice1{}{}{}choice2{}{}{}literal{}",
                       logpar::syntax::EXPR_BEGIN,
                       logpar::syntax::EXPR_END,
                       logpar::syntax::EXPR_BEGIN,
                       logpar::syntax::EXPR_END,
                       logpar::syntax::EXPR_OPT,
                       logpar::syntax::EXPR_BEGIN,
                       logpar::syntax::EXPR_END,
                       logpar::syntax::EXPR_GROUP_BEGIN,
                       logpar::syntax::EXPR_OPT,
                       logpar::syntax::EXPR_GROUP_END);
    parserInfos = {
        logpar::parser::Literal {"literal"},
        logpar::parser::Field {logpar::parser::FieldName {"field", false}, {}, false},
        logpar::parser::Choice {
            logpar::parser::Field {
                logpar::parser::FieldName {"choice1", false}, {}, false},
            logpar::parser::Field {
                logpar::parser::FieldName {"choice2", false}, {}, false}},
        logpar::parser::Group {{logpar::parser::Literal {"literal"}}}};
    useCases.push_back({true, text, parserInfos, text.size()});

    // Case 6 literal?leftover
    text = "literal";
    auto size = text.size();
    text += fmt::format("{}leftover", logpar::syntax::EXPR_OPT);
    useCases.push_back({false, text, parserInfos, size});

    // Case 7 [date] <~host> <text>:(?<?~opt/text> (?<long>?<~/literal/->))

    // Test
    int caseN = 1;
    for (auto [success, t, v, i] : useCases)
    {
        auto res = logpar::parser::pLogpar()(t, 0);
        if (success)
        {
            ASSERT_TRUE(res.success());
            auto resVal = res.value();
            ASSERT_EQ(v, res.value());
        }
        else
        {
            ASSERT_FALSE(res.success());
        }
        ASSERT_EQ(i, res.index);
        ASSERT_EQ(t, res.text);
        caseN++;
    }
}

#include <gtest/gtest.h>

#include "builders/helperParser.hpp"

using namespace builder::builders;
using namespace builder::builders::parsers;
using namespace parsec;

/******************************************************************************/
/* Helper functions */
/******************************************************************************/
std::shared_ptr<Argument> val(const std::string& jsonStr = "")
{
    if (jsonStr.empty())
    {
        return std::make_shared<Value>();
    }

    return std::make_shared<Value>(json::Json(jsonStr.c_str()));
}

std::shared_ptr<Argument> ref(const std::string& dotPath)
{
    return std::make_shared<Reference>(dotPath);
}

/******************************************************************************/
/* Tests definitions */
/******************************************************************************/
template<typename T>
using ArgsT = std::tuple<std::string, Result<T>>;

template<typename T>
class Test : public ::testing::TestWithParam<ArgsT<T>>
{
};

template<typename T, typename CmpFn>
void parserTest(const std::string& input, Parser<T> parser, Result<T> expected, CmpFn&& cmpFn)
{
    auto result = parser(input, 0);
    // std::cout << parsec::detailedTrace(result.trace(), true) << std::endl;

    ASSERT_EQ(result.success(), expected.success());
    ASSERT_EQ(result.index(), expected.index());
    if (result.success())
    {
        cmpFn(result.value(), expected.value());
    }
}

using ParseHelperNameTest = Test<std::string>;
using NameT = ArgsT<std::string>;
TEST_P(ParseHelperNameTest, parse)
{
    auto [input, expected] = GetParam();
    auto cmpFn = [](const std::string& got, const std::string& expected)
    {
        ASSERT_EQ(got, expected);
    };
    parserTest<std::string>(input, getHelperNameParser(), expected, cmpFn);
}

using ParseHelperQuotedArgTest = Test<OpArg>;
using QuotedArgT = ArgsT<OpArg>;
TEST_P(ParseHelperQuotedArgTest, parse)
{
    auto [input, expected] = GetParam();
    auto cmpFn = [](const OpArg& got, const OpArg& expected)
    {
        ASSERT_TRUE(got->isValue());
        ASSERT_TRUE(expected->isValue());
        auto gotValue = std::static_pointer_cast<Value>(got);
        auto expectedValue = std::static_pointer_cast<Value>(expected);
        ASSERT_EQ(gotValue->value(), expectedValue->value());
    };
    parserTest<OpArg>(input, getHelperQuotedArgParser(), expected, cmpFn);
}

using ParseHelperRefArgTest = Test<OpArg>;
using RefArgT = ArgsT<OpArg>;
TEST_P(ParseHelperRefArgTest, parse)
{
    auto [input, expected] = GetParam();
    auto cmpFn = [](const OpArg& got, const OpArg& expected)
    {
        if (expected->isReference())
        {
            ASSERT_TRUE(got->isReference());
            auto gotRef = std::static_pointer_cast<Reference>(got);
            auto expectedRef = std::static_pointer_cast<Reference>(expected);
            ASSERT_EQ(gotRef->dotPath(), expectedRef->dotPath());
        }
        else
        {
            ASSERT_TRUE(got->isValue());
            auto gotValue = std::static_pointer_cast<Value>(got);
            auto expectedValue = std::static_pointer_cast<Value>(expected);
            ASSERT_EQ(gotValue->value(), expectedValue->value());
        }
    };
    parserTest<OpArg>(input, getHelperRefArgParser(), expected, cmpFn);
}

using ParseHelperJsonArgTest = Test<OpArg>;
using JsonArgT = ArgsT<OpArg>;
TEST_P(ParseHelperJsonArgTest, parse)
{
    auto [input, expected] = GetParam();
    auto cmpFn = [](const OpArg& got, const OpArg& expected)
    {
        ASSERT_TRUE(got->isValue());
        ASSERT_TRUE(expected->isValue());
        auto gotValue = std::static_pointer_cast<Value>(got);
        auto expectedValue = std::static_pointer_cast<Value>(expected);
        ASSERT_EQ(gotValue->value(), expectedValue->value());
    };
    parserTest<OpArg>(input, getHelperJsonArgParser(), expected, cmpFn);
}

using ParseHelperRawArgTest = Test<OpArg>;
using RawArgT = ArgsT<OpArg>;
TEST_P(ParseHelperRawArgTest, parse)
{
    auto [input, expected] = GetParam();
    auto cmpFn = [](const OpArg& got, const OpArg& expected)
    {
        ASSERT_TRUE(got->isValue());
        ASSERT_TRUE(expected->isValue());
        auto gotValue = std::static_pointer_cast<Value>(got);
        auto expectedValue = std::static_pointer_cast<Value>(expected);
        ASSERT_TRUE(gotValue->value().isString() || gotValue->value().isNull());
        ASSERT_EQ(gotValue->value(), expectedValue->value());
    };
    parserTest<OpArg>(input, getHelperRawArgParser(), expected, cmpFn);
}

using ParseHelperArgTest = Test<OpArg>;
using ArgT = ArgsT<OpArg>;
TEST_P(ParseHelperArgTest, parse)
{
    auto [input, expected] = GetParam();
    auto cmpFn = [](const OpArg& got, const OpArg& expected)
    {
        if (expected->isReference())
        {
            ASSERT_TRUE(got->isReference());
            auto gotRef = std::static_pointer_cast<Reference>(got);
            auto expectedRef = std::static_pointer_cast<Reference>(expected);
            ASSERT_EQ(gotRef->dotPath(), expectedRef->dotPath());
        }
        else
        {
            ASSERT_TRUE(got->isValue());
            auto gotValue = std::static_pointer_cast<Value>(got);
            auto expectedValue = std::static_pointer_cast<Value>(expected);
            ASSERT_EQ(gotValue->value(), expectedValue->value());
        }
    };
    parserTest<OpArg>(input, getHelperArgParser(), expected, cmpFn);
}

using ParseHelperTest = Test<HelperToken>;
using HelperT = ArgsT<HelperToken>;
TEST_P(ParseHelperTest, parse)
{
    auto [input, expected] = GetParam();
    auto cmpFn = [](const HelperToken& got, const HelperToken& expected)
    {
        ASSERT_EQ(got.name, expected.name);
        ASSERT_EQ(got.args.size(), expected.args.size());
        for (auto i = 0; i < got.args.size(); ++i)
        {
            auto gotArg = got.args[i];
            auto expectedArg = expected.args[i];

            if (expectedArg->isReference())
            {
                ASSERT_TRUE(gotArg->isReference());
                ASSERT_EQ(std::static_pointer_cast<Reference>(gotArg)->dotPath(),
                          std::static_pointer_cast<Reference>(expectedArg)->dotPath());
                ASSERT_EQ(std::static_pointer_cast<Reference>(gotArg)->jsonPath(),
                          std::static_pointer_cast<Reference>(expectedArg)->jsonPath());
            }
            else
            {
                ASSERT_TRUE(gotArg->isValue());
                ASSERT_EQ(std::static_pointer_cast<Value>(gotArg)->value(),
                          std::static_pointer_cast<Value>(expectedArg)->value());
            }
        }
    };
    parserTest<HelperToken>(input, getHelperParser(true), expected, cmpFn);
}

using IsDefaultT = std::tuple<std::string, bool>;
class IsDefaultHelperTest : public ::testing::TestWithParam<IsDefaultT>
{
};

TEST_P(IsDefaultHelperTest, parse)
{
    auto [input, expected] = GetParam();
    auto result = isDefaultHelper(input);
    ASSERT_EQ(result, expected);
}

using ParseOperatorTest = Test<Operator>;
using OperatorT = ArgsT<Operator>;
TEST_P(ParseOperatorTest, parse)
{
    auto [input, expected] = GetParam();
    auto cmpFn = [](const Operator& got, const Operator& expected)
    {
        ASSERT_EQ(got, expected);
    };
    parserTest<Operator>(input, getOperatorParser(), expected, cmpFn);
}

using ParseOperationTest = Test<OperationToken>;
using OperationT = ArgsT<OperationToken>;
TEST_P(ParseOperationTest, parse)
{
    auto [input, expected] = GetParam();
    auto cmpFn = [](const OperationToken& got, const OperationToken& expected)
    {
        auto gotFieldRef = std::static_pointer_cast<Reference>(got.field);
        auto expectedFieldRef = std::static_pointer_cast<Reference>(expected.field);
        ASSERT_EQ(gotFieldRef->dotPath(), expectedFieldRef->dotPath());
        ASSERT_EQ(got.op, expected.op);
        if (expected.value->isValue())
        {
            ASSERT_TRUE(got.value->isValue());
            ASSERT_EQ(std::static_pointer_cast<Value>(got.value)->value(),
                      std::static_pointer_cast<Value>(expected.value)->value());
        }
        else
        {
            ASSERT_TRUE(got.value->isReference());
            ASSERT_EQ(std::static_pointer_cast<Reference>(got.value)->dotPath(),
                      std::static_pointer_cast<Reference>(expected.value)->dotPath());
        }
    };
    parserTest<OperationToken>(input, getOperationParser(), expected, cmpFn);
}

using ParseTermTest = Test<HelperToken>;
using TermT = ArgsT<HelperToken>;
TEST_P(ParseTermTest, parse)
{
    auto [input, expected] = GetParam();
    auto cmpFn = [](const HelperToken& got, const HelperToken& expected)
    {
        ASSERT_EQ(got.name, expected.name);
        ASSERT_EQ(got.args.size(), expected.args.size());
        for (auto i = 0; i < got.args.size(); ++i)
        {
            auto gotArg = got.args[i];
            auto expectedArg = expected.args[i];

            if (expectedArg->isReference())
            {
                ASSERT_TRUE(gotArg->isReference());
                ASSERT_EQ(std::static_pointer_cast<Reference>(gotArg)->dotPath(),
                          std::static_pointer_cast<Reference>(expectedArg)->dotPath());
                ASSERT_EQ(std::static_pointer_cast<Reference>(gotArg)->jsonPath(),
                          std::static_pointer_cast<Reference>(expectedArg)->jsonPath());
            }
            else
            {
                ASSERT_TRUE(gotArg->isValue());
                ASSERT_EQ(std::static_pointer_cast<Value>(gotArg)->value(),
                          std::static_pointer_cast<Value>(expectedArg)->value());
            }
        }
    };
    parserTest<HelperToken>(input, getTermParser(), expected, cmpFn);
}

/******************************************************************************/
/* Tests Instantiations */
/******************************************************************************/
INSTANTIATE_TEST_SUITE_P(Builder,
                         ParseHelperNameTest,
                         testing::Values(NameT("helper", makeSuccess<std::string>("helper", 6)),
                                         NameT("", makeError<std::string>("", 0)),
                                         NameT("hel}leftover", makeSuccess<std::string>("hel", 3)),
                                         NameT("helper_name", makeSuccess<std::string>("helper_name", 11)),
                                         NameT("helper", makeSuccess<std::string>("helper", 6)),
                                         NameT("}leftover", makeError<std::string>("", 0)),
                                         NameT("01234_56789", makeSuccess<std::string>("01234_56789", 11))));

INSTANTIATE_TEST_SUITE_P(
    Builder,
    ParseHelperQuotedArgTest,
    testing::Values(QuotedArgT(R"("unquoted")", makeError<OpArg>("", 0)),
                    QuotedArgT(R"('quoted')", makeSuccess<OpArg>(val(R"("quoted")"), 8)),
                    QuotedArgT(R"('missing_end_quote)", makeError<OpArg>("", 18)),
                    QuotedArgT(R"('missing_end_quote\')", makeError<OpArg>("", 20)),
                    QuotedArgT(R"(missing_start_quote')", makeError<OpArg>("", 0)),
                    QuotedArgT(R"()", makeError<OpArg>("", 0)),
                    QuotedArgT(R"('')", makeSuccess<OpArg>(val(R"("")"), 2)),
                    QuotedArgT(R"(' ')", makeSuccess<OpArg>(val(R"(" ")"), 3)),
                    QuotedArgT(R"('escaped\'quote')", makeSuccess<OpArg>(val(R"("escaped'quote")"), 16)),
                    QuotedArgT(R"('invalid\scape')", makeError<OpArg>("", 9)),
                    QuotedArgT(R"('escaped\\')", makeSuccess<OpArg>(val(R"("escaped\\")"), 11)),
                    QuotedArgT(R"('1')", makeSuccess<OpArg>(val(R"("1")"), 3)),
                    QuotedArgT(R"('true')", makeSuccess<OpArg>(val(R"("true")"), 6)),
                    QuotedArgT(R"('[1]')", makeSuccess<OpArg>(val(R"("[1]")"), 5)),
                    QuotedArgT(R"('{"key":"value"}')", makeSuccess<OpArg>(val(R"("{\"key\":\"value\"}")"), 17)),
                    QuotedArgT(R"('null')", makeSuccess<OpArg>(val(R"("null")"), 6)),
                    QuotedArgT(R"(\'escaped_quote')", makeError<OpArg>("", 0)),
                    QuotedArgT(R"('quoted'leftover)", makeSuccess<OpArg>(val(R"("quoted")"), 8)),
                    QuotedArgT(R"('$ref')", makeSuccess<OpArg>(val(R"("$ref")"), 6))));

INSTANTIATE_TEST_SUITE_P(
    Builder,
    ParseHelperRefArgTest,
    testing::Values(RefArgT("", makeError<OpArg>("", 0)),
                    RefArgT(R"($ref)", makeSuccess<OpArg>(ref("ref"), 4)),
                    RefArgT(R"($ref_extended)", makeSuccess<OpArg>(ref("ref_extended"), 13)),
                    RefArgT(R"($ref@extended)", makeSuccess<OpArg>(ref("ref@extended"), 13)),
                    RefArgT(R"($ref#extended)", makeSuccess<OpArg>(ref("ref#extended"), 13)),
                    RefArgT(R"($ref.name)", makeSuccess<OpArg>(ref("ref.name"), 9)),
                    RefArgT(R"($ref_extended.name)", makeSuccess<OpArg>(ref("ref_extended.name"), 18)),
                    RefArgT(R"($ref}invalid)", makeSuccess<OpArg>(ref("ref"), 4)),
                    RefArgT(R"($ref_extended.name$leftover)", makeSuccess<OpArg>(ref("ref_extended.name"), 18)),
                    RefArgT(R"(ref)", makeError<OpArg>("", 0)),
                    RefArgT(R"(\$ref)", makeError<OpArg>("", 0))));

INSTANTIATE_TEST_SUITE_P(
    Builder,
    ParseHelperJsonArgTest,
    testing::Values(JsonArgT("", makeError<OpArg>("", 0)),
                    JsonArgT(R"(123)", makeSuccess<OpArg>(val(R"(123)"), 3)),
                    JsonArgT(R"(123.456)", makeSuccess<OpArg>(val(R"(123.456)"), 7)),
                    JsonArgT(R"(true)", makeSuccess<OpArg>(val(R"(true)"), 4)),
                    JsonArgT(R"(false)", makeSuccess<OpArg>(val(R"(false)"), 5)),
                    JsonArgT(R"({})", makeSuccess<OpArg>(val(R"({})"), 2)),
                    JsonArgT(R"([])", makeSuccess<OpArg>(val(R"([])"), 2)),
                    JsonArgT(R"([1,2,3,4])", makeSuccess<OpArg>(val(R"([1,2,3,4])"), 9)),
                    JsonArgT(R"("string")", makeSuccess<OpArg>(val(R"("string")"), 8)),
                    JsonArgT(R"("")", makeSuccess<OpArg>(val(R"("")"), 2)),
                    JsonArgT(R"("string with spaces")", makeSuccess<OpArg>(val(R"("string with spaces")"), 20)),
                    JsonArgT(R"("string with \t escape")", makeSuccess<OpArg>(val(R"("string with \t escape")"), 23)),
                    JsonArgT(R"("string with , ")", makeSuccess<OpArg>(val(R"("string with , ")"), 16)),
                    JsonArgT(R"(["value", "value2"])", makeSuccess<OpArg>(val(R"(["value", "value2"])"), 19)),
                    JsonArgT(R"(["value", "value2"]leftover)", makeSuccess<OpArg>(val(R"(["value", "value2"])"), 19)),
                    JsonArgT(R"({"key":"value"})", makeSuccess<OpArg>(val(R"({"key":"value"})"), 15)),
                    JsonArgT(R"({"key":"value"}leftover)", makeSuccess<OpArg>(val(R"({"key":"value"})"), 15)),
                    JsonArgT(R"(")", makeError<OpArg>("", 0)),
                    JsonArgT(R"({"key":"value")", makeError<OpArg>("", 0))));

INSTANTIATE_TEST_SUITE_P(
    Builder,
    ParseHelperRawArgTest,
    testing::Values(RawArgT("", makeError<OpArg>("", 0)),
                    RawArgT(",", makeSuccess<OpArg>(val(), 0)),
                    RawArgT(" ", makeSuccess<OpArg>(val(), 0)),
                    RawArgT(")", makeSuccess<OpArg>(val(), 0)),
                    RawArgT("a", makeSuccess<OpArg>(val(R"("a")"), 1)),
                    RawArgT("a,", makeSuccess<OpArg>(val(R"("a")"), 1)),
                    RawArgT("a ", makeSuccess<OpArg>(val(R"("a")"), 1)),
                    RawArgT("a)", makeSuccess<OpArg>(val(R"("a")"), 1)),
                    RawArgT("a$", makeSuccess<OpArg>(val(R"("a$")"), 2)),
                    RawArgT("$a", makeError<OpArg>("", 0)),
                    RawArgT(R"(a\$)", makeSuccess<OpArg>(val(R"("a$")"), 3)),
                    RawArgT(R"(\$a)", makeSuccess<OpArg>(val(R"("$a")"), 3)),
                    RawArgT(R"({"key":"value")", makeSuccess<OpArg>(val(R"("{\"key\":\"value\"")"), 14)),
                    RawArgT(R"({"key": "value")", makeSuccess<OpArg>(val(R"("{\"key\":")"), 7)),
                    RawArgT(R"({"key":,"value")", makeSuccess<OpArg>(val(R"("{\"key\":")"), 7)),
                    RawArgT(R"z({"key":)"value")z", makeSuccess<OpArg>(val(R"("{\"key\":")"), 7)),
                    RawArgT(R"({"key":)", makeSuccess<OpArg>(val(R"("{\"key\":")"), 7)),
                    RawArgT(R"({"key":\ "value")", makeSuccess<OpArg>(val(R"("{\"key\": \"value\"")"), 16)),
                    RawArgT(R"({"key":\,"value")", makeSuccess<OpArg>(val(R"("{\"key\":,\"value\"")"), 16)),
                    RawArgT(R"z({"key":\)"value")z", makeSuccess<OpArg>(val(R"z("{\"key\":)\"value\"")z"), 16)),
                    RawArgT(R"(invalid\scape)", makeError<OpArg>("", 8)),
                    RawArgT(R"(escaped\\)", makeSuccess<OpArg>(val(R"("escaped\\")"), 9)),
                    RawArgT(R"(1234)", makeSuccess<OpArg>(val(R"("1234")"), 4))));

INSTANTIATE_TEST_SUITE_P(Builder,
                         ParseHelperArgTest,
                         testing::Values(ArgT(R"('quoted')", makeSuccess<OpArg>(val(R"("quoted")"), 8)),
                                         ArgT(R"($ref)", makeSuccess<OpArg>(ref("ref"), 4)),
                                         ArgT(R"(123)", makeSuccess<OpArg>(val(R"(123)"), 3)),
                                         ArgT(R"([])", makeSuccess<OpArg>(val("[]"), 2)),
                                         ArgT(R"([1,2,3,4])", makeSuccess<OpArg>(val(R"([1,2,3,4])"), 9)),
                                         ArgT(R"(\$ref)", makeSuccess<OpArg>(val(R"("$ref")"), 5)),
                                         ArgT(R"(invalid\scape)", makeError<OpArg>("", 0)),
                                         ArgT(R"("")", makeSuccess<OpArg>(val(R"("")"), 2)),
                                         ArgT("", makeError<OpArg>("", 0)),
                                         ArgT(" ", makeSuccess<OpArg>(val(), 0)),
                                         ArgT("'' )", makeSuccess<OpArg>(val(R"("")"), 2))));

INSTANTIATE_TEST_SUITE_P(
    Builder,
    ParseHelperTest,
    testing::Values(
        HelperT("stringValue", makeError<HelperToken>("", 11)),
        HelperT("123", makeError<HelperToken>("", 3)),
        HelperT("123.456", makeError<HelperToken>("", 3)),
        HelperT("true", makeError<HelperToken>("", 4)),
        HelperT("false", makeError<HelperToken>("", 5)),
        HelperT("{}", makeError<HelperToken>("", 0)),
        HelperT("[]", makeError<HelperToken>("", 0)),
        HelperT("$ref", makeError<HelperToken>("", 0)),
        HelperT("helper()", makeSuccess<HelperToken>({.name = "helper", .args = {}}, 8)),
        HelperT("helper('')", makeSuccess<HelperToken>({.name = "helper", .args = {val(R"("")")}}, 10)),
        HelperT("helper( '')", makeSuccess<HelperToken>({.name = "helper", .args = {val(R"("")")}}, 11)),
        HelperT("helper( ''  )", makeSuccess<HelperToken>({.name = "helper", .args = {val(R"("")")}}, 13)),
        HelperT("helper(arg1)", makeSuccess<HelperToken>({.name = "helper", .args = {val(R"("arg1")")}}, 12)),
        HelperT("helper(arg1, '')",
                makeSuccess<HelperToken>({.name = "helper", .args = {val(R"("arg1")"), val(R"("")")}}, 16)),
        HelperT("helper(arg1, )", makeSuccess<HelperToken>({.name = "helper", .args = {val(R"("arg1")"), val()}}, 14)),
        HelperT("helper(arg1,arg2)",
                makeSuccess<HelperToken>({.name = "helper", .args = {val(R"("arg1")"), val(R"("arg2")")}}, 17)),
        HelperT(R"(helper(arg1,  ""))",
                makeSuccess<HelperToken>({.name = "helper", .args = {val(R"("arg1")"), val(R"("")")}}, 17)),
        HelperT("helper(arg1, '', arg3)",
                makeSuccess<HelperToken>({.name = "helper", .args = {val(R"("arg1")"), val(R"("")"), val(R"("arg3")")}},
                                         22)),
        HelperT("helper(arg1, '' , arg3)",
                makeSuccess<HelperToken>({.name = "helper", .args = {val(R"("arg1")"), val(R"("")"), val(R"("arg3")")}},
                                         23)),
        HelperT("helper(arg1, arg2, arg3)",
                makeSuccess<HelperToken>(
                    {.name = "helper", .args = {val(R"("arg1")"), val(R"("arg2")"), val(R"("arg3")")}}, 24)),
        HelperT(R"(helper(arg1, arg2\,arg3))",
                makeSuccess<HelperToken>({.name = "helper", .args = {val(R"("arg1")"), val(R"("arg2,arg3")")}},
                                         24)), // Testing escaped comma
        HelperT(R"(helper(arg1,\ arg2))",
                makeSuccess<HelperToken>({.name = "helper", .args = {val(R"("arg1")"), val(R"(" arg2")")}},
                                         19)),                 // Testing escaped space
        HelperT("helper(arg1", makeError<HelperToken>("", 7)), // Missing closing parenthesis
        HelperT("'helper(arg1'", makeError<HelperToken>("", 0)),
        HelperT("test arg1)", makeError<HelperToken>("", 4)), // Missing opening parenthesis
        HelperT("", makeError<HelperToken>("", 0)),           // Empty string
        HelperT("()", makeError<HelperToken>("", 0)),         // No function name
        HelperT("test()", makeSuccess<HelperToken>({.name = "test"}, 6)),
        HelperT("test(,)", makeSuccess<HelperToken>({.name = "test", .args {val(), val()}}, 7)),
        HelperT("test(,,)", makeSuccess<HelperToken>({.name = "test", .args {val(), val(), val()}}, 8)),
        HelperT("test(, ,)", makeSuccess<HelperToken>({.name = "test", .args {val(), val(), val()}}, 9)),
        HelperT("test(arg1,)", makeSuccess<HelperToken>({.name = "test", .args {val(R"("arg1")"), val()}}, 11)),
        HelperT("test(arg1, )", makeSuccess<HelperToken>({.name = "test", .args {val(R"("arg1")"), val()}}, 12)),
        HelperT(R"(test(arg1,\ ))",
                makeSuccess<HelperToken>({.name = "test", .args {val(R"("arg1")"), val(R"(" ")")}}, 13)),
        HelperT("test(arg1,' ')",
                makeSuccess<HelperToken>({.name = "test", .args {val(R"("arg1")"), val(R"(" ")")}}, 14)),
        HelperT("test('arg1')", makeSuccess<HelperToken>({.name = "test", .args {val(R"("arg1")")}}, 12)),
        HelperT("test($arg1)", makeSuccess<HelperToken>({.name = "test", .args {ref("arg1")}}, 11)),
        HelperT("test(arg1,  )", makeSuccess<HelperToken>({.name = "test", .args {val(R"("arg1")"), val()}}, 13)),
        HelperT("test(arg1, ())", makeError<HelperToken>("", 13)),
        HelperT(R"(test(arg1, (\)))",
                makeSuccess<HelperToken>({.name = "test", .args {val(R"("arg1")"), val(R"z("()")z")}}, 15)),
        HelperT("test(arg1, ( arg2)", makeError<HelperToken>("", 11)),
        HelperT(R"(test(arg1, \) arg2))", makeError<HelperToken>("", 11)),
        HelperT(R"(test(arg1, \)\ arg2))",
                makeSuccess<HelperToken>({.name = "test", .args = {val(R"("arg1")"), val(R"(") arg2")")}}, 20)),
        HelperT(R"(test(arg1, \)\ arg2\)\)\)))",
                makeSuccess<HelperToken>({.name = "test", .args = {val(R"("arg1")"), val(R"z(") arg2)))")z")}}, 26)),
        HelperT("test(arg1)leftover", makeError<HelperToken>("", 10)),
        HelperT("test(arg1, ' , ( ) ' )",
                makeSuccess<HelperToken>({.name = "test", .args {val(R"("arg1")"), val(R"(" , ( ) ")")}}, 22)),
        HelperT("test(arg1, $ref, ' , ( ) ' , 123)",
                makeSuccess<HelperToken>(
                    {.name = "test", .args {val(R"("arg1")"), ref("ref"), val(R"(" , ( ) ")"), val("123")}}, 33)),
        HelperT("binary_and(0x10000000000000)",
                makeSuccess<HelperToken>({.name = "binary_and", .args = {val(R"("0x10000000000000")")}}, 28)),
        HelperT("binary_and('0x10000000000000')",
                makeSuccess<HelperToken>({.name = "binary_and", .args = {val(R"("0x10000000000000")")}}, 30)),
        HelperT(R"(regex_extract($windows.EventData.Details, 'DWORD \\((0x[0-9A-F]{8})\\)'))",
                makeSuccess<HelperToken>({.name = "regex_extract",
                                          .args = {ref("windows.EventData.Details"),
                                                   val(R"z("DWORD \\((0x[0-9A-F]{8})\\)")z")}},
                                         72)),
        HelperT(R"(regex_extract($event.original, '(?:f|F)ile \'(.*?)\''))",
                makeSuccess<HelperToken>(
                    {.name = "regex_extract", .args = {ref("event.original"), val(R"z("(?:f|F)ile '(.*?)'")z")}}, 54)),
        HelperT(R"(test([1]))", makeSuccess<HelperToken>({.name = "test", .args = {val(R"([1])")}}, 9)),
        HelperT(R"(test(["hello"]))", makeSuccess<HelperToken>({.name = "test", .args = {val(R"(["hello"])")}}, 15)),
        HelperT(R"(test(["hello, yes"]))",
                makeSuccess<HelperToken>({.name = "test", .args = {val(R"(["hello, yes"])")}}, 20)),
        HelperT(R"(test(arg1, arg2, {"hello":"yes, no?"}))",
                makeSuccess<HelperToken>({.name = "test",
                                          .args = {val(R"("arg1")"), val(R"("arg2")"), val(R"({"hello":"yes, no?"})")}},
                                         38)),
        HelperT(R"(test(arg1, arg2, 'other, test'))",
                makeSuccess<HelperToken>(
                    {.name = "test", .args = {val(R"("arg1")"), val(R"("arg2")"), val(R"("other, test")")}}, 31)),
        HelperT(R"(test([1,2,3,4]))", makeSuccess<HelperToken>({.name = "test", .args = {val(R"([1,2,3,4])")}}, 15)),
        HelperT(R"(test([1,2,3,4], 1))",
                makeSuccess<HelperToken>({.name = "test", .args = {val(R"([1,2,3,4])"), val(R"(1)")}}, 18)),
        HelperT(R"(test(1, [1,2,3,4]))",
                makeSuccess<HelperToken>({.name = "test", .args = {val(R"(1)"), val(R"([1,2,3,4])")}}, 18)),
        HelperT(R"(test(1, [1,2,3,4], 2))",
                makeSuccess<HelperToken>({.name = "test", .args = {val(R"(1)"), val(R"([1,2,3,4])"), val(R"(2)")}},
                                         21)),
        HelperT(R"(test([1,2,3,4],))",
                makeSuccess<HelperToken>({.name = "test", .args = {val(R"([1,2,3,4])"), val()}}, 16)),
        HelperT(R"(test({"key": "value"}))",
                makeSuccess<HelperToken>({.name = "test", .args = {val(R"({"key": "value"})")}}, 22)),
        HelperT(R"(test({"key": "value"}, {"key2": "value2"}))",
                makeSuccess<HelperToken>(
                    {.name = "test", .args = {val(R"({"key": "value"})"), val(R"({"key2": "value2"})")}}, 42)),
        HelperT(R"(test({"key": "value", "key2": "value2"}))",
                makeSuccess<HelperToken>({.name = "test", .args = {val(R"({"key": "value", "key2": "value2"})")}}, 40)),
        HelperT(R"(test(1, {"key": "value", "key2": "value2"}))",
                makeSuccess<HelperToken>(
                    {.name = "test", .args = {val(R"(1)"), val(R"({"key": "value", "key2": "value2"})")}}, 43)),
        HelperT(R"(test([1]123))",
                makeSuccess<HelperToken>(
                    {.name = "test", .args = {val(R"("[1]123")")}}, 12))
        ));

INSTANTIATE_TEST_SUITE_P(Builder,
                         IsDefaultHelperTest,
                         testing::Values(IsDefaultT("helper", true),
                                         IsDefaultT("helper(", false),
                                         IsDefaultT("$ref", true),
                                         IsDefaultT("", true)));

INSTANTIATE_TEST_SUITE_P(Builder,
                         ParseOperatorTest,
                         testing::Values(OperatorT("==", makeSuccess<Operator>(Operator::EQUAL, 2)),
                                         OperatorT("!=", makeSuccess<Operator>(Operator::NOT_EQUAL, 2)),
                                         OperatorT(">=", makeSuccess<Operator>(Operator::GREATER_THAN_OR_EQUAL, 2)),
                                         OperatorT(">", makeSuccess<Operator>(Operator::GREATER_THAN, 1)),
                                         OperatorT("<=", makeSuccess<Operator>(Operator::LESS_THAN_OR_EQUAL, 2)),
                                         OperatorT("<", makeSuccess<Operator>(Operator::LESS_THAN, 1)),
                                         OperatorT("=", makeError<Operator>("", 1)),
                                         OperatorT("!", makeError<Operator>("", 1)),
                                         OperatorT("  ==", makeSuccess<Operator>(Operator::EQUAL, 4)),
                                         OperatorT("  !=", makeSuccess<Operator>(Operator::NOT_EQUAL, 4)),
                                         OperatorT("  >=", makeSuccess<Operator>(Operator::GREATER_THAN_OR_EQUAL, 4)),
                                         OperatorT("  >", makeSuccess<Operator>(Operator::GREATER_THAN, 3)),
                                         OperatorT("  <=", makeSuccess<Operator>(Operator::LESS_THAN_OR_EQUAL, 4)),
                                         OperatorT("  <", makeSuccess<Operator>(Operator::LESS_THAN, 3)),
                                         OperatorT("  ==  ", makeSuccess<Operator>(Operator::EQUAL, 6)),
                                         OperatorT("  !=  ", makeSuccess<Operator>(Operator::NOT_EQUAL, 6)),
                                         OperatorT("  >=  ", makeSuccess<Operator>(Operator::GREATER_THAN_OR_EQUAL, 6)),
                                         OperatorT("  >  ", makeSuccess<Operator>(Operator::GREATER_THAN, 5)),
                                         OperatorT("  <=  ", makeSuccess<Operator>(Operator::LESS_THAN_OR_EQUAL, 6)),
                                         OperatorT("  <  ", makeSuccess<Operator>(Operator::LESS_THAN, 5))));

INSTANTIATE_TEST_SUITE_P(
    Builder,
    ParseOperationTest,
    testing::Values(
        // Equal
        OperationT(R"($field==123)",
                   makeSuccess<OperationToken>({.field = ref("field"), .op = Operator::EQUAL, .value = val("123")},
                                               11)),
        OperationT(R"($field =="123")",
                   makeSuccess<OperationToken>({.field = ref("field"), .op = Operator::EQUAL, .value = val(R"("123")")},
                                               14)),
        OperationT(R"($field== true)",
                   makeSuccess<OperationToken>({.field = ref("field"), .op = Operator::EQUAL, .value = val(R"(true)")},
                                               13)),
        OperationT(R"($field == null)",
                   makeSuccess<OperationToken>({.field = ref("field"), .op = Operator::EQUAL, .value = val(R"(null)")},
                                               14)),
        OperationT(R"($field=={} )",
                   makeSuccess<OperationToken>({.field = ref("field"), .op = Operator::EQUAL, .value = val(R"({})")},
                                               10)),
        OperationT(R"($field==[])",
                   makeSuccess<OperationToken>({.field = ref("field"), .op = Operator::EQUAL, .value = val(R"([])")},
                                               10)),
        OperationT(R"($field==$ref)",
                   makeSuccess<OperationToken>({.field = ref("field"), .op = Operator::EQUAL, .value = ref("ref")},
                                               12)),
        // Greater than or equal
        OperationT(R"($field>=123)",
                   makeSuccess<OperationToken>(
                       {.field = ref("field"), .op = Operator::GREATER_THAN_OR_EQUAL, .value = val("123")}, 11)),
        OperationT(R"($field >="123")",
                   makeSuccess<OperationToken>(
                       {.field = ref("field"), .op = Operator::GREATER_THAN_OR_EQUAL, .value = val(R"("123")")}, 14)),
        OperationT(R"($field>= true)",
                   makeSuccess<OperationToken>(
                       {.field = ref("field"), .op = Operator::GREATER_THAN_OR_EQUAL, .value = val(R"(true)")}, 13)),
        OperationT(R"($field >= null)",
                   makeSuccess<OperationToken>(
                       {.field = ref("field"), .op = Operator::GREATER_THAN_OR_EQUAL, .value = val(R"(null)")}, 14)),
        OperationT(R"($field>={} )",
                   makeSuccess<OperationToken>(
                       {.field = ref("field"), .op = Operator::GREATER_THAN_OR_EQUAL, .value = val(R"({})")}, 10)),
        OperationT(R"($field>=[])",
                   makeSuccess<OperationToken>(
                       {.field = ref("field"), .op = Operator::GREATER_THAN_OR_EQUAL, .value = val(R"([])")}, 10)),
        OperationT(R"($field>=$ref)",
                   makeSuccess<OperationToken>(
                       {.field = ref("field"), .op = Operator::GREATER_THAN_OR_EQUAL, .value = ref("ref")}, 12)),
        // Greater than
        OperationT(R"($field>123)",
                   makeSuccess<OperationToken>(
                       {.field = ref("field"), .op = Operator::GREATER_THAN, .value = val("123")}, 10)),
        OperationT(R"($field >"123")",
                   makeSuccess<OperationToken>(
                       {.field = ref("field"), .op = Operator::GREATER_THAN, .value = val(R"("123")")}, 13)),
        OperationT(R"($field> true)",
                   makeSuccess<OperationToken>(
                       {.field = ref("field"), .op = Operator::GREATER_THAN, .value = val(R"(true)")}, 12)),
        OperationT(R"($field > null)",
                   makeSuccess<OperationToken>(
                       {.field = ref("field"), .op = Operator::GREATER_THAN, .value = val(R"(null)")}, 13)),
        OperationT(R"($field>{} )",
                   makeSuccess<OperationToken>(
                       {.field = ref("field"), .op = Operator::GREATER_THAN, .value = val(R"({})")}, 9)),
        OperationT(R"($field>[] )",
                   makeSuccess<OperationToken>(
                       {.field = ref("field"), .op = Operator::GREATER_THAN, .value = val(R"([])")}, 9)),
        OperationT(R"($field>$ref)",
                   makeSuccess<OperationToken>(
                       {.field = ref("field"), .op = Operator::GREATER_THAN, .value = ref("ref")}, 11)),
        // Less than or equal
        OperationT(R"($field<=123)",
                   makeSuccess<OperationToken>(
                       {.field = ref("field"), .op = Operator::LESS_THAN_OR_EQUAL, .value = val("123")}, 11)),
        OperationT(R"($field <="123")",
                   makeSuccess<OperationToken>(
                       {.field = ref("field"), .op = Operator::LESS_THAN_OR_EQUAL, .value = val(R"("123")")}, 14)),
        OperationT(R"($field<= true)",
                   makeSuccess<OperationToken>(
                       {.field = ref("field"), .op = Operator::LESS_THAN_OR_EQUAL, .value = val(R"(true)")}, 13)),
        OperationT(R"($field <= null)",
                   makeSuccess<OperationToken>(
                       {.field = ref("field"), .op = Operator::LESS_THAN_OR_EQUAL, .value = val(R"(null)")}, 14)),
        OperationT(R"($field<={} )",
                   makeSuccess<OperationToken>(
                       {.field = ref("field"), .op = Operator::LESS_THAN_OR_EQUAL, .value = val(R"({})")}, 10)),
        OperationT(R"($field<=[])",
                   makeSuccess<OperationToken>(
                       {.field = ref("field"), .op = Operator::LESS_THAN_OR_EQUAL, .value = val(R"([])")}, 10)),
        OperationT(R"($field<=$ref)",
                   makeSuccess<OperationToken>(
                       {.field = ref("field"), .op = Operator::LESS_THAN_OR_EQUAL, .value = ref("ref")}, 12)),
        // Less than
        OperationT(R"($field<123)",
                   makeSuccess<OperationToken>({.field = ref("field"), .op = Operator::LESS_THAN, .value = val("123")},
                                               10)),
        OperationT(R"($field <"123")",
                   makeSuccess<OperationToken>(
                       {.field = ref("field"), .op = Operator::LESS_THAN, .value = val(R"("123")")}, 13)),
        OperationT(R"($field< true)",
                   makeSuccess<OperationToken>(
                       {.field = ref("field"), .op = Operator::LESS_THAN, .value = val(R"(true)")}, 12)),
        OperationT(R"($field < null)",
                   makeSuccess<OperationToken>(
                       {.field = ref("field"), .op = Operator::LESS_THAN, .value = val(R"(null)")}, 13)),
        OperationT(
            R"($field<{} )",
            makeSuccess<OperationToken>({.field = ref("field"), .op = Operator::LESS_THAN, .value = val(R"({})")}, 9)),
        OperationT(
            R"($field<[])",
            makeSuccess<OperationToken>({.field = ref("field"), .op = Operator::LESS_THAN, .value = val(R"([])")}, 9)),
        OperationT(R"($field<$ref)",
                   makeSuccess<OperationToken>({.field = ref("field"), .op = Operator::LESS_THAN, .value = ref("ref")},
                                               11)),
        // Not equal
        OperationT(R"($field!=123)",
                   makeSuccess<OperationToken>({.field = ref("field"), .op = Operator::NOT_EQUAL, .value = val("123")},
                                               11)),
        OperationT(R"($field !="123")",
                   makeSuccess<OperationToken>(
                       {.field = ref("field"), .op = Operator::NOT_EQUAL, .value = val(R"("123")")}, 14)),
        OperationT(R"($field!= true)",
                   makeSuccess<OperationToken>(
                       {.field = ref("field"), .op = Operator::NOT_EQUAL, .value = val(R"(true)")}, 13)),
        OperationT(R"($field != null)",
                   makeSuccess<OperationToken>(
                       {.field = ref("field"), .op = Operator::NOT_EQUAL, .value = val(R"(null)")}, 14)),
        OperationT(
            R"($field!={} )",
            makeSuccess<OperationToken>({.field = ref("field"), .op = Operator::NOT_EQUAL, .value = val(R"({})")}, 10)),
        OperationT(
            R"($field!=[])",
            makeSuccess<OperationToken>({.field = ref("field"), .op = Operator::NOT_EQUAL, .value = val(R"([])")}, 10)),
        OperationT(R"($field!=$ref)",
                   makeSuccess<OperationToken>({.field = ref("field"), .op = Operator::NOT_EQUAL, .value = ref("ref")},
                                               12)),
        // Invalid
        OperationT(R"($field=123)", makeError<OperationToken>("", 7)),
        OperationT(R"(not_ref==123)", makeError<OperationToken>("", 0)),
        OperationT(R"($field==)", makeError<OperationToken>("", 8))));

INSTANTIATE_TEST_SUITE_P(
    Builder,
    ParseTermTest,
    testing::Values(
        //**************************
        // Expression TESTS
        //**************************
        TermT(R"($field==123)",
              makeSuccess<HelperToken>(HelperToken {"filter", Reference("field"), {val(R"(123)")}}, 11)),
        TermT(R"($field=="123")",
              makeSuccess<HelperToken>(HelperToken {"filter", Reference("field"), {val(R"("123")")}}, 13)),
        TermT(R"($field==$field2)",
              makeSuccess<HelperToken>(HelperToken {"filter", Reference("field"), {ref("field2")}}, 15)),
        TermT(R"($field=={})",
              makeSuccess<HelperToken>(HelperToken {"filter", Reference("field"), {val(R"({})")}}, 10)),
        TermT(R"($field==null)",
              makeSuccess<HelperToken>(HelperToken {"filter", Reference("field"), {val(R"(null)")}}, 12)),
        TermT(R"($field==true)",
              makeSuccess<HelperToken>(HelperToken {"filter", Reference("field"), {val(R"(true)")}}, 12)),
        TermT(R"($field>=123)",
              makeSuccess<HelperToken>(HelperToken {"int_greater_or_equal", Reference("field"), {val(R"(123)")}}, 11)),
        TermT(R"($field>123)",
              makeSuccess<HelperToken>(HelperToken {"int_greater", Reference("field"), {val(R"(123)")}}, 10)),
        TermT(R"($field<="123")",
              makeSuccess<HelperToken>(HelperToken {"string_less_or_equal", Reference("field"), {val(R"("123")")}},
                                       13)),
        TermT(R"($field<"123")",
              makeSuccess<HelperToken>(HelperToken {"string_less", Reference("field"), {val(R"("123")")}}, 12)),
        TermT(R"($field!=$field2)", makeError<HelperToken>("", 0)),
        TermT(R"($field<$field2)", makeError<HelperToken>("", 0)),
        TermT(R"($field=={"key_str":"asd","key_num":123,"key_obj":{"custom_key":true}})",
              makeSuccess<HelperToken>({"filter",
                                        Reference("field"),
                                        {val(R"({"key_str":"asd","key_num":123,"key_obj":{"custom_key":true}})")}},
                                       69)),
        // Expression Ok - with spaces
        TermT(R"($field == 123)", makeSuccess<HelperToken>({"filter", Reference("field"), {val(R"(123)")}}, 13)),
        TermT(R"($field == "123")", makeSuccess<HelperToken>({"filter", Reference("field"), {val(R"("123")")}}, 15)),
        TermT(R"($field == $field2)", makeSuccess<HelperToken>({"filter", Reference("field"), {ref("field2")}}, 17)),
        TermT(R"($field == {})", makeSuccess<HelperToken>({"filter", Reference("field"), {val(R"({})")}}, 12)),
        TermT(R"($field == null)", makeSuccess<HelperToken>({"filter", Reference("field"), {val(R"(null)")}}, 14)),
        TermT(R"($field == true)", makeSuccess<HelperToken>({"filter", Reference("field"), {val(R"(true)")}}, 14)),
        TermT(R"($field >= 123)",
              makeSuccess<HelperToken>({"int_greater_or_equal", Reference("field"), {val(R"(123)")}}, 13)),
        TermT(R"($field > 123)", makeSuccess<HelperToken>({"int_greater", Reference("field"), {val(R"(123)")}}, 12)),
        TermT(R"($field <= "123")",
              makeSuccess<HelperToken>({"string_less_or_equal", Reference("field"), {val(R"("123")")}}, 15)),
        TermT(R"($field < "123")",
              makeSuccess<HelperToken>({"string_less", Reference("field"), {val(R"("123")")}}, 14)),
        TermT(R"($field != $field2)", makeError<HelperToken>("", 0)),
        TermT(R"($field < $field2)", makeError<HelperToken>("", 0)),
        TermT(R"($field == {"key_str":"asd","key_num":123,"key_obj":{"custom_key":true}})",
              makeSuccess<HelperToken>({"filter",
                                        Reference("field"),
                                        {val(R"({"key_str":"asd","key_num":123,"key_obj":{"custom_key":true}})")}},
                                       71)),
        // Expression Ok - with spaces after field only
        TermT(R"($field   ==123)", makeSuccess<HelperToken>({"filter", Reference("field"), {val(R"(123)")}}, 14)),
        TermT(R"($field   =="123")", makeSuccess<HelperToken>({"filter", Reference("field"), {val(R"("123")")}}, 16)),
        TermT(R"($field   ==$field2)", makeSuccess<HelperToken>({"filter", Reference("field"), {ref("field2")}}, 18)),
        TermT(R"($field   =={})", makeSuccess<HelperToken>({"filter", Reference("field"), {val(R"({})")}}, 13)),
        TermT(R"($field   ==null)", makeSuccess<HelperToken>({"filter", Reference("field"), {val(R"(null)")}}, 15)),
        TermT(R"($field   ==true)", makeSuccess<HelperToken>({"filter", Reference("field"), {val(R"(true)")}}, 15)),
        TermT(R"($field   >=123)",
              makeSuccess<HelperToken>({"int_greater_or_equal", Reference("field"), {val(R"(123)")}}, 14)),
        TermT(R"($field   >123)", makeSuccess<HelperToken>({"int_greater", Reference("field"), {val(R"(123)")}}, 13)),
        TermT(R"($field   <="123")",
              makeSuccess<HelperToken>({"string_less_or_equal", Reference("field"), {val(R"("123")")}}, 16)),
        TermT(R"($field   <"123")",
              makeSuccess<HelperToken>({"string_less", Reference("field"), {val(R"("123")")}}, 15)),
        TermT(R"($field   !=$field2)", makeError<HelperToken>("", 0)),
        TermT(R"($field   <$field2)", makeError<HelperToken>("", 0)),
        TermT(R"($field =={"key_str":"asd","key_num":123,"key_obj":{"custom_key":true}})",
              makeSuccess<HelperToken>({"filter",
                                        Reference("field"),
                                        {val(R"({"key_str":"asd","key_num":123,"key_obj":{"custom_key":true}})")}},
                                       70)),
        // Expression Ok - with spaces after operator only
        TermT(R"($field==   123)", makeSuccess<HelperToken>({"filter", Reference("field"), {val(R"(123)")}}, 14)),
        TermT(R"($field==  "123")", makeSuccess<HelperToken>({"filter", Reference("field"), {val(R"("123")")}}, 15)),
        TermT(R"($field==   $field2)", makeSuccess<HelperToken>({"filter", Reference("field"), {ref("field2")}}, 18)),
        TermT(R"($field==   {})", makeSuccess<HelperToken>({"filter", Reference("field"), {val(R"({})")}}, 13)),
        TermT(R"($field==   null)", makeSuccess<HelperToken>({"filter", Reference("field"), {val(R"(null)")}}, 15)),
        TermT(R"($field==   true)", makeSuccess<HelperToken>({"filter", Reference("field"), {val(R"(true)")}}, 15)),
        TermT(R"($field>=   123)",
              makeSuccess<HelperToken>({"int_greater_or_equal", Reference("field"), {val(R"(123)")}}, 14)),
        TermT(R"($field>    123)", makeSuccess<HelperToken>({"int_greater", Reference("field"), {val(R"(123)")}}, 14)),
        TermT(R"($field<=   "123")",
              makeSuccess<HelperToken>({"string_less_or_equal", Reference("field"), {val(R"("123")")}}, 16)),
        TermT(R"($field<   "123")",
              makeSuccess<HelperToken>({"string_less", Reference("field"), {val(R"("123")")}}, 15)),
        TermT(R"($field!=   $field2)", makeError<HelperToken>("", 0)),
        TermT(R"($field<   $field2)", makeError<HelperToken>("", 0)),
        TermT(R"($field==    {"key_str":"asd","key_num":123,"key_obj":{"custom_key":true}})",
              makeSuccess<HelperToken>({"filter",
                                        Reference("field"),
                                        {val(R"({"key_str":"asd","key_num":123,"key_obj":{"custom_key":true}})")}},
                                       73)),
        TermT(R"($field->123)", makeSuccess<HelperToken>({"int_greater", Reference("field-"), {val(R"(123)")}}, 11)),
        // Expression fail - bad operator
        TermT(R"($field=!123)", makeError<HelperToken>("", 0)),
        TermT(R"($field=123)", makeError<HelperToken>("", 0)),
        TermT(R"($field.123)", makeError<HelperToken>("", 0)),
        TermT(R"($field!123)", makeError<HelperToken>("", 0)),
        TermT(R"($field|123)", makeError<HelperToken>("", 0)),
        TermT(R"($field?123)", makeError<HelperToken>("", 0)),
        TermT(R"($field =! 123)", makeError<HelperToken>("", 0)),
        TermT(R"($field = 123)", makeError<HelperToken>("", 0)),
        TermT(R"($field -> 123)", makeError<HelperToken>("", 0)),
        // Expression fail - bad field
        TermT(R"(field == 123)", makeError<HelperToken>("", 0)),
        TermT(R"(field == "123")", makeError<HelperToken>("", 0)),
        TermT(R"(field == $field2)", makeError<HelperToken>("", 0)),
        TermT(R"(field == {})", makeError<HelperToken>("", 0)),
        TermT(R"(field == null)", makeError<HelperToken>("", 0)),
        TermT(R"(field == true)", makeError<HelperToken>("", 0)),
        TermT(R"(field >= 123)", makeError<HelperToken>("", 0)),
        TermT(R"(field > 123)", makeError<HelperToken>("", 0)),
        TermT(R"(field <= "123")", makeError<HelperToken>("", 0)),
        TermT(R"(field < "123")", makeError<HelperToken>("", 0)),
        TermT(R"(field != $field2)", makeError<HelperToken>("", 0)),
        // Expression fail - Missing field
        TermT(R"($field == )", makeError<HelperToken>("", 0)),
        TermT(R"($ == 123)", makeError<HelperToken>("", 0)),
        TermT(R"($field 123)", makeError<HelperToken>("", 0)),
        //**************************
        // Helper TEST
        //**************************
        // Helper Ok - spaces after separator
        TermT(R"(helper_name123($target_field1))",
              makeSuccess<HelperToken>({"helper_name123", Reference("target_field1")}, 30)),
        TermT(R"(helper_name123($target_field1, ))",
              makeSuccess<HelperToken>({"helper_name123", Reference("target_field1"), {val()}}, 32)),
        TermT(R"(hp($f1, $f2, $f3))", makeSuccess<HelperToken>({"hp", Reference("f1"), {ref("f2"), ref("f3")}}, 17)),
        TermT(R"(hp($f1, $f2, $f3, ))",
              makeSuccess<HelperToken>({"hp", Reference("f1"), {ref("f2"), ref("f3"), val()}}, 19)),
        TermT(R"(hp($f1, f2, f3, f4))",
              makeSuccess<HelperToken>({"hp", Reference("f1"), {val(R"("f2")"), val(R"("f3")"), val(R"("f4")")}}, 19)),
        TermT(R"(hp($f1, f2, f3, f4, ))",
              makeSuccess<HelperToken>({"hp", Reference("f1"), {val(R"("f2")"), val(R"("f3")"), val(R"("f4")"), val()}},
                                       21)),
        TermT(R"(hp($f1, , , f4, ))",
              makeSuccess<HelperToken>({"hp", Reference("f1"), {val(), val(), val(R"("f4")"), val()}}, 17)),
        // Helper Ok - without spaces
        TermT(R"(hp($f1,$f2,$f3))", makeSuccess<HelperToken>({"hp", Reference("f1"), {ref("f2"), ref("f3")}}, 15)),
        TermT(R"(hp($f1,$f2,$f3, ))",
              makeSuccess<HelperToken>({"hp", Reference("f1"), {ref("f2"), ref("f3"), val()}}, 17)),
        TermT(R"(hp($f1,f2,f3,f4))",
              makeSuccess<HelperToken>({"hp", Reference("f1"), {val(R"("f2")"), val(R"("f3")"), val(R"("f4")")}}, 16)),
        TermT(R"(hp($f1,f2,f3,f4,))",
              makeSuccess<HelperToken>({"hp", Reference("f1"), {val(R"("f2")"), val(R"("f3")"), val(R"("f4")"), val()}},
                                       17)),
        TermT(R"(hp($f1,,,f4,))",
              makeSuccess<HelperToken>({"hp", Reference("f1"), {val(), val(), val(R"("f4")"), val()}}, 13)),
        // Helper Ok - with spaces before separator
        TermT(R"(hp(   $f1,   $f2,   $f3))",
              makeSuccess<HelperToken>({"hp", Reference("f1"), {ref("f2"), ref("f3")}}, 24)),
        TermT(R"(hp(   $f1,   $f2,   $f3,   ))",
              makeSuccess<HelperToken>({"hp", Reference("f1"), {ref("f2"), ref("f3"), val()}}, 28)),
        TermT(R"(hp(   $f1,   f2,   f3,   f4))",
              makeSuccess<HelperToken>({"hp", Reference("f1"), {val(R"("f2")"), val(R"("f3")"), val(R"("f4")")}}, 28)),
        TermT(R"(hp(   $f1,   f2,   f3,   f4,   ))",
              makeSuccess<HelperToken>({"hp", Reference("f1"), {val(R"("f2")"), val(R"("f3")"), val(R"("f4")"), val()}},
                                       32)),
        TermT(R"(hp(   $f1,\   ,  \ ,   f4,   ))",
              makeSuccess<HelperToken>({"hp", Reference("f1"), {val(R"(" ")"), val(R"(" ")"), val(R"("f4")"), val()}},
                                       30)),
        TermT(R"(hp(   $f1,   ,   ,   f4,   ))",
              makeSuccess<HelperToken>({"hp", Reference("f1"), {val(), val(), val(R"("f4")"), val()}}, 28)),
        // Helper Ok - with spaces before and after separator
        TermT(R"(hp(   $f1   ,   $f2   ,   $f3   ))",
              makeSuccess<HelperToken>({"hp", Reference("f1"), {ref("f2"), ref("f3")}}, 33)),
        TermT(R"(hp(   $f1   ,   $f2   ,   $f3   ,   ))",
              makeSuccess<HelperToken>({"hp", Reference("f1"), {ref("f2"), ref("f3"), val()}}, 37)),
        TermT(R"(hp(   $f1   ,   f2   ,   f3   ,   f4   ))",
              makeSuccess<HelperToken>({"hp", Reference("f1"), {val(R"("f2")"), val(R"("f3")"), val(R"("f4")")}}, 40)),
        TermT(R"(hp(   $f1   ,\   f2   ,   f3   ,   f4   ,   ))", makeError<HelperToken>("", 0)),
        // Scape characters
        TermT(R"(hp(\ \, ,,,\,\,,\,\,\,))", makeError<HelperToken>("", 0)),
        TermT(R"(hp($f1,\ \, ,,,\,\,,\,\,\,))",
              makeSuccess<HelperToken>(
                  {"hp", Reference("f1"), {val(R"(" ,")"), val(), val(), val(R"(",,")"), val(R"(",,,")")}}, 27)),
        TermT(R"(hp($f1,   \ \, ,  ,  ,  \,\, ,  \,\,\\\,))",
              makeSuccess<HelperToken>(
                  {"hp", Reference("f1"), {val(R"(" ,")"), val(), val(), val(R"(",,")"), val(R"(",,\\,")")}}, 41)),
        // Helper Ok - Check in builder time the validity of the helper name and content of parameters
        TermT(R"(helper_name123())", makeError<HelperToken>("", 0)),
        TermT(R"(helper_name123(rawvalue))", makeError<HelperToken>("", 0)),
        TermT(R"(hp($wazuh.queue) )", makeSuccess<HelperToken>({"hp", Reference("wazuh.queue")}, 16)),
        TermT(R"(hp($wazuh.queue) ())", makeSuccess<HelperToken>({"hp", Reference("wazuh.queue")}, 16)),
        TermT(R"(hp($wazuh.queue)==())", makeSuccess<HelperToken>({"hp", Reference("wazuh.queue")}, 16)),
        TermT(R"(hp($wazuh.queue) AND)", makeSuccess<HelperToken>({"hp", Reference("wazuh.queue")}, 16)),
        TermT(R"(hp($wazuh.queue)==)", makeSuccess<HelperToken>({"hp", Reference("wazuh.queue")}, 16)),
        TermT(R"(hp($wazuh.queue)!!)", makeSuccess<HelperToken>({"hp", Reference("wazuh.queue")}, 16)),
        TermT(R"(hp($wazuh.queue)>)", makeSuccess<HelperToken>({"hp", Reference("wazuh.queue")}, 16)),
        TermT(R"(hp($wazuh.queue, ,\ \,) )",
              makeSuccess<HelperToken>({"hp", Reference("wazuh.queue"), {val(), val(R"(" ,")")}}, 23)),
        TermT(R"(hp($wazuh.queue, ,\ \,) ())",
              makeSuccess<HelperToken>({"hp", Reference("wazuh.queue"), {val(), val(R"(" ,")")}}, 23)),
        TermT(R"(hp($wazuh.queue, ,\ \,)==())",
              makeSuccess<HelperToken>({"hp", Reference("wazuh.queue"), {val(), val(R"(" ,")")}}, 23)),
        TermT(R"(hp($wazuh.queue, ,\ \,) AND)",
              makeSuccess<HelperToken>({"hp", Reference("wazuh.queue"), {val(), val(R"(" ,")")}}, 23)),
        TermT(R"(hp($wazuh.queue, ,\ \,)==)",
              makeSuccess<HelperToken>({"hp", Reference("wazuh.queue"), {val(), val(R"(" ,")")}}, 23)),
        TermT(R"(hp($wazuh.queue, ,\ \,)!!)",
              makeSuccess<HelperToken>({"hp", Reference("wazuh.queue"), {val(), val(R"(" ,")")}}, 23)),
        TermT(R"(hp($wazuh.queue, ,\ \,)>)",
              makeSuccess<HelperToken>({"hp", Reference("wazuh.queue"), {val(), val(R"(" ,")")}}, 23))));

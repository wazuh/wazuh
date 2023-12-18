#include <gtest/gtest.h>

#include "builders/helperParser.hpp"

std::shared_ptr<builder::builders::Argument> val(const std::string& jsonStr = "")
{
    if (jsonStr.empty())
    {
        return std::make_shared<builder::builders::Value>();
    }

    return std::make_shared<builder::builders::Value>(json::Json(jsonStr.c_str()));
}

std::shared_ptr<builder::builders::Argument> ref(const std::string& dotPath)
{
    return std::make_shared<builder::builders::Reference>(dotPath);
}

using HelperParserT = std::tuple<bool, std::string, builder::builders::detail::HelperToken>;
class HelperParserTest : public ::testing::TestWithParam<HelperParserT>
{
};

TEST_P(HelperParserTest, parse)
{
    auto& [shouldPass, input, expected] = GetParam();

    auto result = builder::builders::detail::parseHelper(input);

    if (shouldPass)
    {
        ASSERT_TRUE(std::holds_alternative<builder::builders::detail::HelperToken>(result));
        ASSERT_EQ(std::get<builder::builders::detail::HelperToken>(result).name, expected.name);
        // Arguments are stored in shared_ptr, so we need to manually compare them
        ASSERT_EQ(std::get<builder::builders::detail::HelperToken>(result).args.size(), expected.args.size());
        auto gotArgs = std::get<builder::builders::detail::HelperToken>(result).args;
        for (auto i = 0; i < gotArgs.size(); ++i)
        {
            auto gotArg = gotArgs[i];
            auto expectedArg = expected.args[i];

            if (expectedArg->isReference())
            {
                ASSERT_TRUE(gotArg->isReference());
                ASSERT_EQ(std::static_pointer_cast<builder::builders::Reference>(gotArg)->dotPath(),
                          std::static_pointer_cast<builder::builders::Reference>(expectedArg)->dotPath());
                ASSERT_EQ(std::static_pointer_cast<builder::builders::Reference>(gotArg)->jsonPath(),
                          std::static_pointer_cast<builder::builders::Reference>(expectedArg)->jsonPath());
            }
            else
            {
                ASSERT_TRUE(gotArg->isValue());
                ASSERT_EQ(std::static_pointer_cast<builder::builders::Value>(gotArg)->value(),
                          std::static_pointer_cast<builder::builders::Value>(expectedArg)->value());
            }
        }
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
        HelperParserT(true, "stringValue", {.name = "", .args = {val("\"stringValue\"")}}),
        HelperParserT(true, "123", {.name = "", .args = {val("123")}}),
        HelperParserT(true, "123.456", {.name = "", .args = {val("123.456")}}),
        HelperParserT(true, "true", {.name = "", .args = {val("true")}}),
        HelperParserT(true, "false", {.name = "", .args = {val("false")}}),
        HelperParserT(true, "{}", {.name = "", .args = {val("{}")}}),
        HelperParserT(true, "[]", {.name = "", .args = {val("[]")}}),
        HelperParserT(true, "$ref", {.name = "", .args = {ref("ref")}}),
        HelperParserT(true, "helper()", {.name = "helper"}),
        HelperParserT(true, "helper('')", {.name = "helper", .args = {val("\"\"")}}),
        HelperParserT(true, "helper( '')", {.name = "helper", .args = {val("\"\"")}}),
        HelperParserT(true, "helper( ''  )", {.name = "helper", .args = {val("\"\"")}}),
        HelperParserT(true, "helper(arg1)", {.name = "helper", .args = {val("\"arg1\"")}}),
        HelperParserT(true, "helper(arg1, '')", {.name = "helper", .args = {val("\"arg1\""), val("\"\"")}}),
        HelperParserT(true, "helper(arg1, )", {.name = "helper", .args = {val("\"arg1\""), val("\"\"")}}),
        HelperParserT(true, "helper(arg1,arg2)", {.name = "helper", .args = {val("\"arg1\""), val("\"arg2\"")}}),
        HelperParserT(true, "helper(arg1,  \"\")", {.name = "helper", .args = {val("\"arg1\""), val("\"\"")}}),
        HelperParserT(true,
                      "helper(arg1, '', arg3)",
                      {.name = "helper", .args = {val("\"arg1\""), val("\"\""), val("\"arg3\"")}}),
        HelperParserT(true,
                      "helper(arg1, '' , arg3)",
                      {.name = "helper", .args = {val("\"arg1\""), val("\"\""), val("\"arg3\"")}}),
        HelperParserT(true,
                      "helper(arg1, arg2, arg3)",
                      {.name = "helper", .args = {val("\"arg1\""), val("\"arg2\""), val("\"arg3\"")}}),
        HelperParserT(true,
                      "helper(arg1, arg2\\,arg3)",
                      {.name = "helper", .args = {val("\"arg1\""), val("\"arg2,arg3\"")}}), // Testing escaped comma
        HelperParserT(true,
                      "helper(arg1,\\ arg2)",
                      {.name = "helper", .args = {val("\"arg1\""), val("\" arg2\"")}}), // Testing escaped space
        HelperParserT(false, "helper(arg1", {}),                                        // Missing closing parenthesis
        HelperParserT(true, "'helper(arg1'", {.name = "", .args = {val("\"helper(arg1\"")}}),
        HelperParserT(true, "test arg1)", {.name = "", .args = {val("\"test arg1)\"")}}), // Missing opening parenthesis
        HelperParserT(false, "", {}),                                                     // Empty string
        HelperParserT(true, "()", {.name = "", .args = {val("\"()\"")}}),                 // No function name
        HelperParserT(true, "test(,)", {.name = "test", .args {val("\"\""), val("\"\"")}}),
        HelperParserT(true, "test(,,)", {.name = "test", .args {val("\"\""), val("\"\""), val("\"\"")}}),
        HelperParserT(true, "test(, ,)", {.name = "test", .args {val("\"\""), val("\"\""), val("\"\"")}}),
        HelperParserT(true, "test(arg1,)", {.name = "test", .args {val("\"arg1\""), val("\"\"")}}),
        HelperParserT(true, "test(arg1, )", {.name = "test", .args {val("\"arg1\""), val("\"\"")}}),
        HelperParserT(true, "test(arg1,\\ )", {.name = "test", .args {val("\"arg1\""), val("\" \"")}}),
        HelperParserT(true, "test(arg1,' ')", {.name = "test", .args {val("\"arg1\""), val("\" \"")}}),
        HelperParserT(true, "test(arg1,  )", {.name = "test", .args {val("\"arg1\""), val("\"\"")}}),
        HelperParserT(false, "test(arg1, ())", {}),
        HelperParserT(true, "test(arg1, (\\))", {.name = "test", .args {val("\"arg1\""), val("\"()\"")}}),
        HelperParserT(true, "test(arg1, ( arg2)", {.name = "test", .args = {val("\"arg1\""), val("\"( arg2\"")}}),
        HelperParserT(true, "test(arg1, \\) arg2)", {.name = "test", .args = {val("\"arg1\""), val("\") arg2\"")}}),
        HelperParserT(true,
                      "test(arg1, \\)\\ arg2\\)\\)\\))",
                      {.name = "test", .args = {val("\"arg1\""), val("\") arg2)))\"")}}),
        HelperParserT(false, "test(arg1)leftover", {}),
        HelperParserT(true, "test(arg1, ' , ( ) ' )", {.name = "test", .args {val("\"arg1\""), val("\" , ( ) \"")}})));

using TermParserT = std::tuple<bool, std::string, builder::builders::detail::BuildToken>;
class TermParserTest : public ::testing::TestWithParam<TermParserT>
{
};

using expToken = builder::builders::detail::ExpressionToken;
using helpToken = builder::builders::detail::HelperToken;

TEST_P(TermParserTest, parse)
{

    auto& [shouldPass, input, expected] = GetParam();

    auto result = builder::builders::detail::getTermParser()(input, 0);

    if (shouldPass)
    {
        ASSERT_TRUE(result.success());
        const auto&& resultVToken = result.value();

        // Expression expected
        if (std::holds_alternative<expToken>(expected))
        {
            ASSERT_TRUE(std::holds_alternative<expToken>(resultVToken)) << "Expected ExpressionToken";
            const auto& expectedToken = std::get<expToken>(expected);
            const auto& resultToken = std::get<expToken>(resultVToken);

            ASSERT_EQ(resultToken.op, expectedToken.op);
            ASSERT_EQ(resultToken.field, expectedToken.field);
            ASSERT_EQ(resultToken.value, expectedToken.value);
        }
        else if (std::holds_alternative<helpToken>(expected))
        {
            ASSERT_TRUE(std::holds_alternative<helpToken>(resultVToken)) << "Expected HelperToken";
            const auto& expectedToken = std::get<helpToken>(expected);
            const auto& resultToken = std::get<helpToken>(resultVToken);

            ASSERT_EQ(resultToken.name, expectedToken.name);
            ASSERT_EQ(resultToken.targetField.dotPath(), expectedToken.targetField.dotPath());
            ASSERT_EQ(resultToken.targetField.jsonPath(), expectedToken.targetField.jsonPath());

            // Arguments are stored in shared_ptr, so we need to manually compare them
            ASSERT_EQ(resultToken.args.size(), expectedToken.args.size());
            auto gotArgs = resultToken.args;

            for (auto i = 0; i < gotArgs.size(); ++i)
            {
                auto gotArg = gotArgs[i];
                auto expectedArg = expectedToken.args[i];

                if (expectedArg->isReference())
                {
                    ASSERT_TRUE(gotArg->isReference());
                    ASSERT_EQ(std::static_pointer_cast<builder::builders::Reference>(gotArg)->dotPath(),
                              std::static_pointer_cast<builder::builders::Reference>(expectedArg)->dotPath());
                    ASSERT_EQ(std::static_pointer_cast<builder::builders::Reference>(gotArg)->jsonPath(),
                              std::static_pointer_cast<builder::builders::Reference>(expectedArg)->jsonPath());
                }
                else
                {
                    ASSERT_TRUE(gotArg->isValue());
                    ASSERT_EQ(std::static_pointer_cast<builder::builders::Value>(gotArg)->value(),
                              std::static_pointer_cast<builder::builders::Value>(expectedArg)->value());
                }
            }
        }
        else
        {
            FAIL() << "Expected ExpressionToken";
        }
    }
    else
    {
        ASSERT_TRUE(result.failure());
    }
}

builder::builders::Reference target(const std::string& dotPath)
{
    return builder::builders::Reference(dotPath);
}

using eOp = builder::builders::detail::ExpressionOperator;
INSTANTIATE_TEST_SUITE_P(
    Builder,
    TermParserTest,
    ::testing::Values(
        //**************************
        // Expression TEST
        // TODO check $field op $Field should failt, y think it is sufficient with helper with field comparison
        //**************************
        TermParserT(true, R"($field==123)", expToken {"$field", eOp::EQUAL, json::Json {R"(123)"}}),
        TermParserT(true, R"($field=="123")", expToken {"$field", eOp::EQUAL, json::Json {R"("123")"}}),
        TermParserT(true, R"($field==$field2)", expToken {"$field", eOp::EQUAL, json::Json {R"("$field2")"}}),
        TermParserT(true, R"($field=={})", expToken {"$field", eOp::EQUAL, json::Json {R"({})"}}),
        TermParserT(true, R"($field==null)", expToken {"$field", eOp::EQUAL, json::Json {R"(null)"}}),
        TermParserT(true, R"($field==true)", expToken {"$field", eOp::EQUAL, json::Json {R"(true)"}}),
        TermParserT(true, R"($field>=123)", expToken {"$field", eOp::GREATER_THAN_OR_EQUAL, json::Json {R"(123)"}}),
        TermParserT(true, R"($field>123)", expToken {"$field", eOp::GREATER_THAN, json::Json {R"(123)"}}),
        TermParserT(true, R"($field<="123")", expToken {"$field", eOp::LESS_THAN_OR_EQUAL, json::Json {R"("123")"}}),
        TermParserT(true, R"($field<"123")", expToken {"$field", eOp::LESS_THAN, json::Json {R"("123")"}}),
        TermParserT(true, R"($field!=$field2)", expToken {"$field", eOp::NOT_EQUAL, json::Json {R"("$field2")"}}),
        TermParserT(true, R"($field<$field2)", expToken {"$field", eOp::LESS_THAN, json::Json {R"("$field2")"}}),
        TermParserT(true,
                    R"($field=={"key_str":"asd","key_num":123,"key_obj":{"custom_key":true}})",
                    expToken {"$field",
                              eOp::EQUAL,
                              json::Json {R"({"key_str":"asd","key_num":123,"key_obj":{"custom_key":true}})"}}),

        // Expression Ok - with spaces
        TermParserT(true, R"($field == 123)", expToken {"$field", eOp::EQUAL, json::Json {R"(123)"}}),
        TermParserT(true, R"($field == "123")", expToken {"$field", eOp::EQUAL, json::Json {R"("123")"}}),
        TermParserT(true, R"($field == $field2)", expToken {"$field", eOp::EQUAL, json::Json {R"("$field2")"}}),
        TermParserT(true, R"($field == {})", expToken {"$field", eOp::EQUAL, json::Json {R"({})"}}),
        TermParserT(true, R"($field == null)", expToken {"$field", eOp::EQUAL, json::Json {R"(null)"}}),
        TermParserT(true, R"($field == true)", expToken {"$field", eOp::EQUAL, json::Json {R"(true)"}}),
        TermParserT(true, R"($field >= 123)", expToken {"$field", eOp::GREATER_THAN_OR_EQUAL, json::Json {R"(123)"}}),
        TermParserT(true, R"($field > 123)", expToken {"$field", eOp::GREATER_THAN, json::Json {R"(123)"}}),
        TermParserT(true, R"($field <= "123")", expToken {"$field", eOp::LESS_THAN_OR_EQUAL, json::Json {R"("123")"}}),
        TermParserT(true, R"($field < "123")", expToken {"$field", eOp::LESS_THAN, json::Json {R"("123")"}}),
        TermParserT(true, R"($field != $field2)", expToken {"$field", eOp::NOT_EQUAL, json::Json {R"("$field2")"}}),
        TermParserT(true, R"($field < $field2)", expToken {"$field", eOp::LESS_THAN, json::Json {R"("$field2")"}}),
        TermParserT(true,
                    R"($field == {"key_str":"asd","key_num":123,"key_obj":{"custom_key":true}})",
                    expToken {"$field",
                              eOp::EQUAL,
                              json::Json {R"({"key_str":"asd","key_num":123,"key_obj":{"custom_key":true}})"}}),
        // Expression Ok - with spaces after field only
        TermParserT(true, R"($field   ==123)", expToken {"$field", eOp::EQUAL, json::Json {R"(123)"}}),
        TermParserT(true, R"($field   =="123")", expToken {"$field", eOp::EQUAL, json::Json {R"("123")"}}),
        TermParserT(true, R"($field   ==$field2)", expToken {"$field", eOp::EQUAL, json::Json {R"("$field2")"}}),
        TermParserT(true, R"($field   =={})", expToken {"$field", eOp::EQUAL, json::Json {R"({})"}}),
        TermParserT(true, R"($field   ==null)", expToken {"$field", eOp::EQUAL, json::Json {R"(null)"}}),
        TermParserT(true, R"($field   ==true)", expToken {"$field", eOp::EQUAL, json::Json {R"(true)"}}),
        TermParserT(true, R"($field   >=123)", expToken {"$field", eOp::GREATER_THAN_OR_EQUAL, json::Json {R"(123)"}}),
        TermParserT(true, R"($field   >123)", expToken {"$field", eOp::GREATER_THAN, json::Json {R"(123)"}}),
        TermParserT(true, R"($field   <="123")", expToken {"$field", eOp::LESS_THAN_OR_EQUAL, json::Json {R"("123")"}}),
        TermParserT(true, R"($field   <"123")", expToken {"$field", eOp::LESS_THAN, json::Json {R"("123")"}}),
        TermParserT(true, R"($field   !=$field2)", expToken {"$field", eOp::NOT_EQUAL, json::Json {R"("$field2")"}}),
        TermParserT(true, R"($field   <$field2)", expToken {"$field", eOp::LESS_THAN, json::Json {R"("$field2")"}}),
        TermParserT(true,
                    R"($field =={"key_str":"asd","key_num":123,"key_obj":{"custom_key":true}})",
                    expToken {"$field",
                              eOp::EQUAL,
                              json::Json {R"({"key_str":"asd","key_num":123,"key_obj":{"custom_key":true}})"}}),
        // Expression Ok - with spaces after operator only
        TermParserT(true, R"($field==   123)", expToken {"$field", eOp::EQUAL, json::Json {R"(123)"}}),
        TermParserT(true, R"($field==  "123")", expToken {"$field", eOp::EQUAL, json::Json {R"("123")"}}),
        TermParserT(true, R"($field==   $field2)", expToken {"$field", eOp::EQUAL, json::Json {R"("$field2")"}}),
        TermParserT(true, R"($field==   {})", expToken {"$field", eOp::EQUAL, json::Json {R"({})"}}),
        TermParserT(true, R"($field==   null)", expToken {"$field", eOp::EQUAL, json::Json {R"(null)"}}),
        TermParserT(true, R"($field==   true)", expToken {"$field", eOp::EQUAL, json::Json {R"(true)"}}),
        TermParserT(true, R"($field>=   123)", expToken {"$field", eOp::GREATER_THAN_OR_EQUAL, json::Json {R"(123)"}}),
        TermParserT(true, R"($field>    123)", expToken {"$field", eOp::GREATER_THAN, json::Json {R"(123)"}}),
        TermParserT(true, R"($field<=   "123")", expToken {"$field", eOp::LESS_THAN_OR_EQUAL, json::Json {R"("123")"}}),
        TermParserT(true, R"($field<   "123")", expToken {"$field", eOp::LESS_THAN, json::Json {R"("123")"}}),
        TermParserT(true, R"($field!=   $field2)", expToken {"$field", eOp::NOT_EQUAL, json::Json {R"("$field2")"}}),
        TermParserT(true, R"($field<   $field2)", expToken {"$field", eOp::LESS_THAN, json::Json {R"("$field2")"}}),
        TermParserT(true,
                    R"($field==    {"key_str":"asd","key_num":123,"key_obj":{"custom_key":true}})",
                    expToken {"$field",
                              eOp::EQUAL,
                              json::Json {R"({"key_str":"asd","key_num":123,"key_obj":{"custom_key":true}})"}}),
        // Expression fail - bad operator
        TermParserT(false, R"($field=!123)", expToken {}),
        TermParserT(false, R"($field=123)", expToken {}),
        TermParserT(false, R"($field->123)", expToken {}),
        TermParserT(false, R"($field.123)", expToken {}),
        TermParserT(false, R"($field!123)", expToken {}),
        TermParserT(false, R"($field|123)", expToken {}),
        TermParserT(false, R"($field?123)", expToken {}),
        TermParserT(false, R"($field =! 123)", expToken {}),
        TermParserT(false, R"($field = 123)", expToken {}),
        TermParserT(false, R"($field -> 123)", expToken {}),
        // Expression fail - bad field
        TermParserT(false, R"(field == 123)", expToken {}),
        TermParserT(false, R"(field == "123")", expToken {}),
        TermParserT(false, R"(field == $field2)", expToken {}),
        TermParserT(false, R"(field == {})", expToken {}),
        TermParserT(false, R"(field == null)", expToken {}),
        TermParserT(false, R"(field == true)", expToken {}),
        TermParserT(false, R"(field >= 123)", expToken {}),
        TermParserT(false, R"(field > 123)", expToken {}),
        TermParserT(false, R"(field <= "123")", expToken {}),
        TermParserT(false, R"(field < "123")", expToken {}),
        TermParserT(false, R"(field != $field2)", expToken {}),
        // Expression fail - Missing field
        TermParserT(false, R"($field == )", expToken {}),
        TermParserT(false, R"($ == 123)", expToken {}),
        TermParserT(false, R"($field 123)", expToken {}),
        //**************************
        // Helper TEST
        //**************************
        // Helper Ok - spaces after separator
        TermParserT(true, R"(helper_name123($target_field1))", helpToken {"helper_name123", target("target_field1")}),
        TermParserT(true,
                    R"(helper_name123($target_field1, ))",
                    helpToken {"helper_name123", target("target_field1"), {val("\"\"")}}),
        TermParserT(true, R"(hp($f1, $f2, $f3))", helpToken {"hp", target("f1"), {ref("f2"), ref("f3")}}),
        TermParserT(true,
                    R"(hp($f1, $f2, $f3, ))",
                    helpToken {"hp", target("f1"), {ref("f2"), ref("f3"), val("\"\"")}}),
        TermParserT(true,
                    R"(hp($f1, f2, f3, f4))",
                    helpToken {"hp", target("f1"), {val("\"f2\""), val("\"f3\""), val("\"f4\"")}}),
        TermParserT(true,
                    R"(hp($f1, f2, f3, f4, ))",
                    helpToken {"hp", target("f1"), {val("\"f2\""), val("\"f3\""), val("\"f4\""), val("\"\"")}}),
        TermParserT(true,
                    R"(hp($f1, , , f4, ))",
                    helpToken {"hp", target("f1"), {val("\"\""), val("\"\""), val("\"f4\""), val("\"\"")}}),
        TermParserT(true,
                    R"(hp($f1, , , f4, ))",
                    helpToken {"hp", target("f1"), {val("\"\""), val("\"\""), val("\"f4\""), val("\"\"")}}),
        // Helper Ok - without spaces
        TermParserT(true, R"(hp($f1,$f2,$f3))", helpToken {"hp", target("f1"), {ref("f2"), ref("f3")}}),
        TermParserT(true, R"(hp($f1,$f2,$f3, ))", helpToken {"hp", target("f1"), {ref("f2"), ref("f3"), val("\"\"")}}),
        TermParserT(true,
                    R"(hp($f1,f2,f3,f4))",
                    helpToken {"hp", target("f1"), {val("\"f2\""), val("\"f3\""), val("\"f4\"")}}),
        TermParserT(true,
                    R"(hp($f1,f2,f3,f4,))",
                    helpToken {"hp", target("f1"), {val("\"f2\""), val("\"f3\""), val("\"f4\""), val("\"\"")}}),
        TermParserT(true,
                    R"(hp($f1,,,f4,))",
                    helpToken {"hp", target("f1"), {val("\"\""), val("\"\""), val("\"f4\""), val("\"\"")}}),
        // Helper Ok - with spaces before separator
        TermParserT(true, R"(hp(   $f1,   $f2,   $f3))", helpToken {"hp", target("f1"), {ref("f2"), ref("f3")}}),
        TermParserT(true,
                    R"(hp(   $f1,   $f2,   $f3,   ))",
                    helpToken {"hp", target("f1"), {ref("f2"), ref("f3"), val("\"\"")}}),
        TermParserT(true,
                    R"(hp(   $f1,   f2,   f3,   f4))",
                    helpToken {"hp", target("f1"), {val("\"f2\""), val("\"f3\""), val("\"f4\"")}}),
        TermParserT(true,
                    R"(hp(   $f1,   f2,   f3,   f4,   ))",
                    helpToken {"hp", target("f1"), {val("\"f2\""), val("\"f3\""), val("\"f4\""), val("\"\"")}}),
        TermParserT(true,
                    R"(hp(   $f1,\   ,  \ ,   f4,   ))",
                    helpToken {"hp", target("f1"), {val("\"   \""), val("\" \""), val("\"f4\""), val("\"\"")}}),
        TermParserT(true,
                    R"(hp(   $f1,   ,   ,   f4,   ))",
                    helpToken {"hp", target("f1"), {val("\"\""), val("\"\""), val("\"f4\""), val("\"\"")}}),
        // Helper Ok - with spaces before and after separator
        TermParserT(true,
                    R"(hp(   $f1   ,   $f2   ,   $f3   ))",
                    helpToken {"hp", target("f1   "), {ref("f2   "), ref("f3   ")}}),
        TermParserT(true,
                    R"(hp(   $f1   ,   $f2   ,   $f3   ,   ))",
                    helpToken {"hp", target("f1   "), {ref("f2   "), ref("f3   "), val("\"\"")}}),
        TermParserT(true,
                    R"(hp(   $f1   ,   f2   ,   f3   ,   f4   ))",
                    helpToken {"hp", target("f1   "), {val("\"f2   \""), val("\"f3   \""), val("\"f4   \"")}}),
        TermParserT(true,
                    R"(hp(   $f1   ,\   f2   ,   f3   ,   f4   ,   ))",
                    helpToken {
                        "hp", target("f1   "), {val("\"   f2   \""), val("\"f3   \""), val("\"f4   \""), val("\"\"")}}),
        // Scape characters
        TermParserT(false, R"(hp(\ \, ,,,\,\,,\,\,\,))", {}),
        TermParserT(true,
                    R"(hp($f1,\ \, ,,,\,\,,\,\,\,))",
                    helpToken {
                        "hp", target("f1"), {val("\" , \""), val("\"\""), val("\"\""), val("\",,\""), val("\",,,\"")}}),
        TermParserT(true,
                    R"(hp($f1,   \ \, ,  ,  ,  \,\, ,  \,\,\\\,))",
                    helpToken {"hp",
                               target("f1"),
                               {val("\" , \""), val("\"\""), val("\"\""), val("\",, \""), val("\",,\\\\,\"")}}),
        // Helper Ok - Check in builder time the validity of the helper name and content of parameters
        TermParserT(false, R"(helper_name123())", {}),
        TermParserT(false, R"(helper_name123(rawvalue))", {}),
        TermParserT(true, R"(hp($wazuh.queue) )", helpToken {"hp", target("wazuh.queue")}),
        TermParserT(true, R"(hp($wazuh.queue) ())", helpToken {"hp", target("wazuh.queue")}),
        TermParserT(true, R"(hp($wazuh.queue)==())", helpToken {"hp", target("wazuh.queue")}),
        TermParserT(true, R"(hp($wazuh.queue) AND)", helpToken {"hp", target("wazuh.queue")}),
        TermParserT(true, R"(hp($wazuh.queue)==)", helpToken {"hp", target("wazuh.queue")}),
        TermParserT(true, R"(hp($wazuh.queue)!!)", helpToken {"hp", target("wazuh.queue")}),
        TermParserT(true, R"(hp($wazuh.queue)>)", helpToken {"hp", target("wazuh.queue")}),
        TermParserT(true,
                    R"(hp($wazuh.queue, ,\ \,) )",
                    helpToken {"hp", target("wazuh.queue"), {val("\"\""), val("\" ,\"")}}),
        TermParserT(true,
                    R"(hp($wazuh.queue, ,\ \,) ())",
                    helpToken {"hp", target("wazuh.queue"), {val("\"\""), val("\" ,\"")}}),
        TermParserT(true,
                    R"(hp($wazuh.queue, ,\ \,)==())",
                    helpToken {"hp", target("wazuh.queue"), {val("\"\""), val("\" ,\"")}}),
        TermParserT(true,
                    R"(hp($wazuh.queue, ,\ \,) AND)",
                    helpToken {"hp", target("wazuh.queue"), {val("\"\""), val("\" ,\"")}}),
        TermParserT(true,
                    R"(hp($wazuh.queue, ,\ \,)==)",
                    helpToken {"hp", target("wazuh.queue"), {val("\"\""), val("\" ,\"")}}),
        TermParserT(true,
                    R"(hp($wazuh.queue, ,\ \,)!!)",
                    helpToken {"hp", target("wazuh.queue"), {val("\"\""), val("\" ,\"")}}),
        TermParserT(true,
                    R"(hp($wazuh.queue, ,\ \,)>)",
                    helpToken {"hp", target("wazuh.queue"), {val("\"\""), val("\" ,\"")}})));

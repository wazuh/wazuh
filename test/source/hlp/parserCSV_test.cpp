#include <any>
#include <vector>

#include <gtest/gtest.h>
#include <hlp/hlp.hpp>

using namespace hlp;

TEST(parseCSV, build)
{
    ASSERT_NO_THROW(getParserOp("<~test/csv/field_1>"));
}

TEST(parseCSV, extract_exact_fields_1_not_null_end_string)
{
    const char* logpar = "<~custom/csv/field_1>";
    const char* event = R"(hi)";
    const char* expectedJSON = R"({"field_1":"hi"})";

    ParserFn parseOp = getParserOp(logpar);
    ASSERT_TRUE(static_cast<bool>(parseOp));

    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_TRUE(ret);
    ASSERT_STREQ(expectedJSON,
                 std::any_cast<JsonString>(result["~custom"]).jsonString.c_str());
}

TEST(parseCSV, extract_exact_fields_1_not_null_not_end_string)
{
    const char* logpar = "<~custom/csv/field_1> <~dummy>";
    const char* event = R"(hi bye)";
    const char* expectedJSON = R"({"field_1":"hi"})";

    ParserFn parseOp = getParserOp(logpar);
    ASSERT_TRUE(static_cast<bool>(parseOp));

    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_TRUE(ret);
    ASSERT_STREQ(expectedJSON,
                 std::any_cast<JsonString>(result["~custom"]).jsonString.c_str());
    ASSERT_EQ("bye", std::any_cast<std::string>(result["~dummy"]));
}

TEST(parseCSV, extract_exact_fields_2_not_null_end_string)
{
    const char* logpar = "<~custom/csv/field_1/field_2>";
    const char* event = R"(hi,hi2)";
    const char* expectedJSON = R"({"field_1":"hi","field_2":"hi2"})";

    ParserFn parseOp = getParserOp(logpar);
    ASSERT_TRUE(static_cast<bool>(parseOp));

    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_TRUE(ret);
    ASSERT_STREQ(expectedJSON,
                 std::any_cast<JsonString>(result["~custom"]).jsonString.c_str());
}

TEST(parseCSV, extract_exact_fields_2_not_null_not_end_string)
{
    const char* logpar = "<~custom/csv/field_1/field_2> <~dummy>";
    const char* event = R"(hi,hi2 bye)";
    const char* expectedJSON = R"({"field_1":"hi","field_2":"hi2"})";

    ParserFn parseOp = getParserOp(logpar);
    ASSERT_TRUE(static_cast<bool>(parseOp));

    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_TRUE(ret);
    ASSERT_STREQ(expectedJSON,
                 std::any_cast<JsonString>(result["~custom"]).jsonString.c_str());
    ASSERT_EQ("bye", std::any_cast<std::string>(result["~dummy"]));
}

TEST(parseCSV, extract_exact_fields_2_null_end_string)
{
    const char* logpar = "<~custom/csv/field_1/field_2>";
    const char* event = R"(,)";
    const char* expectedJSON = R"({"field_1":null,"field_2":null})";

    ParserFn parseOp = getParserOp(logpar);
    ASSERT_TRUE(static_cast<bool>(parseOp));

    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_TRUE(ret);
    ASSERT_STREQ(expectedJSON,
                 std::any_cast<JsonString>(result["~custom"]).jsonString.c_str());
}

TEST(parseCSV, extract_exact_fields_2_null_not_end_string)
{
    const char* logpar = "<~custom/csv/field_1/field_2> <~dummy>";
    const char* event = R"(, bye)";
    const char* expectedJSON = R"({"field_1":null,"field_2":null})";

    ParserFn parseOp = getParserOp(logpar);
    ASSERT_TRUE(static_cast<bool>(parseOp));

    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_TRUE(ret);
    ASSERT_STREQ(expectedJSON,
                 std::any_cast<JsonString>(result["~custom"]).jsonString.c_str());
    ASSERT_EQ("bye", std::any_cast<std::string>(result["~dummy"]));
}

TEST(parseCSV, extract_minor_fields_2_not_null_not_end_string)
{
    const char* logpar = "<~custom/csv/field_1/field_2>,hi3,hi4 <~dummy>";
    const char* event = R"(hi1,hi2,hi3,hi4 bye)";
    const char* expectedJSON = R"({"field_1":"hi1","field_2":"hi2"})";

    ParserFn parseOp = getParserOp(logpar);
    ASSERT_TRUE(static_cast<bool>(parseOp));

    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_TRUE(ret);
    ASSERT_STREQ(expectedJSON,
                 std::any_cast<JsonString>(result["~custom"]).jsonString.c_str());
    ASSERT_EQ("bye", std::any_cast<std::string>(result["~dummy"]));
}

TEST(parseCSV, extract_minor_fields_2_not_null_not_end_string_2)
{
    const char* logpar = "<~custom/csv/field_1/field_2>,<~dummy>";
    const char* event = R"(hi1,hi2,hi3,hi4 bye)";
    const char* expectedJSON = R"({"field_1":"hi1","field_2":"hi2"})";

    ParserFn parseOp = getParserOp(logpar);
    ASSERT_TRUE(static_cast<bool>(parseOp));

    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_TRUE(ret);
    ASSERT_STREQ(expectedJSON,
                 std::any_cast<JsonString>(result["~custom"]).jsonString.c_str());
    ASSERT_EQ("hi3,hi4 bye", std::any_cast<std::string>(result["~dummy"]));
}

TEST(parseCSV, extract_exact_fields)
{
    const char* logpar = "<~custom/csv/null_1/null_2/word/esacaped_1/no_escape,null_3/"
                         "null_4/new/null_5/null_6/null_7>";
    const char* event =
        R"(,,hi,"semicolon scaped'"",""' <-- other here <,>",other value,,,value new,,)";
    const char* expectedJSON =
        R"({"null_1":null,"null_2":null,"word":"hi","esacaped_1":"semicolon scaped'\",\"' <-- other here <,>","no_escape,null_3":"other value","null_4":null,"new":null,"null_5":"value new","null_6":null,"null_7":null})";

    ParserFn parseOp = getParserOp(logpar);
    ASSERT_TRUE(static_cast<bool>(parseOp));

    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_TRUE(ret);
    ASSERT_STREQ(expectedJSON,
                 std::any_cast<JsonString>(result["~custom"]).jsonString.c_str());
}

TEST(parseCSV, more_arguments_than_values)
{
    const char* logpar = "<~custom/csv/field_1/field_2/field_3/field_4>";
    const char* event = R"(f1,f3,f3)";

    ParserFn parseOp = getParserOp(logpar);
    ASSERT_TRUE(static_cast<bool>(parseOp));

    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_FALSE(ret);
}

TEST(parseCSV, less_arguments_than_values)
{
    const char* logpar = "<~custom/csv/field_1/field_2/field_3/field_4>";
    const char* event = R"(f1,f3,f3,f4,f5)";

    ParserFn parseOp = getParserOp(logpar);
    ASSERT_TRUE(static_cast<bool>(parseOp));

    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_FALSE(ret);
}

TEST(parseCSV, less_arguments_than_values_not_null)
{
    const char* logpar = "<~custom/csv/field_1/field_2/field_3/field_4>,<~dummy/any>";
    const char* event = R"(f1,f2,f3,f4,f5)";
    const char* expectedJSON =
        R"({"field_1":"f1","field_2":"f2","field_3":"f3","field_4":"f4"})";

    ParserFn parseOp = getParserOp(logpar);
    ASSERT_TRUE(static_cast<bool>(parseOp));

    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_TRUE(ret);
    ASSERT_STREQ(expectedJSON,
                 std::any_cast<JsonString>(result["~custom"]).jsonString.c_str());
    ASSERT_STREQ(R"(f5)", std::any_cast<std::string>(result["~dummy"]).c_str());
}

TEST(parseCSV, end_quoted)
{
    const char* logpar = "<~custom/csv/field_1/field_2/field_3/field_4>";
    const char* event = R"(f1,f2,f3,"f4,f5")";
    const char* expectedJSON =
        R"({"field_1":"f1","field_2":"f2","field_3":"f3","field_4":"f4,f5"})";

    ParserFn parseOp = getParserOp(logpar);
    ASSERT_TRUE(static_cast<bool>(parseOp));

    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_TRUE(ret);
    ASSERT_STREQ(expectedJSON,
                 std::any_cast<JsonString>(result["~custom"]).jsonString.c_str());
}

TEST(parseCSV, end_bad_quoted)
{
    const char* logpar = "<~custom/csv/field_1/field_2/field_3/field_4>";
    const char* event = R"(f1,f2,f3,"f4,f5)";

    ParserFn parseOp = getParserOp(logpar);
    ASSERT_TRUE(static_cast<bool>(parseOp));

    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_FALSE(ret);
}

TEST(parseCSV, end_inten_quoted_2)
{
    const char* logpar = "<~custom/csv/field_1/field_2/field_3/field_4>";
    const char* event = R"(f1,f2,f3,f4""")";
    const char* expectedJSON =
        R"({"field_1":"f1","field_2":"f2","field_3":"f3","field_4":"f4\"\"\""})";

    ParserFn parseOp = getParserOp(logpar);
    ASSERT_TRUE(static_cast<bool>(parseOp));

    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_TRUE(ret);
    ASSERT_STREQ(expectedJSON,
                 std::any_cast<JsonString>(result["~custom"]).jsonString.c_str());
}

TEST(parseCSV, end_inten_quoted_3)
{
    const char* logpar = "<~custom/csv/field_1/field_2/field_3/field_4>";
    const char* event = R"(f1,f2,f3,"--""--")";
    const char* expectedJSON =
        R"({"field_1":"f1","field_2":"f2","field_3":"f3","field_4":"--\"--"})";

    ParserFn parseOp = getParserOp(logpar);
    ASSERT_TRUE(static_cast<bool>(parseOp));

    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_TRUE(ret);
    ASSERT_STREQ(expectedJSON,
                 std::any_cast<JsonString>(result["~custom"]).jsonString.c_str());
}

TEST(parseCSV, end_inten_quoted_4)
{
    const char* logpar = "<~custom/csv/field_1/field_2/field_3/field_4/field_5>";
    const char* event = R"(f1,f2,f3,"--""--",)";
    const char* expectedJSON =
        R"({"field_1":"f1","field_2":"f2","field_3":"f3","field_4":"--\"--","field_5":null})";

    ParserFn parseOp = getParserOp(logpar);
    ASSERT_TRUE(static_cast<bool>(parseOp));

    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_TRUE(ret);
    ASSERT_STREQ(expectedJSON,
                 std::any_cast<JsonString>(result["~custom"]).jsonString.c_str());
}

TEST(parseCSV, end_separator_unquoted)
{
    const char* logpar = "<~custom/csv/field_1/field_2>;asd";
    const char* event = R"(f1,f2;asd)";
    const char* expectedJSON = R"({"field_1":"f1","field_2":"f2"})";

    ParserFn parseOp = getParserOp(logpar);
    ASSERT_TRUE(static_cast<bool>(parseOp));

    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_TRUE(ret);
    ASSERT_STREQ(expectedJSON,
                 std::any_cast<JsonString>(result["~custom"]).jsonString.c_str());
}

TEST(parseCSV, end_separator_quoted)
{
    const char* logpar = "<~custom/csv/field_1/field_2>;asd";
    const char* event = R"(f1,"f2;wazuh";asd)";
    const char* expectedJSON = R"({"field_1":"f1","field_2":"f2;wazuh"})";

    ParserFn parseOp = getParserOp(logpar);
    ASSERT_TRUE(static_cast<bool>(parseOp));

    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_TRUE(ret);
    ASSERT_STREQ(expectedJSON,
                 std::any_cast<JsonString>(result["~custom"]).jsonString.c_str());
}

TEST(parseCSV, end_separator_quoted_2)
{
    const char* logpar = "<~custom/csv/field_1/field_2>;asd";
    const char* event = R"(f1,"f2;asd";asd)";
    const char* expectedJSON = R"({"field_1":"f1","field_2":"f2;asd"})";

    ParserFn parseOp = getParserOp(logpar);
    ASSERT_TRUE(static_cast<bool>(parseOp));

    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_TRUE(ret);
    ASSERT_STREQ(expectedJSON,
                 std::any_cast<JsonString>(result["~custom"]).jsonString.c_str());
}

TEST(parseCSV, comma_after_end_token)
{
    const char* logpar = "<~custom/csv/field_1/field_2>,sd";
    const char* event = R"(f1,f2;a,sd)";
    const char* expectedJSON = R"({"field_1":"f1","field_2":"f2;a"})";

    ParserFn parseOp = getParserOp(logpar);
    ASSERT_TRUE(static_cast<bool>(parseOp));

    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_TRUE(ret);
    ASSERT_STREQ(expectedJSON,
                 std::any_cast<JsonString>(result["~custom"]).jsonString.c_str());
}

TEST(parseCSV, all_types)
{
    const char* logpar = "<~custom/csv/field_1/field_2/field_3/field_4>";
    const char* event = R"(0,1.0,,"")";
    const char* expectedJSON =
        R"({"field_1":0,"field_2":1.0,"field_3":null,"field_4":null})";

    ParserFn parseOp = getParserOp(logpar);
    ASSERT_TRUE(static_cast<bool>(parseOp));

    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_TRUE(ret);
    ASSERT_STREQ(expectedJSON,
                 std::any_cast<JsonString>(result["~custom"]).jsonString.c_str());
}

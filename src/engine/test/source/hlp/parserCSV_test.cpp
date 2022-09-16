#include <any>
#include <vector>

#include <gtest/gtest.h>
#include <hlp/hlp.hpp>

using namespace hlp;

using std::any_cast;
using std::string;

TEST(parseCSV, build)
{
    ASSERT_NO_THROW(getParserOp("<_test/csv/field_1>"));

}


TEST(parseCSV, extract_exact_fields_1_not_null_end_string)
{
    const char* logQl = "<_custom/csv/field_1>";
    const char* event = R"(hi)";
    const char* expectedJSON = R"({"field_1":"hi"})";

    ParserFn parseOp = getParserOp(logQl);
    ASSERT_TRUE(static_cast<bool>(parseOp));

    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_TRUE(ret);
    ASSERT_STREQ(expectedJSON, std::any_cast<JsonString>(result["_custom"]).jsonString.c_str());
}

TEST(parseCSV, extract_exact_fields_1_not_null_not_end_string)
{
    const char* logQl = "<_custom/csv/field_1> <_dummy>";
    const char* event = R"(hi bye)";
    const char* expectedJSON = R"({"field_1":"hi"})";

    ParserFn parseOp = getParserOp(logQl);
    ASSERT_TRUE(static_cast<bool>(parseOp));

    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_TRUE(ret);
    ASSERT_STREQ(expectedJSON, std::any_cast<JsonString>(result["_custom"]).jsonString.c_str());
    ASSERT_EQ("bye", std::any_cast<std::string>(result["_dummy"]));
}


TEST(parseCSV, extract_exact_fields_2_not_null_end_string)
{
    const char* logQl = "<_custom/csv/field_1/field_2>";
    const char* event = R"(hi,hi2)";
    const char* expectedJSON = R"({"field_1":"hi","field_2":"hi2"})";

    ParserFn parseOp = getParserOp(logQl);
    ASSERT_TRUE(static_cast<bool>(parseOp));

    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_TRUE(ret);
    ASSERT_STREQ(expectedJSON, std::any_cast<JsonString>(result["_custom"]).jsonString.c_str());
}

TEST(parseCSV, extract_exact_fields_2_not_null_not_end_string)
{
    const char* logQl = "<_custom/csv/field_1/field_2> <_dummy>";
    const char* event = R"(hi,hi2 bye)";
    const char* expectedJSON = R"({"field_1":"hi","field_2":"hi2"})";

    ParserFn parseOp = getParserOp(logQl);
    ASSERT_TRUE(static_cast<bool>(parseOp));

    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_TRUE(ret);
    ASSERT_STREQ(expectedJSON, std::any_cast<JsonString>(result["_custom"]).jsonString.c_str());
    ASSERT_EQ("bye", std::any_cast<std::string>(result["_dummy"]));
}


TEST(parseCSV, extract_exact_fields_2_null_end_string)
{
    const char* logQl = "<_custom/csv/field_1/field_2>";
    const char* event = R"(,)";
    const char* expectedJSON = R"({"field_1":null,"field_2":null})";

    ParserFn parseOp = getParserOp(logQl);
    ASSERT_TRUE(static_cast<bool>(parseOp));

    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_TRUE(ret);
    ASSERT_STREQ(expectedJSON, std::any_cast<JsonString>(result["_custom"]).jsonString.c_str());
}

TEST(parseCSV, extract_exact_fields_2_null_not_end_string)
{
    const char* logQl = "<_custom/csv/field_1/field_2> <_dummy>";
    const char* event = R"(, bye)";
    const char* expectedJSON = R"({"field_1":null,"field_2":null})";

    ParserFn parseOp = getParserOp(logQl);
    ASSERT_TRUE(static_cast<bool>(parseOp));

    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_TRUE(ret);
    ASSERT_STREQ(expectedJSON, std::any_cast<JsonString>(result["_custom"]).jsonString.c_str());
    ASSERT_EQ("bye", std::any_cast<std::string>(result["_dummy"]));
}


TEST(parseCSV, extract_minor_fields_2_not_null_not_end_string)
{
    const char* logQl = "<_custom/csv/field_1/field_2>,hi3,hi4 <_dummy>";
    const char* event = R"(hi1,hi2,hi3,hi4 bye)";
    const char* expectedJSON = R"({"field_1":"hi1","field_2":"hi2"})";

    ParserFn parseOp = getParserOp(logQl);
    ASSERT_TRUE(static_cast<bool>(parseOp));

    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_TRUE(ret);
    ASSERT_STREQ(expectedJSON, std::any_cast<JsonString>(result["_custom"]).jsonString.c_str());
    ASSERT_EQ("bye", std::any_cast<std::string>(result["_dummy"]));
}


TEST(parseCSV, extract_minor_fields_2_not_null_not_end_string_2)
{
    const char* logQl = "<_custom/csv/field_1/field_2>,<_dummy>";
    const char* event = R"(hi1,hi2,hi3,hi4 bye)";
    const char* expectedJSON = R"({"field_1":"hi1","field_2":"hi2"})";

    ParserFn parseOp = getParserOp(logQl);
    ASSERT_TRUE(static_cast<bool>(parseOp));

    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_TRUE(ret);
    ASSERT_STREQ(expectedJSON, std::any_cast<JsonString>(result["_custom"]).jsonString.c_str());
    ASSERT_EQ("hi3,hi4 bye", std::any_cast<std::string>(result["_dummy"]));
}

TEST(parseCSV, extract_exact_fields)
{
    const char* logQl = "<_custom/csv/null_1/null_2/word/esacaped_1/no_escape,null_3/null_4/new/null_5/null_6/null_7>";
    const char* event = R"(,,hi,"semicolon scaped'"",""' <-- other here <,>",other value,,,value new,,)";
    const char* expectedJSON =
        R"({"null_1":null,"null_2":null,"word":"hi","esacaped_1":"semicolon scaped'\",\"' <-- other here <,>","no_escape,null_3":"other value","null_4":null,"new":null,"null_5":"value new","null_6":null,"null_7":null})";

    ParserFn parseOp = getParserOp(logQl);
    ASSERT_TRUE(static_cast<bool>(parseOp));

    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_TRUE(ret);
    ASSERT_STREQ(expectedJSON, std::any_cast<JsonString>(result["_custom"]).jsonString.c_str());
}

#include <hlp/hlp.hpp>

#include <gtest/gtest.h>

#include <json/json.hpp>

using namespace hlp;

TEST(parseJson, parameters_failure_cases)
{
    const char* logpar1 = "<~json/json/param1/param2>";
    const char* logpar2 = "<~json/json/wrongType>";

    const char* event = "{\"key1\":\"value1\",\"key2\":\"value2\"}";

    ASSERT_THROW(getParserOp(logpar1), std::runtime_error);
    ASSERT_THROW(getParserOp(logpar2), std::runtime_error);
}

TEST(parseJson, object_success)
{
    const char* logpar = "<~json/json/object>";

    const char* event = "{\"key1\":\"value1\",\"key2\":\"value2\"}";

    auto parseOp = getParserOp(logpar);
    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_TRUE(static_cast<bool>(parseOp));
    const auto expectedResult {R"({"key1":"value1","key2":"value2"})"};
    ASSERT_STREQ(expectedResult,
                 std::any_cast<JsonString>(result["~json"]).jsonString.data());
}

TEST(parseJson, object_failure_cases)
{
    const char* logpar = "<~json/json/object>";

    const char* eventNotClosed = "{\"key1\":\"value1\",\"key2\":\"value2\"";
    const char* eventNumber = "1234";
    const char* eventString = "\"string\"";
    const char* eventArray = "[1,2,3,4]";
    const char* eventBool = "true";
    const char* eventNull = "null";

    auto parseOp = getParserOp(logpar);
    ParseResult result;

    ASSERT_FALSE(parseOp(eventNotClosed, result));
    ASSERT_FALSE(parseOp(eventNumber, result));
    ASSERT_FALSE(parseOp(eventString, result));
    ASSERT_FALSE(parseOp(eventArray, result));
    ASSERT_FALSE(parseOp(eventBool, result));
    ASSERT_FALSE(parseOp(eventNull, result));
}

TEST(parseJson, success_parsing_object_by_default)
{
    const char* logpar = "<~field1/json> - <~field2/json>";
    const char* event = "{\"String\":\"This is a string\"} - "
                        "{\"String\":\"This is another string\"}";

    auto parseOp = getParserOp(logpar);
    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_TRUE(static_cast<bool>(parseOp));
    ASSERT_STREQ("{\"String\":\"This is a string\"}",
                 std::any_cast<JsonString>(result["~field1"]).jsonString.data());
    ASSERT_STREQ("{\"String\":\"This is another string\"}",
                 std::any_cast<JsonString>(result["~field2"]).jsonString.data());
}

TEST(parseJson, several_results_different_types)
{
    const char* logparObject = " <~json1/json> ";
    const char* logparAny = " <~json2/json/any> ";
    const char* logparString = " <~json3/json/string> ";
    const char* event = " {\"String\":\"This is a string\"} ";

    auto parseOpObj = getParserOp(logparObject);
    auto parseOpString = getParserOp(logparString);
    auto parseOpAny = getParserOp(logparAny);

    ParseResult result;
    bool retObj = parseOpObj(event, result);
    ASSERT_TRUE(retObj);
    ASSERT_FALSE(result.find("~json1") == result.end());
    ASSERT_STREQ("{\"String\":\"This is a string\"}",
                 std::any_cast<JsonString>(result["~json1"]).jsonString.data());

    bool retAny = parseOpAny(event, result);
    ASSERT_TRUE(retAny);
    ASSERT_FALSE(result.find("~json2") == result.end());
    ASSERT_STREQ("{\"String\":\"This is a string\"}",
                 std::any_cast<JsonString>(result["~json2"]).jsonString.data());

    bool retString = parseOpString(event, result);
    ASSERT_FALSE(retString);
    ASSERT_TRUE(result.find("~json3") == result.end());
}

TEST(parseJson, success_matching_string_and_any)
{
    const char* logparObject = "<~json1/json>";
    const char* logparAny = "<~json2/json/any>";
    const char* logparString = "<~json3/json/string>";
    const char* event = "\"String\"{\"This is a string\"}";

    auto parseOpObj = getParserOp(logparObject);
    auto parseOpString = getParserOp(logparString);
    auto parseOpAny = getParserOp(logparAny);

    ParseResult result;
    bool retObj = parseOpObj(event, result);
    ASSERT_FALSE(retObj);
    ASSERT_TRUE(result.find("~json1") == result.end());

    bool retAny = parseOpAny(event, result);
    ASSERT_TRUE(retAny);
    ASSERT_FALSE(result.find("~json2") == result.end());
    ASSERT_STREQ("\"String\"",
                 std::any_cast<JsonString>(result["~json2"]).jsonString.data());

    bool retString = parseOpString(event, result);
    ASSERT_TRUE(retString);
    ASSERT_FALSE(result.find("~json3") == result.end());
    ASSERT_STREQ("\"String\"",
                 std::any_cast<JsonString>(result["~json3"]).jsonString.data());
}

TEST(parseJson, success_array_in_object)
{
    const char* logpar = "<~json/json>";
    const char* event = "{\"String\": [ {\"SecondString\":\"This is a "
                        "string\"}, {\"ThirdString\":\"This is a string\"} ] }";

    auto parseOp = getParserOp(logpar);
    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_TRUE(static_cast<bool>(parseOp));
    ASSERT_STREQ("{\"String\": [ {\"SecondString\":\"This is a "
                 "string\"}, {\"ThirdString\":\"This is a string\"} ] }",
                 std::any_cast<JsonString>(result["~json"]).jsonString.data());
}

TEST(parseJson, failed_not_string)
{
    const char* logpar = "<~json/json>";
    const char* event = "{somestring}, {\"String\":\"This is another string\"}";

    auto parseOp = getParserOp(logpar);
    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_TRUE(static_cast<bool>(parseOp));
    ASSERT_TRUE(result.find("~json") == result.end());
}

TEST(parseJson, success_array)
{
    const char* logpar = "<~json/json/array>";
    const char* event = "[ {\"A\":\"1\"}, {\"B\":\"2\"}, {\"C\":\"3\"} ]";

    auto parseOp = getParserOp(logpar);
    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_TRUE(static_cast<bool>(parseOp));
    ASSERT_STREQ("[ {\"A\":\"1\"}, {\"B\":\"2\"}, {\"C\":\"3\"} ]",
                 std::any_cast<JsonString>(result["~json"]).jsonString.data());
}

TEST(parseJson, success_any)
{
    const char* logpar = " <~json/json/any> ";
    const char* event = " {\"C\":\"3\"} ";

    auto parseOp = getParserOp(logpar);
    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_TRUE(static_cast<bool>(parseOp));
    ASSERT_STREQ("{\"C\":\"3\"}",
                 std::any_cast<JsonString>(result["~json"]).jsonString.data());
}

TEST(parseJson, success_string)
{
    const char* logpar = " <~json/json/string> ";
    const char* event = " \"string\" ";

    auto parseOp = getParserOp(logpar);
    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_TRUE(static_cast<bool>(parseOp));
    ASSERT_STREQ("\"string\"",
                 std::any_cast<JsonString>(result["~json"]).jsonString.data());
}

TEST(parseJson, success_bool)
{
    const char* logpar = " <~json/json/bool> ";
    const char* event = " true ";

    auto parseOp = getParserOp(logpar);
    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_TRUE(static_cast<bool>(parseOp));
    ASSERT_STREQ("true", std::any_cast<JsonString>(result["~json"]).jsonString.data());
}

TEST(parseJson, success_number)
{
    const char* logpar = " <~json/json/number> ";
    const char* event = " 123 ";

    auto parseOp = getParserOp(logpar);
    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_TRUE(static_cast<bool>(parseOp));
    ASSERT_STREQ("123", std::any_cast<JsonString>(result["~json"]).jsonString.data());
}

TEST(parseJson, success_null)
{
    const char* logpar = " <~json/json/null> ";
    const char* event = " null ";

    auto parseOp = getParserOp(logpar);
    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_TRUE(static_cast<bool>(parseOp));
    ASSERT_STREQ("null", std::any_cast<JsonString>(result["~json"]).jsonString.data());
}

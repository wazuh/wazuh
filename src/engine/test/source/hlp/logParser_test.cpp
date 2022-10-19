#include <any>
#include <vector>

#include <gtest/gtest.h>
#include <hlp/hlp.hpp>

using namespace hlp;

TEST(parseLogQL, literal_matching)
{
    std::string logQl_expression =
        R"(123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz:;?@[\]^_`{|}~>=)";
    const char* event =
        R"(123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz:;?@[\]^_`{|}~>=)";

    auto parseOp = getParserOp(logQl_expression);
    ParseResult result;

    ASSERT_TRUE(parseOp(event, result));
}

TEST(parseLogQL, literal_matching_escaped_cases)
{
    std::string logQl_expression = R"( - \\a\b\f\n\r\t\v\'\"\?\0 - )";
    const char* event = R"( - \\a\b\f\n\r\t\v\'\"\?\0 - )";

    auto parseOp = getParserOp(logQl_expression);
    ParseResult result;

    ASSERT_TRUE(parseOp(event, result));
}

TEST(parseLogQL, literal_not_matching)
{
    std::string expression = R"(\\\A\\B - 12369 )";
    const char* event1 = R"(\\\/A\\B - 12369 )";
    const char* event2 = R"(\\\a\\b - 12369 )";
    const char* event3 = R"( \\\A\\B - 12369 )";
    const char* event4 = R"(\\\\A\\B - 12369 )";
    const char* event5 = R"(\\\A\\B)";

    auto parseOp = getParserOp(expression);
    ParseResult result;

    ASSERT_FALSE(parseOp(event1, result));
    ASSERT_FALSE(parseOp(event2, result));
    ASSERT_FALSE(parseOp(event3, result));
    ASSERT_FALSE(parseOp(event4, result));
    ASSERT_FALSE(parseOp(event5, result));
}

TEST(parseLogQL, literal_not_matching_longer_logQlExpre)
{
    std::string logQl_expression = R"( ABC - ABC)";
    const char* event = R"( ABC - )";

    auto parseOp = getParserOp(logQl_expression);
    ParseResult result;

    ASSERT_FALSE(parseOp(event, result));
}

// The logQL expression matches altough the event is longer
TEST(parseLogQL, literal_matching_longer_event)
{
    std::string logQl_expression = R"( ABC -)";
    const char* event = R"( ABC - ABC)";

    auto parseOp = getParserOp(logQl_expression);
    ParseResult result;

    ASSERT_TRUE(parseOp(event, result));
}

TEST(parseLogQL, logQL_expression)
{
    const char* logQl_expression =
        "<source.address> - <_json/json> - [<event.created/RFC1123>] "
        "\"<http.request.method> <host> "
        "HTTP/<http.version>\" <http.response.status_code> "
        "<http.response.body.bytes> \"-\" \"<user_agent.original>\""
        "<agent.ip> - - [<file.created/RFC822Z>] \"-\" "
        "<http.response.status_code> <http.response.body.bytes> ";
    const char* event =
        "monitoring-server - {\"data\":\"this is a json\"} - [Mon, 02 Jan 2006 "
        "15:04:05 MST] \"GET "
        "https://user:password@wazuh.com:8080/"
        "status?query=%22a%20query%20with%20a%20space%22#fragment "
        "HTTP/1.1\" 200 612 \"-\" \"Mozilla/5.0 (Windows NT 6.1; rv:15.0) "
        "Gecko/20120716 Firefox/15.0a2\""
        "127.0.0.1 - - [02 Jan 06 15:04 -0700] \"-\" 408 152 ";

    auto parseOp = getParserOp(logQl_expression);
    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_TRUE(parseOp);
    ASSERT_EQ("{\"data\":\"this is a json\"}",
              std::any_cast<JsonString>(result["_json"]).jsonString);
    ASSERT_EQ("Mon, 02 Jan 2006 15:04:05 MST",
              std::any_cast<std::string>(result["event.created"]));
    ASSERT_EQ("https://user:password@wazuh.com:8080/"
              "status?query=%22a%20query%20with%20a%20space%22#fragment",
              std::any_cast<std::string>(result["host"]));
    ASSERT_EQ("127.0.0.1", std::any_cast<std::string>(result["agent.ip"]));
    ASSERT_EQ("02 Jan 06 15:04 -0700",
              std::any_cast<std::string>(result["file.created"]));
}

TEST(parseLogQL, invalid_logql_expression)
{
    GTEST_SKIP();
    const char* logQl = "<source.ip><invalid>";
    ASSERT_THROW(getParserOp(logQl), std::runtime_error);

    const char* logQl2 = "invalid capture <source.ip><invalid> between strings";
    ASSERT_THROW(getParserOp(logQl2), std::runtime_error);

    const char* logQl3 = "invalid capture <source.ip between strings";
    ASSERT_THROW(getParserOp(logQl3), std::runtime_error);
}

TEST(parseLogQL, optional_Field_Not_Found)
{
    GTEST_SKIP();
    static const char* logQl = "this won't match an IP address "
                               "-<_ts/timestamp/UnixDate>- <?url> <_field/json>";
    static const char* event = "this won't match an IP address -Mon Jan 2 "
                               "15:04:05 MST 2006-  {\"String\":\"SomeValue\"}";

    auto parseOp = getParserOp(logQl);
    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_EQ(true, static_cast<bool>(parseOp));
    ASSERT_TRUE(result.find("url.original") == result.end());
    ASSERT_EQ(2006, std::any_cast<int>(result["_ts.year"]));
    ASSERT_EQ(1, std::any_cast<unsigned>(result["_ts.month"]));
    ASSERT_EQ(2, std::any_cast<unsigned>(result["_ts.day"]));
    ASSERT_EQ(15, std::any_cast<long>(result["_ts.hour"]));
    ASSERT_EQ(4, std::any_cast<long>(result["_ts.minutes"]));
    ASSERT_EQ(5, std::any_cast<double>(result["_ts.seconds"]));
    ASSERT_EQ("{\"String\":\"SomeValue\"}",
              std::any_cast<JsonString>(result["_field"]).jsonString);
}

TEST(parseLogQL, optional_Or)
{
    // TODO: this should be fixed and tested in other aspects
    static const char* logQl = "<_url/url>?<_field/json>";
    static const char* eventjson = "{\"String\":\"SomeValue\"}";
    static const char* eventURL = "https://user:password@wazuh.com:8080/path"
                                  "?query=%22a%20query%20with%20a%20space%22#fragment";
    static const char* eventNone = "Mon Jan 2 15:04:05 MST 2006";

    auto parseOp = getParserOp(logQl);
    ParseResult resultJSON;
    bool ret = parseOp(eventjson, resultJSON);
    ASSERT_EQ(true, static_cast<bool>(parseOp));
    ASSERT_EQ("{\"String\":\"SomeValue\"}",
              std::any_cast<JsonString>(resultJSON["_field"]).jsonString);

    ParseResult resultURL;
    ret = parseOp(eventURL, resultURL);
    std::string url = "https://user:password@wazuh.com:8080/"
                      "path?query=%22a%20query%20with%20a%20space%22#fragment";
    ASSERT_EQ(url, std::any_cast<std::string>(resultURL["_url.original"]));

    ParseResult resultEmpty;
    ret = parseOp(eventNone, resultEmpty);
    ASSERT_TRUE(resultEmpty.empty());
}

TEST(parseLogQL, options_parsing)
{
    const char* logQl = "<_> <_temp> <_temp1/type> <_temp2/type/type2>";
    const char* event = "one temp temp1 temp2";

    auto parseOp = getParserOp(logQl);
    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_EQ(true, static_cast<bool>(parseOp));
    ASSERT_EQ("temp", std::any_cast<std::string>(result["_temp"]));
    ASSERT_EQ("temp1", std::any_cast<std::string>(result["_temp1"]));
    ASSERT_EQ("temp2", std::any_cast<std::string>(result["_temp2"]));
}

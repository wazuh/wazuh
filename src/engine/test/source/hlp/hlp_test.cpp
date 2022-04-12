#include <hlp/hlp.hpp>

#include "gtest/gtest.h"

TEST(hlpTests_logQL, logQL_expression)
{
    const char *logQl_expression =
        "<source.address> - <_json/JSON> - [<timestamp/RFC1123>] "
        "\"<http.request.method> <url> "
        "HTTP/<http.version>\" <http.response.status_code> "
        "<http.response.body.bytes> \"-\" \"<user_agent.original>\""
        "<source.ip> - - [<file.created/RFC822Z>] \"-\" "
        "<http.response.status_code> <http.response.body.bytes> ";
    const char *event =
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

    ASSERT_EQ(true, static_cast<bool>(parseOp));
    ASSERT_EQ("{\"data\":\"this is a json\"}", result["_json"]);
    ASSERT_EQ("2006", result["timestamp.year"]);
    ASSERT_EQ("1", result["timestamp.month"]);
    ASSERT_EQ("2", result["timestamp.day"]);
    ASSERT_EQ("15", result["timestamp.hour"]);
    ASSERT_EQ("4", result["timestamp.minutes"]);
    ASSERT_EQ("5", result["timestamp.seconds"]);
    ASSERT_EQ("wazuh.com", result["url.domain"]);
    ASSERT_EQ("fragment", result["url.fragment"]);
    ASSERT_EQ("password", result["url.password"]);
    ASSERT_EQ("/status", result["url.path"]);
    ASSERT_EQ("8080", result["url.port"]);
    ASSERT_EQ("query=%22a%20query%20with%20a%20space%22", result["url.query"]);
    ASSERT_EQ("https", result["url.scheme"]);
    ASSERT_EQ("user", result["url.username"]);
    ASSERT_EQ("127.0.0.1", result["source.ip"]);
    ASSERT_EQ("2006", result["file.created.year"]);
    ASSERT_EQ("1", result["file.created.month"]);
    ASSERT_EQ("2", result["file.created.day"]);
    ASSERT_EQ("15", result["file.created.hour"]);
    ASSERT_EQ("4", result["file.created.minutes"]);
    ASSERT_EQ("0", result["file.created.seconds"]);
    ASSERT_EQ("-0700", result["file.created.timezone"]);
}

TEST(hlpTests_logQL, invalid_logql_expression)
{
    const char *logQl = "<source.ip><invalid>";
    ASSERT_THROW(getParserOp(logQl), std::runtime_error);

    const char *logQl2 = "invalid capture <source.ip><invalid> between strings";
    ASSERT_THROW(getParserOp(logQl2), std::runtime_error);

    const char *logQl3 = "invalid capture <source.ip between strings";
    ASSERT_THROW(getParserOp(logQl3), std::runtime_error);
}

TEST(hlpTests_logQL, optional_Field_Not_Found)
{
    static const char *logQl = "this won't match an IP address "
                               "-<timestamp/UnixDate>- <?url> <_field/JSON>";
    static const char *event = "this won't match an IP address -Mon Jan 2 "
                               "15:04:05 MST 2006-  {\"String\":\"SomeValue\"}";

    auto parseOp = getParserOp(logQl);
    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_EQ(true, static_cast<bool>(parseOp));
    ASSERT_TRUE(result["url.original"].empty());
    ASSERT_EQ("2006", result["timestamp.year"]);
    ASSERT_EQ("1", result["timestamp.month"]);
    ASSERT_EQ("2", result["timestamp.day"]);
    ASSERT_EQ("15", result["timestamp.hour"]);
    ASSERT_EQ("4", result["timestamp.minutes"]);
    ASSERT_EQ("5", result["timestamp.seconds"]);
    ASSERT_EQ("{\"String\":\"SomeValue\"}", result["_field"]);
}

TEST(hlpTests_logQL, optional_Or)
{
    static const char *logQl = "<url>?<_field/JSON>";
    static const char *eventJSON = "{\"String\":\"SomeValue\"}";
    static const char *eventURL =
        "https://user:password@wazuh.com:8080/path"
        "?query=%22a%20query%20with%20a%20space%22#fragment";
    static const char *eventNone = "Mon Jan 2 15:04:05 MST 2006";

    auto parseOp = getParserOp(logQl);
    ParseResult resultJSON;
    bool ret = parseOp(eventJSON, resultJSON);
    ASSERT_EQ(true, static_cast<bool>(parseOp));
    ASSERT_EQ("{\"String\":\"SomeValue\"}", resultJSON["_field"]);

    ParseResult resultURL;
    ret = parseOp(eventURL, resultURL);
    std::string url = "https://user:password@wazuh.com:8080/"
                      "path?query=%22a%20query%20with%20a%20space%22#fragment";
    ASSERT_EQ(url, resultURL["url.original"]);

    ParseResult resultEmpty;
    ret = parseOp(eventNone, resultEmpty);
    ASSERT_TRUE(resultEmpty.empty());
}

TEST(hlpTests_logQL, options_parsing)
{
    const char *logQl = "<_> <_temp> <_temp1/type> <_temp2/type/type2>";
    const char *event = "one temp temp1 temp2";

    auto parseOp = getParserOp(logQl);
    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_EQ(true, static_cast<bool>(parseOp));
    ASSERT_EQ("temp", result["_temp"]);
    ASSERT_EQ("temp1", result["_temp1"]);
    ASSERT_EQ("temp2", result["_temp2"]);

}

// TODO: this test shouldn't be failing
TEST(hlpTests_URL, url_wrong_format)
{
    const char *logQl = "the temp param has an [<_temp/url>] type";
    const char *event = "the temp param has an [incorrect] type";

    auto parseOp = getParserOp(logQl);
    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_FALSE(ret);
}

TEST(hlpTests_URL, url_success)
{
    static const char *logQl = "this is an url <url> in text";
    static const char *event =
        "this is an url "
        "https://user:password@wazuh.com:8080/"
        "path?query=%22a%20query%20with%20a%20space%22#fragment in text";

    auto parseOp = getParserOp(logQl);
    ParseResult result;
    bool ret = parseOp(event, result);

    std::string url = "https://user:password@wazuh.com:8080/"
                      "path?query=%22a%20query%20with%20a%20space%22#fragment";
    ASSERT_EQ(true, static_cast<bool>(parseOp));
    ASSERT_EQ(url, result["url.original"]);
    ASSERT_EQ("wazuh.com", result["url.domain"]);
    ASSERT_EQ("fragment", result["url.fragment"]);
    ASSERT_EQ("password", result["url.password"]);
    ASSERT_EQ("/path", result["url.path"]);
    ASSERT_EQ("8080", result["url.port"]);
    ASSERT_EQ("query=%22a%20query%20with%20a%20space%22", result["url.query"]);
    ASSERT_EQ("https", result["url.scheme"]);
    ASSERT_EQ("user", result["url.username"]);
}

TEST(hlpTests_IPaddress, IPV4_success)
{
    const char *logQl =
        "<source.ip> - <server.ip> -- <source.nat.ip> \"-\" \"-\"";
    const char *event =
        "127.0.0.1 - 192.168.100.25 -- 255.255.255.0 \"-\" \"-\"";

    auto parseOp = getParserOp(logQl);
    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_EQ(true, static_cast<bool>(parseOp));
    ASSERT_EQ("127.0.0.1", result["source.ip"]);
    ASSERT_EQ("192.168.100.25", result["server.ip"]);
    ASSERT_EQ("255.255.255.0", result["source.nat.ip"]);
}

TEST(hlpTests_IPaddress, IPV4_failed)
{
    const char *logQl = "<server.ip> -";
    const char *event = "..100.25 -";

    auto parseOp = getParserOp(logQl);
    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_EQ(true, static_cast<bool>(parseOp));
    ASSERT_EQ("", result["server.ip"]);
}

TEST(hlpTests_IPaddress, IPV6_success)
{
    const char *logQl = " - <source.nat.ip>";
    const char *event = " - 2001:db8:3333:AB45:1111:00A:4:1";

    auto parseOp = getParserOp(logQl);
    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_EQ(true, static_cast<bool>(parseOp));
    ASSERT_EQ("2001:db8:3333:AB45:1111:00A:4:1", result["source.nat.ip"]);
}

TEST(hlpTests_IPaddress, IPV6_failed)
{
    const char *logQl = "<server.ip>";
    const char *event = "2001:db8:#:$:CCCC:DDDD:EEEE:FFFF";

    auto parseOp = getParserOp(logQl);
    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_EQ(true, static_cast<bool>(parseOp));
    ASSERT_EQ("", result["server.ip"]);
}

// Test: parsing JSON objects
TEST(hlpTests_json, success_parsing)
{
    const char *logQl = "<_field1/JSON> - <_field2/JSON>";
    const char *event = "{\"String\":\"This is a string\"} - "
                        "{\"String\":\"This is another string\"}";

    auto parseOp = getParserOp(logQl);
    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_EQ(true, static_cast<bool>(parseOp));
    ASSERT_EQ("{\"String\":\"This is a string\"}", result["_field1"]);
    ASSERT_EQ("{\"String\":\"This is another string\"}", result["_field2"]);
}

TEST(hlpTests_json, failed_incomplete_json)
{
    const char *logQl = "<_json/JSON>";
    const char *event = "{\"String\":{\"This is a string\"}";

    auto parseOp = getParserOp(logQl);
    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_EQ(true, static_cast<bool>(parseOp));
    ASSERT_TRUE(result["_json"].empty());
}

TEST(hlpTests_json, success_array)
{
    const char *logQl = "<_json/JSON>";
    const char *event = "{\"String\": [ {\"SecondString\":\"This is a "
                        "string\"}, {\"ThirdString\":\"This is a string\"} ] }";

    auto parseOp = getParserOp(logQl);
    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_EQ(true, static_cast<bool>(parseOp));
    ASSERT_EQ("{\"String\":[{\"SecondString\":\"This is a "
              "string\"},{\"ThirdString\":\"This is a string\"}]}",
              result["_json"]);
}

TEST(hlpTests_json, failed_not_string)
{
    const char *logQl = "<_json/JSON>";
    const char *event = "{somestring}, {\"String\":\"This is another string\"}";

    auto parseOp = getParserOp(logQl);
    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_EQ(true, static_cast<bool>(parseOp));
    ASSERT_TRUE(result["_json"].empty());
}

// Test: parsing maps objects
TEST(hlpTests_map, success_test)
{
    const char *logQl = "<_map/MAP/ /=>-<_dummy>";
    const char *event = "key1=Value1 Key2=Value2-dummy";

    ParserFn parseOp = getParserOp(logQl);
    ASSERT_EQ(true, static_cast<bool>(parseOp));

    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_EQ("{\"key1\":\"Value1\",\"Key2\":\"Value2\"}", result["_map"]);
    ASSERT_EQ("dummy", result["_dummy"]);
}

TEST(hlpTests_map, end_mark_test)
{
    const char *logQl = "<_map/MAP/ /=/.> <_dummy>";
    const char *event = "key1=Value1 Key2=Value2. dummy";

    ParserFn parseOp = getParserOp(logQl);
    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_EQ(true, static_cast<bool>(parseOp));
    ASSERT_EQ("{\"key1\":\"Value1\",\"Key2\":\"Value2\"}", result["_map"]);
    ASSERT_EQ("dummy", result["_dummy"]);
}

TEST(hlpTests_map, incomplete_map_test)
{
    const char *logQl = "<_map/MAP/ /=>";
    const char *event1 = "key1=Value1 Key2=";
    const char *event2 = "key1=Value1 Key2";
    const char *event3 = "key1=Value1 =Value2";

    ParserFn parseOp = getParserOp(logQl);
    ParseResult result1;
    ParseResult result2;
    ParseResult result3;
    bool ret1 = parseOp(event1, result1);
    bool ret2 = parseOp(event2, result2);
    bool ret3 = parseOp(event3, result3);

    ASSERT_EQ(true, static_cast<bool>(parseOp));
    ASSERT_TRUE(result1.empty());
    ASSERT_TRUE(result2.empty());
    ASSERT_TRUE(result3.empty());
}

TEST(hlpTests_Timestamp, ansic)
{
    static const char *logQl = "[<timestamp/ANSIC>]";
    static const char *ansicTs = "[Mon Jan 2 15:04:05 2006]";
    static const char *ansimTs = "[Mon Jan 2 15:04:05.123456 2006]";

    auto parseOp = getParserOp(logQl);
    ParseResult result;
    bool ret = parseOp(ansicTs, result);

    ASSERT_EQ(true, static_cast<bool>(parseOp));
    ASSERT_EQ("2006", result["timestamp.year"]);
    ASSERT_EQ("1", result["timestamp.month"]);
    ASSERT_EQ("2", result["timestamp.day"]);
    ASSERT_EQ("15", result["timestamp.hour"]);
    ASSERT_EQ("4", result["timestamp.minutes"]);
    ASSERT_EQ("5", result["timestamp.seconds"]);

    ParseResult resultMillis;
    ret = parseOp(ansimTs, resultMillis);
    ASSERT_EQ("2006", resultMillis["timestamp.year"]);
    ASSERT_EQ("1", resultMillis["timestamp.month"]);
    ASSERT_EQ("2", resultMillis["timestamp.day"]);
    ASSERT_EQ("15", resultMillis["timestamp.hour"]);
    ASSERT_EQ("4", resultMillis["timestamp.minutes"]);
    ASSERT_EQ("5.123456", resultMillis["timestamp.seconds"]);
}

TEST(hlpTests_Timestamp, apache)
{
    static const char *logQl = "[<timestamp/APACHE>]";
    static const char *apacheTs = "[Tue Feb 11 15:04:05 2020]";

    auto parseOp = getParserOp(logQl);
    ParseResult result;
    bool ret = parseOp(apacheTs, result);

    ASSERT_EQ(true, static_cast<bool>(parseOp));
    ASSERT_EQ("2020", result["timestamp.year"]);
    ASSERT_EQ("2", result["timestamp.month"]);
    ASSERT_EQ("11", result["timestamp.day"]);
    ASSERT_EQ("15", result["timestamp.hour"]);
    ASSERT_EQ("4", result["timestamp.minutes"]);
    ASSERT_EQ("5", result["timestamp.seconds"]);
}

TEST(hlpTests_Timestamp, rfc1123)
{
    static const char *logQl = "[<timestamp/RFC1123>]";
    static const char *logQlz = "[<timestamp/RFC1123Z>]";
    static const char *rfc1123Ts = "[Mon, 02 Jan 2006 15:04:05 MST]";
    static const char *rfc1123zTs = "[Mon, 02 Jan 2006 15:04:05 -0700]";

    auto parseOp = getParserOp(logQl);
    ParseResult result;
    bool ret = parseOp(rfc1123Ts, result);

    ASSERT_EQ(true, static_cast<bool>(parseOp));
    ASSERT_EQ("2006", result["timestamp.year"]);
    ASSERT_EQ("1", result["timestamp.month"]);
    ASSERT_EQ("2", result["timestamp.day"]);
    ASSERT_EQ("15", result["timestamp.hour"]);
    ASSERT_EQ("4", result["timestamp.minutes"]);
    ASSERT_EQ("5", result["timestamp.seconds"]);

    auto parseOpz = getParserOp(logQlz);
    ASSERT_EQ(true, static_cast<bool>(parseOpz));

    ParseResult resultz;
    ret = parseOpz(rfc1123zTs, resultz);

    ASSERT_EQ("2006", resultz["timestamp.year"]);
    ASSERT_EQ("1", resultz["timestamp.month"]);
    ASSERT_EQ("2", resultz["timestamp.day"]);
    ASSERT_EQ("15", resultz["timestamp.hour"]);
    ASSERT_EQ("4", resultz["timestamp.minutes"]);
    ASSERT_EQ("5", resultz["timestamp.seconds"]);
}

TEST(hlpTests_Timestamp, rfc3339)
{
    static const char *logQl = "[<timestamp/RFC3339>]";
    static const char *rfc3339Ts = "[2006-01-02T15:04:05Z07:00]";
    static const char *rfc3339nanoTs = "[2006-01-02T15:04:05.999999999Z07:00]";

    auto parseOp = getParserOp(logQl);
    ParseResult result;
    bool ret = parseOp(rfc3339Ts, result);

    ASSERT_EQ(true, static_cast<bool>(parseOp));
    ASSERT_EQ("2006", result["timestamp.year"]);
    ASSERT_EQ("1", result["timestamp.month"]);
    ASSERT_EQ("2", result["timestamp.day"]);
    ASSERT_EQ("15", result["timestamp.hour"]);
    ASSERT_EQ("4", result["timestamp.minutes"]);
    ASSERT_EQ("5", result["timestamp.seconds"]);

    ParseResult resultNano;
    ret = parseOp(rfc3339nanoTs, resultNano);

    ASSERT_EQ("2006", resultNano["timestamp.year"]);
    ASSERT_EQ("1", resultNano["timestamp.month"]);
    ASSERT_EQ("2", resultNano["timestamp.day"]);
    ASSERT_EQ("15", resultNano["timestamp.hour"]);
    ASSERT_EQ("4", resultNano["timestamp.minutes"]);
    ASSERT_EQ("5.999999999", resultNano["timestamp.seconds"]);
}

TEST(hlpTests_Timestamp, rfc822)
{
    static const char *logQl = "[<timestamp/RFC822>]";
    static const char *logQlz = "[<timestamp/RFC822Z>]";
    static const char *rfc822Ts = "[02 Jan 06 15:04 MST]";
    static const char *rfc822zTs = "[02 Jan 06 15:04 -0700]";

    auto parseOp = getParserOp(logQl);
    ParseResult result;
    bool ret = parseOp(rfc822Ts, result);

    ASSERT_EQ(true, static_cast<bool>(parseOp));
    ASSERT_EQ("2006", result["timestamp.year"]);
    ASSERT_EQ("1", result["timestamp.month"]);
    ASSERT_EQ("2", result["timestamp.day"]);
    ASSERT_EQ("15", result["timestamp.hour"]);
    ASSERT_EQ("4", result["timestamp.minutes"]);
    ASSERT_EQ("0", result["timestamp.seconds"]);
    ASSERT_EQ("MST", result["timestamp.timezone"]);

    auto parseOpz = getParserOp(logQlz);
    ASSERT_EQ(true, static_cast<bool>(parseOpz));

    ParseResult resultz;
    ret = parseOpz(rfc822zTs, resultz);

    ASSERT_EQ("2006", resultz["timestamp.year"]);
    ASSERT_EQ("1", resultz["timestamp.month"]);
    ASSERT_EQ("2", resultz["timestamp.day"]);
    ASSERT_EQ("15", resultz["timestamp.hour"]);
    ASSERT_EQ("4", resultz["timestamp.minutes"]);
    ASSERT_EQ("0", resultz["timestamp.seconds"]);
    ASSERT_EQ("-0700", resultz["timestamp.timezone"]);
}

TEST(hlpTests_Timestamp, rfc850)
{
    static const char *logQl = "[<timestamp/RFC850>]";
    static const char *rfc850Ts = "[Monday, 02-Jan-06 15:04:05 MST]";

    auto parseOp = getParserOp(logQl);
    ParseResult result;
    bool ret = parseOp(rfc850Ts, result);

    ASSERT_EQ(true, static_cast<bool>(parseOp));
    ASSERT_EQ("2006", result["timestamp.year"]);
    ASSERT_EQ("1", result["timestamp.month"]);
    ASSERT_EQ("2", result["timestamp.day"]);
    ASSERT_EQ("15", result["timestamp.hour"]);
    ASSERT_EQ("4", result["timestamp.minutes"]);
    ASSERT_EQ("5", result["timestamp.seconds"]);
    ASSERT_EQ("MST", result["timestamp.timezone"]);
}

TEST(hlpTests_Timestamp, ruby)
{
    static const char *logQl = "[<timestamp/RubyDate>]";
    static const char *rubyTs = "[Mon Jan 02 15:04:05 -0700 2006]";

    auto parseOp = getParserOp(logQl);
    ParseResult result;
    bool ret = parseOp(rubyTs, result);

    ASSERT_EQ(true, static_cast<bool>(parseOp));
    ASSERT_EQ("2006", result["timestamp.year"]);
    ASSERT_EQ("1", result["timestamp.month"]);
    ASSERT_EQ("2", result["timestamp.day"]);
    ASSERT_EQ("15", result["timestamp.hour"]);
    ASSERT_EQ("4", result["timestamp.minutes"]);
    ASSERT_EQ("5", result["timestamp.seconds"]);
    ASSERT_EQ("-0700", result["timestamp.timezone"]);
}

TEST(hlpTests_Timestamp, stamp)
{
    static const char *logQl = "[<timestamp/Stamp>]";
    static const char *stampTs = "[Jan 2 15:04:05]";
    static const char *stampmilliTs = "[Jan 2 15:04:05.000]";
    static const char *stampmicroTs = "[Jan 2 15:04:05.000000]";
    static const char *stampnanoTs = "[Jan 2 15:04:05.000000000]";

    auto parseOp = getParserOp(logQl);
    ParseResult result;
    bool ret = parseOp(stampTs, result);

    ASSERT_EQ(true, static_cast<bool>(parseOp));
    ASSERT_EQ("1", result["timestamp.month"]);
    ASSERT_EQ("2", result["timestamp.day"]);
    ASSERT_EQ("15", result["timestamp.hour"]);
    ASSERT_EQ("4", result["timestamp.minutes"]);
    ASSERT_EQ("5", result["timestamp.seconds"]);

    ParseResult resultMillis;
    ret = parseOp(stampmilliTs, resultMillis);
    ASSERT_EQ("1", resultMillis["timestamp.month"]);
    ASSERT_EQ("2", resultMillis["timestamp.day"]);
    ASSERT_EQ("15", resultMillis["timestamp.hour"]);
    ASSERT_EQ("4", resultMillis["timestamp.minutes"]);
    ASSERT_EQ("5", resultMillis["timestamp.seconds"]);

    ParseResult resultMicros;
    ret = parseOp(stampmicroTs, resultMicros);
    ASSERT_EQ("1", resultMicros["timestamp.month"]);
    ASSERT_EQ("2", resultMicros["timestamp.day"]);
    ASSERT_EQ("15", resultMicros["timestamp.hour"]);
    ASSERT_EQ("4", resultMicros["timestamp.minutes"]);
    ASSERT_EQ("5", resultMicros["timestamp.seconds"]);

    ParseResult resultNanos;
    ret = parseOp(stampnanoTs, resultNanos);
    ASSERT_EQ("1", resultNanos["timestamp.month"]);
    ASSERT_EQ("2", resultNanos["timestamp.day"]);
    ASSERT_EQ("15", resultNanos["timestamp.hour"]);
    ASSERT_EQ("4", resultNanos["timestamp.minutes"]);
    ASSERT_EQ("5", resultNanos["timestamp.seconds"]);
}

TEST(hlpTests_Timestamp, Unix)
{
    static const char *logQl = "[<timestamp/UnixDate>]";
    static const char *unixTs = "[Mon Jan 2 15:04:05 MST 2006]";

    auto parseOp = getParserOp(logQl);
    ParseResult result;
    bool ret = parseOp(unixTs, result);

    ASSERT_EQ(true, static_cast<bool>(parseOp));
    ASSERT_EQ("2006", result["timestamp.year"]);
    ASSERT_EQ("1", result["timestamp.month"]);
    ASSERT_EQ("2", result["timestamp.day"]);
    ASSERT_EQ("15", result["timestamp.hour"]);
    ASSERT_EQ("4", result["timestamp.minutes"]);
    ASSERT_EQ("5", result["timestamp.seconds"]);
}

TEST(hlpTests_Timestamp, Unix_fail)
{
    static const char *logQl = "[<timestamp/UnixDate>]";
    static const char *unixTs = "[Mon Jan 2 15:04:05 MST 1960]";

    auto parseOp = getParserOp(logQl);
    ASSERT_EQ(true, static_cast<bool>(parseOp));

    ParseResult result;
    bool ret = parseOp(unixTs, result);
    ASSERT_TRUE(result.empty());
}

TEST(hlpTests_Timestamp, specific_format)
{
    static const char *logQl = "[<timestamp>] - "
                               "[<_ansicTs/timestamp>] - "
                               "[<_unixTs/timestamp>] - "
                               "[<_stampTs/timestamp>]";
    static const char *event = "[Mon Jan 02 15:04:05 -0700 2006] - "
                               "[Mon Jan 2 15:04:05 2006] - "
                               "[Mon Jan 2 15:04:05 MST 2006] - "
                               "[Jan 2 15:04:05]";

    auto parseOp = getParserOp(logQl);
    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_EQ(true, static_cast<bool>(parseOp));
    ASSERT_EQ("2006", result["timestamp.year"]);
    ASSERT_EQ("1", result["timestamp.month"]);
    ASSERT_EQ("2", result["timestamp.day"]);
    ASSERT_EQ("15", result["timestamp.hour"]);
    ASSERT_EQ("4", result["timestamp.minutes"]);
    ASSERT_EQ("5", result["timestamp.seconds"]);
    ASSERT_EQ("-0700", result["timestamp.timezone"]);

    ASSERT_EQ("2006", result["_ansicTs.year"]);
    ASSERT_EQ("1", result["_ansicTs.month"]);
    ASSERT_EQ("2", result["_ansicTs.day"]);
    ASSERT_EQ("15", result["_ansicTs.hour"]);
    ASSERT_EQ("4", result["_ansicTs.minutes"]);
    ASSERT_EQ("5", result["_ansicTs.seconds"]);

    ASSERT_EQ("2006", result["_unixTs.year"]);
    ASSERT_EQ("1", result["_unixTs.month"]);
    ASSERT_EQ("2", result["_unixTs.day"]);
    ASSERT_EQ("15", result["_unixTs.hour"]);
    ASSERT_EQ("4", result["_unixTs.minutes"]);
    ASSERT_EQ("5", result["_unixTs.seconds"]);

    ASSERT_EQ("1", result["_stampTs.month"]);
    ASSERT_EQ("2", result["_stampTs.day"]);
    ASSERT_EQ("15", result["_stampTs.hour"]);
    ASSERT_EQ("4", result["_stampTs.minutes"]);
    ASSERT_EQ("5", result["_stampTs.seconds"]);
}

TEST(hlpTests_Timestamp, kitchen)
{
    // FIXME: this specific test is know to fail even at a chronos library level.
    GTEST_SKIP();

    static const char *logQl = "[<timestamp/Kitchen>]";
    static const char *kitchenTs = "[3:04a.m.]";
    auto parseOp = getParserOp(logQl);
    ParseResult result;
    bool ret = parseOp(kitchenTs, result);

    ASSERT_EQ(true, static_cast<bool>(parseOp));
    ASSERT_EQ("3", result["timestamp.hour"]);
    ASSERT_EQ("4", result["timestamp.minutes"]);
}

// Test: domain parsing
TEST(hlpTests_domain, success)
{
    const char *logQl = "<_my_domain/domain>";
    ParserFn parseOp = getParserOp(logQl);
    ParseResult result;

    ASSERT_EQ(true, static_cast<bool>(parseOp));
    // Single TLD
    const char *event1 = "www.wazuh.com";
    bool ret = parseOp(event1, result);
    ASSERT_EQ("www", result["_my_domain.subdomain"]);
    ASSERT_EQ("wazuh.com", result["_my_domain.registered_domain"]);
    ASSERT_EQ("com", result["_my_domain.top_level_domain"]);

    // Dual TLD
    const char *event2 = "www.wazuh.com.ar";
    ret = parseOp(event2, result);
    ASSERT_EQ("www", result["_my_domain.subdomain"]);
    ASSERT_EQ("wazuh.com.ar", result["_my_domain.registered_domain"]);
    ASSERT_EQ("com.ar", result["_my_domain.top_level_domain"]);

    // Multiple subdomains
    const char *event3 = "www.subdomain1.wazuh.com.ar";
    ret = parseOp(event3, result);
    ASSERT_EQ("www.subdomain1", result["_my_domain.subdomain"]);
    ASSERT_EQ("wazuh.com.ar", result["_my_domain.registered_domain"]);
    ASSERT_EQ("com.ar", result["_my_domain.top_level_domain"]);

    // No subdomains
    const char *event4 = "wazuh.com.ar";
    ret = parseOp(event4, result);
    ASSERT_EQ("", result["_my_domain.subdomain"]);
    ASSERT_EQ("wazuh.com.ar", result["_my_domain.registered_domain"]);
    ASSERT_EQ("com.ar", result["_my_domain.top_level_domain"]);

    // No TLD
    const char *event5 = "www.wazuh";
    ret = parseOp(event5, result);
    ASSERT_EQ("www", result["_my_domain.subdomain"]);
    ASSERT_EQ("wazuh", result["_my_domain.registered_domain"]);
    ASSERT_EQ("", result["_my_domain.top_level_domain"]);

    // Only Host
    const char *event6 = "wazuh";
    ret = parseOp(event6, result);
    ASSERT_EQ("", result["_my_domain.subdomain"]);
    ASSERT_EQ("wazuh", result["_my_domain.registered_domain"]);
    ASSERT_EQ("", result["_my_domain.top_level_domain"]);
}

TEST(hlpTests_domain, FQDN_validation)
{
    const char *logQl = "<_my_domain/domain/FQDN>";
    ParserFn parseOp = getParserOp(logQl);
    ParseResult result;

    ASSERT_EQ(true, static_cast<bool>(parseOp));
    // Single TLD
    const char *event1 = "www.wazuh.com";
    bool ret = parseOp(event1, result);
    ASSERT_EQ("www", result["_my_domain.subdomain"]);
    ASSERT_EQ("wazuh.com", result["_my_domain.registered_domain"]);
    ASSERT_EQ("com", result["_my_domain.top_level_domain"]);

    // No subdomains
    result.clear();
    const char *event2 = "wazuh.com";
    ret = parseOp(event2, result);
    ASSERT_TRUE(result.empty());

    // No TLD
    result.clear();
    const char *event3 = "www.wazuh";
    ret = parseOp(event3, result);
    ASSERT_TRUE(result.empty());

    // Only Host
    result.clear();
    const char *event4 = "wazuh";
    ret = parseOp(event4, result);
    ASSERT_TRUE(result.empty());
}

TEST(hlpTests_domain, host_route)
{
    const char *logQl = "<_my_domain/domain>";
    ParserFn parseOp = getParserOp(logQl);

    ASSERT_EQ(true, static_cast<bool>(parseOp));
    const char *event1 = "ftp://www.wazuh.com/route.txt";
    ParseResult result;
    auto ret = parseOp(event1, result);
    // TODO protocol and route aren´t part of the result. We only extract it
    // from the event
    ASSERT_EQ("www", result["_my_domain.subdomain"]);
    ASSERT_EQ("wazuh.com", result["_my_domain.registered_domain"]);
    ASSERT_EQ("com", result["_my_domain.top_level_domain"]);
}

TEST(hlpTests_domain, valid_content)
{
    const char *logQl = "<_my_domain/domain>";
    ParserFn parseOp = getParserOp(logQl);
    ParseResult result;

    ASSERT_EQ(true, static_cast<bool>(parseOp));
    std::string big_domain(254, 'w');
    bool ret = parseOp(big_domain.c_str(), result);
    ASSERT_TRUE(result.empty());

    const char *invalid_character_domain = "www.wazuh?.com";
    ret = parseOp(invalid_character_domain, result);
    ASSERT_TRUE(result.empty());

    std::string invalid_label(64, 'w');
    std::string invalid_label_domain = "www." + invalid_label + ".com";
    ret = parseOp(invalid_label_domain, result);
    ASSERT_TRUE(result.empty());
}

TEST(hlpTests_filepath, windows_path)
{
    const char *logQl = "<_file/FilePath>";
    ParserFn parseOp = getParserOp(logQl);
    ParseResult result;

    ASSERT_EQ(true, static_cast<bool>(parseOp));
    const char *full_path = "C:\\Users\\Name\\Desktop\\test.txt";
    bool ret = parseOp(full_path, result);
    ASSERT_EQ("C:\\Users\\Name\\Desktop\\test.txt", result["_file.path"]);
    ASSERT_EQ("C", result["_file.drive_letter"]);
    ASSERT_EQ("C:\\Users\\Name\\Desktop", result["_file.folder"]);
    ASSERT_EQ("test.txt", result["_file.name"]);
    ASSERT_EQ("txt", result["_file.extension"]);

    const char *relative_path = "Desktop\\test.txt";
    ret = parseOp(relative_path, result);
    ASSERT_EQ("Desktop\\test.txt", result["_file.path"]);
    ASSERT_EQ("", result["_file.drive_letter"]);
    ASSERT_EQ("Desktop", result["_file.folder"]);
    ASSERT_EQ("test.txt", result["_file.name"]);
    ASSERT_EQ("txt", result["_file.extension"]);

    const char *file_without_ext = "Desktop\\test";
    ret = parseOp(file_without_ext, result);
    ASSERT_EQ("Desktop\\test", result["_file.path"]);
    ASSERT_EQ("", result["_file.drive_letter"]);
    ASSERT_EQ("Desktop", result["_file.folder"]);
    ASSERT_EQ("test", result["_file.name"]);
    ASSERT_EQ("", result["_file.extension"]);

    const char *only_file = "test.txt";
    ret = parseOp(only_file, result);
    ASSERT_EQ("test.txt", result["_file.path"]);
    ASSERT_EQ("", result["_file.drive_letter"]);
    ASSERT_EQ("", result["_file.folder"]);
    ASSERT_EQ("test.txt", result["_file.name"]);
    ASSERT_EQ("txt", result["_file.extension"]);

    const char *folder_path = "D:\\Users\\Name\\Desktop\\";
    ret = parseOp(folder_path, result);
    ASSERT_EQ("D:\\Users\\Name\\Desktop\\", result["_file.path"]);
    ASSERT_EQ("D", result["_file.drive_letter"]);
    ASSERT_EQ("D:\\Users\\Name\\Desktop", result["_file.folder"]);
    ASSERT_EQ("", result["_file.name"]);
    ASSERT_EQ("", result["_file.extension"]);

    const char *lower_case_drive = "c:\\test.txt";
    ret = parseOp(lower_case_drive, result);
    ASSERT_EQ("c:\\test.txt", result["_file.path"]);
    ASSERT_EQ("C", result["_file.drive_letter"]);
    ASSERT_EQ("c:", result["_file.folder"]);
    ASSERT_EQ("test.txt", result["_file.name"]);
    ASSERT_EQ("txt", result["_file.extension"]);
}

TEST(hlpTests_filepath, unix_path)
{
    const char *logQl = "<_file/FilePath>";
    ParserFn parseOp = getParserOp(logQl);
    ParseResult result;

    ASSERT_EQ(true, static_cast<bool>(parseOp));
    const char *full_path = "/Desktop/test.txt";
    bool ret = parseOp(full_path, result);
    ASSERT_EQ("/Desktop/test.txt", result["_file.path"]);
    ASSERT_EQ("", result["_file.drive_letter"]);
    ASSERT_EQ("/Desktop", result["_file.folder"]);
    ASSERT_EQ("test.txt", result["_file.name"]);
    ASSERT_EQ("txt", result["_file.extension"]);

    const char *relative_path = "Desktop/test.txt";
    ret = parseOp(relative_path, result);
    ASSERT_EQ("Desktop/test.txt", result["_file.path"]);
    ASSERT_EQ("", result["_file.drive_letter"]);
    ASSERT_EQ("Desktop", result["_file.folder"]);
    ASSERT_EQ("test.txt", result["_file.name"]);
    ASSERT_EQ("txt", result["_file.extension"]);

    const char *folder_path = "/Desktop/";
    ret = parseOp(folder_path, result);
    ASSERT_EQ("/Desktop/", result["_file.path"]);
    ASSERT_EQ("", result["_file.drive_letter"]);
    ASSERT_EQ("/Desktop", result["_file.folder"]);
    ASSERT_EQ("", result["_file.name"]);
    ASSERT_EQ("", result["_file.extension"]);
}

TEST(hlpTests_filepath, force_unix_format)
{
    const char *logQl = "<_file/FilePath/UNIX>";
    ParserFn parseOp = getParserOp(logQl);
    ParseResult result;

    ASSERT_EQ(true, static_cast<bool>(parseOp));
    const char *drive_like_file = "C:\\_test.txt";
    bool ret = parseOp(drive_like_file, result);
    ASSERT_EQ("C:\\_test.txt", result["_file.path"]);
    ASSERT_EQ("", result["_file.drive_letter"]);
    ASSERT_EQ("", result["_file.folder"]);
    ASSERT_EQ("C:\\_test.txt", result["_file.name"]);
    ASSERT_EQ("txt", result["_file.extension"]);

    const char *file_with_back_slash = "/Desktop/test\\1:2.txt";
    ret = parseOp(file_with_back_slash, result);
    ASSERT_EQ("/Desktop/test\\1:2.txt", result["_file.path"]);
    ASSERT_EQ("", result["_file.drive_letter"]);
    ASSERT_EQ("/Desktop", result["_file.folder"]);
    ASSERT_EQ("test\\1:2.txt", result["_file.name"]);
    ASSERT_EQ("txt", result["_file.extension"]);
}

TEST(hlpTests_UserAgent, user_agent_firefox)
{
    const char *logQl = "[<userAgent>] <_>";
    const char *userAgent =
        "[Mozilla/5.0 (Macintosh; Intel Mac OS X x.y; "
        "rv:42.0) Gecko/20100101 Firefox/42.0] the rest of the log";

    ParserFn parseOp = getParserOp(logQl);
    ParseResult result;
    auto ret = parseOp(userAgent, result);

    ASSERT_EQ(result["userAgent.original"],
              "Mozilla/5.0 (Macintosh; Intel Mac OS X x.y; "
              "rv:42.0) Gecko/20100101 Firefox/42.0");
}

TEST(hlpTests_UserAgent, user_agent_chrome)
{
    const char *logQl = "[<userAgent>] <_>";
    const char *userAgent =
        "[Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like "
        "Gecko) Chrome/51.0.2704.103 Safari/537.36] the rest of the log";

    ParserFn parseOp = getParserOp(logQl);
    ParseResult result;
    auto ret = parseOp(userAgent, result);

    ASSERT_EQ(result["userAgent.original"],
              "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like "
              "Gecko) Chrome/51.0.2704.103 Safari/537.36");
}

TEST(hlpTests_UserAgent, user_agent_edge)
{
    const char *logQl = "[<userAgent>] <_>";
    const char *userAgent =
        "[Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, "
        "like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59] the "
        "rest of the log";

    ParserFn parseOp = getParserOp(logQl);
    ParseResult result;
    auto ret = parseOp(userAgent, result);

    ASSERT_EQ(
        result["userAgent.original"],
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, "
        "like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59");
}

TEST(hlpTests_UserAgent, user_agent_opera)
{
    const char *logQl = "[<userAgent>] <_>";
    const char *userAgent =
        "[Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like "
        "Gecko) Chrome/51.0.2704.106 Safari/537.36 OPR/38.0.2220.41] the rest "
        "of the log";

    ParserFn parseOp = getParserOp(logQl);
    ParseResult result;
    auto ret = parseOp(userAgent, result);

    ASSERT_EQ(result["userAgent.original"],
              "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like "
              "Gecko) Chrome/51.0.2704.106 Safari/537.36 OPR/38.0.2220.41");
}

TEST(hlpTests_UserAgent, user_agent_safari)
{
    const char *logQl = "[<userAgent>] <_>";
    const char *userAgent =
        "[Mozilla/5.0 (iPhone; CPU iPhone OS 13_5_1 like Mac OS X) "
        "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1.1 Mobile/15E148 "
        "Safari/604.1] the rest of the log";

    ParserFn parseOp = getParserOp(logQl);
    ParseResult result;
    auto ret = parseOp(userAgent, result);

    ASSERT_EQ(result["userAgent.original"],
              "Mozilla/5.0 (iPhone; CPU iPhone OS 13_5_1 like Mac OS X) "
              "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1.1 "
              "Mobile/15E148 Safari/604.1");
}

TEST(hlpTests_ParseAny, success)
{
    const char* logQl = "{<any> }";
    const char *anyMessage = "{Lorem ipsum dolor sit amet, consectetur adipiscing elit }";

    ParserFn parseOp = getParserOp(logQl);
    ParseResult result;
    bool ret = parseOp(anyMessage, result);

    ASSERT_EQ(result["any"],"Lorem ipsum dolor sit amet, consectetur adipiscing elit }");
}

TEST(hlpTests_ParseAny, failed)
{
    const char* logQl = "{ <any> }";
    const char *anyMessage = "{ Lorem {ipsum} dolor sit [amet], consectetur adipiscing elit }";

    ParserFn parseOp = getParserOp(logQl);
    ParseResult result;
    bool ret = parseOp(anyMessage, result);

    ASSERT_EQ(result["any"],"Lorem {ipsum} dolor sit [amet], consectetur adipiscing elit }");
}

TEST(hlpTests_ParseKeyword, success)
{
    const char* logQl = "{<client.registered_domain> }";
    const char *anyMessage = "{Lorem ipsum dolor sit amet, consectetur adipiscing elit }";

    ParserFn parseOp = getParserOp(logQl);
    ParseResult result;
    bool ret = parseOp(anyMessage, result);

    ASSERT_EQ(result["client.registered_domain"],"Lorem");
}

TEST(hlpTests_ParseKeyword, success_long)
{
    const char* logQl = "{<client.registered_domain> }";
    const char *anyMessage = "{Loremipsumdolorsitamet,consecteturadipiscingelit}";

    ParserFn parseOp = getParserOp(logQl);
    ParseResult result;
    bool ret = parseOp(anyMessage, result);

    ASSERT_EQ(result["client.registered_domain"],"Loremipsumdolorsitamet,consecteturadipiscingelit}");
}

TEST(hlpTests_ParseNumber, succes_long)
{
    const char* logQl = " <file.size> ";
    const char* event =" 125 ";

    ParserFn parseOp = getParserOp(logQl);
    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_EQ(true, static_cast<bool>(ret));
    ASSERT_EQ(result["file.size"],"125");
}

TEST(hlpTests_ParseNumber, succes_float)
{
    const char* logQl = " <vulnerability.score.temporal> ";
    const char* event =" 125.256 ";

    ParserFn parseOp = getParserOp(logQl);
    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_EQ(true, static_cast<bool>(ret));
    ASSERT_EQ(result["vulnerability.score.temporal"],"125.256");
}

TEST(hlpTests_ParseNumber, failed_long)
{
    const char* logQl = " <file.size> ";
    const char* event =" A125 ";

    ParserFn parseOp = getParserOp(logQl);
    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_EQ(false, static_cast<bool>(ret));
    ASSERT_EQ(result["file.size"],"");
}

TEST(hlpTests_ParseNumber, failed_float)
{
    const char* logQl = " <vulnerability.score.temporal> ";
    const char* event =" .125.256 ";

    ParserFn parseOp = getParserOp(logQl);
    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_EQ(false, static_cast<bool>(ret));
    ASSERT_EQ(result["vulnerability.score.temporal"],"");
}

TEST(hlpTests_QuotedString, success)
{
    const char* logQl = " ASRTR <_val/quoted_string> STRINGS ";
    const char* event = " ASRTR \"this is some quoted string \" STRINGS ";

    ParserFn parseOp = getParserOp(logQl);
    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_EQ(result["_val"],"this is some quoted string ");
}

TEST(hlpTests_QuotedString, success_simple_char)
{
    const char* logQl = " ASRTR <_val/quoted_string/SIMPLE> STRINGS ";
    const char* event = " ASRTR \'this is some quoted string \' STRINGS ";

    ParserFn parseOp = getParserOp(logQl);
    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_EQ(result["_val"],"this is some quoted string ");
}

TEST(hlpTests_QuotedString, failed)
{
    const char* logQl = " ASRTR <_val/quoted_string> STRINGS ";
    const char* event = " ASRTR \"this is some quoted string STRINGS ";

    ParserFn parseOp = getParserOp(logQl);
    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_EQ(result["_val"],"");
}

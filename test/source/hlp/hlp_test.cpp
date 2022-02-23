#include "gtest/gtest.h"

#include <hlp/hlp.hpp>

static const char *logQl =
    "<source.address> - <json> - [<timestamp/APACHE>] \"<http.request.method> <url> HTTP/<http.version>\" "
    "<http.response.status_code> <http.response.body.bytes> \"-\" \"<user_agent.original>\"";
static const char *event =
    "monitoring-server - {\"data\":\"this is a json\"} - [29/May/2017:19:02:48 +0000] \"GET "
    "https://user:password@wazuh.com:8080/status?query=%22a%20query%20with%20a%20space%22#fragment "
    "HTTP/1.1\" 200 612 \"-\" \"Mozilla/5.0 (Windows NT 6.1; rv:15.0) Gecko/20120716 "
    "Firefox/15.0a2\"";

static const char *logQl2 = "<source.ip> - - [<timestamp/APACHE>] \"-\" "
                            "<http.response.status_code> <http.response.body.bytes> \"-\" \"-\"";
static const char *event2 = "127.0.0.1 - - [02/Feb/2019:05:38:45 +0100] \"-\" 408 152 \"-\" \"-\"";

// Test: An asset that fails the check against the schema
TEST(hlpTests, general)
{
    fprintf(stderr, "\n\n---HLP Test---\n");

    auto parseOp = getParserOp(logQl);
    auto result = parseOp(event);
    fprintf(stderr, "\n%30s | %s\n", "Key", "Val");
    fprintf(stderr, "-------------------------------|------------\n");
    for (auto const &r : result) { fprintf(stderr, "%30s | %s\n", r.first.c_str(), r.second.c_str()); }

    auto parseOp2 = getParserOp(logQl2);
    auto result2 = parseOp2(event2);
    fprintf(stderr, "\n%30s | %s\n", "Key", "Val");
    fprintf(stderr, "-------------------------------|------------\n");
    for (auto const &r : result2) { fprintf(stderr, "%30s | %s\n", r.first.c_str(), r.second.c_str()); }

    fprintf(stderr, "\n--------------\n\n");
}

// Test: parsing succesfully three different IP addresses
TEST(hlpTests, IP_Parser)
{
    const char *logQl = "<source.ip> - <server.ip> -- <source.nat.ip> \"-\" \"-\"";
    const char *event = "127.0.0.1 - 2001:db8:3333:4444:CCCC:DDDD:EEEE:FFFF -- 0:db8:0:4:CCCC:0:EEEE:FFFF \"-\" \"-\"";

    fprintf(stderr, "\n\n---HLP IP parser Test---\n");

    auto parseOp = getParserOp(logQl);
    auto result = parseOp(event);
    fprintf(stderr, "\n%30s | %s\n", "Key", "Val");
    fprintf(stderr, "-------------------------------|------------\n");
    for (auto const &r : result) { fprintf(stderr, "%30s | %s\n", r.first.c_str(), r.second.c_str()); }

    fprintf(stderr, "\n--------------\n\n");

    ASSERT_EQ("127.0.0.1", result["source.ip"]);
    ASSERT_EQ("2001:db8:3333:4444:CCCC:DDDD:EEEE:FFFF", result["server.ip"]);
    ASSERT_EQ("0:db8:0:4:CCCC:0:EEEE:FFFF", result["source.nat.ip"]);
}

TEST(hlpTests, invalid_logql)
{
    const char *logQl = "<source.ip><invalid>";
    auto invalidFunc = getParserOp(logQl);
    ASSERT_EQ(false, static_cast<bool>(invalidFunc));

    const char *logQl2 = "invalid capture <source.ip><invalid> between strings";
    auto invalidFunc2 = getParserOp(logQl2);
    ASSERT_EQ(false, static_cast<bool>(invalidFunc2));

    const char *logQl3 = "invalid capture <source.ip between strings";
    auto invalidFunc3 = getParserOp(logQl3);
    ASSERT_EQ(false, static_cast<bool>(invalidFunc3));
}

TEST(hlpTests, optional_Or)
{
    static const char *logQl = "this won't match an url <url>?<source.ip> but will match ip";
    static const char *event = "this won't match an url 127.0.0.1 but will match ip";

    auto parseOp = getParserOp(logQl);
    auto result = parseOp(event);

    fprintf(stderr, "Matched: [%s]\n", result["source.ip"].c_str());

    ASSERT_EQ("127.0.0.1", result["source.ip"]);
}

TEST(hlpTests, options_parsing)
{
    static const char *logQl = "<_> <_temp> <_temp1/type> <_temp2/type/type2>";
    static const char *event = "one temp temp1 temp2";

    auto parseOp = getParserOp(logQl);
    auto result = parseOp(event);

    ASSERT_EQ("temp", result["_temp"]);
    ASSERT_EQ("temp1", result["_temp1"]);
    ASSERT_EQ("temp2", result["_temp2"]);
}

TEST(hlpTests, url_parsing)
{
    static const char *logQl = "this is an url <url> in text";
    static const char *event = "this is an url "
                               "https://user:password@wazuh.com:8080/"
                               "path?query=%22a%20query%20with%20a%20space%22#fragment in text";

    auto parseOp = getParserOp(logQl);
    auto result = parseOp(event);

    std::string url = "https://user:password@wazuh.com:8080/"
                      "path?query=%22a%20query%20with%20a%20space%22#fragment";
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

TEST(json_test, dummy_test)
{
    const char *logQl = "<_json1/JSON> - <_json2/JSON>";
    const char *event = "{\"String\":\"This is a string\"} - {\"String\":\"This is another string\"}";

    auto parseOp = getParserOp(logQl);
    auto result = parseOp(event);

    ASSERT_EQ("{\"String\":\"This is a string\"}", result["_json1"]);
    ASSERT_EQ("{\"String\":\"This is another string\"}", result["_json2"]);
}

TEST(map_test, success_test)
{
    const char *logQl ="<_map/MAP/ /=>-<_dummy>";
    const char *event ="key1=Value1 Key2=Value2-dummy";

    ParserFn parseOp = getParserOp(logQl);
    auto result = parseOp(event);


    ASSERT_EQ("{\"key1\":\"Value1\",\"Key2\":\"Value2\"}", result["_map"]);
    ASSERT_EQ("dummy", result["_dummy"]);
}

TEST(map_test, end_mark_test)
{
    const char *logQl ="<_map/MAP/ /=/.> <_dummy>";
    const char *event ="key1=Value1 Key2=Value2. dummy";

    ParserFn parseOp = getParserOp(logQl);
    auto result = parseOp(event);

    ASSERT_EQ("{\"key1\":\"Value1\",\"Key2\":\"Value2\"}", result["_map"]);
    ASSERT_EQ("dummy", result["_dummy"]);
}

TEST(map_test, incomplete_map_test)
{
    const char *logQl ="<_map/MAP/ /=>";
    const char *event1 ="key1=Value1 Key2=";
    const char *event2 ="key1=Value1 Key2";
    const char *event3 ="key1=Value1 =Value2";

    ParserFn parseOp = getParserOp(logQl);
    auto result1 = parseOp(event1);
    auto result2 = parseOp(event2);
    auto result3 = parseOp(event3);

    ASSERT_TRUE(result1.empty());
    ASSERT_TRUE(result2.empty());
    ASSERT_TRUE(result3.empty());
}

TEST(hlpTimestampTests, ansic)
{
    static const char *logQl   = "[<timestamp>]";
    static const char *ansicTs = "[Mon Jan 2 15:04:05 2006]";
    static const char *ansimTs = "[Mon Jan 2 15:04:05.123456 2006]";

    auto parseOp = getParserOp(logQl);
    auto result  = parseOp(ansicTs);
    ASSERT_EQ("2006", result["timestamp.year"]);
    ASSERT_EQ("1", result["timestamp.month"]);
    ASSERT_EQ("2", result["timestamp.day"]);
    ASSERT_EQ("15", result["timestamp.hour"]);
    ASSERT_EQ("4", result["timestamp.minutes"]);
    ASSERT_EQ("5", result["timestamp.seconds"]);

    auto resultMillis = parseOp(ansimTs);
    ASSERT_EQ("2006", resultMillis["timestamp.year"]);
    ASSERT_EQ("1", resultMillis["timestamp.month"]);
    ASSERT_EQ("2", resultMillis["timestamp.day"]);
    ASSERT_EQ("15", resultMillis["timestamp.hour"]);
    ASSERT_EQ("4", resultMillis["timestamp.minutes"]);
    ASSERT_EQ("5.123456", resultMillis["timestamp.seconds"]);
}

TEST(hlpTimestampTests, kitchen)
{

    static const char *logQl     = "[<timestamp>]";
    static const char *kitchenTs = "[3:04a.m.]";
    auto parseOp                 = getParserOp(logQl);
    auto result                  = parseOp(kitchenTs);
    ASSERT_EQ("3", result["timestamp.hour"]);
    ASSERT_EQ("4", result["timestamp.minutes"]);
}

TEST(hlpTimestampTests, rfc1123)
{
    static const char *logQl      = "[<timestamp>]";
    static const char *rfc1123Ts  = "[Mon, 02 Jan 2006 15:04:05 MST]";
    static const char *rfc1123zTs = "[Mon, 02 Jan 2006 15:04:05 -0700]";

    auto parseOp = getParserOp(logQl);
    auto result  = parseOp(rfc1123Ts);
    ASSERT_EQ("2006", result["timestamp.year"]);
    ASSERT_EQ("1", result["timestamp.month"]);
    ASSERT_EQ("2", result["timestamp.day"]);
    ASSERT_EQ("15", result["timestamp.hour"]);
    ASSERT_EQ("4", result["timestamp.minutes"]);
    ASSERT_EQ("5", result["timestamp.seconds"]);

    auto resultz = parseOp(rfc1123zTs);
    ASSERT_EQ("2006", resultz["timestamp.year"]);
    ASSERT_EQ("1", resultz["timestamp.month"]);
    ASSERT_EQ("2", resultz["timestamp.day"]);
    ASSERT_EQ("15", resultz["timestamp.hour"]);
    ASSERT_EQ("4", resultz["timestamp.minutes"]);
    ASSERT_EQ("5", resultz["timestamp.seconds"]);
}

TEST(hlpTimestampTests, rfc3339)
{
    static const char *logQl         = "[<timestamp>]";
    static const char *rfc3339Ts     = "[2006-01-02T15:04:05Z07:00]";
    static const char *rfc3339nanoTs = "[2006-01-02T15:04:05.999999999Z07:00]";

    auto parseOp = getParserOp(logQl);
    auto result  = parseOp(rfc3339Ts);
    ASSERT_EQ("2006", result["timestamp.year"]);
    ASSERT_EQ("1", result["timestamp.month"]);
    ASSERT_EQ("2", result["timestamp.day"]);
    ASSERT_EQ("15", result["timestamp.hour"]);
    ASSERT_EQ("4", result["timestamp.minutes"]);
    ASSERT_EQ("5", result["timestamp.seconds"]);

    auto resultNano = parseOp(rfc3339nanoTs);
    ASSERT_EQ("2006", resultNano["timestamp.year"]);
    ASSERT_EQ("1", resultNano["timestamp.month"]);
    ASSERT_EQ("2", resultNano["timestamp.day"]);
    ASSERT_EQ("15", resultNano["timestamp.hour"]);
    ASSERT_EQ("4", resultNano["timestamp.minutes"]);
    ASSERT_EQ("5.999999999", resultNano["timestamp.seconds"]);
}

TEST(hlpTimestampTests, rfc822)
{
    static const char *logQl     = "[<timestamp>]";
    static const char *rfc822Ts  = "[02 Jan 06 15:04 MST]";
    static const char *rfc822zTs = "[02 Jan 06 15:04 -0700]";

    auto parseOp = getParserOp(logQl);
    auto result  = parseOp(rfc822Ts);
    ASSERT_EQ("2006", result["timestamp.year"]);
    ASSERT_EQ("1", result["timestamp.month"]);
    ASSERT_EQ("2", result["timestamp.day"]);
    ASSERT_EQ("15", result["timestamp.hour"]);
    ASSERT_EQ("4", result["timestamp.minutes"]);
    ASSERT_EQ("0", result["timestamp.seconds"]);
    ASSERT_EQ("MST", result["timestamp.timezone"]);

    auto resultz = parseOp(rfc822zTs);
    ASSERT_EQ("2006", resultz["timestamp.year"]);
    ASSERT_EQ("1", resultz["timestamp.month"]);
    ASSERT_EQ("2", resultz["timestamp.day"]);
    ASSERT_EQ("15", resultz["timestamp.hour"]);
    ASSERT_EQ("4", resultz["timestamp.minutes"]);
    ASSERT_EQ("0", resultz["timestamp.seconds"]);
    ASSERT_EQ("-0700", resultz["timestamp.timezone"]);
}

TEST(hlpTimestampTests, rfc850)
{
    static const char *logQl    = "[<timestamp>]";
    static const char *rfc850Ts = "[Monday, 02-Jan-06 15:04:05 MST]";

    auto parseOp = getParserOp(logQl);
    auto result  = parseOp(rfc850Ts);
    ASSERT_EQ("2006", result["timestamp.year"]);
    ASSERT_EQ("1", result["timestamp.month"]);
    ASSERT_EQ("2", result["timestamp.day"]);
    ASSERT_EQ("15", result["timestamp.hour"]);
    ASSERT_EQ("4", result["timestamp.minutes"]);
    ASSERT_EQ("5", result["timestamp.seconds"]);
    ASSERT_EQ("MST", result["timestamp.timezone"]);
}

TEST(hlpTimestampTests, ruby)
{
    static const char *logQl  = "[<timestamp>]";
    static const char *rubyTs = "[Mon Jan 02 15:04:05 -0700 2006]";

    auto parseOp = getParserOp(logQl);
    auto result  = parseOp(rubyTs);
    ASSERT_EQ("2006", result["timestamp.year"]);
    ASSERT_EQ("1", result["timestamp.month"]);
    ASSERT_EQ("2", result["timestamp.day"]);
    ASSERT_EQ("15", result["timestamp.hour"]);
    ASSERT_EQ("4", result["timestamp.minutes"]);
    ASSERT_EQ("5", result["timestamp.seconds"]);
    ASSERT_EQ("-0700", result["timestamp.timezone"]);
}

TEST(hlpTimestampTests, stamp)
{
    static const char *logQl        = "[<timestamp>]";
    static const char *stampTs      = "[Jan 2 15:04:05]";
    static const char *stampmilliTs = "[Jan 2 15:04:05.000]";
    static const char *stampmicroTs = "[Jan 2 15:04:05.000000]";
    static const char *stampnanoTs  = "[Jan 2 15:04:05.000000000]";

    auto parseOp = getParserOp(logQl);
    auto result  = parseOp(stampTs);
    ASSERT_EQ("1", result["timestamp.month"]);
    ASSERT_EQ("2", result["timestamp.day"]);
    ASSERT_EQ("15", result["timestamp.hour"]);
    ASSERT_EQ("4", result["timestamp.minutes"]);
    ASSERT_EQ("5", result["timestamp.seconds"]);

    auto resultMillis = parseOp(stampmilliTs);
    ASSERT_EQ("1", resultMillis["timestamp.month"]);
    ASSERT_EQ("2", resultMillis["timestamp.day"]);
    ASSERT_EQ("15", resultMillis["timestamp.hour"]);
    ASSERT_EQ("4", resultMillis["timestamp.minutes"]);
    ASSERT_EQ("5", resultMillis["timestamp.seconds"]);

    auto resultMicros = parseOp(stampmicroTs);
    ASSERT_EQ("1", resultMicros["timestamp.month"]);
    ASSERT_EQ("2", resultMicros["timestamp.day"]);
    ASSERT_EQ("15", resultMicros["timestamp.hour"]);
    ASSERT_EQ("4", resultMicros["timestamp.minutes"]);
    ASSERT_EQ("5", resultMicros["timestamp.seconds"]);

    auto resultNanos = parseOp(stampnanoTs);
    ASSERT_EQ("1", resultNanos["timestamp.month"]);
    ASSERT_EQ("2", resultNanos["timestamp.day"]);
    ASSERT_EQ("15", resultNanos["timestamp.hour"]);
    ASSERT_EQ("4", resultNanos["timestamp.minutes"]);
    ASSERT_EQ("5", resultNanos["timestamp.seconds"]);
}

TEST(hlpTimestampTests, Unix)
{
    static const char *logQl  = "[<timestamp>]";
    static const char *unixTs = "[Mon Jan 2 15:04:05 MST 2006]";

    auto parseOp = getParserOp(logQl);
    auto result  = parseOp(unixTs);
    ASSERT_EQ("2006", result["timestamp.year"]);
    ASSERT_EQ("1", result["timestamp.month"]);
    ASSERT_EQ("2", result["timestamp.day"]);
    ASSERT_EQ("15", result["timestamp.hour"]);
    ASSERT_EQ("4", result["timestamp.minutes"]);
    ASSERT_EQ("5", result["timestamp.seconds"]);
}

TEST(hlpTimestampTests, specific_format)
{
    static const char *logQl =
        "[<timestamp/RubyDate>] - "
        "[<_ansicTs/timestamp/ANSIC>] - "
        "[<_unixTs/timestamp/UnixDate>] - "
        "[<_stampTs/timestamp/Stamp>]";
    static const char *event =
        "[Mon Jan 02 15:04:05 -0700 2006] - "
        "[Mon Jan 2 15:04:05 2006] - "
        "[Mon Jan 2 15:04:05 MST 2006] - "
        "[Jan 2 15:04:05]";

    auto parseOp = getParserOp(logQl);
    auto result  = parseOp(event);

    fprintf(stderr, "\n%30s | %s\n", "Key", "Val");
    fprintf(stderr, "-------------------------------|------------\n");
    for (auto const &r : result)
    {
        fprintf(stderr, "%30s | %s\n", r.first.c_str(), r.second.c_str());
    }

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

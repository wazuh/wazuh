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

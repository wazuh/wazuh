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

static const char *logQl3 = "<source.ip><invalid>";

static const char *logQl4 = "<url>?<_>";
static const char *event4 = "this won't match an url";

static const char *logQl5 = "<_> <_temp> <_temp/type> <_temp/type/type2> <name/type> <name/type/type2>";

// Test: An asset that fails the check against the schema
TEST(suite_1, test_1)
{
    printf("\n\n---HLP Test---\n");

    auto parseOp = getParserOp(logQl);
    auto result = parseOp(event);
    printf("\n%30s | %s\n", "Key", "Val");
    printf("-------------------------------|------------\n");
    for (auto const &r : result) { printf("%30s | %s\n", r.first.c_str(), r.second.c_str()); }

    putchar('\n');

    auto parseOp2 = getParserOp(logQl2);
    auto result2 = parseOp2(event2);
    printf("\n%30s | %s\n", "Key", "Val");
    printf("-------------------------------|------------\n");
    for (auto const &r : result2) { printf("%30s | %s\n", r.first.c_str(), r.second.c_str()); }

    getParserOp(logQl3);

    auto parseOp4 = getParserOp(logQl4);
    auto result4 = parseOp4(event4);
    printf("\n%30s | %s\n", "Key", "Val");
    printf("-------------------------------|------------\n");
    for (auto const &r : result4) { printf("%30s | %s\n", r.first.c_str(), r.second.c_str()); }

    getParserOp(logQl5);

    printf("\n--------------\n\n");
}

// Test: parsing succesfully three different IP addresses 
TEST(test_IP_Parser, dummy_test)
{
    const char *logQl = "<source.ip> - <server.ip> -- <source.nat.ip> \"-\" \"-\"";
    const char *event = "127.0.0.1 - 2001:db8:3333:4444:CCCC:DDDD:EEEE:FFFF -- 0:db8:0:4:CCCC:0:EEEE:FFFF \"-\" \"-\"";

    printf("\n\n---HLP IP parser Test---\n");

    auto parseOp = getParserOp(logQl);
    auto result = parseOp(event);
    putchar('\n');
    printf("%30s | %s\n", "Key", "Val");
    printf("-------------------------------|------------\n");
    for (auto const &r : result) { printf("%30s | %s\n", r.first.c_str(), r.second.c_str()); }

    printf("\n--------------\n\n");
}

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
    static const char *logQl   = "[<timestamp/ANSIC>]";
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

    static const char *logQl     = "[<timestamp/Kitchen>]";
    static const char *kitchenTs = "[3:04a.m.]";
    auto parseOp                 = getParserOp(logQl);
    auto result                  = parseOp(kitchenTs);
    ASSERT_EQ("3", result["timestamp.hour"]);
    ASSERT_EQ("4", result["timestamp.minutes"]);
}

TEST(hlpTimestampTests, rfc1123)
{
    static const char *logQl      = "[<timestamp/RFC1123>]";
    static const char *logQlz      = "[<timestamp/RFC1123Z>]";
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

    auto parseOpz = getParserOp(logQlz);
    auto resultz = parseOpz(rfc1123zTs);
    ASSERT_EQ("2006", resultz["timestamp.year"]);
    ASSERT_EQ("1", resultz["timestamp.month"]);
    ASSERT_EQ("2", resultz["timestamp.day"]);
    ASSERT_EQ("15", resultz["timestamp.hour"]);
    ASSERT_EQ("4", resultz["timestamp.minutes"]);
    ASSERT_EQ("5", resultz["timestamp.seconds"]);
}

TEST(hlpTimestampTests, rfc3339)
{
    static const char *logQl         = "[<timestamp/RFC3339>]";
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
    static const char *logQl     = "[<timestamp/RFC822>]";
    static const char *logQlz     = "[<timestamp/RFC822Z>]";
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

    auto parseOpz = getParserOp(logQlz);
    auto resultz = parseOpz(rfc822zTs);
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
    static const char *logQl    = "[<timestamp/RFC850>]";
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
    static const char *logQl  = "[<timestamp/RubyDate>]";
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
    static const char *logQl        = "[<timestamp/Stamp>]";
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
    static const char *logQl  = "[<timestamp/UnixDate>]";
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
        "[<timestamp>] - "
        "[<_ansicTs/timestamp>] - "
        "[<_unixTs/timestamp>] - "
        "[<_stampTs/timestamp>]";
    static const char *event =
        "[Mon Jan 02 15:04:05 -0700 2006] - "
        "[Mon Jan 2 15:04:05 2006] - "
        "[Mon Jan 2 15:04:05 MST 2006] - "
        "[Jan 2 15:04:05]";

    auto parseOp = getParserOp(logQl);
    auto result  = parseOp(event);

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

TEST(domain_test, success)
{
    const char *logQl ="<_my_domain/domain>";
    ParserFn parseOp = getParserOp(logQl);
    ParseResult result;

    // Single TLD
    const char *event1 ="www.wazuh.com";
    result = parseOp(event1);
    ASSERT_EQ("www", result["_my_domain.subdomain"]);
    ASSERT_EQ("wazuh.com", result["_my_domain.registered_domain"]);
    ASSERT_EQ("com", result["_my_domain.top_level_domain"]);

    // Dual TLD
    const char *event2 ="www.wazuh.com.ar";
    result = parseOp(event2);
    ASSERT_EQ("www", result["_my_domain.subdomain"]);
    ASSERT_EQ("wazuh.com.ar", result["_my_domain.registered_domain"]);
    ASSERT_EQ("com.ar", result["_my_domain.top_level_domain"]);

    // Multiple subdomains
    const char *event3 ="www.subdomain1.wazuh.com.ar";
    result = parseOp(event3);
    ASSERT_EQ("www.subdomain1", result["_my_domain.subdomain"]);
    ASSERT_EQ("wazuh.com.ar", result["_my_domain.registered_domain"]);
    ASSERT_EQ("com.ar", result["_my_domain.top_level_domain"]);

    // No subdomains
    const char *event4 ="wazuh.com.ar";
    result = parseOp(event4);
    ASSERT_EQ("", result["_my_domain.subdomain"]);
    ASSERT_EQ("wazuh.com.ar", result["_my_domain.registered_domain"]);
    ASSERT_EQ("com.ar", result["_my_domain.top_level_domain"]);

    // No TLD
    const char *event5 ="www.wazuh";
    result = parseOp(event5);
    ASSERT_EQ("www", result["_my_domain.subdomain"]);
    ASSERT_EQ("wazuh", result["_my_domain.registered_domain"]);
    ASSERT_EQ("", result["_my_domain.top_level_domain"]);

    // Only Host
    const char *event6 ="wazuh";
    result = parseOp(event6);
    ASSERT_EQ("", result["_my_domain.subdomain"]);
    ASSERT_EQ("wazuh", result["_my_domain.registered_domain"]);
    ASSERT_EQ("", result["_my_domain.top_level_domain"]);
}

TEST(domain_test, FQDN_validation)
{
    const char *logQl ="<_my_domain/domain/FQDN>";
    ParserFn parseOp = getParserOp(logQl);
    ParseResult result;

    // Single TLD
    const char *event1 ="www.wazuh.com";
    result = parseOp(event1);
    ASSERT_EQ("www", result["_my_domain.subdomain"]);
    ASSERT_EQ("wazuh.com", result["_my_domain.registered_domain"]);
    ASSERT_EQ("com", result["_my_domain.top_level_domain"]);

    // No subdomains
    const char *event2 ="wazuh.com";
    result = parseOp(event2);
    ASSERT_TRUE(result.empty());

    // No TLD
    const char *event3 ="www.wazuh";
    result = parseOp(event3);
    ASSERT_TRUE(result.empty());

    // Only Host
    const char *event4 ="wazuh";
    result = parseOp(event4);
    ASSERT_TRUE(result.empty());
}

TEST(domain_test, host_route)
{
    const char *logQl ="<_my_domain/domain>";
    ParserFn parseOp = getParserOp(logQl);

    const char *event1 ="ftp://www.wazuh.com/route.txt";
    auto result = parseOp(event1);
    // TODO protocol and route aren´t part of the result. We only extract it from the event
    ASSERT_EQ("www", result["_my_domain.subdomain"]);
    ASSERT_EQ("wazuh.com", result["_my_domain.registered_domain"]);
    ASSERT_EQ("com", result["_my_domain.top_level_domain"]);
}

TEST(domain_test, valid_content)
{
    const char *logQl ="<_my_domain/domain>";
    ParserFn parseOp = getParserOp(logQl);
    ParseResult result;

    std::string big_domain(254, 'w');
    result = parseOp(big_domain.c_str());
    ASSERT_TRUE(result.empty());

    const char *invalid_character_domain = "www.wazuh?.com";
    result = parseOp(invalid_character_domain);
    ASSERT_TRUE(result.empty());

    std::string invalid_label(64, 'w');
    std::string invalid_label_domain = "www." + invalid_label + ".com";
    result = parseOp(invalid_label_domain);
    ASSERT_TRUE(result.empty());
TEST(filepath_test, windows_path)
{
    const char *logQl ="<_file/FilePath>";
    ParserFn parseOp = getParserOp(logQl);
    ParseResult result;

    const char *full_path = "C:\\Users\\Name\\Desktop\\test.txt";
    result = parseOp(full_path);
    ASSERT_EQ("C:\\Users\\Name\\Desktop\\test.txt", result["_file.path"]);
    ASSERT_EQ("C", result["_file.drive_letter"]);
    ASSERT_EQ("C:\\Users\\Name\\Desktop", result["_file.folder"]);
    ASSERT_EQ("test.txt", result["_file.name"]);
    ASSERT_EQ("txt", result["_file.extension"]);

    const char *relative_path = "Desktop\\test.txt";
    result = parseOp(relative_path);
    ASSERT_EQ("Desktop\\test.txt", result["_file.path"]);
    ASSERT_EQ("", result["_file.drive_letter"]);
    ASSERT_EQ("Desktop", result["_file.folder"]);
    ASSERT_EQ("test.txt", result["_file.name"]);
    ASSERT_EQ("txt", result["_file.extension"]);

    const char *file_without_ext = "Desktop\\test";
    result = parseOp(file_without_ext);
    ASSERT_EQ("Desktop\\test", result["_file.path"]);
    ASSERT_EQ("", result["_file.drive_letter"]);
    ASSERT_EQ("Desktop", result["_file.folder"]);
    ASSERT_EQ("test", result["_file.name"]);
    ASSERT_EQ("", result["_file.extension"]);

    const char *only_file = "test.txt";
    result = parseOp(only_file);
    ASSERT_EQ("test.txt", result["_file.path"]);
    ASSERT_EQ("", result["_file.drive_letter"]);
    ASSERT_EQ("", result["_file.folder"]);
    ASSERT_EQ("test.txt", result["_file.name"]);
    ASSERT_EQ("txt", result["_file.extension"]);

    const char *folder_path = "C:\\Users\\Name\\Desktop\\";
    result = parseOp(folder_path);
    ASSERT_EQ("C:\\Users\\Name\\Desktop\\", result["_file.path"]);
    ASSERT_EQ("C", result["_file.drive_letter"]);
    ASSERT_EQ("C:\\Users\\Name\\Desktop", result["_file.folder"]);
    ASSERT_EQ("", result["_file.name"]);
    ASSERT_EQ("", result["_file.extension"]);

    const char *lower_case_drive = "c:\\test.txt";
    result = parseOp(lower_case_drive);
    ASSERT_EQ("c:\\test.txt", result["_file.path"]);
    ASSERT_EQ("C", result["_file.drive_letter"]);
    ASSERT_EQ("c:", result["_file.folder"]);
    ASSERT_EQ("test.txt", result["_file.name"]);
    ASSERT_EQ("txt", result["_file.extension"]);
}

TEST(filepath_test, unix_path)
{
    const char *logQl ="<_file/FilePath>";
    ParserFn parseOp = getParserOp(logQl);
    ParseResult result;

    const char *full_path = "/Desktop/test.txt";
    result = parseOp(full_path);
    ASSERT_EQ("/Desktop/test.txt", result["_file.path"]);
    ASSERT_EQ("", result["_file.drive_letter"]);
    ASSERT_EQ("/Desktop", result["_file.folder"]);
    ASSERT_EQ("test.txt", result["_file.name"]);
    ASSERT_EQ("txt", result["_file.extension"]);

    const char *relative_path = "Desktop/test.txt";
    result = parseOp(relative_path);
    ASSERT_EQ("Desktop/test.txt", result["_file.path"]);
    ASSERT_EQ("", result["_file.drive_letter"]);
    ASSERT_EQ("Desktop", result["_file.folder"]);
    ASSERT_EQ("test.txt", result["_file.name"]);
    ASSERT_EQ("txt", result["_file.extension"]);

    const char *folder_path = "/Desktop/";
    result = parseOp(folder_path);
    ASSERT_EQ("/Desktop/", result["_file.path"]);
    ASSERT_EQ("", result["_file.drive_letter"]);
    ASSERT_EQ("/Desktop", result["_file.folder"]);
    ASSERT_EQ("", result["_file.name"]);
    ASSERT_EQ("", result["_file.extension"]);
}

TEST(filepath_test, force_unix_format)
{
    const char *logQl ="<_file/FilePath/UNIX>";
    ParserFn parseOp = getParserOp(logQl);
    ParseResult result;

    const char *drive_like_file = "C:\\_test.txt";
    result = parseOp(drive_like_file);
    ASSERT_EQ("C:\\_test.txt", result["_file.path"]);
    ASSERT_EQ("", result["_file.drive_letter"]);
    ASSERT_EQ("", result["_file.folder"]);
    ASSERT_EQ("C:\\_test.txt", result["_file.name"]);
    ASSERT_EQ("txt", result["_file.extension"]);

    const char *file_with_back_slash = "/Desktop/test\\1:2.txt";
    result = parseOp(file_with_back_slash);
    ASSERT_EQ("/Desktop/test\\1:2.txt", result["_file.path"]);
    ASSERT_EQ("", result["_file.drive_letter"]);
    ASSERT_EQ("/Desktop", result["_file.folder"]);
    ASSERT_EQ("test\\1:2.txt", result["_file.name"]);
    ASSERT_EQ("txt", result["_file.extension"]);
}

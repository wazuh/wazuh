#include <hlp/hlp.hpp>

#include <gtest/gtest.h>

#include <json/json.hpp>

using namespace hlp;

// TODO: this test shouldn't be failing
TEST(hlpTests_URL, url_wrong_format)
{
    const char* logQl = "the temp param has an [<_temp/url>] type";
    const char* event = "the temp param has an [incorrect] type";

    auto parseOp = getParserOp(logQl);
    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_FALSE(ret);
}

TEST(hlpTests_URL, url_success)
{
    static const char* logQl = "this is an url <_url/url> in text";
    static const char* event =
        "this is an url "
        "https://user:password@wazuh.com:8080/"
        "path?query=%22a%20query%20with%20a%20space%22#fragment in text";

    auto parseOp = getParserOp(logQl);
    ParseResult result;
    bool ret = parseOp(event, result);

    std::string url = "https://user:password@wazuh.com:8080/"
                      "path?query=%22a%20query%20with%20a%20space%22#fragment";
    ASSERT_EQ(true, static_cast<bool>(parseOp));
    ASSERT_EQ(url, std::any_cast<std::string>(result["_url.original"]));
    ASSERT_EQ("wazuh.com", std::any_cast<std::string>(result["_url.domain"]));
    ASSERT_EQ("fragment", std::any_cast<std::string>(result["_url.fragment"]));
    ASSERT_EQ("password", std::any_cast<std::string>(result["_url.password"]));
    ASSERT_EQ("/path", std::any_cast<std::string>(result["_url.path"]));
    ASSERT_EQ(8080, std::any_cast<int>(result["_url.port"]));
    ASSERT_EQ("query=%22a%20query%20with%20a%20space%22",
              std::any_cast<std::string>(result["_url.query"]));
    ASSERT_EQ("https", std::any_cast<std::string>(result["_url.scheme"]));
    ASSERT_EQ("user", std::any_cast<std::string>(result["_url.username"]));
}

TEST(hlpTests_IPaddress, IPV4_success)
{
    const char* logQl = "<_ip/ip> - <_ip2/ip> -- <_ip3/ip> \"-\" \"-\"";
    const char* event = "127.0.0.1 - 192.168.100.25 -- 255.255.255.0 \"-\" \"-\"";

    auto parseOp = getParserOp(logQl);
    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_EQ(true, static_cast<bool>(parseOp));
    ASSERT_EQ("127.0.0.1", std::any_cast<std::string>(result["_ip"]));
    ASSERT_EQ("192.168.100.25", std::any_cast<std::string>(result["_ip2"]));
    ASSERT_EQ("255.255.255.0", std::any_cast<std::string>(result["_ip3"]));
}

TEST(hlpTests_IPaddress, IPV4_failed)
{
    const char* logQl = "<_ip/ip> -";
    const char* event = "..100.25 -";

    auto parseOp = getParserOp(logQl);
    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_EQ(true, static_cast<bool>(parseOp));
    ASSERT_TRUE(result.find("_ip") == result.end());
}

TEST(hlpTests_IPaddress, IPV6_success)
{
    const char* logQl = " - <_ip/ip>";
    const char* event = " - 2001:db8:3333:AB45:1111:00A:4:1";

    auto parseOp = getParserOp(logQl);
    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_EQ(true, static_cast<bool>(parseOp));
    ASSERT_EQ("2001:db8:3333:AB45:1111:00A:4:1",
              std::any_cast<std::string>(result["_ip"]));
}

TEST(hlpTests_IPaddress, IPV6_failed)
{
    const char* logQl = "<_ip/ip>";
    const char* event = "2001:db8:#:$:CCCC:DDDD:EEEE:FFFF";

    auto parseOp = getParserOp(logQl);
    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_EQ(true, static_cast<bool>(parseOp));
    ASSERT_TRUE(result.find("_ip") == result.end());
}

// Test: domain parsing
TEST(hlpTests_domain, success)
{
    const char* logQl = "<_my_domain/domain>";
    ParserFn parseOp = getParserOp(logQl);
    ParseResult result;

    ASSERT_EQ(true, static_cast<bool>(parseOp));
    // Single TLD
    const char* event1 = "www.wazuh.com";
    bool ret = parseOp(event1, result);
    ASSERT_EQ("www", std::any_cast<std::string>(result["_my_domain.subdomain"]));
    ASSERT_EQ("wazuh.com",
              std::any_cast<std::string>(result["_my_domain.registered_domain"]));
    ASSERT_EQ("com", std::any_cast<std::string>(result["_my_domain.top_level_domain"]));

    // Dual TLD
    const char* event2 = "www.wazuh.com.ar";
    ret = parseOp(event2, result);
    ASSERT_EQ("www", std::any_cast<std::string>(result["_my_domain.subdomain"]));
    ASSERT_EQ("wazuh.com.ar",
              std::any_cast<std::string>(result["_my_domain.registered_domain"]));
    ASSERT_EQ("com.ar",
              std::any_cast<std::string>(result["_my_domain.top_level_domain"]));

    // Multiple subdomains
    const char* event3 = "www.subdomain1.wazuh.com.ar";
    ret = parseOp(event3, result);
    ASSERT_EQ("www.subdomain1",
              std::any_cast<std::string>(result["_my_domain.subdomain"]));
    ASSERT_EQ("wazuh.com.ar",
              std::any_cast<std::string>(result["_my_domain.registered_domain"]));
    ASSERT_EQ("com.ar",
              std::any_cast<std::string>(result["_my_domain.top_level_domain"]));

    // No subdomains
    const char* event4 = "wazuh.com.ar";
    ret = parseOp(event4, result);
    ASSERT_EQ("", std::any_cast<std::string>(result["_my_domain.subdomain"]));
    ASSERT_EQ("wazuh.com.ar",
              std::any_cast<std::string>(result["_my_domain.registered_domain"]));
    ASSERT_EQ("com.ar",
              std::any_cast<std::string>(result["_my_domain.top_level_domain"]));

    // No TLD
    const char* event5 = "www.wazuh";
    ret = parseOp(event5, result);
    ASSERT_EQ("www", std::any_cast<std::string>(result["_my_domain.subdomain"]));
    ASSERT_EQ("wazuh",
              std::any_cast<std::string>(result["_my_domain.registered_domain"]));
    ASSERT_EQ("", std::any_cast<std::string>(result["_my_domain.top_level_domain"]));

    // Only Host
    const char* event6 = "wazuh";
    ret = parseOp(event6, result);
    ASSERT_EQ("", std::any_cast<std::string>(result["_my_domain.subdomain"]));
    ASSERT_EQ("wazuh",
              std::any_cast<std::string>(result["_my_domain.registered_domain"]));
    ASSERT_EQ("", std::any_cast<std::string>(result["_my_domain.top_level_domain"]));
}

TEST(hlpTests_domain, FQDN_validation)
{
    const char* logQl = "<_my_domain/domain/FQDN>";
    ParserFn parseOp = getParserOp(logQl);
    ParseResult result;

    ASSERT_EQ(true, static_cast<bool>(parseOp));
    // Single TLD
    const char* event1 = "www.wazuh.com";
    bool ret = parseOp(event1, result);
    ASSERT_EQ("www", std::any_cast<std::string>(result["_my_domain.subdomain"]));
    ASSERT_EQ("wazuh.com",
              std::any_cast<std::string>(result["_my_domain.registered_domain"]));
    ASSERT_EQ("com", std::any_cast<std::string>(result["_my_domain.top_level_domain"]));

    // No subdomains
    result.clear();
    const char* event2 = "wazuh.com";
    ret = parseOp(event2, result);
    ASSERT_TRUE(result.empty());

    // No TLD
    result.clear();
    const char* event3 = "www.wazuh";
    ret = parseOp(event3, result);
    ASSERT_TRUE(result.empty());

    // Only Host
    result.clear();
    const char* event4 = "wazuh";
    ret = parseOp(event4, result);
    ASSERT_TRUE(result.empty());
}

TEST(hlpTests_domain, host_route)
{
    const char* logQl = "<_my_domain/domain>";
    ParserFn parseOp = getParserOp(logQl);

    ASSERT_EQ(true, static_cast<bool>(parseOp));
    const char* event1 = "ftp://www.wazuh.com/route.txt";
    ParseResult result;
    auto ret = parseOp(event1, result);
    // TODO protocol and route aren´t part of the result. We only extract it
    // from the event
    ASSERT_EQ("www", std::any_cast<std::string>(result["_my_domain.subdomain"]));
    ASSERT_EQ("wazuh.com",
              std::any_cast<std::string>(result["_my_domain.registered_domain"]));
    ASSERT_EQ("com", std::any_cast<std::string>(result["_my_domain.top_level_domain"]));
}

TEST(hlpTests_domain, valid_content)
{
    const char* logQl = "<_my_domain/domain>";
    ParserFn parseOp = getParserOp(logQl);
    ParseResult result;

    ASSERT_EQ(true, static_cast<bool>(parseOp));
    std::string big_domain(254, 'w');
    bool ret = parseOp(big_domain.c_str(), result);
    ASSERT_TRUE(result.empty());

    const char* invalid_character_domain = "www.wazuh?.com";
    ret = parseOp(invalid_character_domain, result);
    ASSERT_TRUE(result.empty());

    std::string invalid_label(64, 'w');
    std::string invalid_label_domain = "www." + invalid_label + ".com";
    ret = parseOp(invalid_label_domain, result);
    ASSERT_TRUE(result.empty());
}

TEST(hlpTests_filepath, windows_path)
{
    const char* logQl = "<_file/filepath>";
    ParserFn parseOp = getParserOp(logQl);
    ParseResult result;

    ASSERT_EQ(true, static_cast<bool>(parseOp));
    const char* full_path = "C:\\Users\\Name\\Desktop\\test.txt";
    bool ret = parseOp(full_path, result);
    ASSERT_EQ("C:\\Users\\Name\\Desktop\\test.txt",
              std::any_cast<std::string>(result["_file.path"]));
    ASSERT_EQ("C", std::any_cast<std::string>(result["_file.drive_letter"]));
    ASSERT_EQ("C:\\Users\\Name\\Desktop",
              std::any_cast<std::string>(result["_file.folder"]));
    ASSERT_EQ("test.txt", std::any_cast<std::string>(result["_file.name"]));
    ASSERT_EQ("txt", std::any_cast<std::string>(result["_file.extension"]));

    const char* relative_path = "Desktop\\test.txt";
    ret = parseOp(relative_path, result);
    ASSERT_EQ("Desktop\\test.txt", std::any_cast<std::string>(result["_file.path"]));
    ASSERT_EQ("", std::any_cast<std::string>(result["_file.drive_letter"]));
    ASSERT_EQ("Desktop", std::any_cast<std::string>(result["_file.folder"]));
    ASSERT_EQ("test.txt", std::any_cast<std::string>(result["_file.name"]));
    ASSERT_EQ("txt", std::any_cast<std::string>(result["_file.extension"]));

    const char* file_without_ext = "Desktop\\test";
    ret = parseOp(file_without_ext, result);
    ASSERT_EQ("Desktop\\test", std::any_cast<std::string>(result["_file.path"]));
    ASSERT_EQ("", std::any_cast<std::string>(result["_file.drive_letter"]));
    ASSERT_EQ("Desktop", std::any_cast<std::string>(result["_file.folder"]));
    ASSERT_EQ("test", std::any_cast<std::string>(result["_file.name"]));
    ASSERT_EQ("", std::any_cast<std::string>(result["_file.extension"]));

    const char* only_file = "test.txt";
    ret = parseOp(only_file, result);
    ASSERT_EQ("test.txt", std::any_cast<std::string>(result["_file.path"]));
    ASSERT_EQ("", std::any_cast<std::string>(result["_file.drive_letter"]));
    ASSERT_EQ("", std::any_cast<std::string>(result["_file.folder"]));
    ASSERT_EQ("test.txt", std::any_cast<std::string>(result["_file.name"]));
    ASSERT_EQ("txt", std::any_cast<std::string>(result["_file.extension"]));

    const char* folder_path = "D:\\Users\\Name\\Desktop\\";
    ret = parseOp(folder_path, result);
    ASSERT_EQ("D:\\Users\\Name\\Desktop\\",
              std::any_cast<std::string>(result["_file.path"]));
    ASSERT_EQ("D", std::any_cast<std::string>(result["_file.drive_letter"]));
    ASSERT_EQ("D:\\Users\\Name\\Desktop",
              std::any_cast<std::string>(result["_file.folder"]));
    ASSERT_EQ("", std::any_cast<std::string>(result["_file.name"]));
    ASSERT_EQ("", std::any_cast<std::string>(result["_file.extension"]));

    const char* lower_case_drive = "c:\\test.txt";
    ret = parseOp(lower_case_drive, result);
    ASSERT_EQ("c:\\test.txt", std::any_cast<std::string>(result["_file.path"]));
    ASSERT_EQ("C", std::any_cast<std::string>(result["_file.drive_letter"]));
    ASSERT_EQ("c:", std::any_cast<std::string>(result["_file.folder"]));
    ASSERT_EQ("test.txt", std::any_cast<std::string>(result["_file.name"]));
    ASSERT_EQ("txt", std::any_cast<std::string>(result["_file.extension"]));
}

TEST(hlpTests_filepath, unix_path)
{
    const char* logQl = "<_file/filepath>";
    ParserFn parseOp = getParserOp(logQl);
    ParseResult result;

    ASSERT_EQ(true, static_cast<bool>(parseOp));
    const char* full_path = "/Desktop/test.txt";
    bool ret = parseOp(full_path, result);
    ASSERT_EQ("/Desktop/test.txt", std::any_cast<std::string>(result["_file.path"]));
    ASSERT_EQ("", std::any_cast<std::string>(result["_file.drive_letter"]));
    ASSERT_EQ("/Desktop", std::any_cast<std::string>(result["_file.folder"]));
    ASSERT_EQ("test.txt", std::any_cast<std::string>(result["_file.name"]));
    ASSERT_EQ("txt", std::any_cast<std::string>(result["_file.extension"]));

    const char* relative_path = "Desktop/test.txt";
    ret = parseOp(relative_path, result);
    ASSERT_EQ("Desktop/test.txt", std::any_cast<std::string>(result["_file.path"]));
    ASSERT_EQ("", std::any_cast<std::string>(result["_file.drive_letter"]));
    ASSERT_EQ("Desktop", std::any_cast<std::string>(result["_file.folder"]));
    ASSERT_EQ("test.txt", std::any_cast<std::string>(result["_file.name"]));
    ASSERT_EQ("txt", std::any_cast<std::string>(result["_file.extension"]));

    const char* folder_path = "/Desktop/";
    ret = parseOp(folder_path, result);
    ASSERT_EQ("/Desktop/", std::any_cast<std::string>(result["_file.path"]));
    ASSERT_EQ("", std::any_cast<std::string>(result["_file.drive_letter"]));
    ASSERT_EQ("/Desktop", std::any_cast<std::string>(result["_file.folder"]));
    ASSERT_EQ("", std::any_cast<std::string>(result["_file.name"]));
    ASSERT_EQ("", std::any_cast<std::string>(result["_file.extension"]));
}

TEST(hlpTests_filepath, force_unix_format)
{
    const char* logQl = "<_file/filepath/UNIX>";
    ParserFn parseOp = getParserOp(logQl);
    ParseResult result;

    ASSERT_EQ(true, static_cast<bool>(parseOp));
    const char* drive_like_file = "C:\\_test.txt";
    bool ret = parseOp(drive_like_file, result);
    ASSERT_EQ("C:\\_test.txt", std::any_cast<std::string>(result["_file.path"]));
    ASSERT_EQ("", std::any_cast<std::string>(result["_file.drive_letter"]));
    ASSERT_EQ("", std::any_cast<std::string>(result["_file.folder"]));
    ASSERT_EQ("C:\\_test.txt", std::any_cast<std::string>(result["_file.name"]));
    ASSERT_EQ("txt", std::any_cast<std::string>(result["_file.extension"]));

    const char* file_with_back_slash = "/Desktop/test\\1:2.txt";
    ret = parseOp(file_with_back_slash, result);
    ASSERT_EQ("/Desktop/test\\1:2.txt", std::any_cast<std::string>(result["_file.path"]));
    ASSERT_EQ("", std::any_cast<std::string>(result["_file.drive_letter"]));
    ASSERT_EQ("/Desktop", std::any_cast<std::string>(result["_file.folder"]));
    ASSERT_EQ("test\\1:2.txt", std::any_cast<std::string>(result["_file.name"]));
    ASSERT_EQ("txt", std::any_cast<std::string>(result["_file.extension"]));
}

TEST(hlpTests_UserAgent, user_agent_firefox)
{
    const char* logQl = "[<_userAgent/useragent>] <_>";
    const char* userAgent = "[Mozilla/5.0 (Macintosh; Intel Mac OS X x.y; "
                            "rv:42.0) Gecko/20100101 Firefox/42.0] the rest of the log";

    ParserFn parseOp = getParserOp(logQl);
    ParseResult result;
    auto ret = parseOp(userAgent, result);

    ASSERT_EQ(std::any_cast<std::string>(result["_userAgent.original"]),
              "Mozilla/5.0 (Macintosh; Intel Mac OS X x.y; "
              "rv:42.0) Gecko/20100101 Firefox/42.0");
}

TEST(hlpTests_UserAgent, user_agent_chrome)
{
    const char* logQl = "[<_userAgent/useragent>] <_>";
    const char* userAgent =
        "[Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like "
        "Gecko) Chrome/51.0.2704.103 Safari/537.36] the rest of the log";

    ParserFn parseOp = getParserOp(logQl);
    ParseResult result;
    auto ret = parseOp(userAgent, result);

    ASSERT_EQ(std::any_cast<std::string>(result["_userAgent.original"]),
              "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like "
              "Gecko) Chrome/51.0.2704.103 Safari/537.36");
}

TEST(hlpTests_UserAgent, user_agent_edge)
{
    const char* logQl = "[<_userAgent/useragent>] <_>";
    const char* userAgent =
        "[Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, "
        "like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59] the "
        "rest of the log";

    ParserFn parseOp = getParserOp(logQl);
    ParseResult result;
    auto ret = parseOp(userAgent, result);

    ASSERT_EQ(std::any_cast<std::string>(result["_userAgent.original"]),
              "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, "
              "like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59");
}

TEST(hlpTests_UserAgent, user_agent_opera)
{
    const char* logQl = "[<_userAgent/useragent>] <_>";
    const char* userAgent =
        "[Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like "
        "Gecko) Chrome/51.0.2704.106 Safari/537.36 OPR/38.0.2220.41] the rest "
        "of the log";

    ParserFn parseOp = getParserOp(logQl);
    ParseResult result;
    auto ret = parseOp(userAgent, result);

    ASSERT_EQ(std::any_cast<std::string>(result["_userAgent.original"]),
              "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like "
              "Gecko) Chrome/51.0.2704.106 Safari/537.36 OPR/38.0.2220.41");
}

TEST(hlpTests_UserAgent, user_agent_safari)
{
    const char* logQl = "[<_userAgent/useragent>] <_>";
    const char* userAgent =
        "[Mozilla/5.0 (iPhone; CPU iPhone OS 13_5_1 like Mac OS X) "
        "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1.1 Mobile/15E148 "
        "Safari/604.1] the rest of the log";

    ParserFn parseOp = getParserOp(logQl);
    ParseResult result;
    auto ret = parseOp(userAgent, result);

    ASSERT_EQ(std::any_cast<std::string>(result["_userAgent.original"]),
              "Mozilla/5.0 (iPhone; CPU iPhone OS 13_5_1 like Mac OS X) "
              "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1.1 "
              "Mobile/15E148 Safari/604.1");
}

TEST(hlpTests_ParseAny, success)
{
    const char* logQl = "{<_toend/toend> }";
    const char* anyMessage = "{Lorem ipsum dolor sit amet, consectetur adipiscing elit }";

    ParserFn parseOp = getParserOp(logQl);
    ParseResult result;
    bool ret = parseOp(anyMessage, result);

    ASSERT_EQ(std::any_cast<std::string>(result["_toend"]),
              "Lorem ipsum dolor sit amet, consectetur adipiscing elit }");
}

TEST(hlpTests_ParseAny, failed)
{
    const char* logQl = "{ <_toend/toend> }";
    const char* anyMessage =
        "{ Lorem {ipsum} dolor sit [amet], consectetur adipiscing elit }";

    ParserFn parseOp = getParserOp(logQl);
    ParseResult result;
    bool ret = parseOp(anyMessage, result);

    ASSERT_EQ(std::any_cast<std::string>(result["_toend"]),
              "Lorem {ipsum} dolor sit [amet], consectetur adipiscing elit }");
}

TEST(hlpTests_ParseKeyword, success)
{
    const char* logQl = "{<keyword> }";
    const char* anyMessage = "{Lorem ipsum dolor sit amet, consectetur adipiscing elit }";

    ParserFn parseOp = getParserOp(logQl);
    ParseResult result;
    bool ret = parseOp(anyMessage, result);

    ASSERT_EQ(std::any_cast<std::string>(result["keyword"]), "Lorem");
}

TEST(hlpTests_ParseKeyword, success_end_token)
{
    const char* logQl = "{<client.registered_domain> }";
    const char* anyMessage = "{Loremipsumdolorsitamet,consecteturadipiscingelit}";

    ParserFn parseOp = getParserOp(logQl);
    ParseResult result;
    bool ret = parseOp(anyMessage, result);

    ASSERT_EQ(std::any_cast<std::string>(result["client.registered_domain"]),
              "Loremipsumdolorsitamet,consecteturadipiscingelit}");
}

TEST(hlpTests_ParseNumber, success_long)
{
    const char* logQl = " <_n1/number> <_n2/number>";
    const char* event = " 125 -125";

    ParserFn parseOp = getParserOp(logQl);
    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_TRUE(static_cast<bool>(ret));
    ASSERT_EQ(std::any_cast<long>(result["_n1"]), 125);
    ASSERT_EQ(std::any_cast<long>(result["_n2"]), -125);
}

TEST(hlpTests_ParseNumber, success_float)
{
    const char* logQl = " <_float/number> ";
    const char* event = " 125.256 ";

    ParserFn parseOp = getParserOp(logQl);
    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_TRUE(static_cast<bool>(ret));
    ASSERT_EQ(std::any_cast<float>(result["_float"]), 125.256f);
}

TEST(hlpTests_ParseNumber, failed_long)
{
    const char* logQl = " <_size/number> ";
    const char* event = " 10E2 ";

    ParserFn parseOp = getParserOp(logQl);
    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_FALSE(static_cast<bool>(ret));

    event = " 9223372036854775808 ";
    ret = parseOp(event, result);

    ASSERT_FALSE(static_cast<bool>(ret));
    ASSERT_EQ(result.find("_size"), result.end());
}

TEST(hlpTests_ParseNumber, failed_float)
{
    const char* logQl = " <_float/number> ";
    const char* event = " .125.256 ";

    ParserFn parseOp = getParserOp(logQl);
    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_FALSE(static_cast<bool>(ret));
    ASSERT_EQ(result.find("_float"), result.end());

    event = " 10E63 ";
    ret = parseOp(event, result);

    ASSERT_FALSE(static_cast<bool>(ret));
    ASSERT_EQ(result.find("_float"), result.end());
}

TEST(hlpTests_QuotedString, success)
{
    const char* logQl = " ASRTR <_val/quoted> STRINGS ";
    const char* event = " ASRTR \"this is some quoted string \" STRINGS ";

    ParserFn parseOp = getParserOp(logQl);
    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_EQ(std::any_cast<std::string>(result["_val"]), "this is some quoted string ");
}

TEST(hlpTests_QuotedString, success_START_END)
{
    const char* logQl = " ASRTR <_val/quoted/START STRING / END STRING> STRINGS ";
    const char* event =
        " ASRTR START STRING this is some quoted string END STRING STRINGS ";

    ParserFn parseOp = getParserOp(logQl);
    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_EQ(std::any_cast<std::string>(result["_val"]), "this is some quoted string");
}

TEST(hlpTests_QuotedString, success_simple_char)
{
    const char* logQl = " ASRTR <_val/quoted/'> STRINGS ";
    const char* event = " ASRTR \'this is some quoted string \' STRINGS ";

    ParserFn parseOp = getParserOp(logQl);
    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_EQ(std::any_cast<std::string>(result["_val"]), "this is some quoted string ");
}

TEST(hlpTests_QuotedString, failed)
{
    const char* logQl = " ASRTR <_val/quoted> STRINGS ";
    const char* event = " ASRTR \"this is some quoted string STRINGS ";

    ParserFn parseOp = getParserOp(logQl);
    ParseResult result;
    bool ret = parseOp(event, result);

    ASSERT_EQ(result.find("_val"), result.end());
}

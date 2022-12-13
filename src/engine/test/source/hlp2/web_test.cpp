#include "run_test.hpp"
#include <gtest/gtest.h>
#include <hlp/hlp.hpp>
#include <json/json.hpp>
#include <optional>
#include <string>
#include <vector>

/************************************
 *  Uri parser test
 ************************************/

TEST(URIParser, build_OK)
{
    ASSERT_NO_THROW(hlp::getUriParser({}, {"stop1"}, {}));
    ASSERT_NO_THROW(hlp::getUriParser({}, {"stop1", "stop2"}, {}));
}

TEST(URIParser, build_fail)
{
    // Parser with no stop
    ASSERT_THROW(hlp::getUriParser({}, {}, {}), std::runtime_error);
    ASSERT_THROW(hlp::getUriParser({}, {}, {"arg1"}), std::runtime_error);
    ASSERT_THROW(hlp::getUriParser({}, {}, {"arg1", "arg2"}), std::runtime_error);
    // stop but also options
    ASSERT_THROW(hlp::getUriParser({}, {"stop1"}, {"opt1"}), std::runtime_error);
}

TEST(URIParser, parser)
{

    auto fn = [](std::string in) -> json::Json
    {
        json::Json doc(in.c_str());
        return doc;
    };

    std::vector<TestCase> testCases {
        TestCase {R"(C:\Windows\System32\virus.exe)", false, {""}, Options {}, {}, 0},
        TestCase {"/home", false, {""}, Options {}, fn(R"({"path": "/home"})"), 0},
        TestCase {
            "https://demo.wazuh.com:8080/user.php?name=pepe&pass=123#login",
            true,
            {""},
            Options {},
            fn(R"({"original":"https://demo.wazuh.com:8080/user.php?name=pepe&pass=123#login","domain":"demo.wazuh.com","path":"/user.php","scheme":"https","query":"name=pepe&pass=123","port":"8080","fragment":"login"})"),
            61},
        TestCase {
            "https://john.doe@www.example.com:123/forum/questions/"
            "?tag=networking&order=newest#top",
            true,
            {""},
            Options {},
            fn(R"({"original":"https://john.doe@www.example.com:123/forum/questions/?tag=networking&order=newest#top","domain":"www.example.com","path":"/forum/questions/","scheme":"https","username":"john.doe","query":"tag=networking&order=newest","port":"123","fragment":"top"})"),
            85},
        TestCase {
            "https://john.doe@[2001:db8::7]:123/forum/questions/"
            "?tag=networking&order=newest#top",
            true,
            {""},
            Options {},
            fn(R"({"original":"https://john.doe@[2001:db8::7]:123/forum/questions/?tag=networking&order=newest#top","domain":"[2001:db8::7]","path":"/forum/questions/","scheme":"https","username":"john.doe","query":"tag=networking&order=newest","port":"123","fragment":"top"})"),
            83},
        TestCase {
            "telnet://192.0.2.16:80/",
            true,
            {""},
            Options {},
            fn(R"({"original":"telnet://192.0.2.16:80/","domain":"192.0.2.16","path":"/","scheme":"telnet","port":"80"})"),
            23},
        // TestCase {
        //     "mailto:John.Doe@example.com",
        //     true,
        //     {""},
        //     Options {},
        //     fn(R"({"original":"mailto:John.Doe@example.com","scheme":"mailto","path":"John.Doe@example.com"})"),
        //     27},
        // TestCase {
        //     "ldap://[2001:db8::7]/c=GB?objectClass?one",
        //     true,
        //     {""},
        //     Options {},
        //     fn(R"({"original":"ldap://[2001:db8::7]/c=GB?objectClass?one","domain":"[2001:db8::7]","path":"/c=GB","scheme":"ldap","query":"objectClass?one"})"),
        //     41},
    };

    for (auto t : testCases)
    {
        runTest(t, hlp::getUriParser);
    }
}

/************************************
 *  User Agent test
 ************************************/
TEST(UAParser, build_OK)
{
    ASSERT_NO_THROW(hlp::getUAParser({}, {"stop1"}, {}));
    ASSERT_NO_THROW(hlp::getUAParser({}, {"stop1", "stop2"}, {}));
}

TEST(UAParser, build_fail)
{

    // Parser with no stop
    ASSERT_THROW(hlp::getUAParser({}, {}, {}), std::runtime_error);
    ASSERT_THROW(hlp::getUAParser({}, {}, {"arg1"}), std::runtime_error);
    ASSERT_THROW(hlp::getUAParser({}, {}, {"arg1", "arg2"}), std::runtime_error);
    // stop but also options
    ASSERT_THROW(hlp::getUAParser({}, {"stop1"}, {"opt1"}), std::runtime_error);
}

TEST(UAParser, parser)
{

    auto fn = [](std::string in) -> json::Json
    {
        json::Json doc;
        doc.setString(in.c_str(), "/user_agent/original");
        return doc;
    };

    // https://github.com/ua-parser/uap-core/blob/master/regexes.yaml
    std::vector<TestCase> testCases {
        TestCase {
            R"(Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0)",
            true,
            {""},
            Options {},
            fn(R"(Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0)"),
            77},
        TestCase {
            R"(Mozilla/5.0 (Macintosh; Intel Mac OS X x.y; rv:42.0) Gecko/20100101 Firefox/42.0)",
            true,
            {""},
            Options {},
            fn(R"(Mozilla/5.0 (Macintosh; Intel Mac OS X x.y; rv:42.0) Gecko/20100101 Firefox/42.0)"),
            80},
        TestCase {
            R"(Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36)",
            true,
            {""},
            Options {},
            fn(R"(Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36)"),
            105},
        TestCase {
            R"(Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.106 Safari/537.36 OPR/38.0.2220.41)",
            true,
            {""},
            Options {},
            fn(R"(Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.106 Safari/537.36 OPR/38.0.2220.41)"),
            122},
        TestCase {
            R"(Opera/9.80 (Macintosh; Intel Mac OS X; U; en) Presto/2.2.15 Version/10.00)",
            true,
            {""},
            Options {},
            fn(R"(Opera/9.80 (Macintosh; Intel Mac OS X; U; en) Presto/2.2.15 Version/10.00)"),
            73},
        TestCase {R"(Opera/9.60 (Windows NT 6.0; U; en) Presto/2.1.1)",
                  true,
                  {""},
                  Options {},
                  fn(R"(Opera/9.60 (Windows NT 6.0; U; en) Presto/2.1.1)"),
                  47},
        TestCase {
            R"(Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59)",
            true,
            {""},
            Options {},
            fn(R"(Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59)"),
            131},
        TestCase {
            R"(Mozilla/5.0 (iPhone; CPU iPhone OS 13_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1.1 Mobile/15E148 Safari/604.1)",
            true,
            {""},
            Options {},
            fn(R"(Mozilla/5.0 (iPhone; CPU iPhone OS 13_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1.1 Mobile/15E148 Safari/604.1)"),
            139},
        TestCase {
            R"(Mozilla/5.0 (compatible; MSIE 9.0; Windows Phone OS 7.5; Trident/5.0; IEMobile/9.0))",
            true,
            {""},
            Options {},
            fn(R"(Mozilla/5.0 (compatible; MSIE 9.0; Windows Phone OS 7.5; Trident/5.0; IEMobile/9.0))"),
            83},
        TestCase {
            R"(Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html))",
            true,
            {""},
            Options {},
            fn(R"(Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html))"),
            72},
        TestCase {
            R"(Mozilla/5.0 (compatible; YandexAccessibilityBot/3.0; +http://yandex.com/bots))",
            true,
            {""},
            Options {},
            fn(R"(Mozilla/5.0 (compatible; YandexAccessibilityBot/3.0; +http://yandex.com/bots))"),
            77},
        TestCase {R"(curl/7.64.1)", false, {}, Options {}, fn(R"(curl/7.64.1)"), 0},
        TestCase {R"(PostmanRuntime/7.26.5)",
                  true,
                  {""},
                  Options {},
                  fn(R"(PostmanRuntime/7.26.5)"),
                  21},
        TestCase {
            R"(Mozilla/5.0 (Series40; Nokia201/11.81; Profile/MIDP-2.1 Configuration/CLDC-1.1) Gecko/20100401 S40OviBrowser/2.0.2.68.14)",
            true,
            {""},
            Options {},
            fn(R"(Mozilla/5.0 (Series40; Nokia201/11.81; Profile/MIDP-2.1 Configuration/CLDC-1.1) Gecko/20100401 S40OviBrowser/2.0.2.68.14)"),
            120},
        TestCase {
            R"(Mozilla/5.0 (Series40; Nokia201/11.81; Profile/MIDP-2.1 Configuration/CLDC-1.1) Gecko/20100401 S40OviBrowser/2.0.2.68.14-----)",
            true,
            {"-----"},
            Options {},
            fn(R"(Mozilla/5.0 (Series40; Nokia201/11.81; Profile/MIDP-2.1 Configuration/CLDC-1.1) Gecko/20100401 S40OviBrowser/2.0.2.68.14)"),
            120},
    };

    for (auto t : testCases)
    {
        runTest(t, hlp::getUAParser);
    }
}

/************************************
 *  FQDNParser test
 ************************************/
TEST(FQDNParser, build_fail)
{

    // Parser cannot be built with arguments
    ASSERT_THROW(hlp::getFQDNParser({}, {}, {"arg1"}), std::runtime_error);
    ASSERT_THROW(hlp::getFQDNParser({}, {}, {"arg1", "arg2"}), std::runtime_error);
    ASSERT_THROW(hlp::getFQDNParser({}, {"stop1"}, {"opt1"}), std::runtime_error);
}

TEST(FQDNParser, build_OK)
{
    ASSERT_NO_THROW(hlp::getFQDNParser({}, {"stop1"}, {}));
    ASSERT_NO_THROW(hlp::getFQDNParser({}, {"stop1", "stop2"}, {}));
    ASSERT_NO_THROW(hlp::getFQDNParser({}, {}, {}));
}

TEST(FQDNParser, parser)
{
    auto fn = [](std::string in) -> json::Json
    {
        json::Json doc;
        doc.setString(in);
        return doc;
    };

    std::vector<TestCase> testCases {
        TestCase {R"(www.wazuh.com)", true, {}, Options {}, fn(R"(www.wazuh.com)"), 13},
        TestCase {R"(www.wazuh.com.)", true, {}, Options {}, fn(R"(www.wazuh.com.)"), 14},
        TestCase {R"(..wazuh.com)", false, {}, Options {}, fn(R"()"), 0},
        TestCase {R"(www.wazuh.com.   )",
                  true,
                  {"   "},
                  Options {},
                  fn(R"(www.wazuh.com.)"),
                  14},
    };

    for (auto t : testCases)
    {
        runTest(t, hlp::getFQDNParser);
    }
}

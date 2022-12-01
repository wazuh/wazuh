#include "run_test.hpp"
#include <gtest/gtest.h>
#include <hlp/hlp.hpp>
#include <json/json.hpp>
#include <optional>
#include <string>
#include <vector>

TEST(HLP2, URIParser)
{

    auto fn = [](std::string in) -> json::Json
    {
        json::Json doc(in.c_str());
        return doc;
    };

    std::vector<TestCase> testCases {
        TestCase {R"(C:\Windows\System32\virus.exe)", false, {""}, Options {}, {}, 5},
        TestCase {"/home", false, {""}, Options {}, fn(R"({"path": "/home"})"), 5},
        TestCase {
            "https://demo.wazuh.com:8080/user.php?name=pepe&pass=123#login",
            true,
            {""},
            Options {},
            fn(R"({"original":"https://demo.wazuh.com:8080/user.php?name=pepe&pass=123#login","domain":"demo.wazuh.com","path":"/user.php","scheme":"https","query":"name=pepe&pass=123","port":"8080","fragment":"login"})"),
            61},
    };

    for (auto t : testCases)
    {
        runTest(t, hlp::getUriParser);
    }
}

TEST(HLP2, UAParser)
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
            false,
            {},
            Options {},
            fn(R"(Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36)"),
            0},
        TestCase {
            R"(Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.106 Safari/537.36 OPR/38.0.2220.41)",
            true,
            {""},
            Options {},
            fn(R"(Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.106 Safari/537.36 OPR/38.0.2220.41)"),
            122},
        TestCase {
            R"(Opera/9.80 (Macintosh; Intel Mac OS X; U; en) Presto/2.2.15 Version/10.00)",
            false,
            {},
            Options {},
            fn(R"(Opera/9.80 (Macintosh; Intel Mac OS X; U; en) Presto/2.2.15 Version/10.00)"),
            0},
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
            false,
            {},
            Options {},
            fn(R"(Mozilla/5.0 (compatible; MSIE 9.0; Windows Phone OS 7.5; Trident/5.0; IEMobile/9.0))"),
            0},
        TestCase {
            R"(Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html))",
            false,
            {},
            Options {},
            fn(R"(Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html))"),
            0},
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
    };

    for (auto t : testCases)
    {
        runTest(t, hlp::getUAParser);
    }
}

TEST(HLP2, FQDNParser)
{
    auto fn = [](std::string in) -> json::Json
    {
        json::Json doc;
        doc.setString(in);
        return doc;
    };

    std::vector<TestCase> testCases {
        TestCase {R"(www.wazuh.com)", true, {}, Options {}, fn(R"(www.wazuh.com)"), 13},
        TestCase {R"(..wazuh.com)", false, {}, Options {}, fn(R"()"), 0},
    };

    for (auto t : testCases)
    {
        runTest(t, hlp::getFQDNParser);
    }
}

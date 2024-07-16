#include <gtest/gtest.h>

#include "hlp_test.hpp"

auto constexpr NAME = "webParser";
static const std::string TARGET = "/TargetField";

/************************************
 *  Uri parser test
 ************************************/

INSTANTIATE_TEST_SUITE_P(UriBuild,
                         HlpBuildTest,
                         ::testing::Values(BuildT(FAILURE, getUriParser, {NAME, TARGET, {""}, {"unexpected"}}),
                                           BuildT(SUCCESS, getUriParser, {NAME, TARGET, {""}, {}}),
                                           BuildT(FAILURE, getUriParser, {NAME, TARGET, {}, {}})));

INSTANTIATE_TEST_SUITE_P(
    UriParse,
    HlpParseTest,
    ::testing::Values(
        // testCases
        ParseT(FAILURE, R"(C:\Windows\System32\virus.exe)", {}, 29, getUriParser, {NAME, TARGET, {""}, {}}),
        ParseT(FAILURE, "/home", {}, 5, getUriParser, {NAME, TARGET, {""}, {}}),
        ParseT(
            SUCCESS,
            "https://demo.wazuh.com:8080/user.php?name=pepe&pass=123#login",
            j(fmt::format(
                R"({{"{}": {{"original":"https://demo.wazuh.com:8080/user.php?name=pepe&pass=123#login","domain":"demo.wazuh.com","path":"/user.php","scheme":"https","query":"name=pepe&pass=123","port":"8080","fragment":"login"}}}})",
                TARGET.substr(1))),
            61,
            getUriParser,
            {NAME, TARGET, {""}, {}}),
        ParseT(
            SUCCESS,
            "https://john.doe@localhost:123/forum/questions/"
            "?tag=networking&order=newest#top",
            j(fmt::format(
                R"({{"{}": {{"original":"https://john.doe@localhost:123/forum/questions/?tag=networking&order=newest#top","domain":"localhost","path":"/forum/questions/","scheme":"https","username":"john.doe","query":"tag=networking&order=newest","port":"123","fragment":"top"}}}})",
                TARGET.substr(1))),
            79,
            getUriParser,
            {NAME, TARGET, {""}, {}}),
        ParseT(
            SUCCESS,
            "https://john.doe@[2001:db8::7]:123/forum/questions/"
            "?tag=networking&order=newest#top",
            j(fmt::format(
                R"({{"{}": {{"original":"https://john.doe@[2001:db8::7]:123/forum/questions/?tag=networking&order=newest#top","domain":"[2001:db8::7]","path":"/forum/questions/","scheme":"https","username":"john.doe","query":"tag=networking&order=newest","port":"123","fragment":"top"}}}})",
                TARGET.substr(1))),
            83,
            getUriParser,
            {NAME, TARGET, {""}, {}}),
        ParseT(
            SUCCESS,
            "telnet://192.0.2.16:80/",
            j(fmt::format(
                R"({{"{}":{{"original":"telnet://192.0.2.16:80/","domain":"192.0.2.16","path":"/","scheme":"telnet","port":"80"}}}})",
                TARGET.substr(1))),
            23,
            getUriParser,
            {NAME, TARGET, {""}, {}})));
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
//      41}

/************************************
 *  User Agent test
 ************************************/
INSTANTIATE_TEST_SUITE_P(UABuild,
                         HlpBuildTest,
                         ::testing::Values(BuildT(FAILURE, getUAParser, {NAME, TARGET, {""}, {"unexpected"}}),
                                           BuildT(SUCCESS, getUAParser, {NAME, TARGET, {""}, {}}),
                                           BuildT(FAILURE, getUAParser, {NAME, TARGET, {}, {}})));

INSTANTIATE_TEST_SUITE_P(
    UAParse,
    HlpParseTest,
    ::testing::Values(
        // https://github.com/ua-parser/uap-core/blob/master/regexes.yaml
        ParseT(
            SUCCESS,
            R"(Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0)",
            j(fmt::format(
                R"({{"{}":{{"original":"Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0"}}}})",
                TARGET.substr(1))),
            77,
            getUAParser,
            {NAME, TARGET, {""}, {}}),
        ParseT(
            SUCCESS,
            R"(Mozilla/5.0 (Macintosh; Intel Mac OS X x.y; rv:42.0) Gecko/20100101 Firefox/42.0)",
            j(fmt::format(
                R"({{"{}":{{"original":"Mozilla/5.0 (Macintosh; Intel Mac OS X x.y; rv:42.0) Gecko/20100101 Firefox/42.0"}}}})",
                TARGET.substr(1))),
            80,
            getUAParser,
            {NAME, TARGET, {""}, {}}),
        ParseT(
            SUCCESS,
            R"(Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36)",
            j(fmt::format(
                R"({{"{}":{{"original":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36"}}}})",
                TARGET.substr(1))),
            105,
            getUAParser,
            {NAME, TARGET, {""}, {}}),
        ParseT(
            SUCCESS,
            R"(Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.106 Safari/537.36 OPR/38.0.2220.41)",
            j(fmt::format(
                R"({{"{}":{{"original":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.106 Safari/537.36 OPR/38.0.2220.41"}}}})",
                TARGET.substr(1))),
            122,
            getUAParser,
            {NAME, TARGET, {""}, {}}),
        ParseT(
            SUCCESS,
            R"(Opera/9.80 (Macintosh; Intel Mac OS X; U; en) Presto/2.2.15 Version/10.00)",
            j(fmt::format(
                R"({{"{}":{{"original":"Opera/9.80 (Macintosh; Intel Mac OS X; U; en) Presto/2.2.15 Version/10.00"}}}})",
                TARGET.substr(1))),
            73,
            getUAParser,
            {NAME, TARGET, {""}, {}}),
        ParseT(SUCCESS,
               R"(Opera/9.60 (Windows NT 6.0; U; en) Presto/2.1.1)",
               j(fmt::format(R"({{"{}":{{"original":"Opera/9.60 (Windows NT 6.0; U; en) Presto/2.1.1"}}}})", TARGET.substr(1))),
               47,
               getUAParser,
               {NAME, TARGET, {""}, {}}),
        ParseT(
            SUCCESS,
            R"(Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59)",
            j(fmt::format(
                R"({{"{}":{{"original":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59"}}}})",
                TARGET.substr(1))),
            131,
            getUAParser,
            {NAME, TARGET, {""}, {}}),
        ParseT(
            SUCCESS,
            R"(Mozilla/5.0 (iPhone; CPU iPhone OS 13_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1.1 Mobile/15E148 Safari/604.1)",
            j(fmt::format(
                R"({{"{}":{{"original":"Mozilla/5.0 (iPhone; CPU iPhone OS 13_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1.1 Mobile/15E148 Safari/604.1"}}}})",
                TARGET.substr(1))),
            139,
            getUAParser,
            {NAME, TARGET, {""}, {}}),
        ParseT(
            SUCCESS,
            R"(Mozilla/5.0 (compatible; MSIE 9.0; Windows Phone OS 7.5; Trident/5.0; IEMobile/9.0))",
            j(fmt::format(
                R"d({{"{}":{{"original":"Mozilla/5.0 (compatible; MSIE 9.0; Windows Phone OS 7.5; Trident/5.0; IEMobile/9.0)"}}}})d",
                TARGET.substr(1))),
            83,
            getUAParser,
            {NAME, TARGET, {""}, {}}),
        ParseT(
            SUCCESS,
            R"(Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html))",
            j(fmt::format(
                R"d({{"{}":{{"original":"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"}}}})d",
                TARGET.substr(1))),
            72,
            getUAParser,
            {NAME, TARGET, {""}, {}}),
        ParseT(
            SUCCESS,
            R"(Mozilla/5.0 (compatible; YandexAccessibilityBot/3.0; +http://yandex.com/bots))",
            j(fmt::format(
                R"d({{"{}":{{"original":"Mozilla/5.0 (compatible; YandexAccessibilityBot/3.0; +http://yandex.com/bots)"}}}})d",
                TARGET.substr(1))),
            77,
            getUAParser,
            {NAME, TARGET, {""}, {}}),
        ParseT(SUCCESS,
               R"(PostmanRuntime/7.26.5)",
               j(fmt::format(R"d({{"{}":{{"original":"PostmanRuntime/7.26.5"}}}})d", TARGET.substr(1))),
               21,
               getUAParser,
               {NAME, TARGET, {""}, {}}),
        ParseT(
            SUCCESS,
            R"(Mozilla/5.0 (Series40; Nokia201/11.81; Profile/MIDP-2.1 Configuration/CLDC-1.1) Gecko/20100401 S40OviBrowser/2.0.2.68.14)",
            j(fmt::format(
                R"d({{"{}":{{"original":"Mozilla/5.0 (Series40; Nokia201/11.81; Profile/MIDP-2.1 Configuration/CLDC-1.1) Gecko/20100401 S40OviBrowser/2.0.2.68.14"}}}})d",
                TARGET.substr(1))),
            120,
            getUAParser,
            {NAME, TARGET, {""}, {}}),
        ParseT(
            SUCCESS,
            R"(Mozilla/5.0 (Series40; Nokia201/11.81; Profile/MIDP-2.1 Configuration/CLDC-1.1) Gecko/20100401 S40OviBrowser/2.0.2.68.14-----)",
            j(fmt::format(
                R"d({{"{}":{{"original":"Mozilla/5.0 (Series40; Nokia201/11.81; Profile/MIDP-2.1 Configuration/CLDC-1.1) Gecko/20100401 S40OviBrowser/2.0.2.68.14"}}}})d",
                TARGET.substr(1))),
            120,
            getUAParser,
            {NAME, TARGET, {"-----"}, {}})));

/************************************
 *  FQDNParser test
 ************************************/
INSTANTIATE_TEST_SUITE_P(FQDNBuild,
                         HlpBuildTest,
                         ::testing::Values(BuildT(SUCCESS, getFQDNParser, {NAME, TARGET, {}, {}}),
                                           BuildT(SUCCESS, getFQDNParser, {NAME, TARGET, {""}, {}}),
                                           BuildT(FAILURE, getFQDNParser, {NAME, TARGET, {}, {"unexpected"}}),
                                           BuildT(FAILURE, getFQDNParser, {NAME, TARGET, {""}, {"unexpected"}})));

INSTANTIATE_TEST_SUITE_P(
    FQDNParse,
    HlpParseTest,
    ::testing::Values(ParseT(SUCCESS,
                             R"(www.wazuh.com)",
                             j(fmt::format(R"({{"{}": "www.wazuh.com"}})", TARGET.substr(1))),
                             13,
                             getFQDNParser,
                             {NAME, TARGET, {}, {}}),
                      ParseT(SUCCESS,
                             R"(www.wazuh.com.)",
                             j(fmt::format(R"({{"{}": "www.wazuh.com."}})", TARGET.substr(1))),
                             14,
                             getFQDNParser,
                             {NAME, TARGET, {}, {}}),
                      ParseT(FAILURE, R"(..wazuh.com)", {}, 0, getFQDNParser, {NAME, TARGET, {}, {}}),
                      ParseT(SUCCESS,
                             R"(www.wazuh.com.   )",
                             j(fmt::format(R"({{"{}": "www.wazuh.com."}})", TARGET.substr(1))),
                             14,
                             getFQDNParser,
                             {NAME, TARGET, {"   "}, {}})));

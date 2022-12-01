#include "run_test.hpp"
#include <gtest/gtest.h>
#include <hlp/hlp.hpp>
#include <hlp/parsec.hpp>
#include <json/json.hpp>
#include <string>

TEST(HLP2, FilePathParser)
{

    auto fn = [](std::string in) -> json::Json
    {
        json::Json doc(in.c_str());
        return doc;
    };

    std::vector<TestCase> testCases {
        TestCase {R"(/user/login.php)",
                  true,
                  {""},
                  Options {},
                  fn(R"({"path":"/user","name":"login.php","ext":"php"})"),
                  15},
        TestCase {
            R"(..\Windows\..\Users\"Administrator\rootkit.exe)",
            true,
            {""},
            Options {},
            fn(R"({"path":"..\\Windows\\..\\Users\\\"Administrator","name":"rootkit.exe","ext":"exe"})"),
            46},
        TestCase {R"(/home/user/.rootkit/.file.sh)",
                  true,
                  {""},
                  Options {},
                  fn(R"({"path": "/home/user/.rootkit","name": ".file.sh","ext": "sh"})"),
                  28},
        TestCase {
            R"(C:\Windows\System32\virus.exe)",
            true,
            {""},
            Options {},
            fn(R"({"path": "C:\\Windows\\System32","name": "virus.exe","ext": "exe","drive_letter": "C"})"),
            29},
        TestCase {
            R"(../home/..user/.rootkit/..file.sh)",
            true,
            {""},
            Options {},
            fn(R"({"path": "../home/..user/.rootkit","name": "..file.sh","ext": "sh"})"),
            33},
    };

    for (auto t : testCases)
    {
        runTest(t, hlp::getFilePathParser);
    }
}

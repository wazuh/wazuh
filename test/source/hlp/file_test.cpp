#include "run_test.hpp"
#include <gtest/gtest.h>
#include <hlp/hlp.hpp>
#include <hlp/parsec.hpp>
#include <json/json.hpp>
#include <string>

TEST(FilePath, build_OK)
{
    ASSERT_NO_THROW(hlp::getFilePathParser({}, {"stop1"}, {}));
    ASSERT_NO_THROW(hlp::getFilePathParser({}, {"stop1", "stop2"}, {}));
}

TEST(FilePath, build_fail)
{
    // Parser with no stop
    ASSERT_THROW(hlp::getFilePathParser({}, {}, {}), std::runtime_error);
    ASSERT_THROW(hlp::getFilePathParser({}, {}, {"arg1"}), std::runtime_error);
    ASSERT_THROW(hlp::getFilePathParser({}, {}, {"arg1", "arg2"}), std::runtime_error);
    // stop but also options
    ASSERT_THROW(hlp::getFilePathParser({}, {"stop1"}, {"opt1"}), std::runtime_error);
}


TEST(FilePath, parser)
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
        TestCase {
            R"(relative.test.log)",
            true,
            {""},
            Options {},
            fn(R"({"path":"relative.test.log","name":"relative.test.log","ext":"log"})"),
            17},
        TestCase {R"(.hidden.log)",
                  true,
                  {""},
                  Options {},
                  fn(R"({"path":".hidden.log","name":".hidden.log","ext":"log"})"),
                  11},
        TestCase {"", false, {""}, Options {}, fn(R"({})"), 0},
        TestCase {
            R"(/)", true, {""}, Options {}, fn(R"({"path":"/","name":"","ext":""})"), 1},
    };

    for (auto t : testCases)
    {
        runTest(t, hlp::getFilePathParser);
    }
}

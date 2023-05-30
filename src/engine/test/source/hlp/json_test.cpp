#include <gtest/gtest.h>

#include "fmt/format.h"
#include "run_test.hpp"
#include <hlp/hlp.hpp>
#include <hlp/parsec.hpp>
#include <json/json.hpp>
#include <string>
#include <vector>

TEST(JSONParser, build_OK)
{
    ASSERT_NO_THROW(hlp::getJSONParser({}, {}, {}));
    ASSERT_NO_THROW(hlp::getJSONParser({}, {"stop1"}, {}));
    ASSERT_NO_THROW(hlp::getJSONParser({}, {"stop1", "stop2"}, {}));
}

TEST(JSONParser, build_fail)
{
    // Parser with no stop
    ASSERT_THROW(hlp::getJSONParser({}, {}, {"arg1"}), std::runtime_error);
    ASSERT_THROW(hlp::getJSONParser({}, {}, {"arg1", "arg2"}), std::runtime_error);
    // stop but also options
    ASSERT_THROW(hlp::getJSONParser({}, {"stop1"}, {"opt1"}), std::runtime_error);
}

TEST(JSONParser, parser)
{
    auto fn = [](std::string in) -> json::Json
    {
        json::Json doc {in.c_str()};
        return doc;
    };

    std::vector<TestCase> testCases {
        // TestCase {R"(..\Windows\..\Users\Administrator\rootkit.exe)", true, {},
        // Options{}, R"()", "", 28},
        TestCase {R"({}}}}})", true, {}, Options {}, fn(R"({})"), 2},
        TestCase {R"(42)", true, {}, Options {}, fn(R"(42)"), 2},
        TestCase {
            R"({ "key": "value"})", true, {}, Options {}, fn(R"({ "key": "value"})"), 17},
    };

    for (auto t : testCases)
    {
        runTest(t, hlp::getJSONParser);
    }
}

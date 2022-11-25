#include <gtest/gtest.h>

#include "fmt/format.h"
#include <hlp/hlp.hpp>
#include <hlp/parsec.hpp>
#include <string>
#include <vector>
#include "run_test.hpp"
#include <json/json.hpp>


TEST(HLP2, JSONParser) {
    auto fn = [](std::string in) -> json::Json {
        json::Json doc{in.c_str()};
        return doc;
    };

    std::vector<TestCase> testCases
        {
            // TestCase {R"(..\Windows\..\Users\Administrator\rootkit.exe)", true, {}, Options{}, R"()", "", 28},
            TestCase {R"({}}}}})", true,{}, Options{},  fn(R"({})"), 2},
            TestCase {R"(42)", true,{}, Options{}, fn(R"(42)"),2},
            TestCase {R"({ "key": "value"})", true,{}, Options{}, fn(R"({ "key": "value"})"), 17},
        };

    for (auto t : testCases)
    {
        runTest(t, hlp::getJSONParser);
    }
}
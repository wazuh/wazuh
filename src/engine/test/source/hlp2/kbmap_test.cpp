#include <gtest/gtest.h>

#include "fmt/format.h"
#include "run_test.hpp"
#include <hlp/hlp.hpp>
#include <hlp/parsec.hpp>
#include <json/json.hpp>
#include <string>
#include <vector>

TEST(HLP2, KVParser)
{
    auto fn = [](std::string in) -> json::Json {
        json::Json doc {in.c_str()};
        return doc;
    };

    std::vector<TestCase> testCases {
        TestCase {R"(f1=v1 f2=v2 f3=v3#)", true, "#", Options {" ", "\\", "=", " "}, fn(R"({})"), 2},
    };

    for (auto t : testCases)
    {
        runTest(t, hlp::getKVParser);
    }
}
#include "run_test.hpp"
#include <gtest/gtest.h>
#include <hlp/hlp.hpp>
#include <hlp/parsec.hpp>
#include <json/json.hpp>
#include <string>

TEST(HLP2, ignoreParser)
{

    auto fn = [](std::string in) -> json::Json
    {
        json::Json doc(in.c_str());
        return doc;
    };

    std::vector<TestCase> testCases {
        TestCase {R"(wazuh)", true, {""}, Options {"wazuh"}, fn(R"(null)"), 5},
        TestCase {R"(wazuh 123)", true, {""}, Options {"wazuh"}, fn(R"(null)"), 5},
        TestCase {R"(Wazuh)", true, {""}, Options {"wazuh"}, fn(R"(null)"), 0},
        TestCase {R"(waZuh)", true, {""}, Options {"wazuh"}, fn(R"(null)"), 2},
        TestCase {R"(wazuhwazuh)", true, {""}, Options {"wazuh"}, fn(R"(null)"), 10},
        TestCase {R"(wazuhwa)", true, {""}, Options {"wazuh"}, fn(R"(null)"), 7},
        TestCase {R"(WAZUH)", true, {""}, Options {"wazuh"}, fn(R"(null)"), 0},
        TestCase {R"()", false, {""}, Options {"wazuh"}, fn(R"(null)"), 0},
    };

    for (auto t : testCases)
    {
        runTest(t, hlp::getIgnoreParser);
    }
}

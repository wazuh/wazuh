#include "run_test.hpp"
#include <gtest/gtest.h>
#include <hlp/hlp.hpp>
#include <hlp/parsec.hpp>
#include <json/json.hpp>
#include <string>

TEST(IgnoreParser, build)
{
    // OK
    ASSERT_NO_THROW(hlp::getIgnoreParser({}, {}, {"foo"}));
    // The stop are optional
    ASSERT_NO_THROW(hlp::getIgnoreParser({}, {""}, {"foo"}));

    // Do not allow options
    ASSERT_THROW(hlp::getIgnoreParser({}, {}, {""}), std::runtime_error);
    ASSERT_THROW(hlp::getIgnoreParser({}, {}, {"foo", "bar"}), std::runtime_error);
}

TEST(IgnoreParser, parser)
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
        TestCase {R"()", true, {""}, Options {"wazuh"}, fn(R"(null)"), 0},
        TestCase {R"(wazuh)", false, {""}, Options {""}, fn(R"(null)"), 0}
    };

    for (auto t : testCases)
    {
        runTest(t, hlp::getIgnoreParser);
    }
}

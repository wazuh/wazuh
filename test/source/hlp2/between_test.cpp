#include <optional>
#include <string>
#include <vector>

#include <fmt/format.h>
#include <gtest/gtest.h>

#include <hlp/hlp.hpp>
#include <json/json.hpp>

#include "run_test.hpp"

/************************************
 *  between Parser
 ************************************/

TEST(BetweenParser, build_ok)
{
    ASSERT_NO_THROW(hlp::getBetweenParser({"csv"}, {}, {"start", "end"}));
    ASSERT_NO_THROW(hlp::getBetweenParser({"csv"}, {""}, {"start", "end"}));
}

TEST(BetweenParser, build_fail)
{
    ASSERT_THROW(hlp::getBetweenParser({"csv"}, {""}, {}), std::runtime_error);
    ASSERT_THROW(hlp::getBetweenParser({"csv"}, {""}, {"start"}), std::runtime_error);
    ASSERT_THROW(hlp::getBetweenParser({"csv"}, {""}, {"start", "end", "other"}),
                 std::runtime_error);

    ASSERT_THROW(hlp::getBetweenParser({"csv"}, {""}, {"", ""}), std::runtime_error);
}

TEST(BetweenParser, parser)
{
    auto fn = [](const std::string& in) -> json::Json
    {
        json::Json doc;
        doc.setString(in);
        return doc;
    };

    std::vector<TestCase> testCases {
        TestCase {"[start]value[end]",
                  true,
                  {},
                  Options {"[start]", "[end]"},
                  fn(R"(value)"),
                  17},
        TestCase {"[start][end]", true, {}, Options {"[start]", "[end]"}, fn(R"()"), 12},
        TestCase {"[start]", true, {}, Options {"[start]", ""}, fn(R"()"), 7},
        TestCase {"[end]", true, {}, Options {"", "[end]"}, fn(R"()"), 5},

        TestCase {"[start]value[end] after end",
                  true,
                  {},
                  Options {"[start]", "[end]"},
                  fn(R"(value)"),
                  17},
        TestCase {"[start][end] after end", true, {}, Options {"[start]", "[end]"}, fn(R"()"), 12},
        TestCase {"[start] after end", true, {}, Options {"[start]", ""}, fn(R"()"), 7},
        TestCase {"[end] after end", true, {}, Options {"", "[end]"}, fn(R"()"), 5},

    };
    for (auto t : testCases)
    {
        auto testCase = std::get<0>(t);
        runTest(t, hlp::getBetweenParser);
    }
}

#include <algorithm>
#include <gtest/gtest.h>
#include <rxcpp/rx.hpp>
#include <vector>

#include "builders/output.hpp"
#include "test_utils.hpp"

using namespace builder::internals::builders;

TEST(OutputBuilderTest, Builds)
{
    // Fake entry point
    auto entry_point = observable<>::empty<event_t>();

    // Fake input json
    auto fake_jstring = R"(
    {
      "name": "test_output",
      "parents": [],
      "check": [
        {"field": 1}
      ]
    }
    )";
    json::Document fake_j{fake_jstring};

    ASSERT_NO_THROW(auto obs = outputBuilder(fake_j));
}

TEST(OutputBuilderTest, BuildsErrorNoName)
{
    // Fake entry point
    auto entry_point = observable<>::empty<event_t>();

    // Fake input json
    auto fake_jstring = R"(
    {
      "parents": [],
      "check": [
        {"field": 1}
      ]
    }
    )";
    json::Document fake_j{fake_jstring};

    ASSERT_THROW(auto obs = outputBuilder(fake_j), invalid_argument);
}

TEST(OutputBuilderTest, BuildsErrorNoCheck)
{
    // Fake entry point
    auto entry_point = observable<>::empty<event_t>();

    // Fake input json
    auto fake_jstring = R"(
    {
      "name": "test_output",
      "parents": []
    }
    )";
    json::Document fake_j{fake_jstring};

    ASSERT_THROW(auto obs = outputBuilder(fake_j), invalid_argument);
}

TEST(OutputBuilderTest, OperatesAndConnects)
{
    ASSERT_NO_THROW(throw runtime_error("Test not implemented"));
}

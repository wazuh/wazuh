#include <algorithm>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <iostream>
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
      ],
      "outputs": [
          {"file": {
              "path": "/tmp/file"
          }}
      ]
    }
    )";
    json::Document fake_j{fake_jstring};

    ASSERT_NO_THROW(auto obs = outputBuilder(fake_j));
    std::filesystem::remove("/tmp/file");
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
      ],
      "outputs": [
          {"file": {
              "path": "tmp/file"
          }}
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
      "parents": [],
      "outputs": [
          {"file": {
              "path": "tmp/file"
          }}
      ]
    }
    )";
    json::Document fake_j{fake_jstring};

    ASSERT_THROW(auto obs = outputBuilder(fake_j), invalid_argument);
}

TEST(OutputBuilderTest, BuildsErrorNoOutputs)
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

    ASSERT_THROW(auto obs = outputBuilder(fake_j), invalid_argument);
}

TEST(OutputBuilderTest, BuildsErrorOutputsNotArray)
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
      ],
      "outputs":
          {"file": {
              "path": "tmp/file"
          }}
    }
    )";
    json::Document fake_j{fake_jstring};

    ASSERT_THROW(auto obs = outputBuilder(fake_j), invalid_argument);
}

TEST(OutputBuilderTest, OperatesAndConnects)
{
    // Fake entry point
    observable<event_t> entry_point = observable<>::create<event_t>(
        [](subscriber<event_t> o)
        {
            o.on_next(json::Document{R"(
      {
              "field": 1
      }
  )"});
            o.on_next(json::Document{R"(
      {
              "field": 2
      }
  )"});
            o.on_completed();
        });

    // Fake input json
    auto fake_jstring = R"(
    {
      "name": "test_output",
      "parents": [],
      "check": [
        {"field": 1}
      ],
      "outputs": [
          {
            "file": {
                "path": "/tmp/file"
            }
          }
      ]
    }
    )";
    json::Document fake_j{fake_jstring};

    auto connectable = outputBuilder(fake_j);

    // Fake subscriber
    vector<event_t> observed;
    auto on_next = [&observed](event_t j) { observed.push_back(j); };
    auto on_completed = []() {};
    auto subscriber = make_subscriber<event_t>(on_next, on_completed);

    connectable.output().subscribe(subscriber);
    entry_point.subscribe(connectable.input());

    std::ifstream ifs("/tmp/file");
    std::stringstream buffer;
    ASSERT_EQ(observed.size(), 1);
    for (auto i = 0; i < i; ++i)
    {
        string expected;
        getline(ifs, expected);
        ASSERT_EQ(observed[i].str(), expected);
    }

    // std::filesystem::remove("/tmp/file");
}

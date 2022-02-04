#include <algorithm>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <iostream>
#include <rxcpp/rx.hpp>
#include <vector>

#include "builders/buildOutput.hpp"
#include "test_utils.hpp"

using namespace builder::internals::builders;

TEST(FileOutputBuilderTest, Builds)
{
    // Fake input json
    auto fake_jstring = R"(
    {
        "file": {
            "path": "/tmp/file"
        }
    }
    )";
    json::Document fake_j{fake_jstring};

    // Builds
    ASSERT_NO_THROW(buildFileOutput(fake_j.get(".file")));
    std::filesystem::remove("/tmp/file");
}

TEST(FileOutputBuilderTest, BuildsErrorNotObject)
{
    // Fake input json
    auto fake_jstring = R"(
    {
        "file": [{
            "path": "/tmp/file"
        }]
    }
    )";
    json::Document fake_j{fake_jstring};

    // Builds
    ASSERT_THROW(buildFileOutput(fake_j.get(".file")), invalid_argument);
}

TEST(FileOutputBuilderTest, BuildsErrorMemberCount)
{
    // Fake input json
    auto fake_jstring = R"(
    {
        "file": {
            "path": "/tmp/file",
            "morethanone": "value"
        }
    }
    )";
    json::Document fake_j{fake_jstring};

    // Builds
    ASSERT_THROW(buildFileOutput(fake_j.get(".file")), invalid_argument);
}

TEST(FileOutputBuilderTest, BuildsErrorNoPath)
{
    // Fake input json
    auto fake_jstring = R"(
    {
        "file": {
            "pathwrong": "/tmp/file"
        }
    }
    )";
    json::Document fake_j{fake_jstring};

    // Builds
    ASSERT_THROW(buildFileOutput(fake_j.get(".file")), invalid_argument);
}

TEST(FileOutputBuilderTest, BuildsErrorIncorrectPath)
{
    // Fake input json
    auto fake_jstring = R"(
    {
        "file": {
            "path": "tmp/file"
        }
    }
    )";
    json::Document fake_j{fake_jstring};

    // Builds
    ASSERT_THROW(buildFileOutput(fake_j.get(".file")), invalid_argument);
}

TEST(FileOutputBuilderTest, Operates)
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
            o.on_next(json::Document{R"(
      {
              "field": 3
      }
  )"});

            o.on_completed();
        });

    // Fake input json
    auto fake_jstring = R"(
    {
        "file": {
            "path": "/tmp/file"
        }
    }
    )";
    json::Document fake_j{fake_jstring};

    // Builds
    auto op = buildFileOutput(fake_j.get(".file"));

    // Fake subscriber
    vector<event_t> observed;
    auto on_next = [&observed](event_t j) { observed.push_back(j); };
    auto on_completed = []() {};
    auto subscriber = make_subscriber<event_t>(on_next, on_completed);

    op(entry_point).subscribe(subscriber);
    
    std::ifstream ifs("/tmp/file");
    std::stringstream buffer;
    ASSERT_EQ(observed.size(), 3);
    for (auto i = 0; i < 3; ++i)
    {
        string expected;
        getline(ifs, expected);
        ASSERT_EQ(observed[i].str(), expected);
    }

    std::filesystem::remove("/tmp/file");
}

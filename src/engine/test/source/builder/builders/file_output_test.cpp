#include <algorithm>
#include <gtest/gtest.h>
#include <rxcpp/rx.hpp>
#include <vector>

#include "builders/file_output.hpp"
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
    ASSERT_NO_THROW(auto fileOutput = fileOutputBuilder(fake_j.get(".file")));
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
    ASSERT_THROW(auto fileOutput = fileOutputBuilder(fake_j.get(".file")), invalid_argument);
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
    ASSERT_THROW(auto fileOutput = fileOutputBuilder(fake_j.get(".file")), invalid_argument);
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
    ASSERT_THROW(auto fileOutput = fileOutputBuilder(fake_j.get(".file")), invalid_argument);
}

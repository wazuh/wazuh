#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <vector>

#include "baseTypes.hpp"
#include "builder/builders/opBuilderFileOutput.hpp"
#include <fmt/format.h>

using namespace builder::internals::builders;
using namespace base;
using namespace json;

constexpr auto FILE_PATH = "/tmp/file";

class OpBuilderFileOutputTest : public ::testing::Test
{
    void SetUp() override
    {
        if (std::filesystem::exists(FILE_PATH))
        {
            std::filesystem::remove(FILE_PATH);
        }
    }

    void TearDown() override
    {
        if (std::filesystem::exists(FILE_PATH))
        {
            std::filesystem::remove(FILE_PATH);
        }
    }
};

TEST_F(OpBuilderFileOutputTest, Builds)
{
    Json doc {fmt::format("{{\"path\": \"{}\"}}", FILE_PATH).c_str()};

    ASSERT_NO_THROW(opBuilderFileOutput(doc));
}

TEST_F(OpBuilderFileOutputTest, NotJson)
{
    ASSERT_THROW(opBuilderFileOutput(1), std::runtime_error);
}

TEST_F(OpBuilderFileOutputTest, NotObject)
{
    Json doc {fmt::format("[{{\"path\": \"{}\"}}]", FILE_PATH).c_str()};

    ASSERT_THROW(opBuilderFileOutput(doc), std::runtime_error);
}

TEST_F(OpBuilderFileOutputTest, WrongObjectSize)
{
    Json doc {fmt::format("{{\"path\": \"{}\", \"other\":1}}", FILE_PATH).c_str()};

    ASSERT_THROW(opBuilderFileOutput(doc), std::runtime_error);
}

TEST_F(OpBuilderFileOutputTest, BuildsCorrectExpression)
{
    Json doc {fmt::format("{{\"path\": \"{}\"}}", FILE_PATH).c_str()};

    auto expression = opBuilderFileOutput(doc);
    ASSERT_TRUE(expression->isTerm());
}

TEST_F(OpBuilderFileOutputTest, BuildsOperates)
{
    Json doc {fmt::format("{{\"path\": \"{}\"}}", FILE_PATH).c_str()};

    auto expression = opBuilderFileOutput(doc)->getPtr<Term<EngineOp>>();
    auto op = expression->getFn();

    for (auto event : std::vector<Json> {5, Json {R"({"field":"value"})"}})
    {
        ASSERT_NO_THROW(op(std::make_shared<Json>(event)));
    }

    std::string expected = R"({"field":"value"}
{"field":"value"}
{"field":"value"}
{"field":"value"}
{"field":"value"}
)";

    std::string filepath {FILE_PATH};
    std::ifstream ifs(FILE_PATH);
    std::stringstream buffer;
    buffer << ifs.rdbuf();

    ASSERT_EQ(expected, buffer.str());
}

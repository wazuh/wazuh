#include <filesystem>
#include <gtest/gtest.h>
#include <iostream>
#include <json/json.hpp>
#include <limits>
#include <string>
#include <utilsYml.hpp>

#include "rapidjson/prettywriter.h"

constexpr auto FILE_PATH {"test/source/dataStruct/yml/testFile.yml"};

class UtilsYmlTest : public ::testing::Test
{
};

TEST_F(UtilsYmlTest, ParseScalarTestAllocator)
{
    YAML::Node quotedStringNode = YAML::Node(utilsYml::QUOTED_TAG);
    quotedStringNode = "hello";
    YAML::Node intNode(42);
    YAML::Node doubleNode(3.14);
    YAML::Node boolNode(true);
    YAML::Node stringNode("world");
    YAML::Node invalidNode;

    rapidjson::Document::AllocatorType allocator;

    auto quotedStringResult = utilsYml::Converter::parse_scalar(quotedStringNode, allocator);
    auto intResult = utilsYml::Converter::parse_scalar(intNode, allocator);
    auto doubleResult = utilsYml::Converter::parse_scalar(doubleNode, allocator);
    auto boolResult = utilsYml::Converter::parse_scalar(boolNode, allocator);
    auto stringResult = utilsYml::Converter::parse_scalar(stringNode, allocator);
    auto invalidResult = utilsYml::Converter::parse_scalar(invalidNode, allocator);

    EXPECT_TRUE(quotedStringResult.IsString());
    EXPECT_STREQ(quotedStringResult.GetString(), "hello");
    EXPECT_TRUE(intResult.IsInt());
    EXPECT_EQ(intResult.GetInt(), 42);
    EXPECT_TRUE(doubleResult.IsDouble());
    EXPECT_EQ(doubleResult.GetDouble(), 3.14);
    EXPECT_TRUE(boolResult.IsBool());
    EXPECT_EQ(boolResult.GetBool(), true);
    EXPECT_TRUE(stringResult.IsString());
    EXPECT_STREQ(stringResult.GetString(), "world");
    EXPECT_TRUE(invalidResult.IsNull());
}

TEST_F(UtilsYmlTest, ParseScalarTest)
{
    rapidjson::Value stringNode("hello");
    rapidjson::Value intNode(42);
    rapidjson::Value doubleNode(3.14);
    rapidjson::Value boolNode(true);
    rapidjson::Value invalidNode;

    auto stringResult = utilsYml::Converter::parse_scalar(stringNode);
    auto intResult = utilsYml::Converter::parse_scalar(intNode);
    auto doubleResult = utilsYml::Converter::parse_scalar(doubleNode);
    auto boolResult = utilsYml::Converter::parse_scalar(boolNode);
    auto invalidResult = utilsYml::Converter::parse_scalar(invalidNode);

    EXPECT_EQ(stringResult.Scalar(), "hello");
    EXPECT_EQ(intResult.as<int>(), 42);
    EXPECT_EQ(doubleResult.as<double>(), 3.14);
    EXPECT_EQ(boolResult.as<bool>(), true);
    EXPECT_TRUE(invalidResult.IsNull());
}

TEST_F(UtilsYmlTest, JsonToYamlTest)
{
    const char* jsonString = R"({
        "person": {
            "name": "John",
            "age": 30,
            "address": {
                "street": "123 Main St",
                "city": "New York"
            }
        },
        "colors": ["red", "green", "blue"]
    })";

    rapidjson::Document document;
    document.Parse(jsonString);

    auto resultNode = utilsYml::Converter::json2yaml(document);

    YAML::Emitter resultEmitter;
    YAML::Emitter expectedEmitter;

    resultEmitter << resultNode;
    expectedEmitter << YAML::Load(R"(
        person:
            name: "John"
            age: 30
            address:
                street: "123 Main St"
                city: "New York"
        colors:
            - red
            - green
            - blue
    )");

    auto resultYaml = resultEmitter.c_str();
    auto expectedYaml = expectedEmitter.c_str();

    EXPECT_STREQ(resultYaml, expectedYaml);
}

TEST_F(UtilsYmlTest, YamlToJsonTest)
{
    const char* yamlStr = R"(
        person:
          name: John
          age: 30
          address:
            street: 123 Main St
            city: New York
        colors:
          - red
          - green
          - blue
    )";

    auto yamlNode = YAML::Load(yamlStr);

    rapidjson::Document document;
    auto& allocator = document.GetAllocator();

    const auto& resultValue = utilsYml::Converter::yaml2json(yamlNode, allocator);

    rapidjson::Document resultValueDocument;
    resultValueDocument.CopyFrom(resultValue, resultValueDocument.GetAllocator());
    auto result = json::Json {std::move(resultValueDocument)};

    const char* expectedJsonStr = R"({
        "person": {
            "name": "John",
            "age": 30,
            "address": {
                "street": "123 Main St",
                "city": "New York"
            }
        },
        "colors": [
            "red",
            "green",
            "blue"
        ]
    })";

    auto expected = json::Json {expectedJsonStr};

    EXPECT_TRUE(expected == result);
}

TEST_F(UtilsYmlTest, LoadYMLfromStringTest)
{
    std::string yamlStr = R"(
        person:
            name: John
            age: 30
            address:
                street: 123 Main St
                city: New York
        colors:
            - red
            - green
            - blue
    )";

    const char* expectedJsonStr = R"(
        {
            "person": {
                "name": "John",
                "age": 30,
                "address": {
                    "street": "123 Main St",
                    "city": "New York"
                }
            },
            "colors": ["red", "green", "blue"]
        }
    )";

    auto resultValue = utilsYml::Converter::loadYMLfromString(yamlStr);
    rapidjson::Document resultValueDocument;
    resultValueDocument.CopyFrom(resultValue, resultValueDocument.GetAllocator());
    auto result = json::Json {std::move(resultValueDocument)};

    auto expected = json::Json {expectedJsonStr};
    EXPECT_TRUE(expected == result);
}

TEST_F(UtilsYmlTest, LoadYMLfromFileTest)
{
    std::filesystem::path currentPath = std::filesystem::current_path();

    while (!currentPath.empty())
    {
        if (currentPath.filename() == "engine")
        {
            break;
        }

        currentPath = currentPath.parent_path();
    }

    auto testFilepath = currentPath / FILE_PATH;
    auto resultValue = utilsYml::Converter::loadYMLfromFile(testFilepath);
    rapidjson::Document resultValueDocument;
    resultValueDocument.CopyFrom(resultValue, resultValueDocument.GetAllocator());
    auto result = json::Json {std::move(resultValueDocument)};

    const char* expectedJsonStr = R"(
        {
            "person": {
                "name": "John",
                "age": 30,
                "address": {
                    "street": "123 Main St",
                    "city": "New York"
                }
            },
            "colors": ["red", "green", "blue"]
        }
    )";

    auto expected = json::Json {expectedJsonStr};
    EXPECT_TRUE(expected == result);
}

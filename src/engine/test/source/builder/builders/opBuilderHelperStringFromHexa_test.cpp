#include <any>
#include <gtest/gtest.h>
#include <vector>

#include <baseTypes.hpp>

#include "opBuilderHelperMap.hpp"

using namespace base;
using namespace builder::internals::builders;

const std::string helperFunctionName {"decode_base16"};

const std::string targetField {"/output"};

TEST(opBuilderHelperStringFromHexa, build)
{
    const std::vector<std::string> arguments {"$dummy"};
    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    ASSERT_NO_THROW(opBuilderHelperStringFromHexa(tuple));
}

TEST(opBuilderHelperStringFromHexa, buildNoArgumentsError)
{
    const std::vector<std::string> arguments {};
    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    ASSERT_THROW(opBuilderHelperStringFromHexa(tuple), std::runtime_error);
}

TEST(opBuilderHelperStringFromHexa, buildNoTargetError)
{
    const std::vector<std::string> arguments {};
    const auto tuple = std::make_tuple("", helperFunctionName, arguments);

    ASSERT_THROW(opBuilderHelperStringFromHexa(tuple), std::runtime_error);
}

TEST(opBuilderHelperStringFromHexa, buildNoHelperFunctionError)
{
    const std::vector<std::string> arguments {};
    const auto tuple = std::make_tuple(targetField, "", arguments);

    ASSERT_THROW(opBuilderHelperStringFromHexa(tuple), std::runtime_error);
}

TEST(opBuilderHelperStringFromHexa, buildHexaValueError)
{
    const std::vector<std::string> arguments {"48656C6C6F20776F726C6421"};
    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    ASSERT_THROW(opBuilderHelperStringFromHexa(tuple), std::runtime_error);
}

TEST(opBuilderHelperStringFromHexa, hexaReference)
{
    const std::vector<std::string> arguments {"$sourceField"};
    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    auto event =
        std::make_shared<json::Json>(R"({"sourceField": "48656C6C6F20776F726C6421"})");

    auto op = opBuilderHelperStringFromHexa(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result);

    ASSERT_EQ("Hello world!", result.payload()->getString("/output").value());
}

TEST(opBuilderHelperStringFromHexa, invalidHexaReference)
{
    const std::vector<std::string> arguments {"$sourceField"};
    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    auto event =
        std::make_shared<json::Json>(R"({"sourceField": "48656C6C6F20X776F726C6421"})");

    auto op = opBuilderHelperStringFromHexa(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result);
}

TEST(opBuilderHelperStringFromHexa, allThePrintableCharacters)
{
    const std::vector<std::string> arguments {"$sourceField"};
    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    auto event =
        std::make_shared<json::Json>("{\"sourceField\": "
                                     "\"202122232425262728292A2B2C2D2E2F30313233343536373"
                                     "8393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F5051"
                                     "52535455565758595A5B5C5D5E5F606162636465666768696A6"
                                     "B6C6D6E6F707172737475767778797A7B7C7D7E\"}");

    auto op = opBuilderHelperStringFromHexa(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result);

    ASSERT_EQ(" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`"
              "abcdefghijklmnopqrstuvwxyz{|}~",
              result.payload()->getString("/output").value());
}

TEST(opBuilderHelperStringFromHexa, emptyString)
{
    const std::vector<std::string> arguments {"$sourceField"};
    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    auto event = std::make_shared<json::Json>("{\"sourceField\": "
                                              "\"\"}");

    auto op = opBuilderHelperStringFromHexa(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result);

    ASSERT_STREQ("", result.payload()->getString("/output").value().data());
}

TEST(opBuilderHelperStringFromHexa, fieldNotAString)
{
    const std::vector<std::string> arguments {"$sourceField"};
    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    auto event = std::make_shared<json::Json>("{\"sourceField\": 123456}");

    auto op = opBuilderHelperStringFromHexa(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result);

    ASSERT_FALSE(result.payload()->exists("/output"));
}

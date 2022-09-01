#include <any>
#include <gtest/gtest.h>
#include <vector>

#include <baseTypes.hpp>

#include "opBuilderHelperMap.hpp"

using namespace base;
using namespace builder::internals::builders;

const std::string targetField {"/output"};
const std::string helperFunctionName {"s_fromHexa"};

TEST(opBuilderHelperStringFromHexa, build)
{
    const std::vector<std::string> arguments {"48656C6C6F20776F726C6421"};
    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    ASSERT_NO_THROW(opBuilderHelperStringFromHexa(tuple));
}

TEST(opBuilderHelperStringFromHexa, test)
{
    const std::vector<std::string> arguments {"$sourceField"};
    const auto tuple = std::make_tuple(targetField, helperFunctionName, arguments);

    auto event =
        std::make_shared<json::Json>(R"({"sourceField": "48656C6C6F20776F726C6421"})");

    auto op = opBuilderHelperStringFromHexa(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);

    ASSERT_TRUE(result);

    std::cout << result.payload()->prettyStr() << std::endl;

    ASSERT_EQ("Hello world!", result.payload()->getString("/output").value());
}

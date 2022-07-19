#include <gtest/gtest.h>

#include "baseTypes.hpp"
#include "builder/builders/operationBuilder.hpp"
#include "builder/builders/stageBuilderMap.hpp"
#include "builder/registry.hpp"
#include <json/json.hpp>

using namespace builder::internals;
using namespace builder::internals::builders;
using namespace json;
using namespace base;

#define GTEST_COUT std::cout << "[          ] [ INFO ] "

class StageBuilderMapTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        Registry::registerBuilder(operationMapBuilder, "operation.map");
    }
    void TearDown() override
    {
        Registry::clear();
    }
};

TEST_F(StageBuilderMapTest, Builds)
{
    auto mapJson = Json {R"({
        "string": "value",
        "int": 1,
        "double": 1.0,
        "boolT": true,
        "boolF": false,
        "null": null,
        "array": [1, 2, 3],
        "object": {"a": 1, "b": 2}
})"};

    ASSERT_NO_THROW(stageMapBuilder(mapJson));
}

TEST_F(StageBuilderMapTest, UnexpectedDefinition)
{
    auto mapJson = Json {R"([])"};

    ASSERT_THROW(stageMapBuilder(mapJson), std::runtime_error);
}

TEST_F(StageBuilderMapTest, BuildsCorrectExpression)
{
    auto mapJson = Json {R"({
        "string": "value",
        "int": 1,
        "double": 1.0,
        "boolT": true,
        "boolF": false,
        "null": null,
        "array": [1, 2, 3],
        "object": {"a": 1, "b": 2}
})"};

    auto expression = stageMapBuilder(mapJson);

    ASSERT_TRUE(expression->isOperation());
    ASSERT_TRUE(expression->isChain());
    for (auto term : expression->getPtr<Chain>()->getOperands())
    {
        ASSERT_TRUE(term->isTerm());
    }
}

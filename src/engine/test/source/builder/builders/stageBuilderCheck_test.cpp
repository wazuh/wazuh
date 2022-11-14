#include <gtest/gtest.h>

#include "baseTypes.hpp"
#include "builder/builders/operationBuilder.hpp"
#include "builder/builders/stageBuilderCheck.hpp"
#include "builder/registry.hpp"
#include <json/json.hpp>

using namespace builder::internals;
using namespace builder::internals::builders;
using namespace json;
using namespace base;

#define GTEST_COUT std::cout << "[          ] [ INFO ] "

TEST(StageBuilderCheckTest, ListBuilds)
{
    auto registry = std::make_shared<Registry>();
    registry->registerBuilder(getOperationConditionBuilder(registry),
                              "operation.condition");
    auto checkJson = Json {R"([
        {"string": "value"},
        {"int": 1},
        {"double": 1.0},
        {"boolT": true},
        {"boolF": false},
        {"null": null},
        {"array": [1, 2, 3]},
        {"object": {"a": 1, "b": 2}}
])"};

    ASSERT_NO_THROW(getStageBuilderCheck(registry)(checkJson));
}

TEST(StageBuilderCheckTest, UnexpectedDefinition)
{
    auto registry = std::make_shared<Registry>();
    registry->registerBuilder(getOperationConditionBuilder(registry),
                              "operation.condition");
    auto checkJson = Json {R"({})"};

    ASSERT_THROW(getStageBuilderCheck(registry)(checkJson), std::runtime_error);
}

TEST(StageBuilderCheckTest, ListArrayWrongSizeItem)
{
    auto registry = std::make_shared<Registry>();
    registry->registerBuilder(getOperationConditionBuilder(registry),
                              "operation.condition");
    auto checkJson = Json {R"([
        {"string": "value"},
        {"int": 1},
        {"double": 1.0,
        "boolT": true},
        {"boolT": true},
        {"boolF": false},
        {"null": null},
        {"array": [1, 2, 3]},
        {"object": {"a": 1, "b": 2}}
])"};

    ASSERT_THROW(getStageBuilderCheck(registry)(checkJson), std::runtime_error);
}

TEST(StageBuilderCheckTest, ListArrayWrongTypeItem)
{
    auto registry = std::make_shared<Registry>();
    registry->registerBuilder(getOperationConditionBuilder(registry),
                              "operation.condition");
    auto checkJson = Json {R"([
        ["string", "value"]
])"};

    ASSERT_THROW(getStageBuilderCheck(registry)(checkJson), std::runtime_error);
}

TEST(StageBuilderCheckTest, ListBuildsCorrectExpression)
{
    auto registry = std::make_shared<Registry>();
    registry->registerBuilder(getOperationConditionBuilder(registry),
                              "operation.condition");
    auto checkJson = Json {R"([
        {"string": "value"},
        {"int": 1},
        {"double": 1.0},
        {"boolT": true},
        {"boolF": false},
        {"null": null},
        {"array": [1, 2, 3]},
        {"object": {"a": 1, "b": 2}}
])"};

    auto expression = getStageBuilderCheck(registry)(checkJson);

    ASSERT_TRUE(expression->isOperation());
    ASSERT_TRUE(expression->isAnd());
    for (auto term : expression->getPtr<And>()->getOperands())
    {
        ASSERT_TRUE(term->isTerm() || term->isAnd());
    }
}

TEST(StageBuilderCheckTest, ExpressionBuilds)
{
    auto registry = std::make_shared<Registry>();
    registry->registerBuilder(getOperationConditionBuilder(registry),
                              "operation.condition");
    auto checkJson = Json {R"("field==value")"};

    ASSERT_NO_THROW(getStageBuilderCheck(registry)(checkJson));
}

TEST(StageBuilderCheckTest, ExpressionBuildsCorrectExpression)
{
    auto registry = std::make_shared<Registry>();
    registry->registerBuilder(getOperationConditionBuilder(registry),
                              "operation.condition");
    auto checkJson = Json {R"("field==value")"};

    auto expression = getStageBuilderCheck(registry)(checkJson);

    ASSERT_TRUE(expression->isTerm());
}

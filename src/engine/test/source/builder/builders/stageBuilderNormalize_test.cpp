#include <gtest/gtest.h>

#include "baseTypes.hpp"
#include "builder/builders/operationBuilder.hpp"
#include "builder/builders/stageBuilderCheck.hpp"
#include "builder/builders/stageBuilderMap.hpp"
#include "builder/builders/stageBuilderNormalize.hpp"
#include "builder/registry.hpp"
#include <json/json.hpp>

using namespace builder::internals;
using namespace builder::internals::builders;
using namespace json;
using namespace base;

#define GTEST_COUT std::cout << "[          ] [ INFO ] "

auto initTest()
{
    auto registry = std::make_shared<Registry>();
    registry->registerBuilder(getOperationConditionBuilder(registry),
                              "operation.condition");
    registry->registerBuilder(getOperationMapBuilder(registry), "operation.map");
    registry->registerBuilder(getStageBuilderCheck(registry), "stage.check");
    registry->registerBuilder(getStageMapBuilder(registry), "stage.map");
    return registry;
}

TEST(StageBuilderNormalizeTest, Builds)
{
    auto registry = initTest();
    auto normalizeJson = Json {R"([
        {"map": [
            {"string": "value"},
            {"int": 1},
            {"double": 1.0},
            {"boolT": true},
            {"boolF": false},
            {"null": null},
            {"array": [1, 2, 3]},
            {"object": {"a": 1, "b": 2}}
        ]},
        {"check": [
            {"string": "value"},
            {"int": 1},
            {"double": 1.0},
            {"boolT": true},
            {"boolF": false},
            {"null": null},
            {"array": [1, 2, 3]},
            {"object": {"a": 1, "b": 2}}
        ],
        "map": [
            {"stringCond": "value"},
            {"intCond": 1},
            {"doubleCond": 1.0},
            {"boolTCond": true},
            {"boolFCond": false},
            {"nullCond": null},
            {"arrayCond": [1, 2, 3]},
            {"objectCond": {"a": 1, "b": 2}}
        ]}
])"};

    ASSERT_NO_THROW(getStageNormalizeBuilder(registry)(normalizeJson));
}

TEST(StageBuilderNormalizeTest, UnexpectedDefinition)
{
    auto registry = initTest();
    auto normalizeJson = Json {R"({})"};

    ASSERT_THROW(getStageNormalizeBuilder(registry)(normalizeJson), std::runtime_error);
}

TEST(StageBuilderNormalizeTest, ArrayWrongTypeItem)
{
    auto registry = initTest();
    auto normalizeJson = Json {R"([
        ["string", "value"]
])"};

    ASSERT_THROW(getStageNormalizeBuilder(registry)(normalizeJson), std::runtime_error);
}

TEST(StageBuilderNormalizeTest, BuildsCorrectExpression)
{
    auto registry = initTest();
    auto normalizeJson = Json {R"([
        {"map": [
            {"string": "value"},
            {"int": 1},
            {"double": 1.0},
            {"boolT": true},
            {"boolF": false},
            {"null": null},
            {"array": [1, 2, 3]},
            {"object": {"a": 1, "b": 2}}
        ]},
        {"check": [
            {"string": "value"},
            {"int": 1},
            {"double": 1.0},
            {"boolT": true},
            {"boolF": false},
            {"null": null},
            {"array": [1, 2, 3]},
            {"object": {"a": 1, "b": 2}}
        ],
        "map": [
            {"stringCond": "value"},
            {"intCond": 1},
            {"doubleCond": 1.0},
            {"boolTCond": true},
            {"boolFCond": false},
            {"nullCond": null},
            {"arrayCond": [1, 2, 3]},
            {"objectCond": {"a": 1, "b": 2}}
        ]}
])"};

    auto expression = getStageNormalizeBuilder(registry)(normalizeJson);

    ASSERT_TRUE(expression->isOperation());
    ASSERT_TRUE(expression->isChain());

    auto chain = expression->getPtr<Chain>();
    ASSERT_EQ(chain->getOperands().size(), 2);

    auto map = chain->getOperands()[0];
    ASSERT_TRUE(map->isOperation());
    ASSERT_TRUE(map->isAnd());

    auto conditionalMap = chain->getOperands()[1];
    ASSERT_TRUE(conditionalMap->isOperation());
    ASSERT_TRUE(conditionalMap->isAnd());
}

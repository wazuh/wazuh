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

class StageBuilderCheckTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        Registry::registerBuilder(operationConditionBuilder, "operation.condition");
    }
    void TearDown() override
    {
        Registry::clear();
    }
};

TEST_F(StageBuilderCheckTest, ListBuilds)
{
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

    ASSERT_NO_THROW(stageBuilderCheck(checkJson));
}

TEST_F(StageBuilderCheckTest, UnexpectedDefinition)
{
    auto checkJson = Json {R"({})"};

    ASSERT_THROW(stageBuilderCheck(checkJson), std::runtime_error);
}

TEST_F(StageBuilderCheckTest, ListArrayWrongSizeItem)
{
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

    ASSERT_THROW(stageBuilderCheck(checkJson), std::runtime_error);
}

TEST_F(StageBuilderCheckTest, ListArrayWrongTypeItem)
{
    auto checkJson = Json {R"([
        ["string", "value"]
])"};

    ASSERT_THROW(stageBuilderCheck(checkJson), std::runtime_error);
}

TEST_F(StageBuilderCheckTest, ListBuildsCorrectExpression)
{
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

    auto expression = stageBuilderCheck(checkJson);

    ASSERT_TRUE(expression->isOperation());
    ASSERT_TRUE(expression->isAnd());
    for (auto term : expression->getPtr<And>()->getOperands())
    {
        ASSERT_TRUE(term->isTerm());
    }
}

TEST_F(StageBuilderCheckTest, ExpressionBuilds)
{
    auto checkJson = Json {R"("field==value")"};

    ASSERT_NO_THROW(stageBuilderCheck(checkJson));
}

TEST_F(StageBuilderCheckTest, ExpressionBuildsCorrectExpression)
{
    auto checkJson = Json {R"("field==value")"};

    auto expression = stageBuilderCheck(checkJson);

    ASSERT_TRUE(expression->isTerm());
}

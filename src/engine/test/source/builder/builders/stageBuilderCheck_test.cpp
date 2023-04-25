#include <gtest/gtest.h>

#include "baseTypes.hpp"
#include "builder/builders/opBuilderHelperFilter.hpp"
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
        registry = std::make_shared<Registry<builder::internals::Builder>>();
        auto helperRegistry = std::make_shared<Registry<builder::internals::HelperBuilder>>();
        registry->registerBuilder(getOperationConditionBuilder(helperRegistry),
                                  "operation.condition");
    }

    std::shared_ptr<Registry<builder::internals::Builder>> registry;
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

    ASSERT_NO_THROW(getStageBuilderCheck(registry)(checkJson));
}

TEST_F(StageBuilderCheckTest, UnexpectedDefinition)
{
    auto checkJson = Json {R"({})"};

    ASSERT_THROW(getStageBuilderCheck(registry)(checkJson), std::runtime_error);
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

    ASSERT_THROW(getStageBuilderCheck(registry)(checkJson), std::runtime_error);
}

TEST_F(StageBuilderCheckTest, ListArrayWrongTypeItem)
{
    auto checkJson = Json {R"([
        ["string", "value"]
    ])"};

    ASSERT_THROW(getStageBuilderCheck(registry)(checkJson), std::runtime_error);
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

    auto expression = getStageBuilderCheck(registry)(checkJson);

    ASSERT_TRUE(expression->isOperation());
    ASSERT_TRUE(expression->isAnd());
    for (auto term : expression->getPtr<And>()->getOperands())
    {
        ASSERT_TRUE(term->isTerm() || term->isAnd());
    }
}

TEST_F(StageBuilderCheckTest, ExpressionEqualOperator)
{
    auto checkJson = Json {R"("field==value")"};

    ASSERT_NO_THROW(getStageBuilderCheck(registry)(checkJson));
}

TEST_F(StageBuilderCheckTest, ExpressionNotEqualOperator)
{
    auto checkJson = Json {R"("field!=value")"};

    ASSERT_NO_THROW(getStageBuilderCheck(registry)(checkJson));
}

class StageBuilderCheckHelperOperatorsTest
    : public ::testing::TestWithParam<std::tuple<std::string, std::string, std::function<Expression(const std::any&)>>>
{
protected:
    void SetUp() override
    {
        registry = std::make_shared<Registry<builder::internals::Builder>>();
        auto helperRegistry = std::make_shared<Registry<builder::internals::HelperBuilder>>();
        registry->registerBuilder(getOperationConditionBuilder(helperRegistry),
                                  "operation.condition");
    }

    std::shared_ptr<Registry<builder::internals::Builder>> registry;
};

TEST_P(StageBuilderCheckHelperOperatorsTest, CheckExpressionOperator)
{
    auto [expression, builderName, registerBuilder] = GetParam();

    auto checkJson = Json {expression.c_str()};

    registry->registerBuilder(registerBuilder, builderName);
    ASSERT_NO_THROW(getStageBuilderCheck(registry)(checkJson));
}

INSTANTIATE_TEST_SUITE_P(
    CheckExpressionOperator,
    StageBuilderCheckHelperOperatorsTest,
    ::testing::Values(
        std::make_tuple(R"("field<\"value\"")", "helper.string_less", opBuilderHelperStringLessThan),
        std::make_tuple(R"("field<=\"value\"")", "helper.string_less_or_equal", opBuilderHelperStringLessThanEqual),
        std::make_tuple(R"("field>\"value\"")", "helper.string_greater", opBuilderHelperStringGreaterThan),
        std::make_tuple(R"("field>=\"value\"")",
                        "helper.string_greater_or_equal",
                        opBuilderHelperStringGreaterThanEqual),
        std::make_tuple(R"("field<3")", "helper.int_less", opBuilderHelperIntLessThan),
        std::make_tuple(R"("field<=3")", "helper.int_less_or_equal", opBuilderHelperIntLessThanEqual),
        std::make_tuple(R"("field>3")", "helper.int_greater", opBuilderHelperIntGreaterThan),
        std::make_tuple(R"("field>=3")", "helper.int_greater_or_equal", opBuilderHelperIntGreaterThanEqual)));

class StageBuilderCheckInvalidOperatorsTest : public testing::TestWithParam<std::tuple<Json, std::string>>
{
protected:
    void SetUp() override
    {
        registry = std::make_shared<Registry<builder::internals::Builder>>();
        auto helperRegistry = std::make_shared<Registry<builder::internals::HelperBuilder>>();
        registry->registerBuilder(getOperationConditionBuilder(helperRegistry),
                                  "operation.condition");
    }

    std::shared_ptr<Registry<builder::internals::Builder>> registry;
};

TEST_P(StageBuilderCheckInvalidOperatorsTest, InvalidValuesInField)
{
    auto [checkJson, errorMsg] = GetParam();

    try
    {
        getStageBuilderCheck(registry)(checkJson);
    }
    catch (const std::runtime_error& e)
    {
        EXPECT_STREQ(errorMsg.c_str(), e.what());
    }
}

INSTANTIATE_TEST_SUITE_P(
    InvalidValuesInField,
    StageBuilderCheckInvalidOperatorsTest,
    testing::Values(std::make_tuple(Json {R"("field>{\"key\":\"value\"}")"},
                                    "Check stage: The \">\" operator only allows operate with numbers or string"),
                    std::make_tuple(Json {R"("field>[\"value1\",\"value2\"]")"},
                                    "Check stage: The \">\" operator only allows operate with numbers or string"),
                    std::make_tuple(Json {R"("field>false")"},
                                    "Check stage: The \">\" operator only allows operate with numbers or string"),
                    std::make_tuple(Json {R"("field>null")"},
                                    "Check stage: The \">\" operator only allows operate with numbers or string"),
                    std::make_tuple(Json {R"("field<{\"key\":\"value\"}")"},
                                    "Check stage: The \"<\" operator only allows operate with numbers or string"),
                    std::make_tuple(Json {R"("field<[\"value1\",\"value2\"]")"},
                                    "Check stage: The \"<\" operator only allows operate with numbers or string"),
                    std::make_tuple(Json {R"("field<false")"},
                                    "Check stage: The \"<\" operator only allows operate with numbers or string"),
                    std::make_tuple(Json {R"("field<null")"},
                                    "Check stage: The \"<\" operator only allows operate with numbers or string"),
                    std::make_tuple(Json {R"("field<={\"key\":\"value\"}")"},
                                    "Check stage: The \"<=\" operator only allows operate with numbers or string"),
                    std::make_tuple(Json {R"("field<=[\"value1\",\"value2\"]")"},
                                    "Check stage: The \"<=\" operator only allows operate with numbers or string"),
                    std::make_tuple(Json {R"("field<=false")"},
                                    "Check stage: The \"<=\" operator only allows operate with numbers or string"),
                    std::make_tuple(Json {R"("field<=null")"},
                                    "Check stage: The \"<=\" operator only allows operate with numbers or string"),
                    std::make_tuple(Json {R"("field>={\"key\":\"value\"}")"},
                                    "Check stage: The \">=\" operator only allows operate with numbers or string"),
                    std::make_tuple(Json {R"("field>=[\"value1\",\"value2\"]")"},
                                    "Check stage: The \">=\" operator only allows operate with numbers or string"),
                    std::make_tuple(Json {R"("field>=false")"},
                                    "Check stage: The \">=\" operator only allows operate with numbers or string"),
                    std::make_tuple(Json {R"("field>=null")"},
                                    "Check stage: The \">=\" operator only allows operate with numbers or string")));

TEST_F(StageBuilderCheckTest, InvalidOperator)
{
    auto checkJson = Json {R"("field$value")"};

    try
    {
        getStageBuilderCheck(registry)(checkJson);
    }
    catch (const std::runtime_error& e)
    {
        EXPECT_STREQ("Check stage: Invalid operator \"field$value\"", e.what());
    }
}

TEST_F(StageBuilderCheckTest, ObjectIntoObject)
{
    auto checkJson = Json {R"("field=={\"key\":\"value\",\"key2\":{\"key3\":\"value3\"")"};

    try
    {
        getStageBuilderCheck(registry)(checkJson);
    }
    catch (const std::runtime_error& e)
    {
        EXPECT_STREQ("Check stage: Comparison of objects that have objects inside is not supported.", e.what());
    }
}

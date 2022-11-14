#include <gtest/gtest.h>

#include "baseTypes.hpp"
#include "builder/builders/operationBuilder.hpp"
#include <json/json.hpp>

using namespace builder::internals;
using namespace builder::internals::builders;
using namespace json;
using namespace base;

#define GTEST_COUT std::cout << "[          ] [ INFO ] "

Json operations {R"([
    {"string": "value"},
    {"int": 1},
    {"double": 1.0},
    {"boolT": true},
    {"boolF": false},
    {"null": null},

    {"nested.string": "value"},
    {"nested.int": 1},
    {"nested.double": 1.0},
    {"nested.boolT": true},
    {"nested.boolF": false},
    {"nested.null": null},

    {"stringRef": "$string"},
    {"intRef": "$int"},
    {"doubleRef": "$double"},
    {"boolTRef": "$boolT"},
    {"boolFRef": "$boolF"},
    {"arrayRef": "$array"},
    {"objectRef": "$object"},
    {"nullRef": "$null"},

    {"nestedStringRef": "$nested.string"},
    {"nestedIntRef": "$nested.int"},
    {"nestedDoubleRef": "$nested.double"},
    {"nestedBoolTRef": "$nested.boolT"},
    {"nestedBoolFRef": "$nested.boolF"},
    {"nestedArrayRef": "$nested.array"},
    {"nestedObjectRef": "$nested.object"},

    {"nested.stringRef": "$nested.string"},
    {"nested.intRef": "$nested.int"},
    {"nested.doubleRef": "$nested.double"},
    {"nested.boolTRef": "$nested.boolT"},
    {"nested.boolFRef": "$nested.boolF"},
    {"nested.arrayRef": "$nested.array"},
    {"nested.objectRef": "$nested.object"},
    {"nested.nullRef": "$nested.null"}

])"};

auto operationArray {operations.getArray().value()};

TEST(OperationConditionBuilderTest, Builds)
{
    auto registry = std::make_shared<Registry>();
    for (auto operationDef : operationArray)
    {
        auto def = operationDef.getObject().value()[0];
        ASSERT_NO_THROW(getOperationConditionBuilder(registry)(def));
    }
}

TEST(OperationConditionBuilderTest, UnexpectedDefinition)
{
    auto registry = std::make_shared<Registry>();
    for (auto operationDef : operationArray)
    {
        ASSERT_THROW(getOperationConditionBuilder(registry)(operationDef), std::runtime_error);
    }
}

TEST(OperationConditionBuilderTest, BuildsOperates)
{
    auto registry = std::make_shared<Registry>();
    auto eventOk = std::make_shared<Json>(R"({
        "string": "value",
        "int": 1,
        "double": 1.0,
        "boolT": true,
        "boolF": false,
        "null": null,
        "array": [1, 2, 3],
        "object": {"a": 1, "b": 2},

        "nested": {
            "string": "value",
            "int": 1,
            "double": 1.0,
            "boolT": true,
            "boolF": false,
            "null": null,
            "array": [1, 2, 3],
            "object": {"a": 1, "b": 2},

            "stringRef": "value",
            "intRef": 1,
            "doubleRef": 1.0,
            "boolTRef": true,
            "boolFRef": false,
            "arrayRef": [1, 2, 3],
            "objectRef": {"a": 1, "b": 2},
            "nullRef": null
        },

        "stringRef": "value",
        "intRef": 1,
        "doubleRef": 1.0,
        "boolTRef": true,
        "boolFRef": false,
        "arrayRef": [1, 2, 3],
        "objectRef": {"a": 1, "b": 2},
        "nullRef": null,

        "nestedStringRef": "value",
        "nestedIntRef": 1,
        "nestedDoubleRef": 1.0,
        "nestedBoolTRef": true,
        "nestedBoolFRef": false,
        "nestedArrayRef": [1, 2, 3],
        "nestedObjectRef": {"a": 1, "b": 2}

})");

    auto eventNotOk = std::make_shared<Json>(R"({
        "string": "values",
        "int": 2,
        "double": 2.0,
        "boolT": false,
        "boolF": true,
        "null": "null",
        "array": [1],
        "object": {"a": 1},

        "nested": {
            "string": 1,
            "int": "2",
            "double": "2.0",
            "boolT": "false",
            "boolF": "true",
            "array": [1, 3],
            "object": {"n": 1},

            "stringRef": "1",
            "intRef": "value",
            "doubleRef": null,
            "boolTRef": 1,
            "boolFRef": true,
            "arrayRef": ["1"],
            "objectRef": {"a": 1},
            "nullRef": ["null"]
        },

        "stringRef": 1,
        "intRef": "value",
        "doubleRef": null,
        "boolTRef": 1,
        "boolFRef": "true",
        "arrayRef": ["1"],
        "objectRef": {"n": 1},
        "nullRef": ["null"],

        "nestedStringRef": "a value",
        "nestedIntRef": "value",
        "nestedDoubleRef": null,
        "nestedBoolTRef": 1,
        "nestedBoolFRef": false,
        "nestedArrayRef": ["1"],
        "nestedObjectRef": {"a": 1},
        "nestedNullRef": ["1"]

})");

    auto eventNull = std::make_shared<Json>(R"({})");

    for (auto operationDef : operationArray)
    {
        auto def = operationDef.getObject().value()[0];
        auto op = getOperationConditionBuilder(registry)(def)->getPtr<Term<EngineOp>>()->getFn();
        auto result = op(eventOk);
        if (!result)
        {
            GTEST_COUT << "Expected Success, Failed: " << result.trace() << std::endl;
        }
        ASSERT_TRUE(result);
    }

    for (auto operationDef : operationArray)
    {
        auto def = operationDef.getObject().value()[0];
        auto op = getOperationConditionBuilder(registry)(def)->getPtr<Term<EngineOp>>()->getFn();
        auto result = op(eventNotOk);
        if (result)
        {
            GTEST_COUT << "Expected Failure, Success: " << result.trace() << std::endl;
        }
        ASSERT_FALSE(result);
    }

    for (auto operationDef : operationArray)
    {
        auto def = operationDef.getObject().value()[0];
        auto op = getOperationConditionBuilder(registry)(def)->getPtr<Term<EngineOp>>()->getFn();
        auto result = op(eventNull);
        if (result)
        {
            GTEST_COUT << "Expected Failure, Success: " << result.trace() << std::endl;
        }
        ASSERT_FALSE(result);
    }
}

TEST(OperationConditionBuilderTest, BuildsOperatesArray)
{
    auto registry = std::make_shared<Registry>();
    std::string targetField = "array";
    json::Json operation(R"([
        "string",
        1,
        1.2,
        true,
        false,
        null,
        [
            "string",
            1,
            1.2,
            true,
            false,
            null
        ]
    ])");
    auto definition = std::make_tuple(targetField, operation);

    auto eventOk = std::make_shared<Json>(R"({
        "array": [
            "string",
            1,
            1.2,
            true,
            false,
            null,
            [
                "string",
                1,
                1.2,
                true,
                false,
                null
            ]
        ]
    })");

    auto eventNotOk = std::make_shared<Json>(R"({
        "array": [
            "otherstring",
            2,
            2.2,
            false,
            true,
            "null",
            [
                "otherstring",
                2,
                2.2,
                false,
                true,
                "null"
            ]
        ]
    })");

    auto expression = getOperationConditionBuilder(registry)(definition);
    auto expressionRootLevel = expression->getPtr<base::Operation>()->getOperands();
    auto expressionNestedLevel =
        expressionRootLevel[6]->getPtr<base::Operation>()->getOperands();

    for (auto i = 0; i < 6; i++)
    {
        auto result = expressionRootLevel[i]->getPtr<Term<EngineOp>>()->getFn()(eventOk);
        if (!result)
        {
            GTEST_COUT << "Expected Success, Failed: " << result.trace() << std::endl;
        }
        ASSERT_TRUE(result);

        result = expressionRootLevel[i]->getPtr<Term<EngineOp>>()->getFn()(eventNotOk);
        if (result)
        {
            GTEST_COUT << "Expected Failure, Success: " << result.trace() << std::endl;
        }
        ASSERT_FALSE(result);
    }

    for (auto op : expressionNestedLevel)
    {
        auto result = op->getPtr<Term<EngineOp>>()->getFn()(eventOk);
        if (!result)
        {
            GTEST_COUT << "Expected Success, Failed: " << result.trace() << std::endl;
        }
        ASSERT_TRUE(result);

        result = op->getPtr<Term<EngineOp>>()->getFn()(eventNotOk);
        if (result)
        {
            GTEST_COUT << "Expected Failure, Success: " << result.trace() << std::endl;
        }
        ASSERT_FALSE(result);
    }
}

TEST(OperationConditionBuilderTest, BuildsOperatesObject)
{
    auto registry = std::make_shared<Registry>();
    std::string targetField = "object";
    json::Json operation(R"({
        "string": "string",
        "int": 1,
        "double": 1.2,
        "boolT": true,
        "boolF": false,
        "null": null,
        "object": {
            "string": "string",
            "int": 1,
            "double": 1.2,
            "boolT": true,
            "boolF": false,
            "null": null
        }
    })");
    auto definition = std::make_tuple(targetField, operation);

    auto eventOk = std::make_shared<Json>(R"({
        "object": {
            "string": "string",
            "int": 1,
            "double": 1.2,
            "boolT": true,
            "boolF": false,
            "null": null,
            "object": {
                "string": "string",
                "int": 1,
                "double": 1.2,
                "boolT": true,
                "boolF": false,
                "null": null
            }
        }
    })");

    auto eventNotOk = std::make_shared<Json>(R"({
        "object": {
            "string": "otherstring",
            "int": 2,
            "double": 2.2,
            "boolT": false,
            "boolF": true,
            "null": "null",
            "object": {
                "string": "otherstring",
                "int": 2,
                "double": 2.2,
                "boolT": false,
                "boolF": true,
                "null": "null"
            }
        }
    })");

    auto expression = getOperationConditionBuilder(registry)(definition);
    auto expressionRootLevel = expression->getPtr<base::Operation>()->getOperands();
    auto expressionNestedLevel =
        expressionRootLevel[6]->getPtr<base::Operation>()->getOperands();

    for (auto i = 0; i < 6; i++)
    {
        auto result = expressionRootLevel[i]->getPtr<Term<EngineOp>>()->getFn()(eventOk);
        if (!result)
        {
            GTEST_COUT << "Expected Success, Failed: " << result.trace() << std::endl;
        }
        ASSERT_TRUE(result);

        result = expressionRootLevel[i]->getPtr<Term<EngineOp>>()->getFn()(eventNotOk);
        if (result)
        {
            GTEST_COUT << "Expected Failure, Success: " << result.trace() << std::endl;
        }
        ASSERT_FALSE(result);
    }

    for (auto op : expressionNestedLevel)
    {
        auto result = op->getPtr<Term<EngineOp>>()->getFn()(eventOk);
        if (!result)
        {
            GTEST_COUT << "Expected Success, Failed: " << result.trace() << std::endl;
        }
        ASSERT_TRUE(result);

        result = op->getPtr<Term<EngineOp>>()->getFn()(eventNotOk);
        if (result)
        {
            GTEST_COUT << "Expected Failure, Success: " << result.trace() << std::endl;
        }
        ASSERT_FALSE(result);
    }
}

TEST(OperationMapBuilderTest, Builds)
{
    auto registry = std::make_shared<Registry>();
    for (auto operationDef : operationArray)
    {
        auto def = operationDef.getObject().value()[0];
        ASSERT_NO_THROW(getOperationMapBuilder(registry)(def));
    }
}

TEST(OperationMapBuilderTest, UnexpectedDefinition)
{
    auto registry = std::make_shared<Registry>();
    for (auto operationDef : operationArray)
    {
        ASSERT_THROW(getOperationMapBuilder(registry)(operationDef), std::runtime_error);
    }
}

// TODO: add failed map reference test.
TEST(OperationMapBuilderTest, BuildsOperatesLiterals)
{
    auto registry = std::make_shared<Registry>();
    auto expected = std::make_shared<Json>(R"({
        "string": "value",
        "int": 1,
        "double": 1.0,
        "boolT": true,
        "boolF": false,
        "null": null,
        "array": [1, 2, 3],
        "object": {"a": 1, "b": 2},

        "nested": {
            "string": "value",
            "int": 1,
            "double": 1.0,
            "boolT": true,
            "boolF": false,
            "null": null,
            "array": [1, 2, 3],
            "object": {"a": 1, "b": 2},

            "stringRef": "value",
            "intRef": 1,
            "doubleRef": 1.0,
            "boolTRef": true,
            "boolFRef": false,
            "arrayRef": [1, 2, 3],
            "objectRef": {"a": 1, "b": 2},
            "nullRef": null
        },

        "stringRef": "value",
        "intRef": 1,
        "doubleRef": 1.0,
        "boolTRef": true,
        "boolFRef": false,
        "arrayRef": [1, 2, 3],
        "objectRef": {"a": 1, "b": 2},
        "nullRef": null,

        "nestedStringRef": "value",
        "nestedIntRef": 1,
        "nestedDoubleRef": 1.0,
        "nestedBoolTRef": true,
        "nestedBoolFRef": false,
        "nestedArrayRef": [1, 2, 3],
        "nestedObjectRef": {"a": 1, "b": 2}

})");
    auto eventOk = std::make_shared<Json>(R"({
        "array": [1, 2, 3],
        "object": {"a": 1, "b": 2},
        "nested": {
            "array": [1, 2, 3],
            "object": {"a": 1, "b": 2}
        }
    })");

    for (auto operationDef : operationArray)
    {
        auto def = operationDef.getObject().value()[0];
        auto op = getOperationMapBuilder(registry)(def)->getPtr<Term<EngineOp>>()->getFn();
        auto result = op(eventOk);
        if (!result)
        {
            GTEST_COUT << "Expected Success, Failed: " << result.trace() << std::endl;
        }
        ASSERT_TRUE(result);
    }
    ASSERT_EQ(*expected, *eventOk);
}

TEST(OperationMapBuilderTest, BuildsOperatesArray)
{
    auto registry = std::make_shared<Registry>();
    std::string targetField("array");
    json::Json operationJson(R"([
        "string",
        1,
        1.2,
        true,
        false,
        null,
        [
            "string",
            1,
            1.2,
            true,
            false,
            null
        ]
    ])");
    auto definition = std::make_tuple(targetField, operationJson);

    auto expected = std::make_shared<Json>(R"({
        "array": [
            "string",
            1,
            1.2,
            true,
            false,
            null,
            [
                "string",
                1,
                1.2,
                true,
                false,
                null
            ]
        ]
    })");
    auto event = std::make_shared<Json>();
    auto expression = getOperationMapBuilder(registry)(definition);
    auto expressionsRootLevel = expression->getPtr<base::Operation>()->getOperands();
    auto expressionsNestedLevel =
        expressionsRootLevel[6]->getPtr<base::Operation>()->getOperands();

    for (auto i = 0; i < 6; i++)
    {
        auto result =
            expressionsRootLevel[i]->getPtr<base::Term<EngineOp>>()->getFn()(event);
        if (!result)
        {
            GTEST_COUT << "Expected Success, Failed: " << result.trace() << std::endl;
        }
        ASSERT_TRUE(result);
    }

    for (auto op : expressionsNestedLevel)
    {
        auto result = op->getPtr<base::Term<EngineOp>>()->getFn()(event);
        if (!result)
        {
            GTEST_COUT << "Expected Success, Failed: " << result.trace() << std::endl;
        }
        ASSERT_TRUE(result);
    }

    ASSERT_EQ(*expected, *event);
}

TEST(OperationMapBuilderTest, BuildsOperatesObject)
{
    auto registry = std::make_shared<Registry>();
    std::string targetField = "object";
    json::Json operationJson(R"({
        "string": "value",
        "int": 1,
        "double": 1.2,
        "boolT": true,
        "boolF": false,
        "null": null,
        "object": {
            "string": "value",
            "int": 1,
            "double": 1.2,
            "boolT": true,
            "boolF": false,
            "null": null
        }
    })");
    auto definition = std::make_tuple(targetField, operationJson);

    auto expected = std::make_shared<Json>(R"({
        "object": {
            "string": "value",
            "int": 1,
            "double": 1.2,
            "boolT": true,
            "boolF": false,
            "null": null,
            "object": {
                "string": "value",
                "int": 1,
                "double": 1.2,
                "boolT": true,
                "boolF": false,
                "null": null
            }
        }
    })");

    auto event = std::make_shared<Json>();
    auto expression = getOperationMapBuilder(registry)(definition);
    auto expressionsRootLevel = expression->getPtr<base::Operation>()->getOperands();
    auto expressionsNestedLevel =
        expressionsRootLevel[6]->getPtr<base::Operation>()->getOperands();

    for (auto i = 0; i < 6; i++)
    {
        auto result =
            expressionsRootLevel[i]->getPtr<base::Term<EngineOp>>()->getFn()(event);
        if (!result)
        {
            GTEST_COUT << "Expected Success, Failed: " << result.trace() << std::endl;
        }
        ASSERT_TRUE(result);
    }

    for (auto op : expressionsNestedLevel)
    {
        auto result = op->getPtr<base::Term<EngineOp>>()->getFn()(event);
        if (!result)
        {
            GTEST_COUT << "Expected Success, Failed: " << result.trace() << std::endl;
        }
        ASSERT_TRUE(result);
    }

    ASSERT_EQ(*expected, *event);
}

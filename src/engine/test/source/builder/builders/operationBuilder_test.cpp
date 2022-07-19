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
    {"array": [1, 2, 3]},
    {"object": {"a": 1, "b": 2}},

    {"nested.string": "value"},
    {"nested.int": 1},
    {"nested.double": 1.0},
    {"nested.boolT": true},
    {"nested.boolF": false},
    {"nested.null": null},
    {"nested.array": [1, 2, 3]},
    {"nested.object": {"a": 1, "b": 2}},

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
    for (auto operationDef : operationArray)
    {
        auto def = operationDef.getObject().value()[0];
        ASSERT_NO_THROW(operationConditionBuilder(def));
    }
}

TEST(OperationConditionBuilderTest, UnexpectedDefinition)
{
    for (auto operationDef : operationArray)
    {
        ASSERT_THROW(operationConditionBuilder(operationDef), std::runtime_error);
    }
}

TEST(OperationConditionBuilderTest, BuildsOperates)
{
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
        auto op = operationConditionBuilder(def)->getPtr<Term<EngineOp>>()->getFn();
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
        auto op = operationConditionBuilder(def)->getPtr<Term<EngineOp>>()->getFn();
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
        auto op = operationConditionBuilder(def)->getPtr<Term<EngineOp>>()->getFn();
        auto result = op(eventNull);
        if (result)
        {
            GTEST_COUT << "Expected Failure, Success: " << result.trace() << std::endl;
        }
        ASSERT_FALSE(result);
    }
}

TEST(OperationMapBuilderTest, Builds)
{
    for (auto operationDef : operationArray)
    {
        auto def = operationDef.getObject().value()[0];
        ASSERT_NO_THROW(operationMapBuilder(def));
    }
}

TEST(OperationMapBuilderTest, UnexpectedDefinition)
{
    for (auto operationDef : operationArray)
    {
        ASSERT_THROW(operationMapBuilder(operationDef), std::runtime_error);
    }
}

// TODO: add failed map reference test.
TEST(OperationMapBuilderTest, BuildsOperates)
{
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
    auto eventOk = std::make_shared<Json>(R"({})");

    for (auto operationDef : operationArray)
    {
        auto def = operationDef.getObject().value()[0];
        auto op = operationMapBuilder(def)->getPtr<Term<EngineOp>>()->getFn();
        auto result = op(eventOk);
        if (!result)
        {
            GTEST_COUT << "Expected Success, Failed: " << result.trace() << std::endl;
        }
        ASSERT_TRUE(result);
    }
    ASSERT_EQ(expected->str(), eventOk->str());
}

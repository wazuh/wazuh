#include <gtest/gtest.h>

#include "baseTypes.hpp"
#include "builder/builders/operationBuilder.hpp"
#include "builder/register.hpp"

#include <defs/mocks/failDef.hpp>
#include <json/json.hpp>
#include <schemf/mocks/emptySchema.hpp>
#include <schemf/mocks/straightValidator.hpp>

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

    {"escaped\\.string": "value"},
    {"escaped\\.int": 1},
    {"escaped\\.double": 1.0},
    {"escaped\\.boolT": true},
    {"escaped\\.boolF": false},
    {"escaped\\.null": null},

    {"nested.escaped\\.string": "value"},
    {"nested.escaped\\.int": 1},
    {"nested.escaped\\.double": 1.0},
    {"nested.escaped\\.boolT": true},
    {"nested.escaped\\.boolF": false},
    {"nested.escaped\\.null": null},

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
    {"nested.nullRef": "$nested.null"},

    {"escapedStringRef": "$escaped\\.string"},
    {"escapedIntRef": "$escaped\\.int"},
    {"escapedDoubleRef": "$escaped\\.double"},
    {"escapedBoolTRef": "$escaped\\.boolT"},
    {"escapedBoolFRef": "$escaped\\.boolF"},
    {"escapedArrayRef": "$escaped\\.array"},
    {"escapedObjectRef": "$escaped\\.object"},
    {"escapedNullRef": "$escaped\\.null"},

    {"nestedEscapedStringRef": "$nested.escaped\\.string"},
    {"nestedEscapedIntRef": "$nested.escaped\\.int"},
    {"nestedEscapedDoubleRef": "$nested.escaped\\.double"},
    {"nestedEscapedBoolTRef": "$nested.escaped\\.boolT"},
    {"nestedEscapedBoolFRef": "$nested.escaped\\.boolF"},
    {"nestedEscapedArrayRef": "$nested.escaped\\.array"},
    {"nestedEscapedObjectRef": "$nested.escaped\\.object"},

    {"nested.escaped\\.stringRef": "$nested.escaped\\.string"},
    {"nested.escaped\\.intRef": "$nested.escaped\\.int"},
    {"nested.escaped\\.doubleRef": "$nested.escaped\\.double"},
    {"nested.escaped\\.boolTRef": "$nested.escaped\\.boolT"},
    {"nested.escaped\\.boolFRef": "$nested.escaped\\.boolF"},
    {"nested.escaped\\.arrayRef": "$nested.escaped\\.array"},
    {"nested.escaped\\.objectRef": "$nested.escaped\\.object"},
    {"nested.escaped\\.nullRef": "$nested.escaped\\.null"}

])"};

auto operationArray {operations.getArray().value()};

Json helperFunctionsCases {R"([
    {"target": "+array_append/argument"},
    {"nested.target": "+array_append/argument"},
    {"referenceArg": "+array_append/argument/$target"},
    {"nestedreferenceArg": "+array_append/argument/$nested.target"},
    {"escaped\\.target": "+array_append/argument"},
    {"nested.escaped\\.target": "+array_append/argument"},
    {"referenceArg": "+array_append/argument/$escaped\\.target"},
    {"nestedreferenceArg": "+array_append/argument/$nested.escaped\\.target"}
])"};

auto helperFunctionArray {helperFunctionsCases.getArray().value()};

TEST(OperationConditionBuilderTest, Builds)
{
    auto helperRegistry = std::make_shared<Registry<builder::internals::HelperBuilder>>();
    for (auto operationDef : operationArray)
    {
        auto def = operationDef.getObject().value()[0];
        ASSERT_NO_THROW(getOperationConditionBuilder(helperRegistry, schemf::mocks::EmptySchema::create())(
            def, std::make_shared<defs::mocks::FailDef>()));
    }
}

TEST(OperationConditionBuilderTest, UnexpectedDefinition)
{
    auto helperRegistry = std::make_shared<Registry<builder::internals::HelperBuilder>>();
    for (auto operationDef : operationArray)
    {
        ASSERT_THROW(getOperationConditionBuilder(helperRegistry, schemf::mocks::EmptySchema::create())(
                         operationDef, std::make_shared<defs::mocks::FailDef>()),
                     std::runtime_error);
    }
}

TEST(OperationConditionBuilderTest, BuildsOperates)
{
    auto helperRegistry = std::make_shared<Registry<builder::internals::HelperBuilder>>();
    auto eventOk = std::make_shared<Json>(R"({
        "string": "value",
        "int": 1,
        "double": 1.0,
        "boolT": true,
        "boolF": false,
        "null": null,
        "array": [1, 2, 3],
        "object": {"a": 1, "b": 2},

        "escaped.string": "value",
        "escaped.int": 1,
        "escaped.double": 1.0,
        "escaped.boolT": true,
        "escaped.boolF": false,
        "escaped.null": null,
        "escaped.array": [1, 2, 3],
        "escaped.object": {"a": 1, "b": 2},

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
            "nullRef": null,

            "escaped.string": "value",
            "escaped.int": 1,
            "escaped.double": 1.0,
            "escaped.boolT": true,
            "escaped.boolF": false,
            "escaped.null": null,
            "escaped.array": [1, 2, 3],
            "escaped.object": {"a": 1, "b": 2},

            "escaped.stringRef": "value",
            "escaped.intRef": 1,
            "escaped.doubleRef": 1.0,
            "escaped.boolTRef": true,
            "escaped.boolFRef": false,
            "escaped.arrayRef": [1, 2, 3],
            "escaped.objectRef": {"a": 1, "b": 2},
            "escaped.nullRef": null
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
        "nestedObjectRef": {"a": 1, "b": 2},

        "escapedStringRef": "value",
        "escapedIntRef": 1,
        "escapedDoubleRef": 1.0,
        "escapedBoolTRef": true,
        "escapedBoolFRef": false,
        "escapedArrayRef": [1, 2, 3],
        "escapedObjectRef": {"a": 1, "b": 2},
        "escapedNullRef": null,

        "nestedEscapedStringRef": "value",
        "nestedEscapedIntRef": 1,
        "nestedEscapedDoubleRef": 1.0,
        "nestedEscapedBoolTRef": true,
        "nestedEscapedBoolFRef": false,
        "nestedEscapedArrayRef": [1, 2, 3],
        "nestedEscapedObjectRef": {"a": 1, "b": 2},
        "nestedEscapedNullRef": null

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

        "escaped.string": "values",
        "escaped.int": 2,
        "escaped.double": 2.0,
        "escaped.boolT": false,
        "escaped.boolF": true,
        "escaped.null": "null",
        "escaped.array": [1],
        "escaped.object": {"a": 1},

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
            "nullRef": ["null"],

            "escaped.string": 1,
            "escaped.int": "2",
            "escaped.double": "2.0",
            "escaped.boolT": "false",
            "escaped.boolF": "true",
            "escaped.array": [1, 3],
            "escaped.object": {"n": 1},

            "escaped.stringRef": "1",
            "escaped.intRef": "value",
            "escaped.doubleRef": null,
            "escaped.boolTRef": 1,
            "escaped.boolFRef": true,
            "escaped.arrayRef": ["1"],
            "escaped.objectRef": {"a": 1},
            "escaped.nullRef": ["null"]
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
        "nestedNullRef": ["1"],

        "escapedStringRef": 1,
        "escapedIntRef": "value",
        "escapedDoubleRef": null,
        "escapedBoolTRef": 1,
        "escapedBoolFRef": "true",
        "escapedArrayRef": ["1"],
        "escapedObjectRef": {"n": 1},
        "escapedNullRef": ["null"],

        "nestedEscapedStringRef": "a value",
        "nestedEscapedIntRef": "value",
        "nestedEscapedDoubleRef": null,
        "nestedEscapedBoolTRef": 1,
        "nestedEscapedBoolFRef": false,
        "nestedEscapedArrayRef": ["1"],
        "nestedEscapedObjectRef": {"a": 1},
        "nestedEscapedNullRef": ["1"]
})");

    auto eventNull = std::make_shared<Json>(R"({})");

    for (auto operationDef : operationArray)
    {
        auto def = operationDef.getObject().value()[0];
        auto op = getOperationConditionBuilder(helperRegistry, schemf::mocks::EmptySchema::create())(
                      def, std::make_shared<defs::mocks::FailDef>())
                      ->getPtr<Term<EngineOp>>()
                      ->getFn();
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
        auto op = getOperationConditionBuilder(helperRegistry, schemf::mocks::EmptySchema::create())(
                      def, std::make_shared<defs::mocks::FailDef>())
                      ->getPtr<Term<EngineOp>>()
                      ->getFn();
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
        auto op = getOperationConditionBuilder(helperRegistry, schemf::mocks::EmptySchema::create())(
                      def, std::make_shared<defs::mocks::FailDef>())
                      ->getPtr<Term<EngineOp>>()
                      ->getFn();
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
    auto helperRegistry = std::make_shared<Registry<builder::internals::HelperBuilder>>();
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

    auto expression = getOperationConditionBuilder(helperRegistry, schemf::mocks::EmptySchema::create())(
        definition, std::make_shared<defs::mocks::FailDef>());
    auto expressionRootLevel = expression->getPtr<base::Operation>()->getOperands();
    auto expressionNestedLevel = expressionRootLevel[6]->getPtr<base::Operation>()->getOperands();

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
    auto helperRegistry = std::make_shared<Registry<builder::internals::HelperBuilder>>();
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

    auto expression = getOperationConditionBuilder(helperRegistry, schemf::mocks::EmptySchema::create())(
        definition, std::make_shared<defs::mocks::FailDef>());
    auto expressionRootLevel = expression->getPtr<base::Operation>()->getOperands();
    auto expressionNestedLevel = expressionRootLevel[6]->getPtr<base::Operation>()->getOperands();

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

TEST(OperationConditionBuilderTest, BuildsWithHelper)
{
    auto helperRegistry = std::make_shared<Registry<builder::internals::HelperBuilder>>();

    ASSERT_NO_THROW(registerHelperBuilders(helperRegistry));
    ASSERT_NO_THROW(helperRegistry->getBuilder("array_append"));

    for (auto operationDef : helperFunctionArray)
    {
        auto def = operationDef.getObject().value()[0];
        ASSERT_NO_THROW(getOperationConditionBuilder(helperRegistry, schemf::mocks::EmptySchema::create())(
            def, std::make_shared<defs::mocks::FailDef>()));
    }
}

TEST(OperationMapBuilderTest, Builds)
{
    auto helperRegistry = std::make_shared<Registry<builder::internals::HelperBuilder>>();
    for (auto operationDef : operationArray)
    {
        auto def = operationDef.getObject().value()[0];
        ASSERT_NO_THROW(getOperationMapBuilder(helperRegistry, schemf::mocks::EmptySchema::create())(
            def, std::make_shared<defs::mocks::FailDef>()));
    }
}

TEST(OperationMapBuilderTest, UnexpectedDefinition)
{
    auto helperRegistry = std::make_shared<Registry<builder::internals::HelperBuilder>>();
    for (auto operationDef : operationArray)
    {
        ASSERT_THROW(getOperationMapBuilder(helperRegistry, schemf::mocks::EmptySchema::create())(
                         operationDef, std::make_shared<defs::mocks::FailDef>()),
                     std::runtime_error);
    }
}

// TODO: add failed map reference test.
TEST(OperationMapBuilderTest, BuildsOperatesLiterals)
{
    auto helperRegistry = std::make_shared<Registry<builder::internals::HelperBuilder>>();
    auto expected = std::make_shared<Json>(R"({
        "string": "value",
        "int": 1,
        "double": 1.0,
        "boolT": true,
        "boolF": false,
        "null": null,
        "array": [1, 2, 3],
        "object": {"a": 1, "b": 2},

        "escaped.string": "value",
        "escaped.int": 1,
        "escaped.double": 1.0,
        "escaped.boolT": true,
        "escaped.boolF": false,
        "escaped.null": null,
        "escaped.array": [1, 2, 3],
        "escaped.object": {"a": 1, "b": 2},

        "nested": {
            "string": "value",
            "int": 1,
            "double": 1.0,
            "boolT": true,
            "boolF": false,
            "null": null,
            "array": [1, 2, 3],
            "object": {"a": 1, "b": 2},

            "escaped.string": "value",
            "escaped.int": 1,
            "escaped.double": 1.0,
            "escaped.boolT": true,
            "escaped.boolF": false,
            "escaped.null": null,
            "escaped.array": [1, 2, 3],
            "escaped.object": {"a": 1, "b": 2},

            "stringRef": "value",
            "intRef": 1,
            "doubleRef": 1.0,
            "boolTRef": true,
            "boolFRef": false,
            "arrayRef": [1, 2, 3],
            "objectRef": {"a": 1, "b": 2},
            "nullRef": null,

            "escaped.stringRef": "value",
            "escaped.intRef": 1,
            "escaped.doubleRef": 1.0,
            "escaped.boolTRef": true,
            "escaped.boolFRef": false,
            "escaped.arrayRef": [1, 2, 3],
            "escaped.objectRef": {"a": 1, "b": 2},
            "escaped.nullRef": null
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
        "nestedObjectRef": {"a": 1, "b": 2},

        "escapedStringRef": "value",
        "escapedIntRef": 1,
        "escapedDoubleRef": 1.0,
        "escapedBoolTRef": true,
        "escapedBoolFRef": false,
        "escapedArrayRef": [1, 2, 3],
        "escapedObjectRef": {"a": 1, "b": 2},
        "escapedNullRef": null,

        "nestedEscapedStringRef": "value",
        "nestedEscapedIntRef": 1,
        "nestedEscapedDoubleRef": 1.0,
        "nestedEscapedBoolTRef": true,
        "nestedEscapedBoolFRef": false,
        "nestedEscapedArrayRef": [1, 2, 3],
        "nestedEscapedObjectRef": {"a": 1, "b": 2}

})");
    auto eventOk = std::make_shared<Json>(R"({
        "array": [1, 2, 3],
        "object": {"a": 1, "b": 2},
        "escaped.array": [1, 2, 3],
        "escaped.object": {"a": 1, "b": 2},
        "nested": {
            "array": [1, 2, 3],
            "object": {"a": 1, "b": 2},
            "escaped.array": [1, 2, 3],
            "escaped.object": {"a": 1, "b": 2}
        }
    })");

    for (auto operationDef : operationArray)
    {
        auto def = operationDef.getObject().value()[0];
        auto op = getOperationMapBuilder(helperRegistry, schemf::mocks::EmptySchema::create())(
                      def, std::make_shared<defs::mocks::FailDef>())
                      ->getPtr<Term<EngineOp>>()
                      ->getFn();
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
    auto helperRegistry = std::make_shared<Registry<builder::internals::HelperBuilder>>();
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
    auto expression = getOperationMapBuilder(helperRegistry, schemf::mocks::EmptySchema::create())(
        definition, std::make_shared<defs::mocks::FailDef>());
    auto expressionsRootLevel = expression->getPtr<base::Operation>()->getOperands();
    auto expressionsNestedLevel = expressionsRootLevel[6]->getPtr<base::Operation>()->getOperands();

    for (auto i = 0; i < 6; i++)
    {
        auto result = expressionsRootLevel[i]->getPtr<base::Term<EngineOp>>()->getFn()(event);
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
    auto helperRegistry = std::make_shared<Registry<builder::internals::HelperBuilder>>();
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
    auto expression = getOperationMapBuilder(helperRegistry, schemf::mocks::EmptySchema::create())(
        definition, std::make_shared<defs::mocks::FailDef>());
    auto expressionsRootLevel = expression->getPtr<base::Operation>()->getOperands();
    auto expressionsNestedLevel = expressionsRootLevel[6]->getPtr<base::Operation>()->getOperands();

    for (auto i = 0; i < 6; i++)
    {
        auto result = expressionsRootLevel[i]->getPtr<base::Term<EngineOp>>()->getFn()(event);
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

TEST(OperationMapBuilderTest, BuildsWithHelper)
{
    auto helperRegistry = std::make_shared<Registry<builder::internals::HelperBuilder>>();

    ASSERT_NO_THROW(registerHelperBuilders(helperRegistry));
    ASSERT_NO_THROW(helperRegistry->getBuilder("array_append"));

    for (auto helperFunctionDef : helperFunctionArray)
    {
        auto def = helperFunctionDef.getObject().value()[0];
        ASSERT_NO_THROW(getOperationMapBuilder(helperRegistry, schemf::mocks::EmptySchema::create())(
            def, std::make_shared<defs::mocks::FailDef>()));
    }
}

using SchemaParamsTuple = std::tuple<std::string, std::string, std::shared_ptr<schemf::ISchema>, bool>;
class SchemaParams : public ::testing::TestWithParam<SchemaParamsTuple>
{
};

TEST_P(SchemaParams, ChecksSchemaFields)
{
    auto [target, value, schema, shouldPass] = GetParam();
    auto helperRegistry = std::make_shared<Registry<builder::internals::HelperBuilder>>();
    auto definition =
        std::make_any<std::tuple<std::string, json::Json>>(std::make_tuple(target, json::Json(value.c_str())));

    if (shouldPass)
    {
        ASSERT_NO_THROW(
            getOperationMapBuilder(helperRegistry, schema)(definition, std::make_shared<defs::mocks::FailDef>()));
    }
    else
    {
        ASSERT_THROW(
            getOperationMapBuilder(helperRegistry, schema)(definition, std::make_shared<defs::mocks::FailDef>()),
            std::runtime_error);
    }
}

INSTANTIATE_TEST_SUITE_P(
    OperationBuilderTest,
    SchemaParams,
    ::testing::Values(
        SchemaParamsTuple("field", R"("$ref")", schemf::mocks::StraightValidator::create(true, true), true),
        SchemaParamsTuple("field", R"("$ref")", schemf::mocks::StraightValidator::create(false, true), false),
        SchemaParamsTuple("field", R"("$ref")", schemf::mocks::StraightValidator::create(false, false), true),
        SchemaParamsTuple("field", R"("value")", schemf::mocks::StraightValidator::create(true, true), true),
        SchemaParamsTuple("field", R"("value")", schemf::mocks::StraightValidator::create(false, true), false),
        SchemaParamsTuple("field", R"("value")", schemf::mocks::StraightValidator::create(false, false), true),
        SchemaParamsTuple("field", R"(["array"])", schemf::mocks::StraightValidator::create(true, true), true),
        SchemaParamsTuple("field", R"(["array"])", schemf::mocks::StraightValidator::create(false, true), false),
        SchemaParamsTuple("field", R"(["array"])", schemf::mocks::StraightValidator::create(false, false), true),
        SchemaParamsTuple(
            "field", R"({"object": "value"})", schemf::mocks::StraightValidator::create(true, true), true),
        SchemaParamsTuple(
            "field", R"({"object": "value"})", schemf::mocks::StraightValidator::create(false, true), false),
        SchemaParamsTuple(
            "field", R"({"object": "value"})", schemf::mocks::StraightValidator::create(false, false), true)));

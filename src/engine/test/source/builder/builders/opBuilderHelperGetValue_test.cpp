#include <any>
#include <gtest/gtest.h>
#include <vector>

#include <baseTypes.hpp>
#include <defs/defs.hpp>
#include <defs/mocks/failDef.hpp>
#include <schemf/mocks/emptySchema.hpp>

#include "opBuilderHelperMap.hpp"

using namespace base;
namespace bld = builder::internals::builders;

/*************************************************************
 * get_value
 *************************************************************/
TEST(getOpBuilderHelperGetValue, Builds)
{
    // Parameter: Definition
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+get_value"},
                                 std::vector<std::string> {"$defObject", "$keyField"},
                                 std::make_shared<defs::Definitions>(json::Json(R"({"defObject": {"key": "value"}})")));

    ASSERT_NO_THROW(std::apply(bld::getOpBuilderHelperGetValue(schemf::mocks::EmptySchema::create()), tuple));

    // Parameter: Reference
    auto tuple1 = std::make_tuple(std::string {"/field"},
                                  std::string {"+get_value"},
                                  std::vector<std::string> {"$refObject", "$keyField"},
                                  std::make_shared<defs::mocks::FailDef>());

    ASSERT_NO_THROW(std::apply(bld::getOpBuilderHelperGetValue(schemf::mocks::EmptySchema::create()), tuple1));
}

TEST(getOpBuilderHelperGetValue, EmptyParameters)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+get_value"},
                                 std::vector<std::string> {},
                                 std::make_shared<defs::Definitions>(json::Json(R"({"defObject": {"key": "value"}})")));

    ASSERT_THROW(std::apply(bld::getOpBuilderHelperGetValue(schemf::mocks::EmptySchema::create()), tuple),
                 std::runtime_error);
}

TEST(getOpBuilderHelperGetValue, WrongSizeParameters)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+get_value"},
                                 std::vector<std::string> {"$defObject"},
                                 std::make_shared<defs::Definitions>(json::Json(R"({"defObject": {"key": "value"}})")));

    ASSERT_THROW(std::apply(bld::getOpBuilderHelperGetValue(schemf::mocks::EmptySchema::create()), tuple),
                 std::runtime_error);

    tuple = std::make_tuple(std::string {"/field"},
                            std::string {"+get_value"},
                            std::vector<std::string> {"$defObject", "keyField1", "keyField2"},
                            std::make_shared<defs::Definitions>(json::Json(R"({"defObject": {"key": "value"}})")));

    ASSERT_THROW(std::apply(bld::getOpBuilderHelperGetValue(schemf::mocks::EmptySchema::create()), tuple),
                 std::runtime_error);
}

TEST(getOpBuilderHelperGetValue, WrongTypeParameters)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+get_value"},
                                 std::vector<std::string> {"defObject", "$keyField"},
                                 std::make_shared<defs::Definitions>(json::Json(R"({"defObject": {"key": "value"}})")));
    ASSERT_THROW(std::apply(bld::getOpBuilderHelperGetValue(schemf::mocks::EmptySchema::create()), tuple),
                 std::runtime_error);

    tuple = std::make_tuple(std::string {"/field"},
                            std::string {"+get_value"},
                            std::vector<std::string> {"$defObject", "keyField"},
                            std::make_shared<defs::Definitions>(json::Json(R"({"defObject": {"key": "value"}})")));

    ASSERT_THROW(std::apply(bld::getOpBuilderHelperGetValue(schemf::mocks::EmptySchema::create()), tuple),
                 std::runtime_error);
}

TEST(getOpBuilderHelperGetValue, SuccessByDefinition)
{
    // Definition template
    json::Json definitionTemplate {R"({
        "defObject": {
            "keyInt": 49,
            "keyString": "hello",
            "keyBool": true,
            "keyNull": null,
            "keyObject": {"key": "value"},
            "keyArray": ["value"]
        }
    })"};

    // Operation
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+get_value"},
                                 std::vector<std::string> {"$defObject", "$keyField"},
                                 std::make_shared<defs::Definitions>(definitionTemplate));

    auto op = std::apply(bld::getOpBuilderHelperGetValue(schemf::mocks::EmptySchema::create()), tuple)
                  ->getPtr<Term<EngineOp>>()
                  ->getFn();

    // Use case events
    auto event1 = std::make_shared<json::Json>(R"({"keyField": "keyInt"})");
    auto event2 = std::make_shared<json::Json>(R"({"keyField": "keyString"})");
    auto event3 = std::make_shared<json::Json>(R"({"keyField": "keyBool"})");
    auto event4 = std::make_shared<json::Json>(R"({"keyField": "keyNull"})");
    auto event5 = std::make_shared<json::Json>(R"({"keyField": "keyObject"})");
    auto event6 = std::make_shared<json::Json>(R"({"keyField": "keyArray"})");

    // Use case expected events
    auto expectedEvent1 = std::make_shared<json::Json>(R"({"keyField": "keyInt", "field": 49})");
    auto expectedEvent2 = std::make_shared<json::Json>(R"({"keyField": "keyString", "field": "hello"})");
    auto expectedEvent3 = std::make_shared<json::Json>(R"({"keyField": "keyBool", "field": true})");
    auto expectedEvent4 = std::make_shared<json::Json>(R"({"keyField": "keyNull", "field": null})");
    auto expectedEvent5 = std::make_shared<json::Json>(R"({"keyField": "keyObject", "field": {"key": "value"}})");
    auto expectedEvent6 = std::make_shared<json::Json>(R"({"keyField": "keyArray", "field": ["value"]})");

    // Use cases
    result::Result<Event> result = op(event1);
    ASSERT_TRUE(result.success());
    ASSERT_EQ(*result.payload(), *expectedEvent1);

    result = op(event2);
    ASSERT_TRUE(result.success());
    ASSERT_EQ(*result.payload(), *expectedEvent2);

    result = op(event3);
    ASSERT_TRUE(result.success());
    ASSERT_EQ(*result.payload(), *expectedEvent3);

    result = op(event4);
    ASSERT_TRUE(result.success());
    ASSERT_EQ(*result.payload(), *expectedEvent4);

    result = op(event5);
    ASSERT_TRUE(result.success());
    ASSERT_EQ(*result.payload(), *expectedEvent5);

    result = op(event6);
    ASSERT_TRUE(result.success());
    ASSERT_EQ(*result.payload(), *expectedEvent6);
}

TEST(getOpBuilderHelperGetValue, SuccessByReference)
{
    // Event template
    json::Json eventTemplate {R"({
        "refObject": {
            "keyInt": 49,
            "keyString": "hello",
            "keyBool": true,
            "keyNull": null,
            "keyObject": {"key": "value"},
            "keyArray": ["value"]
        }
    })"};

    // Operation
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+get_value"},
                                 std::vector<std::string> {"$refObject", "$keyField"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto op = std::apply(bld::getOpBuilderHelperGetValue(schemf::mocks::EmptySchema::create()), tuple)
                  ->getPtr<Term<EngineOp>>()
                  ->getFn();

    // Use case events
    auto event1 = std::make_shared<json::Json>(eventTemplate);
    event1->setString("keyInt", "/keyField");
    auto event2 = std::make_shared<json::Json>(eventTemplate);
    event2->setString("keyString", "/keyField");
    auto event3 = std::make_shared<json::Json>(eventTemplate);
    event3->setString("keyBool", "/keyField");
    auto event4 = std::make_shared<json::Json>(eventTemplate);
    event4->setString("keyNull", "/keyField");
    auto event5 = std::make_shared<json::Json>(eventTemplate);
    event5->setString("keyObject", "/keyField");
    auto event6 = std::make_shared<json::Json>(eventTemplate);
    event6->setString("keyArray", "/keyField");

    // Use case expected events
    auto expectedEvent1 = std::make_shared<json::Json>(eventTemplate);
    expectedEvent1->setString("keyInt", "/keyField");
    expectedEvent1->setInt(49, "/field");
    auto expectedEvent2 = std::make_shared<json::Json>(eventTemplate);
    expectedEvent2->setString("keyString", "/keyField");
    expectedEvent2->setString("hello", "/field");
    auto expectedEvent3 = std::make_shared<json::Json>(eventTemplate);
    expectedEvent3->setString("keyBool", "/keyField");
    expectedEvent3->setBool(true, "/field");
    auto expectedEvent4 = std::make_shared<json::Json>(eventTemplate);
    expectedEvent4->setString("keyNull", "/keyField");
    expectedEvent4->setNull("/field");
    auto expectedEvent5 = std::make_shared<json::Json>(eventTemplate);
    expectedEvent5->setString("keyObject", "/keyField");
    expectedEvent5->set("/field", json::Json {R"({"key": "value"})"});
    auto expectedEvent6 = std::make_shared<json::Json>(eventTemplate);
    expectedEvent6->setString("keyArray", "/keyField");
    expectedEvent6->set("/field", json::Json {R"(["value"])"});

    // Use cases
    result::Result<Event> result = op(event1);
    ASSERT_TRUE(result.success());
    ASSERT_EQ(*result.payload(), *expectedEvent1);

    result = op(event2);
    ASSERT_TRUE(result.success());
    ASSERT_EQ(*result.payload(), *expectedEvent2);

    result = op(event3);
    ASSERT_TRUE(result.success());
    ASSERT_EQ(*result.payload(), *expectedEvent3);

    result = op(event4);
    ASSERT_TRUE(result.success());
    ASSERT_EQ(*result.payload(), *expectedEvent4);

    result = op(event5);
    ASSERT_TRUE(result.success());
    ASSERT_EQ(*result.payload(), *expectedEvent5);

    result = op(event6);
    ASSERT_TRUE(result.success());
    ASSERT_EQ(*result.payload(), *expectedEvent6);
}

TEST(getOpBuilderHelperGetValue, KeyNotMatchByDefinition)
{
    // Definition template
    json::Json definitionTemplate {R"({
        "defObject": {
            "keyInt": 49,
            "keyString": "hello",
            "keyBool": true,
            "keyNull": null,
            "keyObject": {"key": "value"},
            "keyArray": ["value"]
        }
    })"};

    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+get_value"},
                                 std::vector<std::string> {"$defObject", "$keyField"},
                                 std::make_shared<defs::Definitions>(definitionTemplate));

    auto event = std::make_shared<json::Json>(R"({"keyField": "wrongKey"})");

    auto op = std::apply(bld::getOpBuilderHelperGetValue(schemf::mocks::EmptySchema::create()), tuple)
                  ->getPtr<Term<EngineOp>>()
                  ->getFn();

    result::Result<Event> result = op(event);
    ASSERT_FALSE(result.success());
}

TEST(getOpBuilderHelperGetValue, KeyNotMatchByReference)
{
    // Event template
    json::Json eventTemplate {R"({
        "refObject": {
            "keyInt": 49,
            "keyString": "hello",
            "keyBool": true,
            "keyNull": null,
            "keyObject": {"key": "value"},
            "keyArray": ["value"]
        }
    })"};

    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+get_value"},
                                 std::vector<std::string> {"$refObject", "$keyField"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto event = std::make_shared<json::Json>(eventTemplate);
    event->setString("wrongKey", "/keyField");

    auto op = std::apply(bld::getOpBuilderHelperGetValue(schemf::mocks::EmptySchema::create()), tuple)
                  ->getPtr<Term<EngineOp>>()
                  ->getFn();

    result::Result<Event> result = op(event);
    ASSERT_FALSE(result.success());
}

TEST(getOpBuilderHelperGetValue, KeyNotFound)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+get_value"},
                                 std::vector<std::string> {"$defObject", "$keyField"},
                                 std::make_shared<defs::Definitions>(json::Json(R"({"defObject": {"key": "value"}})")));

    auto event = std::make_shared<json::Json>(R"({"wrongKey": "key"})");

    auto op = std::apply(bld::getOpBuilderHelperGetValue(schemf::mocks::EmptySchema::create()), tuple)
                  ->getPtr<Term<EngineOp>>()
                  ->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(getOpBuilderHelperGetValue, KeyIsNotString)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+get_value"},
                                 std::vector<std::string> {"$defObject", "$keyField"},
                                 std::make_shared<defs::Definitions>(json::Json(R"({"defObject": {"key": "value"}})")));

    auto event = std::make_shared<json::Json>(R"({"keyField": 1})");

    auto op = std::apply(bld::getOpBuilderHelperGetValue(schemf::mocks::EmptySchema::create()), tuple)
                  ->getPtr<Term<EngineOp>>()
                  ->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(getOpBuilderHelperGetValue, DefinitionNotFound)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+get_value"},
                                 std::vector<std::string> {"$def", "$keyField"},
                                 std::make_shared<defs::Definitions>(json::Json(R"({"defObject": {"key": "value"}})")));

    auto event1 = std::make_shared<json::Json>(R"({"defObject": {"key": "value"}, "keyField": "key"})");

    auto op = std::apply(bld::getOpBuilderHelperGetValue(schemf::mocks::EmptySchema::create()), tuple)
                  ->getPtr<Term<EngineOp>>()
                  ->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_FALSE(result.success());
}

TEST(getOpBuilderHelperGetValue, ParameterIsNotAnObject)
{
    // Parameter: Definition
    auto tuple1 = std::make_tuple(std::string {"/field"},
                                  std::string {"+get_value"},
                                  std::vector<std::string> {"$defInt", "$keyField"},
                                  std::make_shared<defs::Definitions>(json::Json(R"({"defInt": 1})")));

    ASSERT_THROW(std::apply(bld::getOpBuilderHelperGetValue(schemf::mocks::EmptySchema::create()), tuple1),
                 std::runtime_error);

    tuple1 = std::make_tuple(std::string {"/field"},
                             std::string {"+get_value"},
                             std::vector<std::string> {"$defArray", "$keyField"},
                             std::make_shared<defs::Definitions>(json::Json(R"({"defArray": [1, 2, 3]})")));

    ASSERT_THROW(std::apply(bld::getOpBuilderHelperGetValue(schemf::mocks::EmptySchema::create()), tuple1),
                 std::runtime_error);

    // Parameter: Reference
    auto tuple2 = std::make_tuple(std::string {"/field"},
                                  std::string {"+get_value"},
                                  std::vector<std::string> {"$refArray", "$keyField"},
                                  std::make_shared<defs::mocks::FailDef>());

    auto event = std::make_shared<json::Json>(R"({"refArray": [1, 2, 3], "keyField": "key"})");

    auto op = std::apply(bld::getOpBuilderHelperGetValue(schemf::mocks::EmptySchema::create()), tuple2)
                  ->getPtr<Term<EngineOp>>()
                  ->getFn();

    result::Result<Event> result = op(event);
    ASSERT_FALSE(result.success());
}



/*************************************************************
 * merge_value
 *************************************************************/
TEST(getOpBuilderHelperMergeValue, Builds)
{
    // Parameter: Definition
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+merge_value"},
                                 std::vector<std::string> {"$defObject", "$keyField"},
                                 std::make_shared<defs::Definitions>(json::Json(R"({"defObject": {"key": "value"}})")));

    ASSERT_NO_THROW(std::apply(bld::getOpBuilderHelperMergeValue(schemf::mocks::EmptySchema::create()), tuple));

    // Parameter: Reference
    auto tuple1 = std::make_tuple(std::string {"/field"},
                                  std::string {"+merge_value"},
                                  std::vector<std::string> {"$refObject", "$keyField"},
                                  std::make_shared<defs::mocks::FailDef>());

    ASSERT_NO_THROW(std::apply(bld::getOpBuilderHelperMergeValue(schemf::mocks::EmptySchema::create()), tuple1));
}

TEST(getOpBuilderHelperMergeValue, EmptyParameters)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+merge_value"},
                                 std::vector<std::string> {},
                                 std::make_shared<defs::Definitions>(json::Json(R"({"defObject": {"key": "value"}})")));

    ASSERT_THROW(std::apply(bld::getOpBuilderHelperMergeValue(schemf::mocks::EmptySchema::create()), tuple),
                 std::runtime_error);
}

TEST(getOpBuilderHelperMergeValue, WrongSizeParameters)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+merge_value"},
                                 std::vector<std::string> {"$defObject"},
                                 std::make_shared<defs::Definitions>(json::Json(R"({"defObject": {"key": "value"}})")));

    ASSERT_THROW(std::apply(bld::getOpBuilderHelperMergeValue(schemf::mocks::EmptySchema::create()), tuple),
                 std::runtime_error);

    tuple = std::make_tuple(std::string {"/field"},
                            std::string {"+merge_value"},
                            std::vector<std::string> {"$defObject", "keyField1", "keyField2"},
                            std::make_shared<defs::Definitions>(json::Json(R"({"defObject": {"key": "value"}})")));

    ASSERT_THROW(std::apply(bld::getOpBuilderHelperMergeValue(schemf::mocks::EmptySchema::create()), tuple),
                 std::runtime_error);
}

TEST(getOpBuilderHelperMergeValue, WrongTypeParameters)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+merge_value"},
                                 std::vector<std::string> {"defObject", "$keyField"},
                                 std::make_shared<defs::Definitions>(json::Json(R"({"defObject": {"key": "value"}})")));
    ASSERT_THROW(std::apply(bld::getOpBuilderHelperMergeValue(schemf::mocks::EmptySchema::create()), tuple),
                 std::runtime_error);

    tuple = std::make_tuple(std::string {"/field"},
                            std::string {"+merge_value"},
                            std::vector<std::string> {"$defObject", "keyField"},
                            std::make_shared<defs::Definitions>(json::Json(R"({"defObject": {"key": "value"}})")));

    ASSERT_THROW(std::apply(bld::getOpBuilderHelperMergeValue(schemf::mocks::EmptySchema::create()), tuple),
                 std::runtime_error);
}

TEST(getOpBuilderHelperMergeValue, failMatchTypesByDefinition)
{
    // Definition template
    json::Json definitionTemplate {R"({
        "defObject": {
            "keyInt": 49,
            "keyString": "hello",
            "keyBool": true,
            "keyNull": null,
            "keyArray": ["value"]
        }
    })"};

    // Operation
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+merge_value"},
                                 std::vector<std::string> {"$defObject", "$keyField"},
                                 std::make_shared<defs::Definitions>(definitionTemplate));

    auto op = std::apply(bld::getOpBuilderHelperMergeValue(schemf::mocks::EmptySchema::create()), tuple)
                  ->getPtr<Term<EngineOp>>()
                  ->getFn();

    // Use case events
    auto event1 = std::make_shared<json::Json>(R"({"keyField": "keyInt"})");
    auto event2 = std::make_shared<json::Json>(R"({"keyField": "keyString"})");
    auto event3 = std::make_shared<json::Json>(R"({"keyField": "keyBool"})");
    auto event4 = std::make_shared<json::Json>(R"({"keyField": "keyNull"})");
    auto event5 = std::make_shared<json::Json>(R"({"keyField": "keyObject"})");
    auto event6 = std::make_shared<json::Json>(R"({"keyField": "keyArray"})");

    // Use case expected events, same as events becose merge value fails if the types don't match and be object or array
    auto expectedEvent1 = event1;
    auto expectedEvent2 = event2;
    auto expectedEvent3 = event3;
    auto expectedEvent4 = event4;
    auto expectedEvent5 = event5;
    auto expectedEvent6 = event6;

    // Use cases
    result::Result<Event> result = op(event1);
    ASSERT_TRUE(result.failure());
    ASSERT_EQ(*result.payload(), *expectedEvent1);

    result = op(event2);
    ASSERT_TRUE(result.failure());
    ASSERT_EQ(*result.payload(), *expectedEvent2);

    result = op(event3);
    ASSERT_TRUE(result.failure());
    ASSERT_EQ(*result.payload(), *expectedEvent3);

    result = op(event4);
    ASSERT_TRUE(result.failure());
    ASSERT_EQ(*result.payload(), *expectedEvent4);

    result = op(event5);
    ASSERT_TRUE(result.failure());
    ASSERT_EQ(*result.payload(), *expectedEvent5);

    result = op(event6);
    ASSERT_TRUE(result.failure());
    ASSERT_EQ(*result.payload(), *expectedEvent6);
}


TEST(getOpBuilderHelperMergeValue, SuccessByDefinition)
{
    // Definition template
    json::Json definitionTemplate {R"({
        "defObject": {
            "keyObj": {
                "keyInt": 49,
                "keyString": "hello",
                "keyBool": true,
                "keyNull": null,
                "keyArray": [
                    "value"
                ]
            }
        }
    })"};

    // Operation
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+merge_value"},
                                 std::vector<std::string> {"$defObject", "$keyField"},
                                 std::make_shared<defs::Definitions>(definitionTemplate));

    auto op = std::apply(bld::getOpBuilderHelperMergeValue(schemf::mocks::EmptySchema::create()), tuple)
                  ->getPtr<Term<EngineOp>>()
                  ->getFn();

    // Use case events
    auto event1 = std::make_shared<json::Json>(R"({"keyField": "keyObj", "field": {}})");
    auto event2 = std::make_shared<json::Json>(R"({"keyField": "keyObj", "field": {"hi": "bye"}})");
    auto event3 = std::make_shared<json::Json>(R"({"keyField": "keyObj", "field": {"keyInt": {}}})");


    // Use case expected events
    auto expectedEvent1 = std::make_shared<json::Json>(R"({"keyField":"keyObj","field":{"keyInt":49,"keyString":"hello","keyBool":true,"keyNull":null,"keyArray":["value"]}})");
    auto expectedEvent2 = std::make_shared<json::Json>(R"({"keyField":"keyObj","field":{"hi": "bye", "keyInt":49,"keyString":"hello","keyBool":true,"keyNull":null,"keyArray":["value"]}})");
    auto expectedEvent3 = std::make_shared<json::Json>(R"({"keyField":"keyObj","field":{"keyInt":49,"keyString":"hello","keyBool":true,"keyNull":null,"keyArray":["value"]}})");

    // Use cases
    result::Result<Event> result = op(event1);
    ASSERT_TRUE(result.success());
    ASSERT_EQ(*result.payload(), *expectedEvent1);

    result = op(event2);
    ASSERT_TRUE(result.success());
    ASSERT_EQ(*result.payload(), *expectedEvent2);

    result = op(event3);
    ASSERT_TRUE(result.success());
    ASSERT_EQ(*result.payload(), *expectedEvent3);

}


TEST(getOpBuilderHelperMergeValue, failMatchTypesByReference)
{
    // Event template
    json::Json eventTemplate {R"({
        "refObject": {
            "keyInt": 49,
            "keyString": "hello",
            "keyBool": true,
            "keyNull": null,
            "keyObject": {"key": "value"},
            "keyArray": ["value"]
        }
    })"};

    // Operation
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+merge_value"},
                                 std::vector<std::string> {"$refObject", "$keyField"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto op = std::apply(bld::getOpBuilderHelperMergeValue(schemf::mocks::EmptySchema::create()), tuple)
                  ->getPtr<Term<EngineOp>>()
                  ->getFn();

    // Use case events
    auto event1 = std::make_shared<json::Json>(eventTemplate);
    event1->setString("keyInt", "/keyField");
    auto event2 = std::make_shared<json::Json>(eventTemplate);
    event2->setString("keyString", "/keyField");
    auto event3 = std::make_shared<json::Json>(eventTemplate);
    event3->setString("keyBool", "/keyField");
    auto event4 = std::make_shared<json::Json>(eventTemplate);
    event4->setString("keyNull", "/keyField");
    auto event5 = std::make_shared<json::Json>(eventTemplate);
    event5->setString("keyObject", "/keyField");
    auto event6 = std::make_shared<json::Json>(eventTemplate);
    event6->setString("keyArray", "/keyField");

    // Use case expected events
    auto expectedEvent1 = std::make_shared<json::Json>(eventTemplate);
    expectedEvent1->setString("keyInt", "/keyField");
    expectedEvent1->setInt(49, "/field");
    auto expectedEvent2 = std::make_shared<json::Json>(eventTemplate);
    expectedEvent2->setString("keyString", "/keyField");
    expectedEvent2->setString("hello", "/field");
    auto expectedEvent3 = std::make_shared<json::Json>(eventTemplate);
    expectedEvent3->setString("keyBool", "/keyField");
    expectedEvent3->setBool(true, "/field");
    auto expectedEvent4 = std::make_shared<json::Json>(eventTemplate);
    expectedEvent4->setString("keyNull", "/keyField");
    expectedEvent4->setNull("/field");
    auto expectedEvent5 = std::make_shared<json::Json>(eventTemplate);
    expectedEvent5->setString("keyObject", "/keyField");
    expectedEvent5->set("/field", json::Json {R"({"key": "value"})"});
    auto expectedEvent6 = std::make_shared<json::Json>(eventTemplate);
    expectedEvent6->setString("keyArray", "/keyField");
    expectedEvent6->set("/field", json::Json {R"(["value"])"});

    // Use cases
    result::Result<Event> result = op(event1);
    ASSERT_TRUE(result.failure());

    result = op(event2);
    ASSERT_TRUE(result.failure());

    result = op(event3);
    ASSERT_TRUE(result.failure());

    result = op(event4);
    ASSERT_TRUE(result.failure());

    result = op(event5);
    ASSERT_TRUE(result.failure());

    result = op(event6);
    ASSERT_TRUE(result.failure());
}


TEST(getOpBuilderHelperMergeValue, SuccessByReference)
{
    // Event template
    json::Json eventTemplate {R"({
        "keyField": "keyObject",
        "refObject": {
            "keyObject": {"key": "value"}
        }
    })"};

    // Operation
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+merge_value"},
                                 std::vector<std::string> {"$refObject", "$keyField"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto op = std::apply(bld::getOpBuilderHelperMergeValue(schemf::mocks::EmptySchema::create()), tuple)
                  ->getPtr<Term<EngineOp>>()
                  ->getFn();

    // Use case events
    auto event1 = std::make_shared<json::Json>(eventTemplate);
    event1->setObject("/field");

    auto event2 = std::make_shared<json::Json>(eventTemplate);
    event2->setString("testString", "/field/keyString");

    // Use case expected events
    auto expectedEvent1 = std::make_shared<json::Json>(eventTemplate);
    expectedEvent1->set("/field", (json::Json {eventTemplate}).getJson("/refObject/keyObject").value_or(json::Json {}));

    auto expectedEvent2 = std::make_shared<json::Json>(eventTemplate);
    expectedEvent2->set("/field", (json::Json {eventTemplate}).getJson("/refObject/keyObject").value_or(json::Json {}));
    expectedEvent2->setString("testString", "/field/keyString");

    // Use cases
    result::Result<Event> result = op(event1);
    ASSERT_TRUE(result.success());
    ASSERT_EQ(*result.payload(), *expectedEvent1);

    result = op(event2);
    ASSERT_TRUE(result.success());
    ASSERT_EQ(*result.payload(), *expectedEvent2);
}

TEST(getOpBuilderHelperMergeValue, KeyNotMatchByDefinition)
{
    // Definition template
    json::Json definitionTemplate {R"({
        "defObject": {
            "keyInt": 49,
            "keyString": "hello",
            "keyBool": true,
            "keyNull": null,
            "keyObject": {"key": "value"},
            "keyArray": ["value"]
        }
    })"};

    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+merge_value"},
                                 std::vector<std::string> {"$defObject", "$keyField"},
                                 std::make_shared<defs::Definitions>(definitionTemplate));

    auto event = std::make_shared<json::Json>(R"({"keyField": "wrongKey"})");

    auto op = std::apply(bld::getOpBuilderHelperMergeValue(schemf::mocks::EmptySchema::create()), tuple)
                  ->getPtr<Term<EngineOp>>()
                  ->getFn();

    result::Result<Event> result = op(event);
    ASSERT_FALSE(result.success());
}

TEST(getOpBuilderHelperMergeValue, KeyNotMatchByReference)
{
    // Event template
    json::Json eventTemplate {R"({
        "refObject": {
            "keyInt": 49,
            "keyString": "hello",
            "keyBool": true,
            "keyNull": null,
            "keyObject": {"key": "value"},
            "keyArray": ["value"]
        }
    })"};

    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+merge_value"},
                                 std::vector<std::string> {"$refObject", "$keyField"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto event = std::make_shared<json::Json>(eventTemplate);
    event->setString("wrongKey", "/keyField");

    auto op = std::apply(bld::getOpBuilderHelperMergeValue(schemf::mocks::EmptySchema::create()), tuple)
                  ->getPtr<Term<EngineOp>>()
                  ->getFn();

    result::Result<Event> result = op(event);
    ASSERT_FALSE(result.success());
}

TEST(getOpBuilderHelperMergeValue, KeyNotFound)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+merge_value"},
                                 std::vector<std::string> {"$defObject", "$keyField"},
                                 std::make_shared<defs::Definitions>(json::Json(R"({"defObject": {"key": "value"}})")));

    auto event = std::make_shared<json::Json>(R"({"wrongKey": "key"})");

    auto op = std::apply(bld::getOpBuilderHelperMergeValue(schemf::mocks::EmptySchema::create()), tuple)
                  ->getPtr<Term<EngineOp>>()
                  ->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(getOpBuilderHelperMergeValue, KeyIsNotString)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+merge_value"},
                                 std::vector<std::string> {"$defObject", "$keyField"},
                                 std::make_shared<defs::Definitions>(json::Json(R"({"defObject": {"key": "value"}})")));

    auto event = std::make_shared<json::Json>(R"({"keyField": 1})");

    auto op = std::apply(bld::getOpBuilderHelperMergeValue(schemf::mocks::EmptySchema::create()), tuple)
                  ->getPtr<Term<EngineOp>>()
                  ->getFn();

    result::Result<Event> result = op(event);

    ASSERT_FALSE(result.success());
}

TEST(getOpBuilderHelperMergeValue, DefinitionNotFound)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+merge_value"},
                                 std::vector<std::string> {"$def", "$keyField"},
                                 std::make_shared<defs::Definitions>(json::Json(R"({"defObject": {"key": "value"}})")));

    auto event1 = std::make_shared<json::Json>(R"({"defObject": {"key": "value"}, "keyField": "key"})");

    auto op = std::apply(bld::getOpBuilderHelperMergeValue(schemf::mocks::EmptySchema::create()), tuple)
                  ->getPtr<Term<EngineOp>>()
                  ->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_FALSE(result.success());
}

TEST(getOpBuilderHelperMergeValue, ParameterIsNotAnObject)
{
    // Parameter: Definition
    auto tuple1 = std::make_tuple(std::string {"/field"},
                                  std::string {"+merge_value"},
                                  std::vector<std::string> {"$defInt", "$keyField"},
                                  std::make_shared<defs::Definitions>(json::Json(R"({"defInt": 1})")));

    ASSERT_THROW(std::apply(bld::getOpBuilderHelperMergeValue(schemf::mocks::EmptySchema::create()), tuple1),
                 std::runtime_error);

    tuple1 = std::make_tuple(std::string {"/field"},
                             std::string {"+merge_value"},
                             std::vector<std::string> {"$defArray", "$keyField"},
                             std::make_shared<defs::Definitions>(json::Json(R"({"defArray": [1, 2, 3]})")));

    ASSERT_THROW(std::apply(bld::getOpBuilderHelperMergeValue(schemf::mocks::EmptySchema::create()), tuple1),
                 std::runtime_error);

    // Parameter: Reference
    auto tuple2 = std::make_tuple(std::string {"/field"},
                                  std::string {"+merge_value"},
                                  std::vector<std::string> {"$refArray", "$keyField"},
                                  std::make_shared<defs::mocks::FailDef>());

    auto event = std::make_shared<json::Json>(R"({"refArray": [1, 2, 3], "keyField": "key"})");

    auto op = std::apply(bld::getOpBuilderHelperMergeValue(schemf::mocks::EmptySchema::create()), tuple2)
                  ->getPtr<Term<EngineOp>>()
                  ->getFn();

    result::Result<Event> result = op(event);
    ASSERT_FALSE(result.success());
}

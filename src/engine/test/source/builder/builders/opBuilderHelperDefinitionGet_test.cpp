#include <any>
#include <gtest/gtest.h>
#include <vector>

#include <baseTypes.hpp>
#include <defs/defs.hpp>
#include <defs/mocks/failDef.hpp>

#include "opBuilderHelperMap.hpp"

using namespace base;
namespace bld = builder::internals::builders;

TEST(OpBuilderHelperDefinitionGet, Builds)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+definition_get"},
                                 std::vector<std::string> {"$defObject", "$keyField"},
                                 std::make_shared<defs::Definitions>(json::Json(R"({"defObject": {"key": "value"}})")));
    ASSERT_NO_THROW(std::apply(bld::opBuilderHelperDefinitionGet, tuple));
}

TEST(OpBuilderHelperDefinitionGet, EmptyParameters)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+definition_get"},
                                 std::vector<std::string> {},
                                 std::make_shared<defs::Definitions>(json::Json(R"({"defObject": {"key": "value"}})")));
    ASSERT_THROW(std::apply(bld::opBuilderHelperDefinitionGet, tuple), std::runtime_error);
}

TEST(OpBuilderHelperDefinitionGet, WrongSizeParameters)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+definition_get"},
                                 std::vector<std::string> {"$defObject"},
                                 std::make_shared<defs::Definitions>(json::Json(R"({"defObject": {"key": "value"}})")));
    ASSERT_THROW(std::apply(bld::opBuilderHelperDefinitionGet, tuple), std::runtime_error);
}

TEST(OpBuilderHelperDefinitionGet, WrongTypeParameters)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+definition_get"},
                                 std::vector<std::string> {"defObject", "$keyField"},
                                 std::make_shared<defs::Definitions>(json::Json(R"({"defObject": {"key": "value"}})")));
    ASSERT_THROW(std::apply(bld::opBuilderHelperDefinitionGet, tuple), std::runtime_error);

    tuple = std::make_tuple(std::string {"/field"},
                            std::string {"+definition_get"},
                            std::vector<std::string> {"$defObject", "keyField"},
                            std::make_shared<defs::Definitions>(json::Json(R"({"defObject": {"key": "value"}})")));
    ASSERT_THROW(std::apply(bld::opBuilderHelperDefinitionGet, tuple), std::runtime_error);
}

TEST(OpBuilderHelperDefinitionGet, DefinitionIsNotAnObject)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+definition_get"},
                                 std::vector<std::string> {"$defInt", "$keyField"},
                                 std::make_shared<defs::Definitions>(json::Json(R"({"defInt": 1})")));

    ASSERT_THROW(std::apply(bld::opBuilderHelperDefinitionGet, tuple), std::runtime_error);
}

TEST(OpBuilderHelperDefinitionGet, Success)
{
    // Event template
    json::Json eventTemplate {R"({
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
                                 std::string {"+definition_get"},
                                 std::vector<std::string> {"$defObject", "$keyField"},
                                 std::make_shared<defs::Definitions>(eventTemplate));

    auto op = std::apply(bld::opBuilderHelperDefinitionGet, tuple)->getPtr<Term<EngineOp>>()->getFn();

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

TEST(OpBuilderHelperDefinitionGet, FailKeyNotMatch)
{
    // Event template
    json::Json eventTemplate {R"({
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
                                 std::string {"+definition_get"},
                                 std::vector<std::string> {"$defObject", "$keyField"},
                                 std::make_shared<defs::Definitions>(eventTemplate));

    auto event1 = std::make_shared<json::Json>(eventTemplate);
    event1->setString("wrongKey", "/keyField");

    auto op = std::apply(bld::opBuilderHelperDefinitionGet, tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);
    ASSERT_FALSE(result.success());
}

TEST(OpBuilderHelperDefinitionGet, KeyNotFound)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+definition_get"},
                                 std::vector<std::string> {"$defObject", "$keyField"},
                                 std::make_shared<defs::Definitions>(json::Json(R"({"defObject": {"key": "value"}})")));

    auto event1 = std::make_shared<json::Json>(R"({"defObject": {"key": "value"}})");

    auto op = std::apply(bld::opBuilderHelperDefinitionGet, tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_FALSE(result.success());
}

TEST(OpBuilderHelperDefinitionGet, KeyIsNotString)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+definition_get"},
                                 std::vector<std::string> {"$defObject", "$keyField"},
                                 std::make_shared<defs::Definitions>(json::Json(R"({"defObject": {"key": "value"}})")));

    auto event1 = std::make_shared<json::Json>(R"({"defObject": {"key": "value"}, "keyField": 1})");

    auto op = std::apply(bld::opBuilderHelperDefinitionGet, tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_FALSE(result.success());
}

TEST(OpBuilderHelperDefinitionGet, DefinitionIsAnArray)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+definition_get"},
                                 std::vector<std::string> {"$defArray", "$keyField"},
                                 std::make_shared<defs::Definitions>(json::Json(R"({"defArray": [1, 2, 3]})")));

    auto event1 = std::make_shared<json::Json>(R"({"defArray": [1, 2, 3], "keyField": "key"})");

    auto op = std::apply(bld::opBuilderHelperDefinitionGet, tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_FALSE(result.success());
}

TEST(OpBuilderHelperDefinitionGet, DefinitionNotFound)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+definition_get"},
                                 std::vector<std::string> {"$def", "$keyField"},
                                 std::make_shared<defs::Definitions>(json::Json(R"({"defObject": {"key": "value"}})")));

    auto event1 = std::make_shared<json::Json>(R"({"defObject": {"key": "value"}, "keyField": "key"})");

    auto op = std::apply(bld::opBuilderHelperDefinitionGet, tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_FALSE(result.success());
}

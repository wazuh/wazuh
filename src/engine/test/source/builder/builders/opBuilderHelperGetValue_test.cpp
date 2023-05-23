#include <any>
#include <gtest/gtest.h>
#include <vector>

#include <baseTypes.hpp>
#include <defs/defs.hpp>
#include <defs/mocks/failDef.hpp>

#include "opBuilderHelperMap.hpp"

using namespace base;
namespace bld = builder::internals::builders;

TEST(OpBuilderHelperGetValue, Builds)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+get_value"},
                                 std::vector<std::string> {"$defObject", "$keyField"},
                                 std::make_shared<defs::Definitions>(json::Json(R"({"defObject": {"key": "value"}})")));
    ASSERT_NO_THROW(std::apply(bld::opBuilderHelperGetValue, tuple));
}

TEST(OpBuilderHelperGetValue, EmptyParameters)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+get_value"},
                                 std::vector<std::string> {},
                                 std::make_shared<defs::Definitions>(json::Json(R"({"defObject": {"key": "value"}})")));
    ASSERT_THROW(std::apply(bld::opBuilderHelperGetValue, tuple), std::runtime_error);
}

TEST(OpBuilderHelperGetValue, WrongSizeParameters)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+get_value"},
                                 std::vector<std::string> {"$defObject"},
                                 std::make_shared<defs::Definitions>(json::Json(R"({"defObject": {"key": "value"}})")));
    ASSERT_THROW(std::apply(bld::opBuilderHelperGetValue, tuple), std::runtime_error);
}

TEST(OpBuilderHelperGetValue, WrongTypeParameters)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+get_value"},
                                 std::vector<std::string> {"defObject", "$keyField"},
                                 std::make_shared<defs::Definitions>(json::Json(R"({"defObject": {"key": "value"}})")));
    ASSERT_THROW(std::apply(bld::opBuilderHelperGetValue, tuple), std::runtime_error);

    tuple = std::make_tuple(std::string {"/field"},
                            std::string {"+get_value"},
                            std::vector<std::string> {"$defObject", "keyField"},
                            std::make_shared<defs::Definitions>(json::Json(R"({"defObject": {"key": "value"}})")));
    ASSERT_THROW(std::apply(bld::opBuilderHelperGetValue, tuple), std::runtime_error);
}

TEST(OpBuilderHelperGetValue, DefinitionIsNotAnObject)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+get_value"},
                                 std::vector<std::string> {"$defInt", "$keyField"},
                                 std::make_shared<defs::Definitions>(json::Json(R"({"defInt": 1})")));

    ASSERT_THROW(std::apply(bld::opBuilderHelperGetValue, tuple), std::runtime_error);
}

TEST(OpBuilderHelperGetValue, Success)
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

    auto op = std::apply(bld::opBuilderHelperGetValue, tuple)->getPtr<Term<EngineOp>>()->getFn();

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

TEST(OpBuilderHelperGetValue, FailKeyNotMatch)
{
    // Event template
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

    auto event1 = std::make_shared<json::Json>(definitionTemplate);
    event1->setString("wrongKey", "/keyField");

    auto op = std::apply(bld::opBuilderHelperGetValue, tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);
    ASSERT_FALSE(result.success());
}

TEST(OpBuilderHelperGetValue, KeyNotFound)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+get_value"},
                                 std::vector<std::string> {"$defObject", "$keyField"},
                                 std::make_shared<defs::Definitions>(json::Json(R"({"defObject": {"key": "value"}})")));

    auto event1 = std::make_shared<json::Json>(R"({"defObject": {"key": "value"}})");

    auto op = std::apply(bld::opBuilderHelperGetValue, tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_FALSE(result.success());
}

TEST(OpBuilderHelperGetValue, KeyIsNotString)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+get_value"},
                                 std::vector<std::string> {"$defObject", "$keyField"},
                                 std::make_shared<defs::Definitions>(json::Json(R"({"defObject": {"key": "value"}})")));

    auto event1 = std::make_shared<json::Json>(R"({"defObject": {"key": "value"}, "keyField": 1})");

    auto op = std::apply(bld::opBuilderHelperGetValue, tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_FALSE(result.success());
}

TEST(OpBuilderHelperGetValue, DefinitionIsAnArray)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+get_value"},
                                 std::vector<std::string> {"$defArray", "$keyField"},
                                 std::make_shared<defs::Definitions>(json::Json(R"({"defArray": [1, 2, 3]})")));

    auto event1 = std::make_shared<json::Json>(R"({"defArray": [1, 2, 3], "keyField": "key"})");

    auto op = std::apply(bld::opBuilderHelperGetValue, tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_FALSE(result.success());
}

TEST(OpBuilderHelperGetValue, DefinitionNotFound)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+get_value"},
                                 std::vector<std::string> {"$def", "$keyField"},
                                 std::make_shared<defs::Definitions>(json::Json(R"({"defObject": {"key": "value"}})")));

    auto event1 = std::make_shared<json::Json>(R"({"defObject": {"key": "value"}, "keyField": "key"})");

    auto op = std::apply(bld::opBuilderHelperGetValue, tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_FALSE(result.success());
}

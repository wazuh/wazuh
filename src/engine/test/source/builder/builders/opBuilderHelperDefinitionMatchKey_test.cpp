#include <any>
#include <gtest/gtest.h>
#include <vector>

#include <baseTypes.hpp>
#include <defs/defs.hpp>
#include <defs/mocks/failDef.hpp>

#include "opBuilderHelperFilter.hpp"

using namespace base;
namespace bld = builder::internals::builders;

TEST(OpBuilderHelperDefinitionMatchKey, Builds)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+definition_match_key"},
                                 std::vector<std::string> {"$defObject"},
                                 std::make_shared<defs::Definitions>(json::Json(R"({"defObject": {"key": "value"}})")));
    ASSERT_NO_THROW(std::apply(bld::opBuilderHelperDefinitionMatchKey, tuple));
}

TEST(OpBuilderHelperDefinitionMatchKey, EmptyParameters)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+definition_match_key"},
                                 std::vector<std::string> {},
                                 std::make_shared<defs::Definitions>(json::Json(R"({"defObject": {"key": "value"}})")));
    ASSERT_THROW(std::apply(bld::opBuilderHelperDefinitionMatchKey, tuple), std::runtime_error);
}

TEST(OpBuilderHelperDefinitionMatchKey, WrongSizeParameters)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+definition_match_key"},
                                 std::vector<std::string> {"$defObject", "$defObject"},
                                 std::make_shared<defs::Definitions>(json::Json(R"({"defObject": {"key": "value"}})")));
    ASSERT_THROW(std::apply(bld::opBuilderHelperDefinitionMatchKey, tuple), std::runtime_error);
}

TEST(OpBuilderHelperDefinitionMatchKey, WrongTypeParameters)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+definition_match_key"},
                                 std::vector<std::string> {"defObject"},
                                 std::make_shared<defs::Definitions>(json::Json(R"({"defObject": {"key": "value"}})")));
    ASSERT_THROW(std::apply(bld::opBuilderHelperDefinitionMatchKey, tuple), std::runtime_error);
}

TEST(OpBuilderHelperDefinitionMatchKey, DefinitionIsNotAnObject)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+definition_match_key"},
                                 std::vector<std::string> {"$defInt"},
                                 std::make_shared<defs::Definitions>(json::Json(R"({"defInt": 1})")));

    ASSERT_THROW(std::apply(bld::opBuilderHelperDefinitionMatchKey, tuple), std::runtime_error);
}

TEST(OpBuilderHelperDefinitionMatchKey, Success)
{
    auto tuple = std::make_tuple(
        std::string {"/field"},
        std::string {"+definition_match_key"},
        std::vector<std::string> {"$defObject"},
        std::make_shared<defs::Definitions>(json::Json(
            R"({"defObject": {"keyInt": 49, "keyString": "hello", "keyBool": true, "keyNull": null, "keyObject": {"key": "value"}}})")));

    auto event1 = std::make_shared<json::Json>(
        R"({"defObject": {"keyInt": 49, "keyString": "hello", "keyBool": true, "keyNull": null, "keyObject": {"key": "value"}}, "field": "keyInt"})");
    auto event2 = std::make_shared<json::Json>(
        R"({"defObject": {"keyInt": 49, "keyString": "hello", "keyBool": true, "keyNull": null, "keyObject": {"key": "value"}}, "field": "keyString"})");
    auto event3 = std::make_shared<json::Json>(
        R"({"defObject": {"keyInt": 49, "keyString": "hello", "keyBool": true, "keyNull": null, "keyObject": {"key": "value"}}, "field": "keyBool"})");
    auto event4 = std::make_shared<json::Json>(
        R"({"defObject": {"keyInt": 49, "keyString": "hello", "keyBool": true, "keyNull": null, "keyObject": {"key": "value"}}, "field": "keyNull"})");
    auto event5 = std::make_shared<json::Json>(
        R"({"defObject": {"keyInt": 49, "keyString": "hello", "keyBool": true, "keyNull": null, "keyObject": {"key": "value"}}, "field": "keyObject"})");

    auto op = std::apply(bld::opBuilderHelperDefinitionMatchKey, tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);
    ASSERT_TRUE(result.success());

    result = op(event2);
    ASSERT_TRUE(result.success());

    result = op(event3);
    ASSERT_TRUE(result.success());

    result = op(event4);
    ASSERT_TRUE(result.success());

    result = op(event5);
    ASSERT_TRUE(result.success());
}

TEST(OpBuilderHelperDefinitionMatchKey, FailKeyNotMatch)
{
    auto tuple = std::make_tuple(
        std::string {"/field"},
        std::string {"+definition_match_key"},
        std::vector<std::string> {"$defObject"},
        std::make_shared<defs::Definitions>(json::Json(
            R"({"defObject": {"keyInt": 49, "keyString": "hello", "keyBool": true, "keyNull": null, "keyObject": {"key": "value"}}})")));

    auto event1 = std::make_shared<json::Json>(
        R"({"defObject": {"keyInt": 49, "keyString": "hello", "keyBool": true, "keyNull": null, "keyObject": {"key": "value"}}, "field": "wrongKey"})");

    auto op = std::apply(bld::opBuilderHelperDefinitionMatchKey, tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);
    ASSERT_FALSE(result.success());
}

TEST(OpBuilderHelperDefinitionMatchKey, TargetNotFound)
{
    auto tuple = std::make_tuple(std::string {"/targetField"},
                                 std::string {"+definition_match_key"},
                                 std::vector<std::string> {"$defObject"},
                                 std::make_shared<defs::Definitions>(json::Json(R"({"defObject": {"key": "value"}})")));

    auto event1 = std::make_shared<json::Json>(R"({"defObject": {"key": "value"}, "field": "key"})");

    auto op = std::apply(bld::opBuilderHelperDefinitionMatchKey, tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_FALSE(result.success());
}

TEST(OpBuilderHelperDefinitionMatchKey, TargetIsNotString)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+definition_match_key"},
                                 std::vector<std::string> {"$defObject"},
                                 std::make_shared<defs::Definitions>(json::Json(R"({"defObject": {"key": "value"}})")));

    auto event1 = std::make_shared<json::Json>(R"({"defObject": {"key": "value"}, "field": 1})");

    auto op = std::apply(bld::opBuilderHelperDefinitionMatchKey, tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_FALSE(result.success());
}

TEST(OpBuilderHelperDefinitionMatchKey, DefinitionIsAnArray)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+definition_match_key"},
                                 std::vector<std::string> {"$defArray"},
                                 std::make_shared<defs::Definitions>(json::Json(R"({"defArray": [1, 2, 3]})")));

    auto event1 = std::make_shared<json::Json>(R"({"defArray": [1, 2, 3], "field": "key"})");

    auto op = std::apply(bld::opBuilderHelperDefinitionMatchKey, tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_FALSE(result.success());
}

TEST(OpBuilderHelperDefinitionMatchKey, DefinitionNotFound)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+definition_match_key"},
                                 std::vector<std::string> {"$def"},
                                 std::make_shared<defs::Definitions>(json::Json(R"({"defObject": {"key": "value"}})")));

    auto event1 = std::make_shared<json::Json>(R"({"defObject": {"key": "value"}, "field": "key"})");

    auto op = std::apply(bld::opBuilderHelperDefinitionMatchKey, tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_FALSE(result.success());
}

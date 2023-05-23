#include <any>
#include <gtest/gtest.h>
#include <vector>

#include <baseTypes.hpp>
#include <defs/defs.hpp>
#include <defs/mocks/failDef.hpp>

#include "opBuilderHelperFilter.hpp"

using namespace base;
namespace bld = builder::internals::builders;

TEST(opBuilderHelperMatchKey, Builds)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+match_key"},
                                 std::vector<std::string> {"$defObject"},
                                 std::make_shared<defs::Definitions>(json::Json(R"({"defObject": {"key": "value"}})")));
    ASSERT_NO_THROW(std::apply(bld::opBuilderHelperMatchKey, tuple));
}

TEST(opBuilderHelperMatchKey, EmptyParameters)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+match_key"},
                                 std::vector<std::string> {},
                                 std::make_shared<defs::Definitions>(json::Json(R"({"defObject": {"key": "value"}})")));
    ASSERT_THROW(std::apply(bld::opBuilderHelperMatchKey, tuple), std::runtime_error);
}

TEST(opBuilderHelperMatchKey, WrongSizeParameters)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+match_key"},
                                 std::vector<std::string> {"$defObject", "$defObject"},
                                 std::make_shared<defs::Definitions>(json::Json(R"({"defObject": {"key": "value"}})")));
    ASSERT_THROW(std::apply(bld::opBuilderHelperMatchKey, tuple), std::runtime_error);
}

TEST(opBuilderHelperMatchKey, Success)
{
    auto tuple = std::make_tuple(
        std::string {"/field"},
        std::string {"+match_key"},
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

    auto op = std::apply(bld::opBuilderHelperMatchKey, tuple)->getPtr<Term<EngineOp>>()->getFn();

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

TEST(opBuilderHelperMatchKey, FailKeyNotMatch)
{
    auto tuple = std::make_tuple(
        std::string {"/field"},
        std::string {"+match_key"},
        std::vector<std::string> {"$defObject"},
        std::make_shared<defs::Definitions>(json::Json(
            R"({"defObject": {"keyInt": 49, "keyString": "hello", "keyBool": true, "keyNull": null, "keyObject": {"key": "value"}}})")));

    auto event1 = std::make_shared<json::Json>(
        R"({"defObject": {"keyInt": 49, "keyString": "hello", "keyBool": true, "keyNull": null, "keyObject": {"key": "value"}}, "field": "wrongKey"})");

    auto op = std::apply(bld::opBuilderHelperMatchKey, tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);
    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperMatchKey, TargetNotFound)
{
    auto tuple = std::make_tuple(std::string {"/targetField"},
                                 std::string {"+match_key"},
                                 std::vector<std::string> {"$defObject"},
                                 std::make_shared<defs::Definitions>(json::Json(R"({"defObject": {"key": "value"}})")));

    auto event1 = std::make_shared<json::Json>(R"({"defObject": {"key": "value"}, "field": "key"})");

    auto op = std::apply(bld::opBuilderHelperMatchKey, tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperMatchKey, TargetIsNotString)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+match_key"},
                                 std::vector<std::string> {"$defObject"},
                                 std::make_shared<defs::Definitions>(json::Json(R"({"defObject": {"key": "value"}})")));

    auto event1 = std::make_shared<json::Json>(R"({"defObject": {"key": "value"}, "field": 1})");

    auto op = std::apply(bld::opBuilderHelperMatchKey, tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperMatchKey, DefinitionIsAnArray)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+match_key"},
                                 std::vector<std::string> {"$defArray"},
                                 std::make_shared<defs::Definitions>(json::Json(R"({"defArray": [1, 2, 3]})")));

    auto event1 = std::make_shared<json::Json>(R"({"defArray": [1, 2, 3], "field": "key"})");

    auto op = std::apply(bld::opBuilderHelperMatchKey, tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperMatchKey, DefinitionNotFound)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+match_key"},
                                 std::vector<std::string> {"$def"},
                                 std::make_shared<defs::Definitions>(json::Json(R"({"defObject": {"key": "value"}})")));

    auto event1 = std::make_shared<json::Json>(R"({"defObject": {"key": "value"}, "field": "key"})");

    auto op = std::apply(bld::opBuilderHelperMatchKey, tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_FALSE(result.success());
}


TEST(opBuilderHelperMatchKey, WrongTypeParameters)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+match_key"},
                                 std::vector<std::string> {"defObject"},
                                 std::make_shared<defs::Definitions>(json::Json(R"({"defObject": {"key": "value"}})")));

    auto event = std::make_shared<json::Json>(R"({"field": "key"})");

    auto op = std::apply(bld::opBuilderHelperMatchKey, tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);
    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperMatchKey, DefinitionIsNotAnObject)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+match_key"},
                                 std::vector<std::string> {"$defInt"},
                                 std::make_shared<defs::Definitions>(json::Json(R"({"defInt": 1})")));

    auto event = std::make_shared<json::Json>(R"({"field": "key"})");

    auto op = std::apply(bld::opBuilderHelperMatchKey, tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);
    ASSERT_FALSE(result.success());
}

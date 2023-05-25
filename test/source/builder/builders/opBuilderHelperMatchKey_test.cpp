#include <any>
#include <gtest/gtest.h>
#include <vector>

#include <baseTypes.hpp>
#include <defs/defs.hpp>
#include <defs/mocks/failDef.hpp>
#include <schemf/mocks/emptySchema.hpp>

#include "opBuilderHelperFilter.hpp"

using namespace base;
namespace bld = builder::internals::builders;

TEST(opBuilderHelperMatchKey, Builds)
{
    // Parameter: Definition
    auto tuple1 =
        std::make_tuple(std::string {"/field"},
                        std::string {"+match_key"},
                        std::vector<std::string> {"$defObject"},
                        std::make_shared<defs::Definitions>(json::Json(R"({"defObject": {"key": "value"}})")));
    ASSERT_NO_THROW(std::apply(bld::getOpBuilderHelperMatchKey(schemf::mocks::EmptySchema::create()), tuple1));

    // Parameter: Reference
    auto tuple2 = std::make_tuple(std::string {"/field"},
                                  std::string {"+match_key"},
                                  std::vector<std::string> {"$refObject"},
                                  std::make_shared<defs::mocks::FailDef>());
    ASSERT_NO_THROW(std::apply(bld::getOpBuilderHelperMatchKey(schemf::mocks::EmptySchema::create()), tuple2));
}

TEST(opBuilderHelperMatchKey, EmptyParameters)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+match_key"},
                                 std::vector<std::string> {},
                                 std::make_shared<defs::mocks::FailDef>());
    ASSERT_THROW(std::apply(bld::getOpBuilderHelperMatchKey(schemf::mocks::EmptySchema::create()), tuple),
                 std::runtime_error);
}

TEST(opBuilderHelperMatchKey, WrongSizeParameters)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+match_key"},
                                 std::vector<std::string> {"$defObject", "$defObject"},
                                 std::make_shared<defs::Definitions>(json::Json(R"({"defObject": {"key": "value"}})")));
    ASSERT_THROW(std::apply(bld::getOpBuilderHelperMatchKey(schemf::mocks::EmptySchema::create()), tuple),
                 std::runtime_error);
}

TEST(opBuilderHelperMatchKey, WrongTypeParameters)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+match_key"},
                                 std::vector<std::string> {"defObject"},
                                 std::make_shared<defs::Definitions>(json::Json(R"({"defObject": {"key": "value"}})")));

    ASSERT_THROW(std::apply(bld::getOpBuilderHelperMatchKey(schemf::mocks::EmptySchema::create()), tuple),
                 std::runtime_error);
}

TEST(opBuilderHelperMatchKey, SuccessByDefinition)
{
    auto tuple = std::make_tuple(
        std::string {"/field"},
        std::string {"+match_key"},
        std::vector<std::string> {"$defObject"},
        std::make_shared<defs::Definitions>(json::Json(
            R"({"defObject": {"keyInt": 49, "keyBool": true, "keyString": "hello", "keyNull": null, "keyObject": {"key": "value"}, "keyArray": [1, 2, 3]}})")));

    auto event1 = std::make_shared<json::Json>(R"({"field": "keyInt"})");
    auto event2 = std::make_shared<json::Json>(R"({"field": "keyBool"})");
    auto event3 = std::make_shared<json::Json>(R"({"field": "keyString"})");
    auto event4 = std::make_shared<json::Json>(R"({"field": "keyNull"})");
    auto event5 = std::make_shared<json::Json>(R"({"field": "keyObject"})");
    auto event6 = std::make_shared<json::Json>(R"({"field": "keyArray"})");

    auto op = std::apply(bld::getOpBuilderHelperMatchKey(schemf::mocks::EmptySchema::create()), tuple)
                  ->getPtr<Term<EngineOp>>()
                  ->getFn();

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

    result = op(event6);
    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperMatchKey, SuccessByReference)
{
    // Event template
    json::Json eventTemplate {
        R"({"refObject": {"keyInt": 49, "keyBool": true, "keyString": "hello", "keyNull": null, "keyObject": {"key": "value"}, "keyArray": [1, 2, 3]}})"};

    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+match_key"},
                                 std::vector<std::string> {"$refObject"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto event1 = std::make_shared<json::Json>(eventTemplate);
    event1->setString("keyInt", "/field");
    auto event2 = std::make_shared<json::Json>(eventTemplate);
    event2->setString("keyBool", "/field");
    auto event3 = std::make_shared<json::Json>(eventTemplate);
    event3->setString("keyString", "/field");
    auto event4 = std::make_shared<json::Json>(eventTemplate);
    event4->setString("keyNull", "/field");
    auto event5 = std::make_shared<json::Json>(eventTemplate);
    event5->setString("keyObject", "/field");
    auto event6 = std::make_shared<json::Json>(eventTemplate);
    event6->setString("keyArray", "/field");

    auto op = std::apply(bld::getOpBuilderHelperMatchKey(schemf::mocks::EmptySchema::create()), tuple)
                  ->getPtr<Term<EngineOp>>()
                  ->getFn();

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

    result = op(event6);
    ASSERT_TRUE(result.success());
}

TEST(opBuilderHelperMatchKey, KeyNotMatchByDefinition)
{
    auto tuple = std::make_tuple(
        std::string {"/field"},
        std::string {"+match_key"},
        std::vector<std::string> {"$defObject"},
        std::make_shared<defs::Definitions>(json::Json(
            R"({"defObject": {"keyInt": 49, "keyString": "hello", "keyBool": true, "keyNull": null, "keyObject": {"key": "value"}}})")));

    auto event1 = std::make_shared<json::Json>(R"({"field": "wrongKey"})");

    auto op = std::apply(bld::getOpBuilderHelperMatchKey(schemf::mocks::EmptySchema::create()), tuple)
                  ->getPtr<Term<EngineOp>>()
                  ->getFn();

    result::Result<Event> result = op(event1);
    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperMatchKey, KeyNotMatchByReference)
{
    // Event template
    json::Json eventTemplate {
        R"({"refObject": {"keyInt": 49, "keyBool": true, "keyString": "hello", "keyNull": null, "keyObject": {"key": "value"}, "keyArray": [1, 2, 3]}})"};

    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+match_key"},
                                 std::vector<std::string> {"$refObject"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto event1 = std::make_shared<json::Json>(eventTemplate);
    event1->setString("wrongKey", "/field");

    auto op = std::apply(bld::getOpBuilderHelperMatchKey(schemf::mocks::EmptySchema::create()), tuple)
                  ->getPtr<Term<EngineOp>>()
                  ->getFn();

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

    auto op = std::apply(bld::getOpBuilderHelperMatchKey(schemf::mocks::EmptySchema::create()), tuple)
                  ->getPtr<Term<EngineOp>>()
                  ->getFn();

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

    auto op = std::apply(bld::getOpBuilderHelperMatchKey(schemf::mocks::EmptySchema::create()), tuple)
                  ->getPtr<Term<EngineOp>>()
                  ->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperMatchKey, ParameterNotFound)
{
    // Parameter: Definition
    auto tuple1 =
        std::make_tuple(std::string {"/field"},
                        std::string {"+match_key"},
                        std::vector<std::string> {"$def"},
                        std::make_shared<defs::Definitions>(json::Json(R"({"defObject": {"key": "value"}})")));

    auto event = std::make_shared<json::Json>(R"({"field": "key"})");

    auto op = std::apply(bld::getOpBuilderHelperMatchKey(schemf::mocks::EmptySchema::create()), tuple1)
                  ->getPtr<Term<EngineOp>>()
                  ->getFn();

    result::Result<Event> result = op(event);
    ASSERT_FALSE(result.success());

    // Parameter: Reference
    auto tuple2 = std::make_tuple(std::string {"/field"},
                                  std::string {"+match_key"},
                                  std::vector<std::string> {"$ref"},
                                  std::make_shared<defs::mocks::FailDef>());

    op = std::apply(bld::getOpBuilderHelperMatchKey(schemf::mocks::EmptySchema::create()), tuple2)
             ->getPtr<Term<EngineOp>>()
             ->getFn();

    result = op(event);
    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperMatchKey, ParameterIsNotAnObject)
{
    // Parameter: Definition
    auto tuple1 = std::make_tuple(std::string {"/field"},
                                  std::string {"+match_key"},
                                  std::vector<std::string> {"$defInt"},
                                  std::make_shared<defs::Definitions>(json::Json(R"({"defInt": 1})")));

    ASSERT_THROW(std::apply(bld::getOpBuilderHelperMatchKey(schemf::mocks::EmptySchema::create()), tuple1),
                 std::runtime_error);

    auto tuple2 = std::make_tuple(std::string {"/field"},
                                  std::string {"+match_key"},
                                  std::vector<std::string> {"$defArray"},
                                  std::make_shared<defs::Definitions>(json::Json(R"({"defArray": [1, 2, 3]})")));

    ASSERT_THROW(std::apply(bld::getOpBuilderHelperMatchKey(schemf::mocks::EmptySchema::create()), tuple2),
                 std::runtime_error);

    // Parameter: Reference
    auto tuple3 = std::make_tuple(std::string {"/field"},
                                  std::string {"+match_key"},
                                  std::vector<std::string> {"$ref"},
                                  std::make_shared<defs::mocks::FailDef>());

    auto event = std::make_shared<json::Json>(R"({"ref": "value", "field": "key"})");

    auto op = std::apply(bld::getOpBuilderHelperMatchKey(schemf::mocks::EmptySchema::create()), tuple3)
                  ->getPtr<Term<EngineOp>>()
                  ->getFn();

    result::Result<Event> result = op(event);
    ASSERT_FALSE(result.success());
}

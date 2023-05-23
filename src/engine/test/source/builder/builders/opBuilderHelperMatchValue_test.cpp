#include <any>
#include <gtest/gtest.h>
#include <vector>

#include <baseTypes.hpp>
#include <defs/defs.hpp>
#include <defs/mocks/failDef.hpp>

#include "opBuilderHelperFilter.hpp"

using namespace base;
namespace bld = builder::internals::builders;

TEST(opBuilderHelperMatchValue, Builds)
{
    // Parameter: Definition
    auto tuple1 = std::make_tuple(std::string {"/field"},
                                  std::string {"+match_value"},
                                  std::vector<std::string> {"$defArray"},
                                  std::make_shared<defs::Definitions>(json::Json(R"({"defArray": [1, 2, 3]})")));
    ASSERT_NO_THROW(std::apply(bld::opBuilderHelperMatchValue, tuple1));

    // Parameter: Reference
    auto tuple2 = std::make_tuple(std::string {"/field"},
                                  std::string {"+match_value"},
                                  std::vector<std::string> {"$refArray"},
                                  std::make_shared<defs::mocks::FailDef>());
    ASSERT_NO_THROW(std::apply(bld::opBuilderHelperMatchValue, tuple2));
}

TEST(opBuilderHelperMatchValue, EmptyParameters)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+match_value"},
                                 std::vector<std::string> {},
                                 std::make_shared<defs::mocks::FailDef>());
    ASSERT_THROW(std::apply(bld::opBuilderHelperMatchValue, tuple), std::runtime_error);
}

TEST(opBuilderHelperMatchValue, WrongSizeParameters)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+match_value"},
                                 std::vector<std::string> {"$defArray", "$defArray"},
                                 std::make_shared<defs::Definitions>(json::Json(R"({"defArray": [1, 2, 3]})")));
    ASSERT_THROW(std::apply(bld::opBuilderHelperMatchValue, tuple), std::runtime_error);
}

TEST(opBuilderHelperMatchValue, WrongTypeParameters)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+match_value"},
                                 std::vector<std::string> {"defArray"},
                                 std::make_shared<defs::Definitions>(json::Json(R"({"defArray": [1, 2, 3]})")));

    ASSERT_THROW(std::apply(bld::opBuilderHelperMatchValue, tuple), std::runtime_error);
}

TEST(opBuilderHelperMatchValue, SuccessByDefinition)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+match_value"},
                                 std::vector<std::string> {"$defArray"},
                                 std::make_shared<defs::Definitions>(json::Json(
                                     R"({"defArray": [49, true, "hello", null, {"key": "value"}, [1, 2, 3]]})")));

    auto event1 = std::make_shared<json::Json>(R"({"field": 49})");
    auto event2 = std::make_shared<json::Json>(R"({"field": true})");
    auto event3 = std::make_shared<json::Json>(R"({"field": "hello"})");
    auto event4 = std::make_shared<json::Json>(R"({"field": null})");
    auto event5 = std::make_shared<json::Json>(R"({"field": {"key": "value"}})");
    auto event6 = std::make_shared<json::Json>(R"({"field": [1, 2, 3]})");

    auto op = std::apply(bld::opBuilderHelperMatchValue, tuple)->getPtr<Term<EngineOp>>()->getFn();

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

TEST(opBuilderHelperMatchValue, SuccessByReference)
{
    // Event template
    json::Json eventTemplate {R"({"refArray": [49, true, "hello", null, {"key": "value"}, [1, 2, 3]]})"};

    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+match_value"},
                                 std::vector<std::string> {"$refArray"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto event1 = std::make_shared<json::Json>(eventTemplate);
    event1->setInt(49, "/field");
    auto event2 = std::make_shared<json::Json>(eventTemplate);
    event2->setBool(true, "/field");
    auto event3 = std::make_shared<json::Json>(eventTemplate);
    event3->setString("hello", "/field");
    auto event4 = std::make_shared<json::Json>(eventTemplate);
    event4->setNull("/field");
    auto event5 = std::make_shared<json::Json>(eventTemplate);
    event5->set("/field", json::Json {R"({"key": "value"})"});
    auto event6 = std::make_shared<json::Json>(eventTemplate);
    event6->set("/field", json::Json {R"([1, 2, 3])"});

    auto op = std::apply(bld::opBuilderHelperMatchValue, tuple)->getPtr<Term<EngineOp>>()->getFn();

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

TEST(opBuilderHelperMatchValue, ValueNotMatchByDefinition)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+match_value"},
                                 std::vector<std::string> {"$defArray"},
                                 std::make_shared<defs::Definitions>(
                                     json::Json(R"({"defArray": [49, true, "hello", null, {"key": "value"}]})")));

    auto event1 = std::make_shared<json::Json>(R"({"field": 1})");
    auto event2 = std::make_shared<json::Json>(R"({"field": false})");
    auto event3 = std::make_shared<json::Json>(R"({"field": "bye"})");
    auto event4 = std::make_shared<json::Json>(R"({"field": {"key": "new_value"}})");
    auto event5 = std::make_shared<json::Json>(R"({"field": [4, 5, 6]})");

    auto op = std::apply(bld::opBuilderHelperMatchValue, tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);
    ASSERT_FALSE(result.success());

    result = op(event2);
    ASSERT_FALSE(result.success());

    result = op(event3);
    ASSERT_FALSE(result.success());

    result = op(event4);
    ASSERT_FALSE(result.success());

    result = op(event5);
    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperMatchValue, ValueNotMatchByReference)
{
    // Event template
    json::Json eventTemplate {R"({"refArray": [49, true, "hello", null, {"key": "value"}, [1, 2, 3]]})"};

    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+match_value"},
                                 std::vector<std::string> {"$refArray"},
                                 std::make_shared<defs::mocks::FailDef>());

    auto event1 = std::make_shared<json::Json>(eventTemplate);
    event1->setInt(1, "/field");
    auto event2 = std::make_shared<json::Json>(eventTemplate);
    event2->setBool(false, "/field");
    auto event3 = std::make_shared<json::Json>(eventTemplate);
    event3->setString("bye", "/field");
    auto event4 = std::make_shared<json::Json>(eventTemplate);
    event4->setString("not_null", "/field");
    auto event5 = std::make_shared<json::Json>(eventTemplate);
    event5->set("/field", json::Json {R"({"key": "new_value"})"});
    auto event6 = std::make_shared<json::Json>(eventTemplate);
    event6->set("/field", json::Json {R"([4, 5, 6])"});

    auto op = std::apply(bld::opBuilderHelperMatchValue, tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);
    ASSERT_FALSE(result.success());

    result = op(event2);
    ASSERT_FALSE(result.success());

    result = op(event3);
    ASSERT_FALSE(result.success());

    result = op(event4);
    ASSERT_FALSE(result.success());

    result = op(event5);
    ASSERT_FALSE(result.success());

    result = op(event6);
    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperMatchValue, TargetNotFound)
{
    auto tuple = std::make_tuple(std::string {"/targetField"},
                                 std::string {"+match_value"},
                                 std::vector<std::string> {"$defArray"},
                                 std::make_shared<defs::Definitions>(json::Json(R"({"defArray": [1, 2, 3]})")));

    auto event1 = std::make_shared<json::Json>(R"({"field": 1})");

    auto op = std::apply(bld::opBuilderHelperMatchValue, tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);
    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperMatchValue, ParameterNotFound)
{
    // Parameter: Definition
    auto tuple1 = std::make_tuple(std::string {"/field"},
                                  std::string {"+match_value"},
                                  std::vector<std::string> {"$def"},
                                  std::make_shared<defs::Definitions>(json::Json(R"({"defArray": [1, 2, 3]})")));

    auto event = std::make_shared<json::Json>(R"({"field": 1})");

    auto op = std::apply(bld::opBuilderHelperMatchValue, tuple1)->getPtr<Term<EngineOp>>()->getFn();
    result::Result<Event> result = op(event);
    ASSERT_FALSE(result.success());

    // Parameter: Reference
    auto tuple2 = std::make_tuple(std::string {"/field"},
                                  std::string {"+match_value"},
                                  std::vector<std::string> {"$ref"},
                                  std::make_shared<defs::mocks::FailDef>());

    op = std::apply(bld::opBuilderHelperMatchValue, tuple2)->getPtr<Term<EngineOp>>()->getFn();

    result = op(event);
    ASSERT_FALSE(result.success());
}

TEST(opBuilderHelperMatchValue, ParameterIsNotAnArray)
{
    // Parameter: Definition
    auto tuple1 =
        std::make_tuple(std::string {"/field"},
                        std::string {"+match_value"},
                        std::vector<std::string> {"$defObject"},
                        std::make_shared<defs::Definitions>(json::Json(R"({"defObject": {"key": "value"}})")));

    ASSERT_THROW(std::apply(bld::opBuilderHelperMatchValue, tuple1), std::runtime_error);

    // Parameter: Reference
    auto tuple2 = std::make_tuple(std::string {"/field"},
                                  std::string {"+match_value"},
                                  std::vector<std::string> {"$ref"},
                                  std::make_shared<defs::mocks::FailDef>());

    auto event = std::make_shared<json::Json>(R"({"ref": "value", "field": 1})");

    auto op = std::apply(bld::opBuilderHelperMatchValue, tuple2)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);
    ASSERT_FALSE(result.success());
}

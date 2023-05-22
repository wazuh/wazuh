#include <any>
#include <gtest/gtest.h>
#include <vector>

#include <baseTypes.hpp>
#include <defs/defs.hpp>
#include <defs/mocks/failDef.hpp>

#include "opBuilderHelperFilter.hpp"

using namespace base;
namespace bld = builder::internals::builders;

TEST(OpBuilderHelperDefinitionMatchValue, Builds)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+definition_match_value"},
                                 std::vector<std::string> {"$defArray"},
                                 std::make_shared<defs::Definitions>(json::Json(R"({"defArray": [1, 2, 3]})")));
    ASSERT_NO_THROW(std::apply(bld::opBuilderHelperDefinitionMatchValue, tuple));
}

TEST(OpBuilderHelperDefinitionMatchValue, EmptyParameters)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+definition_match_value"},
                                 std::vector<std::string> {},
                                 std::make_shared<defs::Definitions>(json::Json(R"({"defArray": [1, 2, 3]})")));
    ASSERT_THROW(std::apply(bld::opBuilderHelperDefinitionMatchValue, tuple), std::runtime_error);
}

TEST(OpBuilderHelperDefinitionMatchValue, WrongSizeParameters)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+definition_match_value"},
                                 std::vector<std::string> {"$defArray", "$defArray"},
                                 std::make_shared<defs::Definitions>(json::Json(R"({"defArray": [1, 2, 3]})")));
    ASSERT_THROW(std::apply(bld::opBuilderHelperDefinitionMatchValue, tuple), std::runtime_error);
}

TEST(OpBuilderHelperDefinitionMatchValue, WrongTypeParameters)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+definition_match_value"},
                                 std::vector<std::string> {"defArray"},
                                 std::make_shared<defs::Definitions>(json::Json(R"({"defArray": [1, 2, 3]})")));
    ASSERT_THROW(std::apply(bld::opBuilderHelperDefinitionMatchValue, tuple), std::runtime_error);
}

TEST(OpBuilderHelperDefinitionMatchValue, DefinitionIsNotAnArray)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+definition_match_value"},
                                 std::vector<std::string> {"$defArray"},
                                 std::make_shared<defs::Definitions>(json::Json(R"({"defArray": 1})")));

    ASSERT_THROW(std::apply(bld::opBuilderHelperDefinitionMatchValue, tuple), std::runtime_error);
}

TEST(OpBuilderHelperDefinitionMatchValue, Success)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+definition_match_value"},
                                 std::vector<std::string> {"$defArray"},
                                 std::make_shared<defs::Definitions>(
                                     json::Json(R"({"defArray": [49, true, "hello", null, {"key": "value"}]})")));

    auto event1 =
        std::make_shared<json::Json>(R"({"defArray": [49, true, "hello", null, {"key": "value"}], "field": 49})");
    auto event2 =
        std::make_shared<json::Json>(R"({"defArray": [49, true, "hello", null, {"key": "value"}], "field": true})");
    auto event3 =
        std::make_shared<json::Json>(R"({"defArray": [49, true, "hello", null, {"key": "value"}], "field": "hello"})");
    auto event4 =
        std::make_shared<json::Json>(R"({"defArray": [49, true, "hello", null, {"key": "value"}], "field": null})");
    auto event5 = std::make_shared<json::Json>(
        R"({"defArray": [49, true, "hello", null, {"key": "value"}], "field": {"key": "value"}})");

    auto op = std::apply(bld::opBuilderHelperDefinitionMatchValue, tuple)->getPtr<Term<EngineOp>>()->getFn();

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

TEST(OpBuilderHelperDefinitionMatchValue, FailValueNotMatch)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+definition_match_value"},
                                 std::vector<std::string> {"$defArray"},
                                 std::make_shared<defs::Definitions>(
                                     json::Json(R"({"defArray": [49, true, "hello", null, {"key": "value"}]})")));

    auto event1 =
        std::make_shared<json::Json>(R"({"defArray": [49, true, "hello", null, {"key": "value"}], "field": 1})");
    auto event2 =
        std::make_shared<json::Json>(R"({"defArray": [49, true, "hello", null, {"key": "value"}], "field": false})");
    auto event3 =
        std::make_shared<json::Json>(R"({"defArray": [49, true, "hello", null, {"key": "value"}], "field": "bye"})");
    auto event4 = std::make_shared<json::Json>(
        R"({"defArray": [49, true, "hello", null, {"key": "value"}], "field": {"key": "new_value"}})");

    auto op = std::apply(bld::opBuilderHelperDefinitionMatchValue, tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);
    ASSERT_FALSE(result.success());

    result = op(event2);
    ASSERT_FALSE(result.success());

    result = op(event3);
    ASSERT_FALSE(result.success());

    result = op(event4);
    ASSERT_FALSE(result.success());
}

TEST(OpBuilderHelperDefinitionMatchValue, TargetNotFound)
{
    auto tuple = std::make_tuple(std::string {"/targetField"},
                                 std::string {"+definition_match_value"},
                                 std::vector<std::string> {"$defArray"},
                                 std::make_shared<defs::Definitions>(json::Json(R"({"defArray": [1, 2, 3]})")));

    auto event1 = std::make_shared<json::Json>(R"({"defArray": [1, 2, 3], "field": 1})");

    auto op = std::apply(bld::opBuilderHelperDefinitionMatchValue, tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_FALSE(result.success());
}

TEST(OpBuilderHelperDefinitionMatchValue, DefinitionNotFound)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+definition_match_value"},
                                 std::vector<std::string> {"$def"},
                                 std::make_shared<defs::Definitions>(json::Json(R"({"defArray": [1, 2, 3]})")));

    auto event1 = std::make_shared<json::Json>(R"({"defArray": [1, 2, 3], "field": 1})");

    auto op = std::apply(bld::opBuilderHelperDefinitionMatchValue, tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_FALSE(result.success());
}

TEST(OpBuilderHelperDefinitionMatchValue, DefinitionIsAnObject)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+definition_match_value"},
                                 std::vector<std::string> {"$defArray"},
                                 std::make_shared<defs::Definitions>(json::Json(R"({"defArray": {"key": "value"}})")));

    auto event1 = std::make_shared<json::Json>(R"({"defArray": {"key": "value"}, "field": 1})");

    auto op = std::apply(bld::opBuilderHelperDefinitionMatchValue, tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);

    ASSERT_FALSE(result.success());
}

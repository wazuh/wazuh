#include <any>
#include <gtest/gtest.h>
#include <vector>

#include <baseTypes.hpp>

#include "opBuilderHelperFilter.hpp"

using namespace base;
namespace bld = builder::internals::builders;

TEST(OpBuilderHelperContainsString, Builds)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+array_contains"},
                                 std::vector<std::string> {"1", "$ref", "3"});
    ASSERT_NO_THROW(bld::opBuilderHelperContainsString(tuple));
}

TEST(OpBuilderHelperContainsString, EmptyParameters)
{
    auto tuple = std::make_tuple(
        std::string {"/field"}, std::string {"+array_contains"}, std::vector<std::string> {});
    ASSERT_THROW(bld::opBuilderHelperContainsString(tuple), std::runtime_error);
}

TEST(OpBuilderHelperContainsString, Success)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+array_contains"},
                                 std::vector<std::string> {"1", "$ref", "3"});
    auto event1 = std::make_shared<json::Json>(R"({"field": ["1"]})");
    auto event2 = std::make_shared<json::Json>(R"({"field": ["2"], "ref": "2"})");
    auto event3 = std::make_shared<json::Json>(R"({"field": ["3"]})");

    auto op = bld::opBuilderHelperContainsString(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);
    ASSERT_TRUE(result.success());
    result = op(event2);
    ASSERT_TRUE(result.success());
    result = op(event3);
    ASSERT_TRUE(result.success());
}

TEST(OpBuilderHelperContainsString, FailureParametersNotFound)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+array_contains"},
                                 std::vector<std::string> {"1", "$ref", "3"});
    auto event1 = std::make_shared<json::Json>(R"({"field": ["2"]})");
    auto event2 = std::make_shared<json::Json>(R"({"field": ["2"], "ref": "4"})");
    auto event3 = std::make_shared<json::Json>(R"({"field": ["4"]})");

    auto op = bld::opBuilderHelperContainsString(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event1);
    ASSERT_FALSE(result.success());
    result = op(event2);
    ASSERT_FALSE(result.success());
    result = op(event3);
    ASSERT_FALSE(result.success());
}

TEST(OpBuilderHelperContainsString, FailureTargetNotFound)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+array_contains"},
                                 std::vector<std::string> {"1"});
    auto event = std::make_shared<json::Json>(R"({"Otherfield": ["1"]})");

    auto op = bld::opBuilderHelperContainsString(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);
    ASSERT_FALSE(result.success());
}

TEST(OpBuilderHelperContainsString, FailureTargetNotArray)
{
    auto tuple = std::make_tuple(std::string {"/field"},
                                 std::string {"+array_contains"},
                                 std::vector<std::string> {"1"});
    auto event = std::make_shared<json::Json>(R"({"field": "1"})");

    auto op = bld::opBuilderHelperContainsString(tuple)->getPtr<Term<EngineOp>>()->getFn();

    result::Result<Event> result = op(event);
    ASSERT_FALSE(result.success());
}
